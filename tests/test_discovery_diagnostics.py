import asyncio
from dataclasses import replace
from decimal import Decimal

from web3 import Web3

from app import core
from app.scanner import (
    DEFAULT_QUOTES, FACTORIES, HISTORICAL_REPLAY_CASES, SCANNER_NAME,
    FactoryEventProvider, RpcRequestError, ScannerConfig, ScannerService,
    replay_historical_range,
)


def _topic_address(address):
    return bytes.fromhex("00" * 12 + address.removeprefix("0x"))


def _fixture_log(protocol):
    case = HISTORICAL_REPLAY_CASES[protocol]
    spec = FACTORIES[protocol]
    topic0 = Web3.keccak(text=spec["event"])
    if protocol == "uniswap_v4":
        topics = [
            topic0, bytes.fromhex(case["pool_id"].removeprefix("0x")),
            _topic_address(case["currency0_address"]),
            _topic_address(case["currency1_address"]),
        ]
        data = bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000000c8"
            "0000000000000000000000005e320ea6278107968c119942e57d876c5f922acc"
            "0000000000000000000000000000000000005fff3c531962481c82e8ccb0bfdb"
            "00000000000000000000000000000000000000000000000000000000000315d8"
        )
        return {
            "address": spec["address"], "topics": topics, "data": data,
            "blockNumber": hex(case["block_number"]),
            "blockHash": "0xaad2a912baa533d52844d4da7feb4a3da8ddbb3ceb44e3cc5a28e25ba1c9afac",
            "transactionHash": case["tx_hash"], "logIndex": "0x301",
        }
    if protocol == "aerodrome_slipstream":
        return {
            "address": spec["address"],
            "topics": [
                topic0, _topic_address(case["token0_address"]),
                _topic_address(case["token1_address"]), (2000).to_bytes(32, "big"),
            ],
            "data": _topic_address(case["pool_address"]),
            "blockNumber": hex(case["block_number"]),
            "blockHash": "0xf4e78255511cdedfb7015a674bdd0e212bbb74810f850746dd872ec87c497af6",
            "transactionHash": case["tx_hash"], "logIndex": "0x4f7",
        }
    third_topic = (10000 if protocol == "uniswap_v3" else 0).to_bytes(32, "big")
    pool_word = _topic_address(case["pool_address"])
    data = ((200).to_bytes(32, "big") + pool_word if protocol == "uniswap_v3"
            else pool_word + (1539).to_bytes(32, "big"))
    return {
        "address": spec["address"],
        "topics": [topic0, _topic_address(case["token0_address"]),
                   _topic_address(case["token1_address"]), third_topic],
        "data": data, "blockNumber": hex(case["block_number"]),
        "blockHash": "0x" + "11" * 32,
        "transactionHash": case["tx_hash"], "logIndex": "0x1",
    }


def _provider(protocol, logs):
    spec = {"protocol": protocol, **FACTORIES[protocol]}

    class Rpc:
        def request(self, method, _params, **_context):
            assert method == "eth_getLogs"
            return logs

    provider = object.__new__(FactoryEventProvider)
    provider.rpc = Rpc()
    provider.provider_host = "mock.base"
    provider.factories = {spec["address"].lower(): spec}
    provider.topics = {Web3.keccak(text=spec["event"]).hex(): spec}
    return provider


def _config(**changes):
    base = ScannerConfig(
        protocols=("uniswap_v3", "aerodrome_v2"), confirmations=10,
        bootstrap_blocks=8, start_block=None, chunk_size=8, poll_seconds=1,
        reorg_rewind_blocks=20, queue_size=10, analysis_workers=1,
        circuit_failures=3, circuit_cooldown_seconds=60,
        min_liquidity_usd=Decimal("1000"), max_token_age_hours=48,
        max_risk_score=35, min_evidence_confidence=60,
        alert_min_interval_seconds=0, alert_max_per_hour=10,
        quote_assets=frozenset(item.lower() for item in DEFAULT_QUOTES),
    )
    return replace(base, **changes)


def test_verified_historical_replays_decode_all_protocols_without_db_writes(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "replay.db"))
    core.save_checkpoint(SCANNER_NAME, 500, "0xcheckpoint")

    for protocol in HISTORICAL_REPLAY_CASES:
        case = HISTORICAL_REPLAY_CASES[protocol]
        result = replay_historical_range(
            _provider(protocol, [_fixture_log(protocol)]),
            case["block_number"], case["block_number"],
        )
        assert result["isolated"] is True
        assert result["raw_log_count"] == 1
        assert len(result["events"]) == 1
        assert result["decode_failures"] == 0
        event = result["events"][0]
        assert event["tx_hash"].lower() == case["tx_hash"].lower()
        assert event["block_number"] == case["block_number"]
        assert event["source"] == "base_rpc"
        assert event["verification_status"] == "verified_onchain"
        if protocol == "uniswap_v4":
            assert event["pool_address"] is None
            assert event["pool_id"].lower() == case["pool_id"].lower()
            assert event["currency0_address"].lower() == case[
                "currency0_address"
            ].lower()
            assert event["currency1_address"].lower() == case[
                "currency1_address"
            ].lower()
            assert event["token0_address"].lower() == case[
                "token0_address"
            ].lower()
            assert event["hook_address"].lower() == (
                "0x5e320ea6278107968c119942e57d876c5f922acc"
            )
        else:
            assert event["pool_address"].lower() == case["pool_address"].lower()
        assert event["token0_address"].lower() == case["token0_address"].lower()
        assert event["token1_address"].lower() == case["token1_address"].lower()

    assert core.get_checkpoint(SCANNER_NAME)["block_number"] == 500
    assert core.recent_tokens() == []
    assert core.list_watchlist() == []


def test_decode_failure_is_not_reported_as_empty_range(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "decode.db"))
    raw = _fixture_log("aerodrome_v2")
    raw["data"] = "0x1234"
    batch = _provider("aerodrome_v2", [raw]).fetch_batch(16894743, 16894743)
    assert batch["raw_log_count"] == 1
    assert batch["events"] == []
    assert batch["decode_failures"] == 1
    assert "shorter" in batch["decode_errors"][0]["reason"]


def test_decode_failure_does_not_advance_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "decode-checkpoint.db"))

    class MalformedBatchProvider(EmptyProvider):
        def fetch_batch(self, _start, _end):
            return {
                "events": [], "raw_log_count": 1, "decode_failures": 1,
                "decode_errors": [{"log_offset": 0, "reason": "bad ABI data"}],
                "protocol_event_counts": {"aerodrome_v2": 1},
                "decode_failures_by_protocol": {"aerodrome_v2": 1},
            }

    service = ScannerService(config=_config(), provider=MalformedBatchProvider())
    assert asyncio.run(service.scan_once()) == 0
    assert core.get_checkpoint(SCANNER_NAME) is None
    status = service.discovery_status()
    assert status["metrics"]["decode_failures"] == 1
    assert status["metrics"]["empty_ranges"] == 0
    assert status["recent_errors"][0]["stage"] == "decode"
    protocol = next(
        row for row in service.protocol_status()["protocols"]
        if row["protocol"] == "aerodrome_v2"
    )
    assert protocol["decoding_failures"] == 1
    assert protocol["blocks_scanned"] == 0
    assert protocol["last_successful_scan"] is None


class EmptyProvider:
    provider_host = "mock.base"

    def head(self):
        return 120

    def block_hash(self, block):
        return f"0xhash{block}"

    def fetch(self, _start, _end):
        return []


def test_empty_ranges_and_provider_failures_have_distinct_metrics(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "metrics.db"))
    service = ScannerService(config=_config(), provider=EmptyProvider())
    assert asyncio.run(service.scan_once()) == 0
    status = service.discovery_status()
    assert status["metrics"]["scanned_ranges"] == 1
    assert status["metrics"]["empty_ranges"] == 1
    assert status["metrics"]["pool_events_found"] == 0

    class Broken(EmptyProvider):
        def fetch(self, start, end):
            raise RpcRequestError(
                "http_transport", "eth_getLogs", provider_host=self.provider_host,
                http_status=500, safe_message="HTTP 500", from_block=start,
                to_block=end, retryable=False,
            )

    core.save_checkpoint(SCANNER_NAME, 100, "0xhash100")
    broken = ScannerService(config=_config(), provider=Broken())
    assert asyncio.run(broken.scan_once()) == 0
    status = broken.discovery_status()
    assert status["metrics"]["provider_failures"] == 1
    assert status["recent_errors"][0]["stage"] == "provider"
    assert core.get_checkpoint(SCANNER_NAME)["block_number"] == 100


def test_duplicate_pool_persists_once_and_recent_is_not_watchlist_dependent(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "duplicate.db"))
    case = HISTORICAL_REPLAY_CASES["uniswap_v3"]
    event = replay_historical_range(
        _provider("uniswap_v3", [_fixture_log("uniswap_v3")]),
        case["block_number"], case["block_number"],
    )["events"][0]
    first = core.record_pool(event, [case["token1_address"]], True)
    second = core.record_pool(event, [case["token1_address"]], True)
    assert first == {"should_process": True, "new_tokens": 1}
    assert second == {"should_process": False, "new_tokens": 0}
    assert len(core.recent_tokens()) == 1
    assert core.list_watchlist() == []


def test_unsupported_token_is_analyzed_rejected_and_counted(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "unsupported.db"))
    address = "0x00000000000000000000000000000000000000A1"
    result = {
        "address": address, "decision": "NO_BUY", "mode": "PAPER_ONLY",
        "contract": {"contract_type": "unknown_contract"},
        "risk": {"risk_score": 100, "evidence_confidence": 80,
                 "hard_rejections": ["address is not a recognized token"],
                 "assessment": "REJECTED"},
        "market": {"liquidity_usd": None, "oldest_pair_age_days": None},
        "developer": {},
    }
    service = ScannerService(
        config=_config(), provider=EmptyProvider(), analyzer=lambda *_: result
    )
    asyncio.run(service._analyze(address, None))
    metrics = core.discovery_diagnostics()["metrics"]
    assert metrics["tokens_analyzed"] == 1
    assert metrics["unsupported_tokens"] == 1
    assert metrics["rejected_tokens"] == 1
    assert metrics["watchlist_filtered"] == 1
    assert core.list_watchlist() == []
