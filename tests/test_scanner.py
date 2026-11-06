import asyncio
from dataclasses import replace
from decimal import Decimal

from web3 import Web3

from app import core
from app.scanner import (
    BASE_WETH, DEFAULT_QUOTES, FACTORIES, NATIVE_CURRENCY, SCANNER_NAME,
    DexScreenerProvider, FactoryEventProvider,
    ScannerConfig, ScannerService,
)


TOKEN = "0x00000000000000000000000000000000000000A1"
TOKEN2 = "0x00000000000000000000000000000000000000A2"
POOL = "0x00000000000000000000000000000000000000B1"
POOL2 = "0x00000000000000000000000000000000000000B2"
FACTORY = "0x33128a8fC17869897dcE68Ed026d694621f6FDfD"
DEVELOPER = "0x00000000000000000000000000000000000000D1"
FUNDER = "0x00000000000000000000000000000000000000F1"
QUOTE = DEFAULT_QUOTES[0]


def config(**changes):
    base = ScannerConfig(
        protocols=("uniswap_v3",), confirmations=10, bootstrap_blocks=11,
        start_block=None, chunk_size=50, poll_seconds=1,
        reorg_rewind_blocks=20, queue_size=10, analysis_workers=1,
        circuit_failures=2, circuit_cooldown_seconds=60,
        min_liquidity_usd=Decimal("1000"), max_token_age_hours=48,
        max_risk_score=35, min_evidence_confidence=60,
        alert_min_interval_seconds=0, alert_max_per_hour=10,
        quote_assets=frozenset(address.lower() for address in DEFAULT_QUOTES),
    )
    return replace(base, **changes)


def event(pool=POOL, token=TOKEN, block=105):
    return {
        "protocol": "uniswap_v3", "factory_address": FACTORY,
        "pool_address": pool, "token0_address": token,
        "token1_address": QUOTE, "block_number": block,
        "block_hash": f"0xblock{block}", "tx_hash": f"0xtx{block}",
        "log_index": 0,
    }


class Provider:
    def __init__(self, head=120, events=None, hashes=None):
        self.value = head
        self.events = list(events or [])
        self.hashes = hashes or {}
        self.fetch_calls = []
        self.head_calls = 0

    def head(self):
        self.head_calls += 1
        return self.value

    def block_hash(self, block):
        return self.hashes.get(block, f"0xblock{block}")

    def fetch(self, start, end):
        self.fetch_calls.append((start, end))
        return [item.copy() for item in self.events
                if start <= item["block_number"] <= end]


def test_verified_factory_log_resolves_pool_tokens_and_block():
    spec = {"protocol": "uniswap_v3", **FACTORIES["uniswap_v3"]}
    topic0 = Web3.keccak(text=spec["event"])

    def topic_address(address):
        return bytes.fromhex("00" * 12 + address[2:])

    pool_word = bytes.fromhex("00" * 12 + POOL[2:])
    tick_spacing = (60).to_bytes(32, "big")
    raw_log = {
        "address": FACTORY, "topics": [topic0, topic_address(TOKEN),
                                         topic_address(QUOTE), (3000).to_bytes(32, "big")],
        "data": tick_spacing + pool_word, "blockNumber": 105,
        "blockHash": bytes.fromhex("11" * 32),
        "transactionHash": bytes.fromhex("22" * 32), "logIndex": 7,
    }

    class Rpc:
        def request(self, method, params, **_context):
            assert method == "eth_getLogs"
            assert params[0]["fromBlock"] == "0x64"
            assert params[0]["toBlock"] == "0x6e"
            return [raw_log]

    provider = object.__new__(FactoryEventProvider)
    provider.rpc = Rpc()
    provider.provider_host = "mock.base"
    provider.factories = {FACTORY.lower(): spec}
    provider.topics = {topic0.hex(): spec}

    result = provider.fetch(100, 110)

    assert len(result) == 1
    assert result[0]["pool_address"].lower() == POOL.lower()
    assert result[0]["token0_address"].lower() == TOKEN.lower()
    assert result[0]["token1_address"].lower() == QUOTE.lower()
    assert result[0]["block_number"] == 105
    assert result[0]["factory_address"].lower() == FACTORY.lower()


def test_new_protocol_addresses_and_signatures_match_deployed_abis():
    assert FACTORIES["uniswap_v4"]["address"].lower() == (
        "0x498581ff718922c3f8e6a244956af099b2652b2b"
    )
    assert FACTORIES["uniswap_v4"]["event"] == (
        "Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)"
    )
    assert Web3.keccak(text=FACTORIES["uniswap_v4"]["event"]).hex() == (
        "dd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438"
    )
    assert FACTORIES["aerodrome_slipstream"]["address"].lower() == (
        "0x5e7bb104d84c7cb9b682aac2f3d509f5f406809a"
    )
    assert FACTORIES["aerodrome_slipstream"]["event"] == (
        "PoolCreated(address,address,int24,address)"
    )
    assert Web3.keccak(
        text=FACTORIES["aerodrome_slipstream"]["event"]
    ).hex() == "ab0d57f0df537bb25e80245ef7748fa62353808c54d6e528a9dd20887aed9ac2"


def test_uniswap_v4_native_currency_is_preserved_and_maps_to_weth():
    spec = {"protocol": "uniswap_v4", **FACTORIES["uniswap_v4"]}
    pool_id = bytes.fromhex(
        "9aef1fbb04d277b2c00dee63ba94e83d7bc74bd77a303fb67be41314aecc0d1b"
    )

    def topic_address(address):
        return bytes.fromhex("00" * 12 + address.removeprefix("0x"))

    data = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000c8"
        "0000000000000000000000005e320ea6278107968c119942e57d876c5f922acc"
        "0000000000000000000000000000000000005fff3c531962481c82e8ccb0bfdb"
        "00000000000000000000000000000000000000000000000000000000000315d8"
    )
    log = {
        "address": spec["address"],
        "topics": [
            Web3.keccak(text=spec["event"]), pool_id,
            topic_address(NATIVE_CURRENCY),
            topic_address("0xf2Ff5654dDE217F82e7602698Fe23Ba4100Ccccc"),
        ],
        "data": data, "blockNumber": "0x330d1fd",
        "blockHash": "0xaad2a912baa533d52844d4da7feb4a3da8ddbb3ceb44e3cc5a28e25ba1c9afac",
        "transactionHash": "0x296eca8ef3428cabc6085a6a718928e271beb33f733477f4cf0f4bad6f593e2e",
        "logIndex": "0x301",
    }

    class Rpc:
        def request(self, method, _params, **_context):
            assert method == "eth_getLogs"
            return [log]

    provider = object.__new__(FactoryEventProvider)
    provider.rpc = Rpc()
    provider.provider_host = "mock.base"
    provider.factories = {spec["address"].lower(): spec}
    provider.topics = {Web3.keccak(text=spec["event"]).hex(): spec}
    batch = provider.fetch_batch(53531133, 53531133)

    assert batch["decode_failures"] == 0
    event = batch["events"][0]
    assert event["pool_id"] == (
        "0x9aef1fbb04d277b2c00dee63ba94e83d7bc74bd77a303fb67be41314aecc0d1b"
    )
    assert event["pool_address"] is None
    assert event["currency0_address"].lower() == NATIVE_CURRENCY
    assert event["token0_address"] == BASE_WETH
    assert event["token1_address"].lower() == (
        "0xf2ff5654dde217f82e7602698fe23ba4100ccccc"
    )
    assert event["chain_id"] == 8453
    assert event["verification_status"] == "verified_onchain"


def test_dexscreener_uses_documented_base_endpoints_and_separates_timestamps(
    monkeypatch,
):
    monkeypatch.setattr("app.scanner.time.sleep", lambda _seconds: None)

    class DexResponse:
        def __init__(self, value):
            self.value = value

        def raise_for_status(self):
            return None

        def json(self):
            return self.value

    class DexSession:
        def __init__(self):
            self.calls = []

        def get(self, url, **_kwargs):
            self.calls.append(url)
            if url.endswith("/token-profiles/latest/v1"):
                return DexResponse([
                    {"chainId": "base", "tokenAddress": TOKEN},
                    {"chainId": "ethereum", "tokenAddress": TOKEN2},
                ])
            return DexResponse([
                {
                    "chainId": "base", "dexId": "aerodrome-slipstream",
                    "pairAddress": POOL, "pairCreatedAt": 1700000000000,
                    "baseToken": {"address": TOKEN},
                    "quoteToken": {"address": QUOTE},
                },
                {
                    "chainId": "base", "dexId": "uniswap-v4",
                    "pairAddress": "0x" + "11" * 32,
                    "baseToken": {"address": TOKEN},
                    "quoteToken": {"address": QUOTE},
                },
                {
                    "chainId": "base", "dexId": "uniswap-v4",
                    "pairAddress": FACTORIES["uniswap_v4"]["address"],
                    "baseToken": {"address": TOKEN},
                    "quoteToken": {"address": QUOTE},
                },
            ])

    session = DexSession()
    provider = DexScreenerProvider(session=session)
    batch = provider.fetch_batch()
    events = batch["events"]
    assert len(events) == 2
    assert batch["raw_log_count"] == 3
    assert batch["ignored_pairs"] == 1
    assert session.calls == [
        "https://api.dexscreener.com/token-profiles/latest/v1",
        f"https://api.dexscreener.com/tokens/v1/base/{Web3.to_checksum_address(TOKEN)}",
    ]
    event = events[0]
    assert event["chain_id"] == 8453
    assert event["pool_address"].lower() == POOL.lower()
    assert event["block_number"] is None
    assert event["tx_hash"] is None
    assert event["source"] == "dexscreener"
    assert event["verification_status"] == "reported_unverified"
    assert event["source_created_at"] == "2023-11-14T22:13:20+00:00"
    assert event["discovered_at"] != event["source_created_at"]
    assert events[1]["pool_address"] is None
    assert events[1]["pool_id"] == "0x" + "11" * 32
    assert provider.usage_status()["requests_made"] == 2
    assert provider.usage_status()["requests_by_endpoint"] == {
        "token-profiles": 1, "tokens": 1,
    }


def test_secondary_pool_is_normalized_and_recent_even_when_rejected(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "secondary.db"))

    class Secondary:
        calls = 0

        def fetch_batch(self):
            self.calls += 1
            return {
                "events": [{
                    "chain_id": 8453, "protocol": "aerodrome-slipstream",
                    "pool_address": POOL, "pool_id": None,
                    "factory_address": None, "token0_address": TOKEN,
                    "token1_address": QUOTE, "currency0_address": None,
                    "currency1_address": None, "block_number": None,
                    "block_hash": None, "tx_hash": None, "log_index": None,
                    "source": "dexscreener",
                    "verification_status": "reported_unverified",
                    "discovered_at": "2026-11-05T05:00:00+00:00",
                    "source_created_at": "2026-11-04T05:00:00+00:00",
                }],
                "raw_log_count": 1,
            }

    secondary = Secondary()
    service = ScannerService(
        config=config(), provider=Provider(), secondary_provider=secondary,
        analyzer=lambda *_: analysis(),
    )
    assert asyncio.run(service.scan_once()) == 0
    rejected = analysis()
    rejected["decision"] = "NO_BUY"
    rejected["risk"]["assessment"] = "REJECTED"
    core.update_token_analysis(TOKEN, rejected)
    assert core.recent_tokens(10)[0]["address"].lower() == TOKEN.lower()
    assert core.recent_tokens(10)[0]["analysis_state"] == "REJECTED"
    with core.db_connect() as con:
        row = con.execute(
            "SELECT source,verification_status,block_number,source_created_at,"
            "discovered_at FROM discovered_pools"
        ).fetchone()
    assert row == (
        "dexscreener", "reported_unverified", None,
        "2026-11-04T05:00:00+00:00", "2026-11-05T05:00:00+00:00",
    )
    status = service.protocol_status()["protocols"]
    dex = next(item for item in status if item["protocol"] == "dexscreener")
    assert dex["blocks_scanned"] == 0
    assert dex["events_detected"] == 1
    assert dex["last_successful_scan"] is not None
    restarted = ScannerService(
        config=config(), provider=Provider(), secondary_provider=secondary,
    )
    assert asyncio.run(restarted._scan_secondary()) == 0
    assert secondary.calls == 1


def test_pool_identity_deduplicates_sources_but_keeps_distinct_v4_ids(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "pool-identities.db"))
    pool_id = "0x" + "11" * 32
    base = {
        "chain_id": 8453, "protocol": "uniswap_v4",
        "pool_address": None, "pool_id": pool_id,
        "factory_address": FACTORIES["uniswap_v4"]["address"],
        "token0_address": TOKEN, "token1_address": QUOTE,
        "currency0_address": NATIVE_CURRENCY,
        "currency1_address": QUOTE, "block_number": 100,
        "block_hash": "0xblock", "tx_hash": "0xtx", "log_index": 1,
        "source": "base_rpc", "verification_status": "verified_onchain",
    }
    assert core.record_discovered_pool(base, [TOKEN], True) == {
        "should_process": True, "new_tokens": 1,
    }
    assert core.record_discovered_pool(base, [TOKEN], True) == {
        "should_process": False, "new_tokens": 0,
    }
    other = {**base, "pool_id": "0x" + "22" * 32, "log_index": 2}
    assert core.record_discovered_pool(other, [TOKEN], True)["should_process"]
    with core.db_connect() as con:
        assert con.execute(
            "SELECT COUNT(*) FROM discovered_pools"
        ).fetchone()[0] == 2
        assert con.execute("SELECT COUNT(*) FROM pools").fetchone()[0] == 0


def test_dex_pool_is_promoted_by_onchain_log_without_duplicate_processing(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "source-promotion.db"))
    reported = {
        "chain_id": 8453, "protocol": "aerodrome-slipstream",
        "pool_address": POOL, "pool_id": None, "factory_address": None,
        "token0_address": TOKEN, "token1_address": QUOTE,
        "block_number": None, "block_hash": None, "tx_hash": None,
        "log_index": None, "source": "dexscreener",
        "verification_status": "reported_unverified",
    }
    core.record_discovered_pool(reported, [TOKEN], True)
    verified = {
        **event(), "protocol": "aerodrome_slipstream",
        "factory_address": FACTORIES["aerodrome_slipstream"]["address"],
        "source": "base_rpc", "verification_status": "verified_onchain",
    }
    persisted = core.record_pool(verified, [TOKEN], True)
    assert persisted == {"should_process": False, "new_tokens": 0}
    with core.db_connect() as con:
        rows = con.execute(
            "SELECT protocol,source,verification_status,block_number "
            "FROM discovered_pools"
        ).fetchall()
    assert rows == [
        ("aerodrome_slipstream", "base_rpc", "verified_onchain", 105)
    ]


def test_reorg_marks_pool_identities_noncanonical_and_rewinds_protocol_cursor(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "normalized-reorg.db"))
    v4 = {
        "chain_id": 8453, "protocol": "uniswap_v4", "pool_address": None,
        "pool_id": "0x" + "33" * 32,
        "factory_address": FACTORIES["uniswap_v4"]["address"],
        "token0_address": TOKEN, "token1_address": QUOTE,
        "block_number": 100, "block_hash": "0xold", "tx_hash": "0xtx",
        "log_index": 1, "source": "base_rpc",
        "verification_status": "verified_onchain",
    }
    core.record_discovered_pool(v4, [TOKEN], True)
    core.save_scan_checkpoint(
        SCANNER_NAME, 110, "0xcheckpoint",
        {"uniswap_v4": {"blocks_scanned": 11, "events_detected": 1}},
    )
    assert core.mark_reorg(100) == 1
    with core.db_connect() as con:
        assert con.execute(
            "SELECT canonical FROM discovered_pools"
        ).fetchone()[0] == 0
        assert con.execute(
            "SELECT analysis_state FROM tokens WHERE address=?",
            (Web3.to_checksum_address(TOKEN),),
        ).fetchone()[0] == "ORPHANED"
        status = con.execute(
            "SELECT cursor_block,blocks_scanned FROM protocol_scan_status "
            "WHERE protocol='uniswap_v4'"
        ).fetchone()
    assert status == (99, 0)


def analysis(address=TOKEN):
    return {
        "address": address, "decision": "WATCHLIST", "mode": "PAPER_ONLY",
        "risk": {"risk_score": 20, "evidence_confidence": 80,
                 "hard_rejections": [], "assessment": "INCONCLUSIVE"},
        "market": {"liquidity_usd": "50000", "oldest_pair_age_days": "0.5"},
        "developer": {
            "deployer": DEVELOPER, "owner": DEVELOPER, "factory": None,
            "funding_wallet": {"address": FUNDER,
                               "evidence": "earliest inbound native transfer"},
            "source": "mock explorer creation record",
        },
    }


def test_discovery_deduplicates_and_resumes_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "scanner.db"))
    provider = Provider(events=[event()])
    service = ScannerService(config=config(), provider=provider,
                             analyzer=lambda *_: analysis())

    assert asyncio.run(service.scan_once()) == 1
    assert asyncio.run(service.scan_once()) == 0
    assert provider.fetch_calls == [(100, 110)]
    assert core.get_checkpoint(SCANNER_NAME)["block_number"] == 110
    protocol = next(
        row for row in service.protocol_status()["protocols"]
        if row["protocol"] == "uniswap_v3"
    )
    assert protocol["blocks_scanned"] == 11
    assert protocol["events_detected"] == 1
    assert protocol["decoding_failures"] == 0
    assert protocol["cursor_block"] == 110
    with core.db_connect() as con:
        assert con.execute("SELECT COUNT(*) FROM pools").fetchone()[0] == 1
        assert con.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 1

    restarted_provider = Provider(head=130)
    restarted = ScannerService(config=config(), provider=restarted_provider,
                               analyzer=lambda *_: analysis())
    assert asyncio.run(restarted.scan_once()) == 0
    assert restarted_provider.fetch_calls == [(111, 120)]
    assert core.get_checkpoint(SCANNER_NAME)["block_number"] == 120


def test_new_protocols_backfill_from_saved_start_without_skipping_ranges(
    monkeypatch, tmp_path,
):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "protocol-backfill.db"))
    first = ScannerService(config=config(), provider=Provider())
    asyncio.run(first.scan_once())
    assert core.get_checkpoint(SCANNER_NAME)["block_number"] == 110

    protocols = (
        "uniswap_v3", "aerodrome_v2", "uniswap_v4", "aerodrome_slipstream",
    )
    expanded_provider = Provider()
    expanded = ScannerService(
        config=config(protocols=protocols), provider=expanded_provider
    )
    asyncio.run(expanded.scan_once())

    assert expanded_provider.fetch_calls == [(100, 110)]
    assert core.get_checkpoint(SCANNER_NAME)["block_number"] == 110
    status = {
        row["protocol"]: row
        for row in expanded.protocol_status()["protocols"]
    }
    for protocol in ("uniswap_v4", "aerodrome_slipstream"):
        assert status[protocol]["cursor_block"] == 110
        assert status[protocol]["blocks_scanned"] == 11
        assert status[protocol]["last_successful_scan"] is not None
    assert expanded.protocol_status()["pending_protocol_backfill_from"] is None


def test_alchemy_provider_retains_ten_block_getlogs_cap(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "alchemy-cap.db"))
    provider = Provider()
    provider.provider_host = "base-mainnet.g.alchemy.com"
    service = ScannerService(config=config(), provider=provider)
    assert service.provider_max_block_range == 10
    assert service.effective_chunk_size == 10


def test_reorg_rewinds_and_marks_missing_pool_noncanonical(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "reorg.db"))
    core.record_pool(event(pool=POOL, block=105), [TOKEN])
    core.record_pool(event(pool=POOL2, token=TOKEN2, block=108), [TOKEN2])
    core.save_checkpoint(SCANNER_NAME, 110, "0xoldhash")
    provider = Provider(head=130, events=[event(pool=POOL, block=105)],
                        hashes={110: "0xnewhash"})
    service = ScannerService(config=config(), provider=provider,
                             analyzer=lambda *_: analysis())

    assert asyncio.run(service.scan_once()) == 1
    assert provider.fetch_calls[0][0] == 90
    with core.db_connect() as con:
        rows = {address.lower(): canonical for address, canonical in con.execute(
            "SELECT pool_address,canonical FROM pools"
        ).fetchall()}
    assert rows[POOL.lower()] == 1
    assert rows[POOL2.lower()] == 0
    with core.db_connect() as con:
        assert con.execute(
            "SELECT analysis_state FROM tokens WHERE address=?",
            (Web3.to_checksum_address(TOKEN2),)
        ).fetchone()[0] == "ORPHANED"
    assert core.get_checkpoint(SCANNER_NAME)["block_number"] == 120


def test_provider_failure_opens_circuit_without_advancing_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "failure.db"))

    class BrokenProvider(Provider):
        def head(self):
            self.head_calls += 1
            raise ConnectionError("provider unavailable with ?apikey=secret")

    provider = BrokenProvider()
    service = ScannerService(config=config(), provider=provider,
                             analyzer=lambda *_: analysis())

    assert asyncio.run(service.scan_once()) == 0
    assert asyncio.run(service.scan_once()) == 0
    assert service.status()["circuit_open"] is True
    assert core.get_checkpoint(SCANNER_NAME) is None
    assert "secret" not in service.last_error  # message is bounded but never logged to Telegram
    calls = provider.head_calls
    assert asyncio.run(service.scan_once()) == 0
    assert provider.head_calls == calls


def test_focus_pauses_discovery_but_queues_related_token(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "focus.db"))
    core.record_pool(event(), [TOKEN])
    core.record_developer_evidence(TOKEN, analysis()["developer"])
    core.write_state("scanner_enabled", True)
    core.set_focus(DEVELOPER)
    provider = Provider()
    service = ScannerService(config=config(), provider=provider,
                             analyzer=lambda *_: analysis())

    assert asyncio.run(service.scan_once()) == 0
    assert provider.head_calls == 0
    queued, _ = service.queue.get_nowait()
    assert queued == TOKEN
    assert core.read_state("scanner_enabled") is True


def test_wallet_relationships_are_evidence_not_identity_claims(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "relationships.db"))
    core.record_developer_evidence(TOKEN, analysis()["developer"])

    summary = core.developer_summary(DEVELOPER)
    assert {item["role"] for item in summary["history"]} == {
        "deployer", "token_owner"
    }
    assert summary["funding_links"][0]["funding_address"].lower() == FUNDER.lower()
    with core.db_connect() as con:
        evidence = con.execute("SELECT evidence FROM funding_links").fetchone()[0]
    assert '"ownership_claim": false' in evidence


def test_analysis_failure_is_inconclusive(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "inconclusive.db"))
    core.record_pool(event(), [TOKEN])

    def fail(*_args):
        raise TimeoutError("analysis provider unavailable")

    service = ScannerService(config=config(), provider=Provider(), analyzer=fail)
    asyncio.run(service._analyze(TOKEN, event()))
    with core.db_connect() as con:
        row = con.execute(
            "SELECT analysis_state,decision FROM tokens WHERE address=?", (TOKEN,)
        ).fetchone()
    assert row == ("INCONCLUSIVE", "WATCHLIST")


def test_watchlist_alert_is_rate_limited_and_deduplicated(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "alerts.db"))
    core.record_pool(event(), [TOKEN])
    sent = []

    async def alert(message):
        sent.append(message)

    service = ScannerService(
        config=config(), provider=Provider(), analyzer=lambda *_: analysis(),
        alert_callback=alert,
    )
    asyncio.run(service._analyze(TOKEN, event()))
    asyncio.run(service._analyze(TOKEN, event(pool=POOL2)))

    assert len(sent) == 1
    assert "PAPER ONLY" in sent[0]
    assert "Assessment: INCONCLUSIVE" in sent[0]
    assert "Liquidity source status: UNKNOWN" in sent[0]
    assert "Scope: token_pair_data_not_pool_matched" in sent[0]
    assert "private" not in sent[0].lower()
    assert len(core.list_watchlist()) == 1
    with core.db_connect() as con:
        assert con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1


def test_v4_market_attribution_matches_bytes32_id_without_contract_address():
    pool_id = "0x" + "44" * 32
    result = {
        "market": {
            "pair_count": 1, "liquidity_usd": "31450000",
            "pair_details": [{
                "pair_id": pool_id, "pair_identity_type": "bytes32_pool_id",
                "liquidity_usd": "31450000",
            }],
        }
    }
    event = {"pool_id": pool_id, "pool_address": None}

    ScannerService._attribute_market_to_discovery(result, event)

    market = result["market"]
    assert market["discovered_pool_identity"] == pool_id
    assert market["discovered_pool_identity_type"] == "bytes32_pool_id"
    assert market["discovered_pool_pair_match"] is True
    assert market["discovered_pool_liquidity_usd"] == "31450000"
    assert market["liquidity_attribution"] == "single_discovered_pool"


def test_v4_scanner_alert_uses_same_provenance_labels(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "v4-alert.db"))
    pool_id = "0x" + "55" * 32
    sent = []

    async def alert(message):
        sent.append(message)

    service = ScannerService(
        config=config(), provider=Provider(), analyzer=lambda *_: analysis(),
        alert_callback=alert,
    )
    result = analysis()
    result["market"].update({
        "liquidity_source_status": "PROVIDER_REPORTED_UNVERIFIED",
        "liquidity_attribution": "single_discovered_pool",
    })

    asyncio.run(service._alert(
        TOKEN, result, {"pool_id": pool_id, "pool_address": None}
    ))

    assert len(sent) == 1
    assert f"Pool ID: {pool_id}" in sent[0]
    assert "Assessment: INCONCLUSIVE" in sent[0]
    assert "Liquidity source status: PROVIDER_REPORTED_UNVERIFIED" in sent[0]
    assert "Scope: single_discovered_pool" in sent[0]
