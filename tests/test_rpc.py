import asyncio
import json
from dataclasses import replace
from decimal import Decimal

import pytest
import requests
from web3 import Web3

from app import core
from app.scanner import (
    DEFAULT_QUOTES, FACTORIES, SCANNER_NAME, FactoryEventProvider,
    JsonRpcClient, RpcBudget, RpcRequestError, ScannerConfig, ScannerService,
)


class Response:
    def __init__(self, status, payload=None, invalid_json=False):
        self.status_code = status
        self.payload = payload
        self.invalid_json = invalid_json

    def json(self):
        if self.invalid_json:
            raise ValueError("not json")
        return self.payload


class Session:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def client(*results):
    return JsonRpcClient(
        "https://user:password@rpc.example.test/v2/private?apikey=secret",
        session=Session(*results), timeout=1,
    )


def test_http_429_is_typed_and_sanitized():
    rpc = client(Response(429, {"error": {"code": -32005,
                 "message": "limit at https://rpc/?apikey=secret"}}))

    with pytest.raises(RpcRequestError) as caught:
        rpc.request("eth_getLogs", [{}], from_block=10, to_block=20)

    error = caught.value
    assert error.category == "rate_limit"
    assert error.http_status == 429
    assert error.retryable is True
    assert error.reduce_range is True
    diagnostic = error.diagnostic(1)
    assert diagnostic["provider_host"] == "rpc.example.test"
    assert diagnostic["from_block"] == 10
    assert "secret" not in json.dumps(diagnostic)
    assert "password" not in json.dumps(diagnostic)


@pytest.mark.parametrize(
    "status,retryable", [(403, False), (500, True)]
)
def test_http_transport_statuses_are_distinct(status, retryable):
    rpc = client(Response(status, {"message": "provider response"}))

    with pytest.raises(RpcRequestError) as caught:
        rpc.request("eth_blockNumber", [])

    assert caught.value.category == "http_transport"
    assert caught.value.http_status == status
    assert caught.value.retryable is retryable


def test_json_rpc_range_error_is_not_http_failure():
    rpc = client(Response(200, {
        "jsonrpc": "2.0", "id": 1,
        "error": {"code": -32005, "message": "block range is too large"},
    }))

    with pytest.raises(RpcRequestError) as caught:
        rpc.request("eth_getLogs", [{}], from_block=1, to_block=500)

    assert caught.value.category == "json_rpc"
    assert caught.value.rpc_code == -32005
    assert caught.value.reduce_range is True


def test_timeout_and_malformed_response_are_distinct():
    timeout_rpc = client(requests.Timeout("https://secret.example/?key=x"))
    with pytest.raises(RpcRequestError) as timeout:
        timeout_rpc.request("eth_chainId", [])
    assert timeout.value.category == "timeout"
    assert timeout.value.retryable is True
    assert "secret" not in (timeout.value.safe_message or "")

    malformed_rpc = client(Response(200, invalid_json=True))
    with pytest.raises(RpcRequestError) as malformed:
        malformed_rpc.request("eth_blockNumber", [])
    assert malformed.value.category == "malformed_response"


def scanner_config(**changes):
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


class RangeProvider:
    provider_host = "mock.base"

    def __init__(self, behavior=None):
        self.behavior = behavior
        self.calls = []

    def head(self):
        return 120

    def block_hash(self, block):
        return f"0xhash{block}"

    def fetch(self, start, end):
        self.calls.append((start, end))
        if self.behavior:
            return self.behavior(start, end, len(self.calls))
        return []


def test_adaptive_range_reduction_then_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "adaptive.db"))

    def behavior(start, end, _call):
        if end - start + 1 > 2:
            raise RpcRequestError(
                "json_rpc", "eth_getLogs", provider_host="mock.base",
                rpc_code=-32005, safe_message="range too large",
                from_block=start, to_block=end, reduce_range=True,
            )
        return []

    provider = RangeProvider(behavior)
    service = ScannerService(config=scanner_config(), provider=provider)
    service.rpc_backoff_seconds = 0

    assert asyncio.run(service.scan_once()) == 0
    assert provider.calls[0] == (103, 110)
    assert sum(1 for start, end in provider.calls if end - start + 1 <= 2) == 4
    assert service.effective_chunk_size == 2
    assert core.get_checkpoint(SCANNER_NAME)["block_number"] == 110


def test_http_403_does_not_retry_or_advance_checkpoint(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "forbidden.db"))

    def behavior(start, end, _call):
        raise RpcRequestError(
            "http_transport", "eth_getLogs", provider_host="mock.base",
            http_status=403, safe_message="HTTP 403", from_block=start,
            to_block=end, retryable=False,
        )

    provider = RangeProvider(behavior)
    service = ScannerService(config=scanner_config(), provider=provider)

    assert asyncio.run(service.scan_once()) == 0
    assert len(provider.calls) == 1
    assert core.get_checkpoint(SCANNER_NAME) is None
    assert service.last_rpc_failure["http_status"] == 403
    assert service.last_rpc_failure["jsonrpc_method"] == "eth_getLogs"
    assert service.last_rpc_failure["from_block"] == 103
    assert '"retry_count": 1' in caplog.text


def test_http_500_recovers_on_retry_and_advances_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "recovery.db"))

    def behavior(start, end, call):
        if call == 1:
            raise RpcRequestError(
                "http_transport", "eth_getLogs", provider_host="mock.base",
                http_status=500, safe_message="HTTP 500", from_block=start,
                to_block=end, retryable=True,
            )
        return []

    provider = RangeProvider(behavior)
    service = ScannerService(config=scanner_config(), provider=provider)
    service.rpc_backoff_seconds = 0

    assert asyncio.run(service.scan_once()) == 0
    assert len(provider.calls) == 2
    assert core.get_checkpoint(SCANNER_NAME)["block_number"] == 110


def test_processing_error_does_not_advance_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "processing.db"))

    def behavior(_start, _end, _call):
        return [{
            "protocol": "uniswap_v3", "factory_address": FACTORIES["uniswap_v3"]["address"],
            "pool_address": "not-an-address", "token0_address": DEFAULT_QUOTES[0],
            "token1_address": DEFAULT_QUOTES[1], "block_number": 105,
            "block_hash": "0xhash", "tx_hash": "0xtx", "log_index": 0,
        }]

    service = ScannerService(
        config=scanner_config(), provider=RangeProvider(behavior)
    )

    assert asyncio.run(service.scan_once()) == 0
    assert core.get_checkpoint(SCANNER_NAME) is None


def test_authoritative_factory_addresses_and_event_topics():
    assert FACTORIES["uniswap_v3"]["address"] == (
        "0x33128a8fC17869897dcE68Ed026d694621f6FDfD"
    )
    assert FACTORIES["aerodrome_v2"]["address"] == (
        "0x420DD381b31aEf6683db6B902084cB0FFECe40Da"
    )
    assert Web3.keccak(text=FACTORIES["uniswap_v3"]["event"]).hex() == (
        "783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118"
    )
    assert Web3.keccak(text=FACTORIES["aerodrome_v2"]["event"]).hex() == (
        "2128d88d14c80cb081c1252a5acff7a264671bf199ce226b53788fb26065005e"
    )


def test_rpc_health_checks_chain_head_and_logs():
    rpc = client(
        Response(200, {"jsonrpc": "2.0", "id": 1, "result": "0x2105"}),
        Response(200, {"jsonrpc": "2.0", "id": 1, "result": "0x100"}),
        Response(429, {"error": {"code": -32005, "message": "rate limit"}}),
    )
    provider = FactoryEventProvider(
        "https://rpc.example.test", ("uniswap_v3",), rpc_client=rpc
    )

    health = provider.health_check(confirmations=12)

    assert health["checks"]["eth_chainId"]["chain_id"] == 8453
    assert health["checks"]["eth_chainId"]["base_mainnet"] is True
    assert health["checks"]["eth_blockNumber"]["block_number"] == 256
    assert health["checks"]["eth_getLogs"]["category"] == "rate_limit"
    assert health["healthy"] is False


def test_alchemy_host_is_capped_to_ten_blocks_before_first_request(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "alchemy.db"))

    class AlchemyProvider(RangeProvider):
        provider_host = "base-mainnet.g.alchemy.com"

    provider = AlchemyProvider()
    service = ScannerService(
        config=scanner_config(chunk_size=50, bootstrap_blocks=25),
        provider=provider,
    )

    assert service.provider_max_block_range == 10
    assert asyncio.run(service.scan_once()) == 0
    assert provider.calls == [(86, 95), (96, 105), (106, 110)]
    assert all(end - start + 1 <= 10 for start, end in provider.calls)
    assert core.get_checkpoint(SCANNER_NAME)["block_number"] == 110


def test_learned_ten_block_limit_persists_across_restart(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "learned-limit.db"))

    def limited(start, end, _call):
        if end - start + 1 > 10:
            raise RpcRequestError(
                "json_rpc", "eth_getLogs", provider_host="custom.rpc",
                rpc_code=-32602, safe_message="maximum range is 10 blocks",
                from_block=start, to_block=end, reduce_range=True,
                max_block_range=10,
            )
        return []

    class LimitedProvider(RangeProvider):
        provider_host = "custom.rpc"

    first = LimitedProvider(limited)
    service = ScannerService(
        config=scanner_config(chunk_size=20, bootstrap_blocks=20), provider=first
    )
    service.rpc_backoff_seconds = 0
    assert asyncio.run(service.scan_once()) == 0
    assert first.calls[0] == (91, 110)
    assert all(end - start + 1 <= 10 for start, end in first.calls[1:])
    assert core.read_state("rpc_range_limit:custom.rpc") == 10

    core.save_checkpoint(SCANNER_NAME, 90, "0xhash90")
    restarted_provider = LimitedProvider(limited)
    restarted = ScannerService(
        config=scanner_config(chunk_size=20, bootstrap_blocks=20),
        provider=restarted_provider,
    )
    assert restarted.provider_max_block_range == 10
    assert asyncio.run(restarted.scan_once()) == 0
    assert restarted_provider.calls == [(91, 100), (101, 110)]


def test_null_checkpoint_reuses_initial_anchor_after_failure_and_restart(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "anchor.db"))

    class MovingProvider(RangeProvider):
        provider_host = "anchor.rpc"

        def fetch(self, start, end):
            self.calls.append((start, end))
            raise RpcRequestError(
                "http_transport", "eth_getLogs", provider_host=self.provider_host,
                http_status=403, safe_message="HTTP 403", from_block=start,
                to_block=end, retryable=False,
            )

    first_provider = MovingProvider()
    first = ScannerService(config=scanner_config(), provider=first_provider)
    assert asyncio.run(first.scan_once()) == 0
    assert first_provider.calls[0][0] == 103
    assert core.get_checkpoint(SCANNER_NAME) is None
    assert core.read_state(f"scanner_initial_start:{SCANNER_NAME}") == 103

    restarted_provider = MovingProvider()
    restarted_provider.head = lambda: 130
    restarted = ScannerService(config=scanner_config(), provider=restarted_provider)
    assert asyncio.run(restarted.scan_once()) == 0
    assert restarted_provider.calls[0][0] == 103
    assert core.get_checkpoint(SCANNER_NAME) is None


def test_rpc_budget_paces_requests_and_persists_daily_limit(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "budget.db"))
    clock = [100.0]
    sleeps = []

    monkeypatch.setattr("app.scanner.time.monotonic", lambda: clock[0])

    def fake_sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr("app.scanner.time.sleep", fake_sleep)
    budget = RpcBudget("budget.rpc", requests_per_second=2, daily_limit=2)
    budget.acquire("eth_chainId")
    budget.acquire("eth_blockNumber")

    assert sleeps == [pytest.approx(0.5)]
    with pytest.raises(RpcRequestError) as caught:
        budget.acquire("eth_getLogs")
    assert caught.value.category == "daily_budget"
    assert core.rpc_usage_status("budget.rpc", 2)["used"] == 2

    restarted = RpcBudget("budget.rpc", requests_per_second=0, daily_limit=2)
    with pytest.raises(RpcRequestError):
        restarted.acquire("eth_chainId")


def test_lag_metric_reports_budget_capacity_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "lag.db"))
    provider = RangeProvider()
    provider.budget = RpcBudget(
        "mock.base", requests_per_second=0.01, daily_limit=100
    )
    service = ScannerService(config=scanner_config(), provider=provider)
    service.latest_confirmed_block = 1000
    core.save_checkpoint(SCANNER_NAME, 995, "0xhash995")

    status = service.status()

    assert status["lag_blocks"] == 5
    assert status["budget_capacity_sufficient"] is False
    assert status["coverage_status"] == "SCANNER_LAGGING"
