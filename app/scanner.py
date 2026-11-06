"""Autonomous read-only Base pool discovery and bounded analysis workers."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import requests
from web3 import Web3

from . import core
from .intelligence import fetch_creator_deployments

logger = logging.getLogger(__name__)
SCANNER_NAME = "base_factory_events_v1"
CHAIN_ID = 8453
BASE_WETH = "0x4200000000000000000000000000000000000006"
NATIVE_CURRENCY = "0x0000000000000000000000000000000000000000"

# Official Base deployments. Addresses are fixed to verified Base contracts.
FACTORIES = {
    "uniswap_v3": {
        "address": "0x33128a8fC17869897dcE68Ed026d694621f6FDfD",
        "event": "PoolCreated(address,address,uint24,int24,address)",
        "kind": "uniswap_v3",
    },
    "aerodrome_v2": {
        "address": "0x420DD381b31aEf6683db6B902084cB0FFECe40Da",
        "event": "PoolCreated(address,address,bool,address,uint256)",
        "kind": "aerodrome_v2",
    },
    "uniswap_v4": {
        "address": "0x498581ff718922c3f8e6a244956af099b2652b2b",
        "event": "Initialize(bytes32,address,address,uint24,int24,address,uint160,int24)",
        "kind": "uniswap_v4",
    },
    "aerodrome_slipstream": {
        "address": "0x5e7BB104d84c7CB9B682AaC2F3d509f5F406809A",
        "event": "PoolCreated(address,address,int24,address)",
        "kind": "aerodrome_slipstream",
    },
}

# Read-only replay anchors verified independently of the configured RPC. Replays
# never call record_pool, move a checkpoint, add a watchlist row, or send alerts.
HISTORICAL_REPLAY_CASES = {
    "uniswap_v3": {
        "block_number": 22712412,
        "tx_hash": "0x4e6da7746f4a228b3ade82939252a84eedcf96617f2785b62d532a1189b7fed5",
        "pool_address": "0xD958eABd2223E9Cb53F226C58f8D37B11A9Ec8B4",
        "token0_address": "0x4200000000000000000000000000000000000006",
        "token1_address": "0xdB92a10Ada9e5a1598AFEd54E28430169150fb66",
        "source": "https://basescan.org/tx/0x4e6da7746f4a228b3ade82939252a84eedcf96617f2785b62d532a1189b7fed5",
    },
    "aerodrome_v2": {
        "block_number": 16894743,
        "tx_hash": "0xc5049804074b77ccb975b9617974ee40533634b8d6d8cabf2865cebb94c462a4",
        "pool_address": "0xa187378f0f3613e42b6ad5cc063a01060f82763f",
        "token0_address": "0x02f92800f57bcd74066f5709f1daa1a4302df875",
        "token1_address": "0xf564f589f58ced0127e48e1a02093ba53c2856ed",
        "source": "https://docs.bitquery.io/docs/blockchain/Base/aerodrome-base-api/",
    },
    "uniswap_v4": {
        "block_number": 53531133,
        "tx_hash": "0x296eca8ef3428cabc6085a6a718928e271beb33f733477f4cf0f4bad6f593e2e",
        "pool_id": "0x9aef1fbb04d277b2c00dee63ba94e83d7bc74bd77a303fb67be41314aecc0d1b",
        "currency0_address": NATIVE_CURRENCY,
        "currency1_address": "0xf2Ff5654dDE217F82e7602698Fe23Ba4100Ccccc",
        "token0_address": BASE_WETH,
        "token1_address": "0xf2Ff5654dDE217F82e7602698Fe23Ba4100Ccccc",
        "source": "https://basescan.org/tx/0x296eca8ef3428cabc6085a6a718928e271beb33f733477f4cf0f4bad6f593e2e",
    },
    "aerodrome_slipstream": {
        "block_number": 53507356,
        "tx_hash": "0x58441a2333203c94491b2b5a51e53a24373a81c8c55eb2bed7476803e735e6cd",
        "pool_address": "0x833cDf2E0991715e4fe70ace10acc95026F46078",
        "token0_address": "0x5d3a1ff2b6bab83b63cd9ad0787074081a52ef34",
        "token1_address": "0xb8cd0b8e056a91c00fd388eddb37e6e445844b21",
        "source": "https://basescan.org/tx/0x58441a2333203c94491b2b5a51e53a24373a81c8c55eb2bed7476803e735e6cd",
    },
}

DEFAULT_QUOTES = (
    "0x4200000000000000000000000000000000000006",  # WETH
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # native USDC
    "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA",  # USDbC
    "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb",  # DAI
)


def _sanitize_rpc_message(value: Any) -> str | None:
    """Bound provider text and remove URLs, credentials, tokens, and control chars."""
    if value is None:
        return None
    text = re.sub(r"https?://[^\s\"']+", "[redacted-url]", str(value))
    text = re.sub(
        r"(?i)(api[_-]?key|token|authorization|bearer)(\s*[:=]\s*)[^\s,;]+",
        r"\1\2[redacted]", text,
    )
    text = re.sub(r"\b[A-Za-z0-9_-]{32,}\b", "[redacted-value]", text)
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()
    return text[:240] or None


class RpcRequestError(Exception):
    """Sanitized, typed failure from one read-only JSON-RPC request."""

    def __init__(
        self, category: str, method: str, *, provider_host: str,
        http_status: int | None = None, rpc_code: int | str | None = None,
        safe_message: str | None = None, from_block: int | None = None,
        to_block: int | None = None, elapsed_ms: int | None = None,
        retryable: bool = False, reduce_range: bool = False,
        max_block_range: int | None = None,
    ):
        self.category = category
        self.method = method
        self.provider_host = provider_host
        self.http_status = http_status
        self.rpc_code = rpc_code
        self.safe_message = _sanitize_rpc_message(safe_message)
        self.from_block = from_block
        self.to_block = to_block
        self.elapsed_ms = elapsed_ms
        self.retryable = retryable
        self.reduce_range = reduce_range
        self.max_block_range = max_block_range
        super().__init__(f"{category}: {method}")

    def diagnostic(self, retry_count: int | None = None) -> dict[str, Any]:
        result = {
            "category": self.category, "provider_host": self.provider_host,
            "jsonrpc_method": self.method, "http_status": self.http_status,
            "rpc_error_code": self.rpc_code,
            "rpc_error_message": self.safe_message,
            "from_block": self.from_block, "to_block": self.to_block,
            "elapsed_ms": self.elapsed_ms,
            "max_block_range": self.max_block_range,
        }
        if retry_count is not None:
            result["retry_count"] = retry_count
        return result


class DiscoveryDecodeError(Exception):
    """A factory log could not be decoded; its range must not be checkpointed."""

    def __init__(self, message, protocol_event_counts=None,
                 decode_failures_by_protocol=None):
        self.protocol_event_counts = protocol_event_counts or {}
        self.decode_failures_by_protocol = decode_failures_by_protocol or {}
        super().__init__(message)


@dataclass(frozen=True)
class DiscoveredPool:
    chain_id: int
    protocol: str
    pool_address: str | None
    pool_id: str | None
    factory_address: str | None
    token0_address: str
    token1_address: str
    currency0_address: str | None
    currency1_address: str | None
    block_number: int | None
    block_hash: str | None
    tx_hash: str | None
    log_index: int | None
    source: str
    verification_status: str
    discovered_at: str
    source_created_at: str | None = None
    hook_address: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

class RpcBudget:
    """Persistent daily allowance plus process-local steady request pacing."""

    def __init__(self, provider_host: str, requests_per_second: float,
                 daily_limit: int):
        self.provider_host = provider_host
        self.requests_per_second = max(0.0, float(requests_per_second))
        self.daily_limit = max(0, int(daily_limit))
        self._lock = threading.Lock()
        self._last_request_at = 0.0

    def acquire(self, method: str) -> None:
        with self._lock:
            if self.daily_limit:
                allowed, _ = core.consume_rpc_request(
                    self.provider_host, self.daily_limit
                )
                if not allowed:
                    raise RpcRequestError(
                        "daily_budget", method,
                        provider_host=self.provider_host,
                        safe_message="configured daily RPC request budget exhausted",
                        retryable=False,
                    )
            if self.requests_per_second:
                interval = 1.0 / self.requests_per_second
                wait = (interval - (time.monotonic() - self._last_request_at)
                        if self._last_request_at else 0)
                if wait > 0:
                    time.sleep(wait)
            self._last_request_at = time.monotonic()

    def status(self) -> dict[str, Any]:
        daily = (core.rpc_usage_status(self.provider_host, self.daily_limit)
                 if self.daily_limit else {
                     "usage_date": datetime.now(timezone.utc).date().isoformat(),
                     "used": None, "limit": 0, "remaining": None,
                     "updated_at": None,
                 })
        return {
            "requests_per_second": self.requests_per_second,
            "daily": daily,
        }


class JsonRpcClient:
    """Minimal read-only JSON-RPC transport with sanitized diagnostics."""

    def __init__(
        self, rpc_url: str, *, timeout: float = 15.0,
        session: requests.Session | None = None, budget: RpcBudget | None = None,
    ):
        parsed = urlparse(rpc_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("BASE_RPC_URL must be an HTTP(S) URL")
        self._rpc_url = rpc_url
        self.provider_host = parsed.hostname
        self.timeout = timeout
        self.session = session or requests.Session()
        self.budget = budget
        self.last_call: dict[str, Any] | None = None

    def request(
        self, method: str, params: list[Any], *,
        from_block: int | None = None, to_block: int | None = None,
    ) -> Any:
        started = time.monotonic()
        if self.budget is not None:
            self.budget.acquire(method)
        try:
            response = self.session.post(
                self._rpc_url,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
        except requests.Timeout as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            raise RpcRequestError(
                "timeout", method, provider_host=self.provider_host,
                safe_message=type(exc).__name__, from_block=from_block,
                to_block=to_block, elapsed_ms=elapsed, retryable=True,
            ) from None
        except requests.RequestException as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            raise RpcRequestError(
                "transport", method, provider_host=self.provider_host,
                safe_message=type(exc).__name__, from_block=from_block,
                to_block=to_block, elapsed_ms=elapsed, retryable=True,
            ) from None

        elapsed = int((time.monotonic() - started) * 1000)
        status = int(response.status_code)
        payload = None
        try:
            payload = response.json()
        except ValueError:
            if 200 <= status < 300:
                raise RpcRequestError(
                    "malformed_response", method, provider_host=self.provider_host,
                    http_status=status, safe_message="response was not valid JSON",
                    from_block=from_block, to_block=to_block, elapsed_ms=elapsed,
                ) from None

        if not 200 <= status < 300:
            error = payload.get("error", {}) if isinstance(payload, dict) else {}
            category = "rate_limit" if status == 429 else "http_transport"
            message = _sanitize_rpc_message(
                error.get("message") or f"HTTP {status}"
            )
            range_match = re.search(
                r"(?:at most|max(?:imum)?(?: range)?|limit(?:ed)? to)\D{0,20}(\d+)\s*blocks?",
                message or "", re.IGNORECASE,
            )
            raise RpcRequestError(
                category, method, provider_host=self.provider_host,
                http_status=status, rpc_code=error.get("code"),
                safe_message=message,
                from_block=from_block, to_block=to_block, elapsed_ms=elapsed,
                retryable=(status == 408 or status == 429 or status >= 500),
                reduce_range=(status in {413, 429}),
                max_block_range=int(range_match.group(1)) if range_match else None,
            ) from None
        if not isinstance(payload, dict):
            raise RpcRequestError(
                "malformed_response", method, provider_host=self.provider_host,
                http_status=status, safe_message="JSON-RPC response was not an object",
                from_block=from_block, to_block=to_block, elapsed_ms=elapsed,
            )
        error = payload.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            message = _sanitize_rpc_message(error.get("message"))
            range_error = bool(re.search(
                r"range|too (?:many|large)|limit|response size|more than",
                message or "", re.IGNORECASE,
            )) or code in {-32005, -32002}
            range_match = re.search(
                r"(?:at most|max(?:imum)?(?: range)?|limit(?:ed)? to)\D{0,20}(\d+)\s*blocks?",
                message or "", re.IGNORECASE,
            )
            raise RpcRequestError(
                "json_rpc", method, provider_host=self.provider_host,
                http_status=status, rpc_code=code, safe_message=message,
                from_block=from_block, to_block=to_block, elapsed_ms=elapsed,
                retryable=not range_error, reduce_range=range_error,
                max_block_range=int(range_match.group(1)) if range_match else None,
            )
        if "result" not in payload:
            raise RpcRequestError(
                "malformed_response", method, provider_host=self.provider_host,
                http_status=status, safe_message="JSON-RPC result was missing",
                from_block=from_block, to_block=to_block, elapsed_ms=elapsed,
            )
        self.last_call = {
            "ok": True, "provider_host": self.provider_host,
            "jsonrpc_method": method, "http_status": status,
            "elapsed_ms": elapsed, "from_block": from_block, "to_block": to_block,
        }
        return payload["result"]


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return max(minimum, default)


def _env_decimal(name: str, default: str) -> Decimal:
    try:
        value = Decimal(os.getenv(name, default))
        return value if value.is_finite() else Decimal(default)
    except InvalidOperation:
        return Decimal(default)


def _structured_log(level: int, event: str, **fields: Any) -> None:
    safe = {key: value for key, value in fields.items()
            if "key" not in key.lower() and "token" not in key.lower()}
    logger.log(level, json.dumps({"event": event, **safe}, default=str, sort_keys=True))


@dataclass(frozen=True)
class ScannerConfig:
    protocols: tuple[str, ...]
    confirmations: int
    bootstrap_blocks: int
    start_block: int | None
    chunk_size: int
    poll_seconds: int
    reorg_rewind_blocks: int
    queue_size: int
    analysis_workers: int
    circuit_failures: int
    circuit_cooldown_seconds: int
    min_liquidity_usd: Decimal
    max_token_age_hours: int
    max_risk_score: int
    min_evidence_confidence: int
    alert_min_interval_seconds: int
    alert_max_per_hour: int
    quote_assets: frozenset[str]
    dexscreener_enabled: bool = False
    dexscreener_poll_seconds: int = 300

    @classmethod
    def from_env(cls) -> "ScannerConfig":
        requested = tuple(filter(None, (
            item.strip().lower()
            for item in os.getenv(
                "SCANNER_PROTOCOLS",
                "uniswap_v3,aerodrome_v2,uniswap_v4,aerodrome_slipstream",
            ).split(",")
        )))
        unsupported = sorted(set(requested) - set(FACTORIES))
        if unsupported:
            raise ValueError(f"Unsupported SCANNER_PROTOCOLS: {', '.join(unsupported)}")
        start_raw = os.getenv("SCANNER_START_BLOCK", "").strip()
        start = int(start_raw) if start_raw else None
        quotes = os.getenv("SCANNER_QUOTE_ASSETS", ",".join(DEFAULT_QUOTES)).split(",")
        quote_assets = frozenset(
            Web3.to_checksum_address(item.strip()).lower()
            for item in quotes if item.strip() and Web3.is_address(item.strip())
        )
        confirmations = _env_int("SCANNER_CONFIRMATIONS", 12, 1)
        return cls(
            protocols=requested, confirmations=confirmations,
            bootstrap_blocks=_env_int("SCANNER_BOOTSTRAP_BLOCKS", 1200, 1),
            start_block=start, chunk_size=_env_int("SCANNER_BLOCK_CHUNK", 500, 1),
            poll_seconds=_env_int("SCANNER_POLL_SECONDS", 15, 1),
            reorg_rewind_blocks=_env_int(
                "SCANNER_REORG_REWIND_BLOCKS", max(24, confirmations * 2), 1
            ),
            queue_size=_env_int("ANALYSIS_QUEUE_SIZE", 100, 1),
            analysis_workers=_env_int("ANALYSIS_CONCURRENCY", 2, 1),
            circuit_failures=_env_int("SCANNER_CIRCUIT_FAILURES", 3, 1),
            circuit_cooldown_seconds=_env_int("SCANNER_CIRCUIT_COOLDOWN_SECONDS", 60, 1),
            min_liquidity_usd=_env_decimal("WATCH_MIN_LIQUIDITY_USD", "10000"),
            max_token_age_hours=_env_int("WATCH_MAX_TOKEN_AGE_HOURS", 48, 1),
            max_risk_score=_env_int("WATCH_MAX_RISK_SCORE", 35, 0),
            min_evidence_confidence=_env_int("WATCH_MIN_EVIDENCE_CONFIDENCE", 60, 0),
            alert_min_interval_seconds=_env_int("ALERT_MIN_INTERVAL_SECONDS", 30, 0),
            alert_max_per_hour=_env_int("ALERT_MAX_PER_HOUR", 20, 1),
            quote_assets=quote_assets,
            dexscreener_enabled=os.getenv(
                "DEXSCREENER_DISCOVERY", "false"
            ).strip().lower() in {"1", "true", "yes", "on"},
            dexscreener_poll_seconds=_env_int(
                "DEXSCREENER_POLL_SECONDS", 300, 60
            ),
        )


class DexScreenerProvider:
    """Optional read-only discovery via DEX Screener's documented API."""

    BASE_URL = "https://api.dexscreener.com"
    MIN_REQUEST_INTERVAL = 1.05
    MAX_PROFILE_TOKENS = 30

    def __init__(
        self, *, session: requests.Session | None = None,
        min_request_interval: float = MIN_REQUEST_INTERVAL,
    ):
        self.session = session or requests.Session()
        self.min_request_interval = max(1.0, float(min_request_interval))
        self._last_request_at = 0.0
        self._request_lock = threading.Lock()
        self.request_count = 0
        self.requests_by_endpoint: dict[str, int] = {}
        self.last_request_at: str | None = None

    def _get_json(self, path: str) -> Any:
        with self._request_lock:
            wait = self.min_request_interval - (
                time.monotonic() - self._last_request_at
            ) if self._last_request_at else 0
            if wait > 0:
                time.sleep(wait)
            self._last_request_at = time.monotonic()
            self.request_count += 1
            endpoint = path.split("?", 1)[0].split("/", 2)[1]
            self.requests_by_endpoint[endpoint] = (
                self.requests_by_endpoint.get(endpoint, 0) + 1
            )
            self.last_request_at = datetime.now(timezone.utc).isoformat()
            response = self.session.get(
                self.BASE_URL + path, timeout=15,
                headers={"Accept": "application/json"},
            )
        response.raise_for_status()
        return response.json()

    def usage_status(self) -> dict[str, Any]:
        with self._request_lock:
            return {
                "provider": "dexscreener",
                "requests_made": self.request_count,
                "requests_by_endpoint": dict(self.requests_by_endpoint),
                "minimum_request_interval_seconds": self.min_request_interval,
                "last_request_at": self.last_request_at,
            }

    @staticmethod
    def _timestamp(value: Any) -> str | None:
        try:
            numeric = int(value)
            if numeric <= 0:
                return None
            return datetime.fromtimestamp(
                numeric / 1000, tz=timezone.utc
            ).isoformat()
        except (OverflowError, OSError, TypeError, ValueError):
            return None

    def fetch_batch(self) -> dict[str, Any]:
        profiles = self._get_json("/token-profiles/latest/v1")
        if not isinstance(profiles, list):
            raise ValueError("DEX Screener token profiles were not an array")
        addresses = []
        seen_addresses = set()
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            address = profile.get("tokenAddress")
            if (str(profile.get("chainId", "")).lower() != "base"
                    or not isinstance(address, str) or not Web3.is_address(address)):
                continue
            checksum = Web3.to_checksum_address(address)
            if checksum.lower() not in seen_addresses:
                addresses.append(checksum)
                seen_addresses.add(checksum.lower())
            if len(addresses) == self.MAX_PROFILE_TOKENS:
                break
        if not addresses:
            return {"events": [], "raw_log_count": 0}
        pairs = self._get_json(
            "/tokens/v1/base/" + ",".join(addresses)
        )
        if not isinstance(pairs, list):
            raise ValueError("DEX Screener token pairs were not an array")
        events = []
        ignored = 0
        now = datetime.now(timezone.utc).isoformat()
        for pair in pairs:
            try:
                if not isinstance(pair, dict) or str(
                    pair.get("chainId", "")
                ).lower() != "base":
                    ignored += 1
                    continue
                pool_address = pair.get("pairAddress")
                base = (pair.get("baseToken") or {}).get("address")
                quote = (pair.get("quoteToken") or {}).get("address")
                protocol = str(pair.get("dexId") or "unknown").lower()
                if not all(
                    isinstance(value, str) and Web3.is_address(value)
                    for value in (base, quote)
                ):
                    ignored += 1
                    continue
                pool_id = None
                if (isinstance(pool_address, str)
                        and re.fullmatch(r"0x[0-9a-fA-F]{64}", pool_address)):
                    pool_id = pool_address.lower()
                    pool_address = None
                elif isinstance(pool_address, str) and Web3.is_address(pool_address):
                    if (protocol in {"uniswap-v4", "uniswap_v4", "uniswapv4"}
                            and pool_address.lower()
                            == FACTORIES["uniswap_v4"]["address"].lower()):
                        ignored += 1
                        continue
                else:
                    ignored += 1
                    continue
                model = DiscoveredPool(
                    chain_id=CHAIN_ID,
                    protocol=protocol,
                    pool_address=(Web3.to_checksum_address(pool_address)
                                  if pool_address else None),
                    pool_id=pool_id,
                    factory_address=None,
                    token0_address=Web3.to_checksum_address(base),
                    token1_address=Web3.to_checksum_address(quote),
                    currency0_address=None,
                    currency1_address=None,
                    block_number=None,
                    block_hash=None,
                    tx_hash=None,
                    log_index=None,
                    source="dexscreener",
                    verification_status="reported_unverified",
                    discovered_at=now,
                    source_created_at=self._timestamp(pair.get("pairCreatedAt")),
                )
                events.append(model.as_dict())
            except (TypeError, ValueError):
                ignored += 1
        return {
            "events": events,
            "raw_log_count": len(pairs),
            "ignored_pairs": ignored,
        }


class FactoryEventProvider:
    """Read verified factory logs from Base JSON-RPC; no transaction methods."""

    def __init__(
        self, rpc_url: str, protocols: tuple[str, ...], *,
        rpc_client: JsonRpcClient | None = None,
    ):
        parsed_host = urlparse(rpc_url).hostname or "unknown"
        budget = RpcBudget(
            parsed_host,
            float(_env_decimal("SCANNER_RPC_REQUESTS_PER_SECOND", "5")),
            _env_int("SCANNER_RPC_DAILY_REQUEST_BUDGET", 100000, 0),
        )
        self.rpc = rpc_client or JsonRpcClient(
            rpc_url, timeout=float(os.getenv("SCANNER_RPC_TIMEOUT_SECONDS", "15")),
            budget=budget,
        )
        self.provider_host = self.rpc.provider_host
        self.budget = getattr(self.rpc, "budget", None)
        self.factories = {
            Web3.to_checksum_address(FACTORIES[name]["address"]).lower():
                {"protocol": name, **FACTORIES[name]}
            for name in protocols
        }
        self.topics = {
            Web3.keccak(text=spec["event"]).hex(): spec
            for spec in self.factories.values()
        }

    def head(self) -> int:
        chain_id = self._hex_int(self.rpc.request("eth_chainId", []), "eth_chainId")
        if chain_id != 8453:
            raise RpcRequestError(
                "chain_validation", "eth_chainId",
                provider_host=self.provider_host, rpc_code=chain_id,
                safe_message=f"expected 8453, received {chain_id}",
            )
        return self._hex_int(
            self.rpc.request("eth_blockNumber", []), "eth_blockNumber"
        )

    def block_hash(self, block_number: int) -> str:
        result = self.rpc.request(
            "eth_getBlockByNumber", [hex(int(block_number)), False],
            from_block=int(block_number), to_block=int(block_number),
        )
        if not isinstance(result, dict) or not isinstance(result.get("hash"), str):
            raise RpcRequestError(
                "malformed_response", "eth_getBlockByNumber",
                provider_host=self.provider_host,
                safe_message="block hash missing from response",
                from_block=int(block_number), to_block=int(block_number),
            )
        return result["hash"]

    def _hex_int(self, value: Any, method: str) -> int:
        try:
            return int(str(value), 16)
        except (TypeError, ValueError):
            raise RpcRequestError(
                "malformed_response", method, provider_host=self.provider_host,
                safe_message="expected hexadecimal quantity",
            ) from None

    @staticmethod
    def _topic_address(topic: Any) -> str:
        raw = (bytes.fromhex(topic.removeprefix("0x"))
               if isinstance(topic, str) else bytes(topic))
        return Web3.to_checksum_address("0x" + raw[-20:].hex())

    @staticmethod
    def _data_bytes(data: Any) -> bytes:
        if isinstance(data, str):
            return bytes.fromhex(data.removeprefix("0x"))
        return bytes(data)

    def fetch_batch(self, from_block: int, to_block: int) -> dict[str, Any]:
        if not self.factories:
            return {"events": [], "raw_log_count": 0, "decode_failures": 0,
                    "decode_errors": [], "protocol_event_counts": {},
                    "decode_failures_by_protocol": {}}
        logs = self.rpc.request("eth_getLogs", [{
            "fromBlock": hex(int(from_block)), "toBlock": hex(int(to_block)),
            "address": [Web3.to_checksum_address(spec["address"])
                        for spec in self.factories.values()],
            "topics": [["0x" + topic.removeprefix("0x") for topic in self.topics]],
        }], from_block=int(from_block), to_block=int(to_block))
        if not isinstance(logs, list):
            raise RpcRequestError(
                "malformed_response", "eth_getLogs",
                provider_host=self.provider_host,
                safe_message="eth_getLogs result was not an array",
                from_block=int(from_block), to_block=int(to_block),
            )
        events, decode_errors = [], []
        protocol_event_counts: dict[str, int] = {}
        decode_failures_by_protocol: dict[str, int] = {}
        for index, log in enumerate(logs):
            spec = None
            try:
                if not isinstance(log, dict):
                    raise ValueError("log was not an object")
                address = str(log["address"]).lower()
                spec = self.factories.get(address)
                if not spec:
                    raise ValueError("log factory was not configured")
                protocol = spec["protocol"]
                protocol_event_counts[protocol] = (
                    protocol_event_counts.get(protocol, 0) + 1
                )
                if len(log.get("topics", [])) < 4:
                    raise ValueError("Factory event indexed topics were incomplete")
                topic0 = self._hex_value(log["topics"][0])
                expected = Web3.keccak(text=spec["event"]).hex().removeprefix("0x")
                if topic0.removeprefix("0x") != expected:
                    raise ValueError("Factory event topic0 did not match ABI")
                topics = log["topics"]
                data = self._data_bytes(log["data"])
                token0 = token1 = None
                currency0 = currency1 = None
                hook = None
                pool = pool_id = None
                if spec["kind"] == "uniswap_v4":
                    if len(data) != 160:
                        raise ValueError(
                            "Initialize data was not exactly five ABI words"
                        )
                    pool_id = self._hex_value(topics[1]).lower()
                    if len(bytes.fromhex(pool_id.removeprefix("0x"))) != 32:
                        raise ValueError("Initialize pool ID was not bytes32")
                    currency0 = self._topic_address(topics[2])
                    currency1 = self._topic_address(topics[3])
                    token0 = (BASE_WETH if currency0.lower() == NATIVE_CURRENCY
                              else currency0)
                    token1 = (BASE_WETH if currency1.lower() == NATIVE_CURRENCY
                              else currency1)
                    decoded_hook = self._word_address(data, 2)
                    hook = decoded_hook if int(decoded_hook, 16) else None
                elif spec["kind"] == "aerodrome_slipstream":
                    if len(data) != 32:
                        raise ValueError(
                            "Slipstream PoolCreated data was not one ABI word"
                        )
                    token0 = self._topic_address(topics[1])
                    token1 = self._topic_address(topics[2])
                    pool = self._word_address(data, 0)
                else:
                    # Preserve the existing Uniswap V3 and Aerodrome V2 decoding.
                    offset = 32 if spec["kind"] == "uniswap_v3" else 0
                    if len(data) < 64:
                        raise ValueError(
                            "PoolCreated data was shorter than two ABI words"
                        )
                    pool = self._word_address(data, offset // 32)
                    token0 = self._topic_address(topics[1])
                    token1 = self._topic_address(topics[2])
                events.append(DiscoveredPool(
                    chain_id=CHAIN_ID,
                    protocol=protocol,
                    pool_address=pool,
                    pool_id=pool_id,
                    factory_address=Web3.to_checksum_address(spec["address"]),
                    token0_address=token0,
                    token1_address=token1,
                    currency0_address=currency0,
                    currency1_address=currency1,
                    block_number=self._quantity(log["blockNumber"]),
                    block_hash=self._hex_value(log["blockHash"]),
                    tx_hash=self._hex_value(log["transactionHash"]),
                    log_index=self._quantity(log["logIndex"]),
                    source="base_rpc",
                    verification_status="verified_onchain",
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                    hook_address=hook,
                ).as_dict())
            except (KeyError, TypeError, ValueError, IndexError) as exc:
                if spec:
                    protocol = spec["protocol"]
                    decode_failures_by_protocol[protocol] = (
                        decode_failures_by_protocol.get(protocol, 0) + 1
                    )
                decode_errors.append({
                    "log_offset": index, "reason": _sanitize_rpc_message(str(exc)),
                    "protocol": spec.get("protocol") if spec else None,
                    "tx_hash": (_sanitize_rpc_message(log.get("transactionHash"))
                                if isinstance(log, dict) else None),
                })
        return {
            "events": sorted(events, key=lambda item: (
                item["block_number"], item["log_index"]
            )),
            "raw_log_count": len(logs),
            "decode_failures": len(decode_errors),
            "decode_errors": decode_errors,
            "protocol_event_counts": protocol_event_counts,
            "decode_failures_by_protocol": decode_failures_by_protocol,
        }

    def fetch(self, from_block: int, to_block: int) -> list[dict[str, Any]]:
        """Compatibility API; scanner uses fetch_batch for full diagnostics."""
        return self.fetch_batch(from_block, to_block)["events"]
    @staticmethod
    def _hex_value(value: Any) -> str:
        if isinstance(value, str):
            return value if value.startswith("0x") else "0x" + value
        return "0x" + bytes(value).hex()

    @staticmethod
    def _quantity(value: Any) -> int:
        return int(value, 16) if isinstance(value, str) else int(value)

    @staticmethod
    def _word_address(data: bytes, word_index: int) -> str:
        start = word_index * 32
        word = data[start:start + 32]
        if len(word) != 32 or any(word[:12]):
            raise ValueError("ABI address word was malformed")
        return Web3.to_checksum_address("0x" + word[12:].hex())

    def _log_filter(self, block_number: int) -> dict[str, Any]:
        return {
            "fromBlock": hex(block_number), "toBlock": hex(block_number),
            "address": [Web3.to_checksum_address(spec["address"])
                        for spec in self.factories.values()],
            "topics": [["0x" + topic.removeprefix("0x") for topic in self.topics]],
        }

    def health_check(self, confirmations: int = 12) -> dict[str, Any]:
        """Run independent sanitized checks without changing scanner state."""
        report: dict[str, Any] = {
            "provider_host": self.provider_host,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "expected_chain_id": 8453, "checks": {},
            "factories": [
                {"protocol": spec["protocol"], "address": spec["address"],
                 "event_signature": spec["event"],
                 "event_topic": "0x" + Web3.keccak(text=spec["event"]).hex().removeprefix("0x")}
                for spec in self.factories.values()
            ],
        }

        def run(name: str, method: str, params: list[Any], **context: Any) -> Any:
            try:
                result = self.rpc.request(method, params, **context)
                report["checks"][name] = dict(self.rpc.last_call or {"ok": True})
                return result
            except RpcRequestError as exc:
                report["checks"][name] = {"ok": False, **exc.diagnostic()}
                return None

        chain_raw = run("eth_chainId", "eth_chainId", [])
        chain_id = None
        if chain_raw is not None:
            try:
                chain_id = int(str(chain_raw), 16)
            except (TypeError, ValueError):
                report["checks"]["eth_chainId"] = {
                    "ok": False, "category": "malformed_response",
                    "provider_host": self.provider_host,
                    "jsonrpc_method": "eth_chainId",
                    "rpc_error_message": "expected hexadecimal quantity",
                }
            else:
                report["checks"]["eth_chainId"]["chain_id"] = chain_id
                report["checks"]["eth_chainId"]["base_mainnet"] = chain_id == 8453
                if chain_id != 8453:
                    report["checks"]["eth_chainId"]["ok"] = False
                    report["checks"]["eth_chainId"]["category"] = "chain_validation"
        head_raw = run("eth_blockNumber", "eth_blockNumber", [])
        head = None
        if head_raw is not None:
            try:
                head = int(str(head_raw), 16)
                report["checks"]["eth_blockNumber"]["block_number"] = head
            except (TypeError, ValueError):
                report["checks"]["eth_blockNumber"] = {
                    "ok": False, "category": "malformed_response",
                    "provider_host": self.provider_host,
                    "jsonrpc_method": "eth_blockNumber",
                    "rpc_error_message": "expected hexadecimal quantity",
                }
        if head is not None:
            block = max(0, head - max(1, confirmations))
            run(
                "eth_getLogs", "eth_getLogs", [self._log_filter(block)],
                from_block=block, to_block=block,
            )
        else:
            report["checks"]["eth_getLogs"] = {
                "ok": False, "category": "skipped",
                "rpc_error_message": "eth_blockNumber unavailable",
            }
        report["healthy"] = all(
            check.get("ok") is True for check in report["checks"].values()
        )
        return report


def replay_historical_range(provider: Any, from_block: int, to_block: int) -> dict[str, Any]:
    """Read and decode <=10 historical blocks without mutating scanner state."""
    if int(to_block) < int(from_block) or int(to_block) - int(from_block) + 1 > 10:
        raise ValueError("historical replay range must contain 1 to 10 blocks")
    if hasattr(provider, "fetch_batch"):
        batch = provider.fetch_batch(int(from_block), int(to_block))
    else:
        events = provider.fetch(int(from_block), int(to_block))
        batch = {"events": events, "raw_log_count": len(events),
                 "decode_failures": 0, "decode_errors": []}
    return {"mode": "READ_ONLY_REPLAY", "isolated": True,
            "from_block": int(from_block), "to_block": int(to_block), **batch}


class ScannerService:
    def __init__(
        self, *, config: ScannerConfig | None = None,
        provider: Any | None = None,
        secondary_provider: Any | None = None,
        analyzer: Callable[..., dict[str, Any]] | None = None,
        alert_callback: Callable[[str], Awaitable[None]] | None = None,
    ):
        self.config = config or ScannerConfig.from_env()
        self.rpc_url = os.getenv("BASE_RPC_URL", "https://mainnet.base.org")
        self.provider = provider or FactoryEventProvider(
            self.rpc_url, self.config.protocols
        )
        self.secondary_provider = (
            secondary_provider if secondary_provider is not None else
            DexScreenerProvider()
            if self.config.dexscreener_enabled else None
        )
        self.analyzer = analyzer or core.inspect_contract
        self.alert_callback = alert_callback
        self.queue: asyncio.Queue[tuple[str, dict[str, Any] | None]] = asyncio.Queue(
            maxsize=self.config.queue_size
        )
        self._tasks: list[asyncio.Task[Any]] = []
        self._wake = asyncio.Event()
        self._stop = asyncio.Event()
        self._queued: set[str] = set()
        self.failure_count = 0
        self.circuit_open_until = 0.0
        self.last_error: str | None = None
        self.last_scan_at: str | None = None
        self._last_alert_at = 0.0
        self.rpc_attempts = _env_int("SCANNER_RPC_RETRIES", 3, 1)
        self.max_backfill_blocks = _env_int("SCANNER_MAX_BACKFILL_BLOCKS", 100000, 1)
        self.developer_refresh_seconds = _env_int("DEVELOPER_REFRESH_SECONDS", 3600, 60)
        self.focus_reanalyze_seconds = _env_int("FOCUS_REANALYZE_SECONDS", 300, 30)
        self._focus_queued_at: dict[str, float] = {}
        self.last_rpc_failure: dict[str, Any] | None = None
        self.last_health: dict[str, Any] | None = None
        self.min_chunk_size = _env_int("SCANNER_MIN_BLOCK_CHUNK", 1, 1)
        self.provider_host = getattr(self.provider, "provider_host", "unknown")
        self.range_limit_state_key = f"rpc_range_limit:{self.provider_host}"
        configured_limit = _env_int("SCANNER_PROVIDER_MAX_BLOCK_RANGE", 0, 0)
        saved_limit = core.read_state(self.range_limit_state_key)
        alchemy_limit = 10 if "alchemy" in self.provider_host.lower() else 0
        limits = [self.config.chunk_size]
        limits.extend(
            value for value in (configured_limit, saved_limit, alchemy_limit)
            if isinstance(value, int) and value > 0
        )
        self.provider_max_block_range = max(self.min_chunk_size, min(limits))
        self.effective_chunk_size = self.provider_max_block_range
        self.rpc_backoff_seconds = float(
            _env_decimal("SCANNER_RPC_BACKOFF_SECONDS", "0.5")
        )
        self.initial_start_state_key = f"scanner_initial_start:{SCANNER_NAME}"
        self.protocol_config_state_key = f"scanner_protocols:{SCANNER_NAME}"
        self.protocol_backfill_state_key = (
            f"scanner_protocol_backfill:{SCANNER_NAME}"
        )
        self._secondary_last_attempt_at: float | None = None
        self.latest_confirmed_block: int | None = None
        self.initial_start_block: int | None = None
        self.lag_threshold_blocks = _env_int("SCANNER_LAG_THRESHOLD_BLOCKS", 30, 0)
        self.base_block_seconds = float(
            _env_decimal("SCANNER_BASE_BLOCK_SECONDS", "2")
        )

    async def start(self) -> None:
        if self._tasks:
            return
        await asyncio.to_thread(lambda: core.db_connect().close())
        self._stop.clear()
        self._tasks = [asyncio.create_task(self._run(), name="pool-scanner")]
        self._tasks.extend(
            asyncio.create_task(self._worker(index), name=f"analysis-{index}")
            for index in range(self.config.analysis_workers)
        )
        _structured_log(logging.INFO, "scanner_started", protocols=self.config.protocols)

    async def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    def wake(self) -> None:
        self._wake.set()

    def status(self) -> dict[str, Any]:
        checkpoint = core.get_checkpoint(SCANNER_NAME)
        focus = core.read_state("focused_developer")
        result = {
            "mode": "PAPER_ONLY", "enabled": core.read_state("scanner_enabled", False),
            "focus": focus, "discovery_paused_by_focus": bool(focus),
            "focus_monitoring_active": bool(focus),
            "queue_depth": self.queue.qsize(), "queue_capacity": self.config.queue_size,
            "workers": self.config.analysis_workers, "protocols": list(self.config.protocols),
            "confirmations": self.config.confirmations, "checkpoint": checkpoint,
            "circuit_open": time.monotonic() < self.circuit_open_until,
            "failures": self.failure_count, "last_error": self.last_error,
            "last_scan_at": self.last_scan_at,
            "provider_host": getattr(self.provider, "provider_host", "unknown"),
            "effective_chunk_size": self.effective_chunk_size,
            "provider_max_block_range": self.provider_max_block_range,
            "last_rpc_failure": self.last_rpc_failure,
        }
        result.update(self._coverage_metrics(checkpoint))
        return result

    async def rpc_status(self, refresh: bool = True) -> dict[str, Any]:
        if refresh and hasattr(self.provider, "health_check"):
            self.last_health = await asyncio.to_thread(
                self.provider.health_check, self.config.confirmations
            )
            head = ((self.last_health.get("checks") or {}).get(
                "eth_blockNumber", {}
            ).get("block_number"))
            if isinstance(head, int):
                self.latest_confirmed_block = head - self.config.confirmations
        report = dict(self.last_health or {
            "provider_host": getattr(self.provider, "provider_host", "unknown"),
            "healthy": None, "checks": {},
        })
        report.update({
            "mode": "PAPER_ONLY", "last_failure": self.last_rpc_failure,
            "checkpoint": await asyncio.to_thread(core.get_checkpoint, SCANNER_NAME),
            "configured_chunk_size": self.config.chunk_size,
            "effective_chunk_size": self.effective_chunk_size,
            "provider_max_block_range": self.provider_max_block_range,
            "retry_limit": self.rpc_attempts,
        })
        report.update(self._coverage_metrics(report.get("checkpoint")))
        return report

    def discovery_status(self) -> dict[str, Any]:
        report = core.discovery_diagnostics()
        report.update({
            "mode": "PAPER_ONLY", "checkpoint": core.get_checkpoint(SCANNER_NAME),
            "queue_depth": self.queue.qsize(), "workers": self.config.analysis_workers,
            "protocols": list(self.config.protocols), "last_scan_at": self.last_scan_at,
            "pipeline": [
                "eth_getLogs", "decode", "persist pool/token", "analysis queue",
                "risk analysis", "watchlist filters", "deduplicated Telegram alert",
            ],
        })
        report.update(self._coverage_metrics(report.get("checkpoint")))
        return report

    def protocol_status(self) -> dict[str, Any]:
        protocols = list(self.config.protocols)
        if self.secondary_provider is not None:
            protocols.append("dexscreener")
        budget = getattr(self.provider, "budget", None)
        secondary_usage = getattr(
            self.secondary_provider, "usage_status", None
        )
        return {
            "mode": "PAPER_ONLY",
            "protocols": core.protocol_scan_status(protocols),
            "onchain_checkpoint": core.get_checkpoint(SCANNER_NAME),
            "pending_protocol_backfill_from": core.read_state(
                self.protocol_backfill_state_key
            ),
            "initial_start_block": core.read_state(self.initial_start_state_key),
            "configured_start_block": self.config.start_block,
            "max_backfill_blocks": self.max_backfill_blocks,
            "provider_usage": {
                "base_rpc": {
                    "provider_host": self.provider_host,
                    "request_budget": budget.status() if budget else None,
                    "max_blocks_per_eth_getLogs": self.provider_max_block_range,
                },
                "dexscreener": (
                    secondary_usage() if callable(secondary_usage) else None
                ),
            },
        }

    async def _record_protocol_configuration(self, target: int, checkpoint):
        configured = list(self.config.protocols)
        previous = await asyncio.to_thread(
            core.read_state, self.protocol_config_state_key
        )
        if previous is None:
            previous = (["uniswap_v3", "aerodrome_v2"]
                        if checkpoint else configured)
        added = set(configured) - set(previous)
        if added:
            prior_start = await asyncio.to_thread(
                core.read_state, self.initial_start_state_key
            )
            requested_start = (
                self.config.start_block if self.config.start_block is not None
                else target - self.config.bootstrap_blocks + 1
            )
            anchor = (prior_start if isinstance(prior_start, int) and prior_start >= 1
                      else requested_start)
            anchor = max(1, anchor, target - self.max_backfill_blocks + 1)
            pending = await asyncio.to_thread(
                core.read_state, self.protocol_backfill_state_key
            )
            if isinstance(pending, int) and pending >= 1:
                anchor = min(anchor, pending)
            await asyncio.to_thread(
                core.write_state, self.protocol_backfill_state_key, anchor
            )
        await asyncio.to_thread(
            core.write_state, self.protocol_config_state_key, configured
        )

    async def _metric(self, name: str, amount: int = 1) -> None:
        if not amount:
            return
        try:
            await asyncio.to_thread(core.increment_discovery_metric, name, amount)
        except Exception as exc:
            _structured_log(logging.WARNING, "discovery_metric_write_failed",
                            metric=name, error_type=type(exc).__name__)

    async def _diagnostic_error(
        self, stage: str, category: str, message: Any = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        try:
            await asyncio.to_thread(
                core.record_discovery_error, stage, category,
                _sanitize_rpc_message(message), context or {},
            )
        except Exception as exc:
            _structured_log(logging.WARNING, "discovery_error_write_failed",
                            stage=stage, error_type=type(exc).__name__)

    async def scan_once(self) -> int:
        if time.monotonic() < self.circuit_open_until:
            return 0
        focus = await asyncio.to_thread(core.read_state, "focused_developer")
        if focus:
            await self._queue_focus(focus)
            return 0
        try:
            head = await self._provider_call("head")
            target = head - self.config.confirmations
            self.latest_confirmed_block = target
            checkpoint = await asyncio.to_thread(core.get_checkpoint, SCANNER_NAME)
            await self._record_protocol_configuration(target, checkpoint)
            if checkpoint:
                if checkpoint["block_number"] > target:
                    start = max(1, target - self.config.reorg_rewind_blocks + 1)
                    orphaned = await asyncio.to_thread(core.mark_reorg, start)
                    _structured_log(
                        logging.WARNING, "scanner_chain_rollback", rewind_block=start,
                        orphaned_pools=orphaned,
                    )
                else:
                    canonical_hash = await self._provider_call(
                        "block_hash", checkpoint["block_number"]
                    )
                    if canonical_hash.lower() != checkpoint["block_hash"].lower():
                        start = max(
                            1, checkpoint["block_number"] - self.config.reorg_rewind_blocks
                        )
                        orphaned = await asyncio.to_thread(core.mark_reorg, start)
                        _structured_log(
                            logging.WARNING, "scanner_reorg", rewind_block=start,
                            orphaned_pools=orphaned,
                        )
                    else:
                        start = checkpoint["block_number"] + 1
            else:
                anchor = await asyncio.to_thread(
                    core.read_state, self.initial_start_state_key
                )
                if isinstance(anchor, int) and anchor >= 1:
                    start = anchor
                else:
                    requested_start = (
                        self.config.start_block if self.config.start_block is not None
                        else target - self.config.bootstrap_blocks + 1
                    )
                    start = max(
                        1, requested_start, target - self.max_backfill_blocks + 1
                    )
                    await asyncio.to_thread(
                        core.write_state, self.initial_start_state_key, start
                    )
                self.initial_start_block = start
            pending_backfill = await asyncio.to_thread(
                core.read_state, self.protocol_backfill_state_key
            )
            if isinstance(pending_backfill, int) and pending_backfill >= 1:
                start = min(start, pending_backfill)
            if start > target:
                self.failure_count = 0
                self.last_scan_at = datetime.now(timezone.utc).isoformat()
                await self._scan_secondary()
                return 0
            discovered = 0
            current = start
            while current <= target and not self._stop.is_set():
                if await asyncio.to_thread(core.read_state, "focused_developer"):
                    break
                end = min(target, current + self.effective_chunk_size - 1)
                try:
                    events, event_counts, decode_failures = (
                        await self._fetch_logs_adaptive(current, end)
                    )
                except DiscoveryDecodeError as exc:
                    protocols = set(self.config.protocols)
                    protocols.update(exc.protocol_event_counts)
                    protocols.update(exc.decode_failures_by_protocol)
                    for protocol in protocols:
                        await asyncio.to_thread(
                            core.record_protocol_scan_failure,
                            protocol, "base_rpc",
                            exc.protocol_event_counts.get(protocol, 0),
                            exc.decode_failures_by_protocol.get(protocol, 0),
                            str(exc),
                        )
                    raise
                for event in events:
                    tokens = self._tokens_for_event(event)
                    event["quote_address"] = self._quote_for_event(event)
                    try:
                        recorder = (
                            core.record_pool
                            if event.get("source", "base_rpc") == "base_rpc"
                            and event.get("pool_address") else
                            core.record_discovered_pool
                        )
                        persisted = await asyncio.to_thread(
                            recorder, event, tokens, True
                        )
                    except Exception as exc:
                        await self._metric("persistence_failures")
                        await self._diagnostic_error(
                            "persistence", "persistence_failure", type(exc).__name__,
                            {"block_number": event.get("block_number"),
                             "protocol": event.get("protocol")},
                        )
                        raise
                    await self._metric("tokens_discovered", persisted["new_tokens"])
                    should_process = persisted["should_process"]
                    if should_process:
                        discovered += 1
                        for address in tokens:
                            if await self._enqueue(address, event):
                                await self._metric("tokens_queued")
                block_hash = await self._provider_call("block_hash", end)
                pending_backfill = await asyncio.to_thread(
                    core.read_state, self.protocol_backfill_state_key
                )
                next_backfill = pending_backfill
                if isinstance(pending_backfill, int) and pending_backfill <= end:
                    next_backfill = end + 1 if end < target else None
                protocol_updates = {
                    protocol: {
                        "source": "base_rpc",
                        "blocks_scanned": end - current + 1,
                        "events_detected": event_counts.get(protocol, 0),
                        "decoding_failures": decode_failures.get(protocol, 0),
                    }
                    for protocol in self.config.protocols
                }
                await asyncio.to_thread(
                    core.save_scan_checkpoint, SCANNER_NAME, end, block_hash,
                    protocol_updates, self.protocol_backfill_state_key,
                    next_backfill,
                )
                current = end + 1
            self.failure_count = 0
            self.last_error = None
            self.last_scan_at = datetime.now(timezone.utc).isoformat()
            await self._scan_secondary()
            return discovered
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.failure_count += 1
            # Status is Telegram-visible; never include provider messages or URLs.
            if isinstance(exc, RpcRequestError):
                self.last_error = f"{exc.category}: {exc.method}"
            else:
                self.last_error = type(exc).__name__
            if self.failure_count >= self.config.circuit_failures:
                self.circuit_open_until = (
                    time.monotonic() + self.config.circuit_cooldown_seconds
                )
            _structured_log(
                logging.WARNING,
                ("scanner_provider_failure" if isinstance(exc, RpcRequestError)
                 else "scanner_processing_failure"),
                error_type=type(exc).__name__, failures=self.failure_count,
            )
            if isinstance(exc, RpcRequestError):
                await self._metric("provider_failures")
                await self._diagnostic_error(
                    "provider", exc.category, exc.safe_message or exc.method,
                    exc.diagnostic(),
                )
            return 0

    async def _provider_call(self, method: str, *args: Any) -> Any:
        """Retry read-only RPC calls with typed, sanitized diagnostics."""
        rpc_methods = {
            "head": "eth_chainId+eth_blockNumber",
            "block_hash": "eth_getBlockByNumber", "fetch": "eth_getLogs",
            "fetch_batch": "eth_getLogs",
        }
        from_block = int(args[0]) if method in {"fetch", "fetch_batch", "block_hash"} and args else None
        to_block = (int(args[1]) if method in {"fetch", "fetch_batch"} and len(args) > 1 else
                    from_block if method == "block_hash" else None)
        for attempt in range(self.rpc_attempts):
            started = time.monotonic()
            try:
                return await asyncio.to_thread(getattr(self.provider, method), *args)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                failure = self._normalize_rpc_failure(
                    exc, rpc_methods.get(method, method), from_block, to_block,
                    int((time.monotonic() - started) * 1000),
                )
                diagnostic = failure.diagnostic(retry_count=attempt + 1)
                diagnostic["retry_limit"] = self.rpc_attempts
                self.last_rpc_failure = diagnostic
                _structured_log(logging.WARNING, "rpc_request_failure", **diagnostic)
                span = ((to_block - from_block + 1)
                        if from_block is not None and to_block is not None else 1)
                if failure.reduce_range and span > self.min_chunk_size:
                    delay = max(0.0, self.rpc_backoff_seconds)
                    delay += random.uniform(0, max(0.001, delay * 0.25))
                    await asyncio.sleep(delay)
                    raise failure
                if not failure.retryable or attempt + 1 == self.rpc_attempts:
                    raise failure
                delay = min(8.0, self.rpc_backoff_seconds * (2 ** attempt))
                delay += random.uniform(0, max(0.001, delay * 0.25))
                await asyncio.sleep(delay)

    def _normalize_rpc_failure(
        self, exc: Exception, method: str, from_block: int | None,
        to_block: int | None, elapsed_ms: int,
    ) -> RpcRequestError:
        if isinstance(exc, RpcRequestError):
            if exc.from_block is None:
                exc.from_block = from_block
                exc.to_block = to_block
            if exc.elapsed_ms is None:
                exc.elapsed_ms = elapsed_ms
            return exc
        host = getattr(self.provider, "provider_host", "unknown")
        if isinstance(exc, requests.Timeout):
            category, retryable, status = "timeout", True, None
        elif isinstance(exc, requests.HTTPError):
            status = getattr(getattr(exc, "response", None), "status_code", None)
            category = "rate_limit" if status == 429 else "http_transport"
            retryable = status == 408 or status == 429 or bool(status and status >= 500)
        elif isinstance(exc, requests.RequestException):
            category, retryable, status = "transport", True, None
        else:
            category, retryable, status = "provider_error", False, None
        return RpcRequestError(
            category, method, provider_host=host, http_status=status,
            safe_message=type(exc).__name__, from_block=from_block,
            to_block=to_block, elapsed_ms=elapsed_ms, retryable=retryable,
            reduce_range=status in {413, 429},
        )

    async def _fetch_logs_adaptive(
        self, from_block: int, to_block: int,
    ) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, int]]:
        """Split rejected log ranges without processing a partial parent range."""
        pending = [(from_block, to_block)]
        events: list[dict[str, Any]] = []
        protocol_event_counts: dict[str, int] = {}
        failures_by_protocol: dict[str, int] = {}
        while pending:
            start, end = pending.pop(0)
            try:
                if hasattr(self.provider, "fetch_batch"):
                    batch = await self._provider_call("fetch_batch", start, end)
                else:
                    found = await self._provider_call("fetch", start, end)
                    batch = {"events": found, "raw_log_count": len(found),
                             "decode_failures": 0, "decode_errors": []}
                found = list(batch.get("events") or [])
                raw_count = int(batch.get("raw_log_count") or 0)
                decode_failures = int(batch.get("decode_failures") or 0)
                batch_counts = batch.get("protocol_event_counts") or {}
                if not batch_counts:
                    batch_counts = {}
                    for event in found:
                        protocol = event.get("protocol", "unknown")
                        batch_counts[protocol] = batch_counts.get(protocol, 0) + 1
                for protocol, count in batch_counts.items():
                    protocol_event_counts[protocol] = (
                        protocol_event_counts.get(protocol, 0) + int(count)
                    )
                batch_failures = batch.get("decode_failures_by_protocol") or {}
                if decode_failures and not batch_failures:
                    for error in batch.get("decode_errors") or []:
                        protocol = error.get("protocol")
                        if protocol:
                            batch_failures[protocol] = (
                                batch_failures.get(protocol, 0) + 1
                            )
                    if not batch_failures:
                        batch_failures["unknown"] = decode_failures
                for protocol, count in batch_failures.items():
                    failures_by_protocol[protocol] = (
                        failures_by_protocol.get(protocol, 0) + int(count)
                    )
                await self._metric("scanned_ranges")
                await self._metric("pool_events_found", raw_count)
                await self._metric("decoded_events", len(found))
                await self._metric("decode_failures", decode_failures)
                if raw_count == 0:
                    await self._metric("empty_ranges")
                for error in (batch.get("decode_errors") or [])[:5]:
                    await self._diagnostic_error(
                        "decode", "decode_failure", error.get("reason"),
                        {"from_block": start, "to_block": end,
                         "log_offset": error.get("log_offset"),
                         "tx_hash": error.get("tx_hash")},
                    )
                if decode_failures:
                    raise DiscoveryDecodeError(
                        f"{decode_failures} factory event(s) failed decoding",
                        protocol_event_counts, failures_by_protocol,
                    )
                events.extend(found)
            except RpcRequestError as exc:
                span = end - start + 1
                if not exc.reduce_range or span <= self.min_chunk_size:
                    raise
                if exc.max_block_range:
                    await self._set_provider_range_limit(exc.max_block_range)
                    limit = self.provider_max_block_range
                    pending[0:0] = [
                        (block, min(end, block + limit - 1))
                        for block in range(start, end + 1, limit)
                    ]
                    continue
                midpoint = start + (span // 2) - 1
                if midpoint < start:
                    raise
                reduced = max(self.min_chunk_size, max(midpoint - start + 1, end - midpoint))
                await self._set_provider_range_limit(reduced)
                _structured_log(
                    logging.WARNING, "rpc_range_reduced",
                    provider_host=exc.provider_host, jsonrpc_method="eth_getLogs",
                    from_block=start, to_block=end,
                    next_chunk_size=self.effective_chunk_size,
                    reason=exc.category,
                )
                pending[0:0] = [(start, midpoint), (midpoint + 1, end)]
        return (
            sorted(events, key=lambda item: (
                item.get("block_number", 0), item.get("log_index", 0)
            )),
            protocol_event_counts,
            failures_by_protocol,
        )

    async def _scan_secondary(self) -> int:
        if self.secondary_provider is None:
            return 0
        now = time.monotonic()
        if (self._secondary_last_attempt_at is not None
                and now - self._secondary_last_attempt_at
                < self.config.dexscreener_poll_seconds):
            return 0
        last_status = await asyncio.to_thread(
            core.protocol_scan_status, ("dexscreener",)
        )
        last_cursor = last_status[0].get("cursor") if last_status else None
        if isinstance(last_cursor, str):
            try:
                last_attempt = datetime.fromisoformat(last_cursor)
                if last_attempt.tzinfo is None:
                    last_attempt = last_attempt.replace(tzinfo=timezone.utc)
                elapsed = (datetime.now(timezone.utc) - last_attempt).total_seconds()
            except ValueError:
                elapsed = self.config.dexscreener_poll_seconds
            if elapsed < self.config.dexscreener_poll_seconds:
                self._secondary_last_attempt_at = now - max(0.0, elapsed)
                return 0
        self._secondary_last_attempt_at = now
        attempt_at = datetime.now(timezone.utc).isoformat()
        try:
            await asyncio.to_thread(
                core.record_protocol_scan_attempt, "dexscreener",
                "dexscreener_api", attempt_at,
            )
            batch = await asyncio.to_thread(
                self.secondary_provider.fetch_batch
            )
            events = list(batch.get("events") or [])
            raw_count = int(batch.get("raw_log_count") or len(events))
            for event in events:
                tokens = self._tokens_for_event(event)
                event["quote_address"] = self._quote_for_event(event)
                persisted = await asyncio.to_thread(
                    core.record_discovered_pool, event, tokens, True
                )
                await self._metric("tokens_discovered", persisted["new_tokens"])
                if persisted["should_process"]:
                    for address in tokens:
                        if await self._enqueue(address, event):
                            await self._metric("tokens_queued")
            await asyncio.to_thread(
                core.record_protocol_scan_success, "dexscreener",
                "dexscreener_api", raw_count, attempt_at,
            )
            await self._metric("secondary_events_found", raw_count)
            await self._metric(
                "secondary_pairs_ignored", int(batch.get("ignored_pairs") or 0)
            )
            return len(events)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await asyncio.to_thread(
                core.record_protocol_scan_failure, "dexscreener",
                "dexscreener_api", 0, 0, type(exc).__name__, attempt_at,
            )
            await self._metric("secondary_provider_failures")
            await self._diagnostic_error(
                "secondary_provider", "dexscreener_failure",
                type(exc).__name__, {"source": "dexscreener"},
            )
            return 0

    async def _set_provider_range_limit(self, limit: int) -> None:
        bounded = max(self.min_chunk_size, min(int(limit), self.config.chunk_size))
        if bounded >= self.provider_max_block_range:
            return
        self.provider_max_block_range = bounded
        self.effective_chunk_size = min(self.effective_chunk_size, bounded)
        await asyncio.to_thread(
            core.write_state, self.range_limit_state_key, bounded
        )

    def _coverage_metrics(self, checkpoint: dict[str, Any] | None) -> dict[str, Any]:
        checkpoint_block = checkpoint.get("block_number") if checkpoint else None
        if self.latest_confirmed_block is None:
            lag = None
        elif checkpoint_block is not None:
            lag = max(0, self.latest_confirmed_block - int(checkpoint_block))
        else:
            anchor = self.initial_start_block or core.read_state(
                self.initial_start_state_key
            )
            lag = (max(0, self.latest_confirmed_block - int(anchor) + 1)
                   if isinstance(anchor, int) else None)
        block_seconds = max(0.1, self.base_block_seconds)
        # One log request and one checkpoint block-hash request per completed range.
        polling_rps = 2.0 / max(1, self.config.poll_seconds)
        required_rps = (2.0 / (block_seconds * self.provider_max_block_range)
                        + polling_rps)
        required_daily = (
            int((86400 / block_seconds) * 2 / self.provider_max_block_range)
            + int(86400 / max(1, self.config.poll_seconds)) * 2 + 1
        )
        budget = getattr(self.provider, "budget", None)
        budget_status = budget.status() if budget else None
        rps_limit = budget.requests_per_second if budget else 0
        daily_limit = budget.daily_limit if budget else 0
        now = datetime.now(timezone.utc)
        tomorrow = datetime.combine(
            now.date() + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc
        )
        seconds_to_reset = max(0, int((tomorrow - now).total_seconds()))
        needed_to_reset = int(required_rps * seconds_to_reset) + 1
        daily_remaining = ((budget_status or {}).get("daily") or {}).get("remaining")
        capacity_ok = (
            (not rps_limit or rps_limit >= required_rps)
            and (not daily_limit or daily_limit >= required_daily)
            and (daily_remaining is None or daily_remaining >= needed_to_reset)
        )
        if not capacity_ok or (lag is not None and lag > self.lag_threshold_blocks):
            coverage = "SCANNER_LAGGING"
        elif checkpoint_block is None:
            coverage = "SCANNER_INITIALIZING"
        elif lag is None:
            coverage = "SCANNER_STATUS_UNKNOWN"
        else:
            coverage = "SCANNER_CAUGHT_UP"
        return {
            "coverage_status": coverage,
            "latest_confirmed_block": self.latest_confirmed_block,
            "checkpoint_block": checkpoint_block,
            "lag_blocks": lag,
            "lag_threshold_blocks": self.lag_threshold_blocks,
            "estimated_required_requests_per_second": round(required_rps, 4),
            "estimated_required_requests_per_day": required_daily,
            "estimated_requests_needed_until_utc_reset": needed_to_reset,
            "budget_capacity_sufficient": capacity_ok,
            "rpc_budget": budget_status,
        }

    def _quote_for_event(self, event: dict[str, Any]) -> str | None:
        for address in (event["token0_address"], event["token1_address"]):
            if address.lower() in self.config.quote_assets:
                return address
        return None

    def _tokens_for_event(self, event: dict[str, Any]) -> list[str]:
        token0, token1 = event["token0_address"], event["token1_address"]
        q0 = token0.lower() in self.config.quote_assets
        q1 = token1.lower() in self.config.quote_assets
        if q0 and q1:
            return []
        if q0:
            return [token1]
        if q1:
            return [token0]
        return [token0, token1]

    async def _enqueue(self, address: str, event: dict[str, Any] | None) -> bool:
        checksum = Web3.to_checksum_address(address)
        if checksum in self._queued:
            return False
        self._queued.add(checksum)
        await self.queue.put((checksum, event))
        return True

    async def _queue_focus(self, focus: str) -> None:
        addresses = await asyncio.to_thread(core.focus_token_addresses, focus)
        if not addresses:
            summary = await asyncio.to_thread(core.developer_summary, focus)
            if not summary.get("developer"):
                addresses = [Web3.to_checksum_address(focus)]
        for address in addresses:
            if (time.monotonic() - self._focus_queued_at.get(address, 0.0)
                    < self.focus_reanalyze_seconds):
                continue
            await self._enqueue(address, None)
            self._focus_queued_at[address] = time.monotonic()

    async def _run(self) -> None:
        while not self._stop.is_set():
            enabled = await asyncio.to_thread(
                core.read_state, "scanner_enabled", False
            )
            focus = await asyncio.to_thread(core.read_state, "focused_developer")
            if enabled or focus:
                await self.scan_once()
                await self._monitor_tracked()
            self._wake.clear()
            try:
                await asyncio.wait_for(
                    self._wake.wait(), timeout=self.config.poll_seconds
                )
            except asyncio.TimeoutError:
                pass

    async def _worker(self, _index: int) -> None:
        while True:
            address, event = await self.queue.get()
            try:
                focus = await asyncio.to_thread(core.read_state, "focused_developer")
                if focus:
                    allowed = await asyncio.to_thread(core.focus_token_addresses, focus)
                    allowed.append(Web3.to_checksum_address(focus))
                    if address not in allowed:
                        continue
                await self._analyze(address, event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await self._metric("worker_failures")
                await self._diagnostic_error(
                    "worker", "worker_failure", type(exc).__name__,
                    {"address": address},
                )
                _structured_log(logging.WARNING, "analysis_worker_failed",
                                address=address, error_type=type(exc).__name__)
            finally:
                self._queued.discard(address)
                self.queue.task_done()

    async def _analyze(self, address: str, event: dict[str, Any] | None) -> None:
        try:
            result = await asyncio.to_thread(self.analyzer, address, self.rpc_url)
        except Exception as exc:
            await asyncio.to_thread(core.update_token_analysis, address, None, exc)
            await self._metric("analysis_failures")
            await self._diagnostic_error(
                "analysis", "analysis_failure", type(exc).__name__,
                {"address": address},
            )
            _structured_log(
                logging.WARNING, "token_analysis_failed", address=address,
                error_type=type(exc).__name__,
            )
            return
        self._attribute_market_to_discovery(result, event)
        await asyncio.to_thread(core.update_token_analysis, address, result)
        await self._metric("tokens_analyzed")
        contract_type = (result.get("contract") or {}).get("contract_type")
        if contract_type in {"unknown_contract", "eoa"}:
            await self._metric("unsupported_tokens")
        if result.get("decision") == "NO_BUY" or (result.get("risk") or {}).get("hard_rejections"):
            await self._metric("rejected_tokens")
        developer = result.get("developer", {})
        await asyncio.to_thread(
            core.record_developer_evidence, address, developer,
            result.get("contract", {}),
        )
        deployer = developer.get("deployer")
        if deployer and (os.getenv("BASESCAN_API_KEY") or os.getenv("ETHERSCAN_API_KEY")):
            summary = await asyncio.to_thread(core.developer_summary, deployer)
            if self._history_due(summary):
                errors: list[dict[str, Any]] = []
                deployments = await asyncio.to_thread(
                    fetch_creator_deployments, deployer, errors
                )
                if not errors:
                    await asyncio.to_thread(
                        core.add_previous_deployments, deployer, deployments
                    )
        matched, criteria = self._watchlist_match(result)
        if matched:
            await asyncio.to_thread(
                core.add_watchlist, address, "configured discovery criteria", criteria
            )
            await self._alert(address, result, event)
        else:
            await self._metric("watchlist_filtered")

    @staticmethod
    def _attribute_market_to_discovery(
        result: dict[str, Any], event: dict[str, Any] | None,
    ) -> None:
        """Label provider liquidity without converting a V4 pool ID to an address."""
        if not event:
            return
        market = result.get("market")
        if not isinstance(market, dict):
            return
        discovered_id = event.get("pool_id")
        discovered_address = event.get("pool_address")
        identity = discovered_id or discovered_address
        if not identity:
            return
        identity_type = "bytes32_pool_id" if discovered_id else "contract_address"
        matches = [
            pair for pair in market.get("pair_details", [])
            if isinstance(pair, dict)
            and str(pair.get("pair_id", "")).lower() == str(identity).lower()
            and pair.get("pair_identity_type") == identity_type
        ]
        market["discovered_pool_identity"] = str(identity)
        market["discovered_pool_identity_type"] = identity_type
        market["discovered_pool_pair_match"] = bool(matches)
        if matches:
            market["discovered_pool_liquidity_usd"] = matches[0].get(
                "liquidity_usd"
            )
            market["liquidity_attribution"] = (
                "single_discovered_pool" if market.get("pair_count") == 1
                else "token_pair_aggregate_includes_discovered_pool"
            )
        else:
            market["liquidity_attribution"] = "token_pair_data_not_pool_matched"

    def _watchlist_match(self, result: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        risk = result.get("risk", {})
        market = result.get("market", {})
        criteria = {
            "min_liquidity_usd": str(self.config.min_liquidity_usd),
            "max_token_age_hours": self.config.max_token_age_hours,
            "max_risk_score": self.config.max_risk_score,
            "min_evidence_confidence": self.config.min_evidence_confidence,
        }
        try:
            liquidity = Decimal(str(market.get("liquidity_usd")))
            age_hours = Decimal(str(market.get("oldest_pair_age_days"))) * 24
            score = int(risk.get("risk_score"))
            confidence = int(risk.get("evidence_confidence"))
        except (InvalidOperation, TypeError, ValueError):
            return False, criteria
        matched = (
            result.get("decision") == "WATCHLIST"
            and not risk.get("hard_rejections")
            and liquidity >= self.config.min_liquidity_usd
            and age_hours <= self.config.max_token_age_hours
            and score <= self.config.max_risk_score
            and confidence >= self.config.min_evidence_confidence
        )
        return matched, criteria

    async def _alert(
        self, address: str, result: dict[str, Any], event: dict[str, Any] | None
    ) -> None:
        if self.alert_callback is None:
            return
        pool = ((event or {}).get("pool_address")
                or (event or {}).get("pool_id") or "manual")
        dedupe_key = f"new-token:{address.lower()}"
        if not await asyncio.to_thread(
            core.reserve_alert, dedupe_key, address, "watchlist_match"
        ):
            return
        now = time.monotonic()
        hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        count = await asyncio.to_thread(core.alert_count_since, hour_ago)
        wait = self.config.alert_min_interval_seconds - (now - self._last_alert_at)
        if count >= self.config.alert_max_per_hour:
            await asyncio.to_thread(core.finish_alert, dedupe_key, "hourly alert limit")
            return
        if wait > 0:
            await asyncio.sleep(wait)
        risk = result.get("risk", {})
        market = result.get("market", {})
        assessment = risk.get("assessment") or "UNKNOWN"
        pool_label = "Pool ID" if (event or {}).get("pool_id") else "Pool"
        liquidity_scope = (
            market.get("liquidity_attribution")
            or market.get("liquidity_scope")
            or "UNKNOWN"
        )
        message = (
            "New Base token watchlist match — PAPER ONLY\n"
            f"Token: {address}\n{pool_label}: {pool}\n"
            f"Risk: {risk.get('risk_score', 'UNKNOWN')}/100 | "
            f"Evidence: {risk.get('evidence_confidence', 'UNKNOWN')}%\n"
            f"Assessment: {assessment}\n"
            f"Liquidity: {market.get('liquidity_usd', 'UNKNOWN')} USD\n"
            f"Liquidity source status: "
            f"{market.get('liquidity_source_status') or 'UNKNOWN'} | "
            f"Scope: {liquidity_scope}\n"
            "No trade or approval was submitted."
        )
        try:
            await self.alert_callback(message)
            self._last_alert_at = time.monotonic()
            await asyncio.to_thread(core.finish_alert, dedupe_key)
            await self._metric("alerts_sent")
        except Exception as exc:
            await asyncio.to_thread(core.finish_alert, dedupe_key, type(exc).__name__)
            await self._diagnostic_error(
                "alert", "alert_failure", type(exc).__name__, {"address": address}
            )

    async def _monitor_tracked(self) -> None:
        if not (os.getenv("BASESCAN_API_KEY") or os.getenv("ETHERSCAN_API_KEY")):
            return
        focus = await asyncio.to_thread(core.read_state, "focused_developer")
        addresses = [focus] if focus else await asyncio.to_thread(core.tracked_addresses)
        for address in filter(None, addresses):
            summary = await asyncio.to_thread(core.developer_summary, address)
            if not self._history_due(summary):
                continue
            errors: list[dict[str, Any]] = []
            deployments = await asyncio.to_thread(
                fetch_creator_deployments, address, errors
            )
            if not errors:
                await asyncio.to_thread(core.add_previous_deployments, address, deployments)

    def _history_due(self, summary: dict[str, Any]) -> bool:
        value = (summary.get("developer") or {}).get("last_history_scan_at")
        if not value:
            return True
        try:
            scanned = datetime.fromisoformat(value)
            return datetime.now(timezone.utc) - scanned >= timedelta(
                seconds=self.developer_refresh_seconds
            )
        except (TypeError, ValueError):
            return True
