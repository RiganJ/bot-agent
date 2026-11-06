"""Read-only Base token intelligence providers and risk assessment."""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlparse

import requests
from web3 import Web3
from .intelligence_v033 import extract_social_intelligence, inspect_bytecode

CHAIN_ID = 8453
GOPLUS_URL = "https://api.gopluslabs.io/api/v1/token_security/8453"
DEXSCREENER_URL = "https://api.dexscreener.com/latest/dex/tokens/"
ETHERSCAN_V2_URL = "https://api.etherscan.io/v2/api"
_HOST_LOCK = threading.Lock()
_HOST_LAST_REQUEST: dict[str, float] = {}
_IMPLEMENTATION_SLOT = int(
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16
)
_BEACON_SLOT = int(
    "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", 16
)
_ADMIN_SLOT = int(
    "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", 16
)
_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
_BURN_ADDRESSES = {
    _ZERO_ADDRESS,
    "0x000000000000000000000000000000000000dead",
}

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


def _record_error(errors: list[dict[str, Any]], source: str, message: str,
                  status_code: int | None = None) -> None:
    error: dict[str, Any] = {"source": source, "message": message}
    if status_code is not None:
        error["status_code"] = status_code
    errors.append(error)


def _rate_limit(host: str) -> None:
    interval = max(0.0, float(os.getenv("API_MIN_INTERVAL_SECONDS", "0.25")))
    with _HOST_LOCK:
        now = time.monotonic()
        wait = interval - (now - _HOST_LAST_REQUEST.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)
        _HOST_LAST_REQUEST[host] = time.monotonic()


def _get_json(
    url: str, params: dict[str, Any] | None = None, *, source: str,
    errors: list[dict[str, Any]], timeout: float = 8.0, attempts: int = 3,
) -> dict[str, Any] | list[Any] | None:
    """Fetch JSON with bounded retries; never log URLs or request parameters."""
    host = urlparse(url).hostname or "unknown"
    for attempt in range(attempts):
        _rate_limit(host)
        try:
            response = requests.get(url, params=params, timeout=timeout)
            if response.status_code == 429 or response.status_code >= 500:
                if attempt + 1 < attempts:
                    retry_after = response.headers.get("Retry-After", "")
                    try:
                        delay = min(3.0, max(0.0, float(retry_after)))
                    except (TypeError, ValueError):
                        delay = min(2.0, 0.25 * (2 ** attempt))
                    time.sleep(delay)
                    continue
                _record_error(errors, source, "HTTP request failed", response.status_code)
                logger.warning("provider_request_failed source=%s status=%s", source,
                               response.status_code)
                return None
            if not 200 <= response.status_code < 300:
                _record_error(errors, source, "HTTP request failed", response.status_code)
                logger.warning("provider_request_failed source=%s status=%s", source,
                               response.status_code)
                return None
            payload = response.json()
            if not isinstance(payload, (dict, list)):
                _record_error(errors, source, "Unexpected JSON response")
                return None
            return payload
        except requests.RequestException as exc:
            if attempt + 1 == attempts:
                _record_error(errors, source, f"Request unavailable ({type(exc).__name__})")
                logger.warning("provider_unavailable source=%s error_type=%s",
                               source, type(exc).__name__)
            else:
                time.sleep(min(2.0, 0.25 * (2 ** attempt)))
        except ValueError:
            _record_error(errors, source, "Invalid JSON response")
            return None
    return None


def _call(w3: Web3, address: str, signature: str, output_type: str) -> Any:
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(address),
        abi=[{"type": "function", "name": signature.split("(")[0],
              "stateMutability": "view", "inputs": [],
              "outputs": [{"type": output_type, "name": ""}]}],
    )
    return getattr(contract.functions, signature.split("(")[0])().call()


def _address_from_slot(value: bytes) -> str | None:
    if len(value) != 32:
        return None
    raw = value[-20:]
    if int.from_bytes(raw, "big") == 0:
        return None
    return Web3.to_checksum_address("0x" + raw.hex())


def _token_metadata(w3: Web3, address: str) -> dict[str, Any]:
    result: dict[str, Any] = {"is_erc20": False}
    try:
        result["decimals"] = int(_call(w3, address, "decimals()", "uint8"))
        result["total_supply_raw"] = str(_call(w3, address, "totalSupply()", "uint256"))
        result["is_erc20"] = True
    except Exception:
        return result
    for field, signature, output_type in (
        ("name", "name()", "string"), ("symbol", "symbol()", "string")
    ):
        try:
            result[field] = _call(w3, address, signature, output_type)
        except Exception:
            pass
    return result


def _proxy_details(w3: Web3, address: str, code: bytes) -> dict[str, Any]:
    """Resolve standard proxy targets and the strongest observable upgrade authority.

    An empty EIP-1967 admin slot does not prove immutability: UUPS implementations can
    authorize upgrades in application-specific storage. Such cases remain UNKNOWN.
    """
    details: dict[str, Any] = {
        "implementation": None, "kind": None, "beacon": None,
        "upgrade_authority": None, "upgrade_authority_status": "NOT_APPLICABLE",
        "upgrade_authority_evidence": None,
    }
    minimal_proxy = re.match(
        rb"\x36\x3d\x3d\x37\x3d\x3d\x3d\x36\x3d\x73(.{20})"
        rb"\x5a\xf4\x3d\x82\x80\x3e\x90\x3d\x91\x60\x2b\x57\xfd\x5b",
        code,
    )
    if minimal_proxy:
        details.update({
            "implementation": Web3.to_checksum_address(
                "0x" + minimal_proxy.group(1).hex()
            ),
            "kind": "clone",
            "upgrade_authority_status": "NOT_APPLICABLE",
            "upgrade_authority_evidence": "EIP-1167 clone target is immutable",
        })
        return details
    try:
        implementation = _address_from_slot(w3.eth.get_storage_at(address, _IMPLEMENTATION_SLOT))
        beacon = None
        if implementation:
            details.update({"implementation": implementation, "kind": "proxy"})
        else:
            beacon = _address_from_slot(w3.eth.get_storage_at(address, _BEACON_SLOT))
        if not implementation and beacon:
            raw = w3.eth.call({"to": beacon, "data": "0x5c60da1b"})
            resolved = _address_from_slot(bytes(raw).rjust(32, b"\x00"))
            if resolved:
                details.update({
                    "implementation": resolved, "kind": "proxy", "beacon": beacon,
                })
        if details["kind"] == "proxy":
            authority_target = beacon or address
            admin = _address_from_slot(w3.eth.get_storage_at(address, _ADMIN_SLOT))
            evidence = "EIP-1967 admin storage slot"
            authority = admin
            if beacon:
                evidence = "beacon owner() call"
                try:
                    authority = _call(w3, beacon, "owner()", "address")
                except Exception:
                    authority = None
            elif admin:
                # Transparent proxies commonly store a ProxyAdmin contract here.
                try:
                    if w3.eth.get_code(admin):
                        owner = _call(w3, admin, "owner()", "address")
                        if owner and int(owner, 16):
                            details["proxy_admin"] = admin
                            authority = owner
                            evidence = "EIP-1967 ProxyAdmin slot plus ProxyAdmin owner()"
                except Exception:
                    pass
            if authority and Web3.is_address(authority) and int(authority, 16):
                details.update({
                    "upgrade_authority": Web3.to_checksum_address(authority),
                    "upgrade_authority_status": "RESOLVED",
                    "upgrade_authority_evidence": evidence,
                })
            else:
                details.update({
                    "upgrade_authority_status": "UNKNOWN",
                    "upgrade_authority_evidence": (
                        "No EIP-1967 admin; UUPS/custom authorization cannot be "
                        "resolved from standard slots"
                        if not beacon else "Beacon owner() was unavailable"
                    ),
                })
    except Exception:
        details.update({
            "upgrade_authority_status": "UNKNOWN",
            "upgrade_authority_evidence": "Proxy storage inspection failed",
        })
    return details


def _proxy_implementation(w3: Web3, address: str, code: bytes) -> tuple[str | None, str | None]:
    """Backward-compatible wrapper used by existing callers/tests."""
    details = _proxy_details(w3, address, code)
    return details["implementation"], details["kind"]


def _detect_pool(w3: Web3, address: str) -> bool:
    try:
        token0 = _call(w3, address, "token0()", "address")
        token1 = _call(w3, address, "token1()", "address")
        if token0.lower() == token1.lower():
            return False
        try:
            reserves = bytes(w3.eth.call({"to": address, "data": "0x0902f1ac"}))
            if len(reserves) >= 96:
                return True
        except Exception:
            pass
        try:
            slot0 = bytes(w3.eth.call({"to": address, "data": "0x3850c7bd"}))
            return len(slot0) >= 224
        except Exception:
            return False
    except Exception:
        return False


def _fetch_goplus(address: str, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    payload = _get_json(
        GOPLUS_URL, {"contract_addresses": address.lower()},
        source="GoPlus", errors=errors,
    )
    if not isinstance(payload, dict) or str(payload.get("code")) != "1":
        if payload is not None:
            _record_error(errors, "GoPlus", "Security data unavailable")
        return None
    result = payload.get("result")
    if not isinstance(result, dict):
        _record_error(errors, "GoPlus", "Security data unavailable")
        return None
    token = result.get(address.lower())
    if token is None:
        token = next((v for k, v in result.items() if k.lower() == address.lower()), None)
    if not isinstance(token, dict):
        _record_error(errors, "GoPlus", "No token security record")
        return None
    return token


def _fetch_dex(address: str, errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    payload = _get_json(
        DEXSCREENER_URL + address, source="DEX Screener", errors=errors
    )
    if not isinstance(payload, dict):
        return []
    pairs = payload.get("pairs")
    if not isinstance(pairs, list):
        return []
    return [
        pair for pair in pairs
        if isinstance(pair, dict) and pair.get("chainId") == "base"
    ]


def _explorer_api_key() -> tuple[str, str | None]:
    """Etherscan V2 accepts one key across supported chains, including Base."""
    basescan = os.getenv("BASESCAN_API_KEY", "").strip()
    etherscan = os.getenv("ETHERSCAN_API_KEY", "").strip()
    if basescan:
        return basescan, "BASESCAN_API_KEY"
    if etherscan:
        return etherscan, "ETHERSCAN_API_KEY"
    return "", None


def _fetch_creation(
    address: str, errors: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    api_key, _ = _explorer_api_key()
    if not api_key:
        return None, None
    params = {
        "chainid": CHAIN_ID, "module": "contract", "action": "getcontractcreation",
        "contractaddresses": address, "apikey": api_key,
    }
    payload = _get_json(ETHERSCAN_V2_URL, params, source="BaseScan", errors=errors)
    if not isinstance(payload, dict) or payload.get("status") != "1":
        if payload is not None:
            _record_error(errors, "BaseScan", "Creation data unavailable")
        return None, None
    rows = payload.get("result")
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        _record_error(errors, "BaseScan", "No creation record")
        return None, None
    creation = rows[0]
    tx_hash = creation.get("txHash")
    if not tx_hash:
        return creation, None
    tx_params = {
        "chainid": CHAIN_ID, "module": "proxy", "action": "eth_getTransactionByHash",
        "txhash": tx_hash, "apikey": api_key,
    }
    tx_payload = _get_json(ETHERSCAN_V2_URL, tx_params, source="BaseScan", errors=errors)
    transaction = tx_payload.get("result") if isinstance(tx_payload, dict) else None
    if isinstance(transaction, dict) and transaction.get("blockNumber"):
        block_params = {
            "chainid": CHAIN_ID, "module": "proxy", "action": "eth_getBlockByNumber",
            "tag": transaction["blockNumber"], "boolean": "false", "apikey": api_key,
        }
        block_payload = _get_json(
            ETHERSCAN_V2_URL, block_params, source="BaseScan", errors=errors
        )
        block = block_payload.get("result") if isinstance(block_payload, dict) else None
        if isinstance(block, dict):
            try:
                transaction["timestamp"] = int(block.get("timestamp", "0x0"), 16)
            except (TypeError, ValueError):
                pass
    return creation, transaction if isinstance(transaction, dict) else None


def _fetch_funding(
    address: str, deployment_timestamp: int | None, errors: list[dict[str, Any]]
) -> dict[str, Any] | None:
    api_key, _ = _explorer_api_key()
    if not api_key or not deployment_timestamp:
        return None
    params = {
        "chainid": CHAIN_ID, "module": "account", "action": "txlist",
        "address": address, "startblock": 0, "endblock": 99999999,
        "page": 1, "offset": 100, "sort": "asc", "apikey": api_key,
    }
    payload = _get_json(ETHERSCAN_V2_URL, params, source="BaseScan", errors=errors)
    rows = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return None
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("to", "").lower() != address.lower() or row.get("isError") == "1":
            continue
        try:
            if int(row.get("timeStamp", "0")) >= deployment_timestamp:
                continue
            if int(row.get("value", "0")) <= 0:
                continue
        except (TypeError, ValueError):
            continue
        source = row.get("from")
        if source and Web3.is_address(source):
            return {
                "address": Web3.to_checksum_address(source),
                "evidence": "earliest observed inbound native-asset transaction",
                "ownership_claim": False,
            }
    return None


def fetch_creator_deployments(
    address: str, errors: list[dict[str, Any]] | None = None, limit: int = 100,
) -> list[dict[str, Any]]:
    """Return explorer-observed direct contract creations by an address.

    This is incomplete by design: internal factory creations need trace evidence and
    are not attributed when the provider does not expose it.
    """
    if not Web3.is_address(address):
        raise ValueError("Invalid EVM address")
    error_list = errors if errors is not None else []
    api_key, _ = _explorer_api_key()
    if not api_key:
        return []
    checksum = Web3.to_checksum_address(address)
    params = {
        "chainid": CHAIN_ID, "module": "account", "action": "txlist",
        "address": checksum, "startblock": 0, "endblock": 99999999,
        "page": 1, "offset": max(1, min(int(limit), 1000)), "sort": "desc",
        "apikey": api_key,
    }
    payload = _get_json(
        ETHERSCAN_V2_URL, params, source="Etherscan V2", errors=error_list
    )
    rows = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return []
    deployments = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        contract = row.get("contractAddress")
        if (row.get("from", "").lower() != checksum.lower()
                or not contract or not Web3.is_address(contract)
                or row.get("isError") == "1"):
            continue
        timestamp = None
        try:
            timestamp = datetime.fromtimestamp(
                int(row.get("timeStamp", "0")), timezone.utc
            ).isoformat()
        except (TypeError, ValueError, OSError):
            pass
        deployments.append({
            "contract_address": Web3.to_checksum_address(contract),
            "tx_hash": row.get("hash"), "block_number": row.get("blockNumber"),
            "timestamp": timestamp, "evidence": "direct explorer transaction",
        })
    return deployments


def fetch_wallet_history(
    address: str, errors: list[dict[str, Any]] | None = None, limit: int = 100,
) -> dict[str, Any]:
    """Summarize public explorer transactions without inferring wallet identity."""
    if not Web3.is_address(address):
        raise ValueError("Invalid EVM address")
    error_list = errors if errors is not None else []
    api_key, _ = _explorer_api_key()
    checksum = Web3.to_checksum_address(address)
    if not api_key:
        return {"status": "UNKNOWN", "address": checksum, "transactions": [],
                "funding_relationships": [], "created_contracts": [],
                "note": "Explorer API key is not configured."}
    params = {
        "chainid": CHAIN_ID, "module": "account", "action": "txlist",
        "address": checksum, "startblock": 0, "endblock": 99999999,
        "page": 1, "offset": max(1, min(int(limit), 1000)), "sort": "asc",
        "apikey": api_key,
    }
    payload = _get_json(ETHERSCAN_V2_URL, params, source="Etherscan V2",
                        errors=error_list)
    rows = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return {"status": "UNKNOWN", "address": checksum, "transactions": [],
                "funding_relationships": [], "created_contracts": [],
                "note": "Public transaction history is unavailable."}
    transactions, funding, created = [], [], []
    for row in rows:
        if not isinstance(row, dict) or row.get("isError") == "1":
            continue
        sender, recipient = row.get("from", ""), row.get("to", "")
        tx = {
            "hash": row.get("hash"), "block_number": row.get("blockNumber"),
            "timestamp": row.get("timeStamp"), "from": sender, "to": recipient,
            "value_wei": row.get("value", "0"),
            "method_id": (row.get("methodId") or (row.get("input") or "")[:10]),
            "source": "Etherscan V2 account history",
        }
        transactions.append(tx)
        contract = row.get("contractAddress")
        if contract and Web3.is_address(contract) and sender.lower() == checksum.lower():
            created.append({"address": Web3.to_checksum_address(contract),
                            "tx_hash": row.get("hash"),
                            "evidence": "direct contract creation transaction"})
        try:
            inbound_value = int(row.get("value", "0")) > 0
        except (TypeError, ValueError):
            inbound_value = False
        if (recipient.lower() == checksum.lower() and inbound_value
                and Web3.is_address(sender)):
            funding.append({
                "from": Web3.to_checksum_address(sender), "to": checksum,
                "tx_hash": row.get("hash"), "value_wei": row.get("value"),
                "relationship": "FUNDING_TRANSACTION", "ownership_claim": False,
                "source": "Etherscan V2 account history",
            })
    return {"status": "PASS", "address": checksum,
            "transaction_count_returned": len(transactions),
            "transactions": transactions, "funding_relationships": funding,
            "created_contracts": created,
            "ownership_status": "UNKNOWN",
            "note": "Funding and transaction relationships are not proof of common ownership."}


def _security_checks(token: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Normalize each documented GoPlus field without assuming shared polarity."""
    checks: dict[str, dict[str, Any]] = {}
    risk_when_one = {
        "is_honeypot": "Honeypot detected",
        "cannot_sell_all": "Cannot sell all tokens",
        "is_blacklisted": "Blacklist mechanism",
        "hidden_owner": "Hidden owner",
        "can_take_back_ownership": "Owner can reclaim ownership",
        "owner_change_balance": "Owner can change balances",
        "is_mintable": "Minting capability",
        "selfdestruct": "Self-destruct capability",
        "transfer_pausable": "Transfers can be paused",
        "slippage_modifiable": "Trading tax can be modified",
        "personal_slippage_modifiable": "Per-address tax can be modified",
    }
    source_dependent = set(risk_when_one) - {"cannot_sell_all", "is_honeypot"}
    proxy_limited = {
        "is_honeypot", "is_blacklisted", "hidden_owner",
        "can_take_back_ownership", "owner_change_balance", "is_mintable",
        "transfer_pausable", "slippage_modifiable",
        "personal_slippage_modifiable",
    }

    def unavailable(field: str, label: str, *, trading: bool = False) -> dict[str, Any]:
        if token is None:
            state, detail = "MISSING", "GoPlus token record unavailable"
        elif trading and str(token.get("is_in_dex", "")) == "0":
            state, detail = "NOT_APPLICABLE", "GoPlus reports token is not in a supported DEX"
        elif field in source_dependent and str(token.get("is_open_source", "")) == "0":
            state, detail = "UNSUPPORTED", "GoPlus does not evaluate this field for closed source code"
        elif field in proxy_limited and str(token.get("is_proxy", "")) == "1":
            state, detail = "UNSUPPORTED", "GoPlus did not evaluate this field for the proxy"
        elif (field == "cannot_sell_all"
              and str(token.get("buy_tax", "")) == "1"):
            state, detail = "UNSUPPORTED", "GoPlus omits this field when buy_tax is 100%"
        else:
            state, detail = "MISSING", "Field not returned by GoPlus"
        return {"status": "UNKNOWN", "evidence_state": state,
                "detail": f"{label}: {detail}"}

    for field, label in risk_when_one.items():
        value = token.get(field) if token else None
        if value is None or str(value).strip() not in {"0", "1"}:
            checks[field] = unavailable(
                field, label, trading=field in {"cannot_sell_all"}
            )
        else:
            failed = str(value).strip() == "1"
            checks[field] = {
                "status": "FAIL" if failed else "PASS",
                "evidence_state": "AVAILABLE",
                "raw_value": str(value).strip(),
                "polarity": "1=risk_present, 0=risk_not_detected",
                "detail": label if failed else f"No {label.lower()} reported",
            }
    # This field has the opposite safety polarity from the risk flags above.
    open_source = token.get("is_open_source") if token else None
    if str(open_source).strip() in {"0", "1"}:
        verified = str(open_source).strip() == "1"
        checks["is_open_source"] = {
            "status": "PASS" if verified else "FAIL",
            "evidence_state": "AVAILABLE", "raw_value": str(open_source).strip(),
            "polarity": "1=source_available, 0=source_unavailable",
            "detail": "Source code reported available" if verified else
                      "Source code not available; other GoPlus checks may be unsupported",
        }
    else:
        checks["is_open_source"] = unavailable(
            "is_open_source", "Source code verification"
        )
    for field in ("buy_tax", "sell_tax"):
        raw = token.get(field) if token else None
        try:
            tax = Decimal(str(raw))
            if not tax.is_finite() or tax < 0 or tax > 1:
                raise InvalidOperation
            checks[field] = {
                "status": "FAIL" if tax >= Decimal("0.10") else "PASS",
                "evidence_state": "AVAILABLE",
                "value_percent": str(tax * 100),
                "detail": f"{field.replace('_', ' ').title()} reported as {tax * 100}%",
            }
        except (InvalidOperation, TypeError, ValueError):
            checks[field] = unavailable(
                field, field.replace("_", " ").title(), trading=True
            )
    return checks


def _classify_holders(
    token: dict[str, Any] | None, verified_pool_addresses: set[str],
    w3: Web3 | None = None, owner: str | None = None,
    deployer: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Classify holders only when the row contains reproducible evidence."""
    result: dict[str, dict[str, Any]] = {}
    holders = token.get("holders") if token else None
    if not isinstance(holders, list):
        return result
    for holder in holders:
        if not isinstance(holder, dict):
            continue
        address = str(holder.get("address", "")).lower()
        if not Web3.is_address(address):
            continue
        tag = str(holder.get("tag", "")).strip()
        tag_lower = tag.lower()
        classification = "unclassified"
        evidence: list[str] = []
        has_code = False
        if w3 is not None:
            try:
                has_code = bool(w3.eth.get_code(address))
            except Exception:
                pass
        active_lock = False
        locked_detail = holder.get("locked_detail")
        if str(holder.get("is_locked", "")) == "1" and isinstance(locked_detail, list):
            for lock in locked_detail:
                if not isinstance(lock, dict):
                    continue
                try:
                    amount = Decimal(str(lock.get("amount")))
                    end_time = int(lock.get("end_time", 0))
                    if amount.is_finite() and amount > 0 and end_time > int(time.time()):
                        active_lock = True
                        break
                except (InvalidOperation, TypeError, ValueError):
                    continue
        if address in verified_pool_addresses and str(holder.get("is_contract", "")) == "1":
            classification = "liquidity_pool"
            evidence = ["DEX Screener pair address", "Base RPC pool interface and bytecode"]
        elif address in _BURN_ADDRESSES:
            classification = "burn"
            evidence = ["canonical irrecoverable burn address"]
        elif active_lock:
            classification = "vesting"
            evidence = ["GoPlus is_locked=1 with positive amount and future end_time"]
        elif ("bridge" in tag_lower and str(holder.get("is_contract", "")) == "1"
              and has_code):
            classification = "bridge"
            evidence = [f"GoPlus public tag: {tag}", "Base RPC verifies contract bytecode"]
        elif ("treasury" in tag_lower and str(holder.get("is_contract", "")) == "1"
              and has_code):
            classification = "treasury"
            evidence = [f"GoPlus public tag: {tag}", "Base RPC verifies contract bytecode"]
        elif owner and address == owner.lower():
            classification = "treasury"
            evidence = ["address equals on-chain owner()"]
        elif deployer and address == deployer.lower():
            classification = "treasury"
            evidence = ["address equals verified contract deployer"]
        # A provider tag alone is never enough to claim pool/burn/bridge/treasury.
        result[address] = {
            "classification": classification,
            "evidence": evidence or ["no verifiable category evidence"],
            "excluded_from_concentration": classification in {
                "liquidity_pool", "burn", "bridge", "vesting"
            },
        }
    return result


def _holder_concentration(
    token: dict[str, Any] | None,
    verified_pool_addresses: set[str] | dict[str, dict[str, Any]],
) -> dict[str, Any]:
    holders = token.get("holders") if token else None
    if not isinstance(holders, list) or not holders:
        return {"status": "UNKNOWN", "reason": "Holder distribution not available"}
    classifications = (
        verified_pool_addresses if isinstance(verified_pool_addresses, dict)
        else _classify_holders(token, verified_pool_addresses)
    )
    rows: list[tuple[Decimal, str]] = []
    all_shares: list[Decimal] = []
    excluded = 0
    classified_rows: list[dict[str, Any]] = []
    for holder in holders:
        if not isinstance(holder, dict):
            continue
        address = str(holder.get("address", "")).lower()
        try:
            share = Decimal(str(holder.get("percent")))
        except (InvalidOperation, TypeError, ValueError):
            continue
        if not share.is_finite() or share < 0 or share > 1:
            continue
        all_shares.append(share)
        classification = classifications.get(address, {
            "classification": "unclassified",
            "evidence": ["no verifiable category evidence"],
            "excluded_from_concentration": False,
        })
        classified_rows.append({
            "address": Web3.to_checksum_address(address),
            "percent": str(share * 100), **classification,
        })
        if classification["excluded_from_concentration"]:
            excluded += 1
            continue
        rows.append((share, address))
    if sum(all_shares, Decimal(0)) > Decimal("1.05"):
        return {"status": "UNKNOWN", "reason": "Holder shares are inconsistent"}
    if not rows:
        return {
            "status": "PASS", "top_holder_percent": "0", "top_10_percent": "0",
            "holders_considered": 0, "excluded_holders": excluded,
            "classifications": classified_rows,
            "reason": "All reported holders had verified non-concentration categories",
        }
    rows.sort(reverse=True)
    return {
        "status": "PASS",
        "top_holder_percent": str(rows[0][0] * 100),
        "top_10_percent": str(sum((share for share, _ in rows[:10]), Decimal(0)) * 100),
        "holders_considered": len(rows),
        "verified_pools_excluded": sum(
            1 for row in classified_rows if row["classification"] == "liquidity_pool"
        ),
        "excluded_holders": excluded,
        "classifications": classified_rows,
        "concentration_scope": (
            "treasury and unclassified holders; excludes only verified liquidity, "
            "burn, bridge, and vesting/locked categories"
        ),
        "source": "GoPlus holder list plus category-specific evidence",
    }


def _dex_summary(
    pairs: list[dict[str, Any]], target_address: str | None = None,
) -> dict[str, Any]:
    target = str(target_address or "").lower()
    matching = []
    for pair in pairs:
        token_addresses = {
            str(pair.get(which, {}).get("address", "")).lower()
            for which in ("baseToken", "quoteToken") if isinstance(pair.get(which), dict)
        }
        if not token_addresses or (target and target not in token_addresses):
            continue
        matching.append(pair)
    if not matching:
        return {"pair_count": 0}
    liquidity_values: list[Decimal] = []
    volume_values: list[Decimal] = []
    activity: dict[str, int] = {}
    price_changes: list[Decimal] = []
    timestamps: list[int] = []
    pair_details: list[dict[str, Any]] = []
    for pair in matching:
        pair_address = str(pair.get("pairAddress", ""))
        base_address = str((pair.get("baseToken") or {}).get("address", ""))
        quote_address = str((pair.get("quoteToken") or {}).get("address", ""))
        pair_liquidity = None
        try:
            value = Decimal(str(pair.get("liquidity", {}).get("usd")))
            if value.is_finite() and value >= 0:
                liquidity_values.append(value)
                pair_liquidity = str(value)
        except (InvalidOperation, TypeError, ValueError, AttributeError):
            pass
        identity_type = (
            "bytes32_pool_id" if re.fullmatch(r"0x[0-9a-fA-F]{64}", pair_address)
            else "contract_address" if Web3.is_address(pair_address)
            else "unknown"
        )
        pair_details.append({
            "dex_id": pair.get("dexId"), "pair_id": pair_address or None,
            "pair_identity_type": identity_type,
            "base_token": base_address or None, "quote_token": quote_address or None,
            "requested_token_role": (
                "base" if target and base_address.lower() == target else
                "quote" if target and quote_address.lower() == target else None
            ),
            "liquidity_usd": pair_liquidity,
            "liquidity_source": "DEX Screener provider-reported",
        })
        try:
            value = Decimal(str(pair.get("volume", {}).get("h24")))
            if value.is_finite() and value >= 0:
                volume_values.append(value)
        except (InvalidOperation, TypeError, ValueError, AttributeError):
            pass
        txns = pair.get("txns")
        transactions = txns.get("h24", {}) if isinstance(txns, dict) else {}
        if isinstance(transactions, dict):
            for side in ("buys", "sells"):
                try:
                    activity[side] = activity.get(side, 0) + int(transactions[side])
                except (KeyError, TypeError, ValueError):
                    pass
        try:
            price_change = pair.get("priceChange")
            change = Decimal(str(
                price_change.get("h24") if isinstance(price_change, dict) else None
            ))
            if change.is_finite():
                price_changes.append(change)
        except (InvalidOperation, TypeError, ValueError, AttributeError):
            pass
        try:
            timestamps.append(int(pair["pairCreatedAt"]))
        except (KeyError, TypeError, ValueError):
            pass
    pool_addresses = {
        str(pair.get("pairAddress", "")).lower()
        for pair in matching if Web3.is_address(str(pair.get("pairAddress", "")))
    }
    pool_ids = {
        str(pair.get("pairAddress", "")).lower() for pair in matching
        if re.fullmatch(
            r"0x[0-9a-fA-F]{64}", str(pair.get("pairAddress", ""))
        )
    }
    summary: dict[str, Any] = {
        "pair_count": len(matching),
        "liquidity_usd": str(sum(liquidity_values, Decimal(0))) if liquidity_values else None,
        "volume_24h_usd": str(sum(volume_values, Decimal(0))) if volume_values else None,
        "candidate_pool_addresses": sorted(pool_addresses),
        "candidate_pool_ids": sorted(pool_ids),
        "pair_details": pair_details,
        "liquidity_scope": (
            "single_token_specific_pair" if len(matching) == 1
            else "aggregate_across_token_specific_pairs"
        ),
        "liquidity_is_aggregated": len(matching) > 1,
        "liquidity_source_status": "PROVIDER_REPORTED_UNVERIFIED",
        "source": "DEX Screener",
    }
    if activity:
        summary["activity_24h"] = activity
    if price_changes:
        summary["price_change_24h_percent"] = str(
            sum(price_changes, Decimal(0)) / len(price_changes)
        )
    if timestamps:
        oldest = min(timestamps)
        summary["oldest_pair_age_days"] = max(
            0, (int(time.time() * 1000) - oldest) // 86_400_000
        )
    return summary


def _risk_assessment(
    checks: dict[str, dict[str, Any]], contract_type: str,
    dex: dict[str, Any], holders: dict[str, Any],
    evidence_components: dict[str, str] | None = None,
) -> dict[str, Any]:
    failed = [name for name, check in checks.items() if check["status"] == "FAIL"]
    unknown = [name for name, check in checks.items() if check["status"] == "UNKNOWN"]
    critical = {"is_honeypot", "cannot_sell_all", "owner_change_balance",
                "buy_tax", "sell_tax"}
    hard_rejections = [name for name in failed if name in critical]
    if contract_type in {"unknown_contract", "eoa"}:
        hard_rejections.append("address is not a recognized token or pool contract")
    try:
        if Decimal(str(holders.get("top_holder_percent"))) >= 50:
            hard_rejections.append("largest reported holder owns at least 50%")
        if Decimal(str(holders.get("top_10_percent"))) >= 90:
            hard_rejections.append("top ten reported holders own at least 90%")
    except (InvalidOperation, TypeError, ValueError):
        pass
    weights = {
        "is_honeypot": 70, "cannot_sell_all": 45, "owner_change_balance": 45,
        "sell_tax": 40, "buy_tax": 30, "hidden_owner": 30,
        "can_take_back_ownership": 25, "is_blacklisted": 25,
        "personal_slippage_modifiable": 25, "slippage_modifiable": 20,
        "transfer_pausable": 20, "is_mintable": 15, "selfdestruct": 15,
        "is_open_source": 15,
    }
    score = sum(weights.get(name, 10) for name in failed)
    if contract_type in {"unknown_contract", "eoa"}:
        score += 35
    if "largest reported holder owns at least 50%" in hard_rejections:
        score += 45
    if "top ten reported holders own at least 90%" in hard_rejections:
        score += 30
    score = min(100, score)
    available = sum(
        1 for check in checks.values() if check.get("evidence_state") == "AVAILABLE"
    )
    assessable = sum(
        1 for check in checks.values()
        if check.get("evidence_state") != "NOT_APPLICABLE"
    )
    components = evidence_components or {}
    available += sum(1 for state in components.values() if state == "AVAILABLE")
    assessable += sum(1 for state in components.values() if state != "NOT_APPLICABLE")
    confidence = round(100 * available / assessable) if assessable else 0
    decision = "NO_BUY" if hard_rejections else "WATCHLIST"
    reasons = [
        "Risk score measures detected risk only; evidence confidence measures coverage."
    ]
    if hard_rejections:
        reasons.insert(0, "Hard rejection rule triggered.")
    if unknown:
        reasons.append(f"{len(unknown)} security checks are UNKNOWN.")
    if dex.get("liquidity_usd") is None:
        reasons.append("Verified liquidity data is unavailable.")
    if holders.get("status") == "UNKNOWN":
        reasons.append("Holder concentration is unknown.")
    return {
        "risk_score": score, "risk_scale": "0=lowest detected risk; 100=highest detected risk",
        "evidence_confidence": confidence,
        "evidence_confidence_basis": (
            f"{available}/{assessable} applicable security and analysis evidence components available"
        ),
        "decision": decision, "assessment": "REJECTED" if hard_rejections else "INCONCLUSIVE",
        "hard_rejections": hard_rejections, "failed_checks": failed,
        "unknown_checks": unknown, "reasons": reasons,
        "safety_proven": False,
    }


def build_analysis(address: str, rpc_url: str | None = None) -> dict[str, Any]:
    """Build read-only intelligence report. Provider failures remain UNKNOWN."""
    if not Web3.is_address(address):
        raise ValueError("Invalid EVM address")
    checksum = Web3.to_checksum_address(address)
    errors: list[dict[str, Any]] = []
    sources: list[str] = []
    w3 = Web3(Web3.HTTPProvider(
        rpc_url or os.getenv("BASE_RPC_URL", "https://mainnet.base.org"),
        request_kwargs={"timeout": 12},
    ))
    onchain: dict[str, Any] = {
        "address": checksum, "chain_id": CHAIN_ID, "contract_type": "unknown_contract",
        "is_contract": False, "bytecode_bytes": 0, "implementation": None,
        "owner": None, "metadata": {"is_erc20": False},
    }
    try:
        if w3.eth.chain_id != CHAIN_ID:
            raise RuntimeError("RPC is not Base mainnet (chain ID 8453)")
        code = bytes(w3.eth.get_code(checksum))
        onchain.update({
            "is_contract": bool(code), "bytecode_bytes": len(code),
            "block_number": w3.eth.block_number,
        })
        if code:
            sources.append("Base RPC")
            onchain["static_inspection"] = inspect_bytecode(code)
            proxy = _proxy_details(w3, checksum, code)
            implementation = proxy["implementation"]
            implementation_kind = proxy["kind"]
            metadata = _token_metadata(w3, checksum)
            is_pool = _detect_pool(w3, checksum)
            if implementation:
                onchain["implementation"] = implementation
                onchain["implementation_type"] = implementation_kind
                onchain["beacon"] = proxy.get("beacon")
                onchain["upgrade_authority"] = proxy.get("upgrade_authority")
                onchain["upgrade_authority_status"] = proxy["upgrade_authority_status"]
                onchain["upgrade_authority_evidence"] = proxy["upgrade_authority_evidence"]
                if proxy.get("proxy_admin"):
                    onchain["proxy_admin"] = proxy["proxy_admin"]
                implementation_code = bytes(w3.eth.get_code(implementation))
                onchain["implementation_is_contract"] = bool(implementation_code)
                if not metadata["is_erc20"] and implementation_code:
                    metadata = _token_metadata(w3, implementation)
            if is_pool:
                onchain["contract_type"] = "pool"
            elif implementation_kind == "clone":
                onchain["contract_type"] = "clone"
            elif implementation_kind == "proxy":
                onchain["contract_type"] = "proxy"
            elif metadata["is_erc20"]:
                onchain["contract_type"] = "erc20"
            try:
                owner = _call(w3, checksum, "owner()", "address")
                if int(owner, 16):
                    onchain["owner"] = Web3.to_checksum_address(owner)
                    onchain["owner_evidence"] = "on-chain owner() call"
            except Exception:
                pass
            onchain["metadata"] = metadata
    except RuntimeError:
        raise
    except Exception as exc:
        _record_error(errors, "Base RPC", f"RPC inspection unavailable ({type(exc).__name__})")
        logger.warning("rpc_inspection_failed error_type=%s", type(exc).__name__)

    token_security = _fetch_goplus(checksum, errors)
    if token_security is not None:
        sources.append("GoPlus")
    pairs = _fetch_dex(checksum, errors)
    if pairs:
        sources.append("DEX Screener")
    dex = _dex_summary(pairs, checksum)
    social = extract_social_intelligence(pairs, "DEX Screener token pair metadata")
    candidate_pools = dex.pop("candidate_pool_addresses", [])
    pool_addresses: set[str] = set()
    for candidate in candidate_pools[:50]:
        try:
            if w3.eth.get_code(candidate) and _detect_pool(w3, candidate):
                pool_addresses.add(candidate)
        except Exception:
            continue
    dex["verified_pool_addresses"] = sorted(pool_addresses)
    checks = _security_checks(token_security)
    creation, transaction = _fetch_creation(checksum, errors)
    deployment: dict[str, Any] = {
        "deployer": None, "factory": None, "owner": onchain["owner"],
        "funding_wallet": None,
        "attribution_note": "Funding evidence does not establish wallet ownership.",
        "data_status": "UNKNOWN",
    }
    creator: str | None = None
    if creation:
        creator = creation.get("contractCreator")
        reported_factory = creation.get("contractFactory")
        tx_from = transaction.get("from") if transaction else None
        if creator and Web3.is_address(creator):
            creator = Web3.to_checksum_address(creator)
            creator_is_factory = False
            if reported_factory and Web3.is_address(reported_factory):
                deployment["deployer"] = creator
                deployment["factory"] = Web3.to_checksum_address(reported_factory)
            elif tx_from and Web3.is_address(tx_from) and tx_from.lower() != creator.lower():
                try:
                    creator_is_factory = bool(w3.eth.get_code(creator))
                except Exception:
                    pass
            if not deployment["deployer"] and creator_is_factory:
                deployment["deployer"] = Web3.to_checksum_address(tx_from)
                deployment["factory"] = creator
            elif not deployment["deployer"]:
                deployment["deployer"] = creator
            deployment["creation_tx"] = creation.get("txHash")
            deployment["source"] = "BaseScan contract creation record"
            deployment["data_status"] = "AVAILABLE"
            sources.append("BaseScan")
        try:
            deployed_at = int(
                (transaction.get("timestamp") if transaction else None)
                or creation.get("timestamp", 0)
            )
        except (TypeError, ValueError):
            deployed_at = 0
        deployment["funding_wallet"] = _fetch_funding(
            deployment["deployer"] or creator or checksum, deployed_at, errors
        )
    api_key, api_key_name = _explorer_api_key()
    if not deployment["deployer"]:
        deployment["data_status"] = "MISSING" if api_key else "NOT_CONFIGURED"
        deployment["deployer_note"] = (
            "Explorer key configured, but no usable contract creation/deployer record was returned."
            if api_key else
            "Deployer data unavailable because neither BASESCAN_API_KEY nor ETHERSCAN_API_KEY is configured."
        )
    deployment["explorer_key_source"] = api_key_name
    holder_classes = _classify_holders(
        token_security, pool_addresses, w3, onchain.get("owner"), deployment.get("deployer")
    )
    holders = _holder_concentration(token_security, holder_classes)
    missing: list[str] = []
    if not onchain["is_contract"]:
        missing.append("Base RPC could not verify contract bytecode")
    elif onchain["contract_type"] == "unknown_contract":
        missing.append("ERC-20, proxy, clone, or pool classification")
    if (onchain["contract_type"] in {"proxy", "clone"}
            and not onchain.get("implementation")):
        missing.append("proxy implementation address")
    if (onchain["contract_type"] == "proxy"
            and onchain.get("upgrade_authority_status") == "UNKNOWN"):
        missing.append("proxy upgrade authority")
    if token_security is None:
        missing.append("GoPlus token security record")
    if not dex.get("pair_count"):
        missing.append("DEX Screener Base pair data")
    else:
        for field, label in (
            ("liquidity_usd", "DEX Screener liquidity"),
            ("volume_24h_usd", "DEX Screener 24h volume"),
            ("oldest_pair_age_days", "DEX Screener pair age"),
            ("activity_24h", "DEX Screener trading activity"),
        ):
            if dex.get(field) is None:
                missing.append(label)
    if holders.get("status") == "UNKNOWN":
        missing.append("reliable holder distribution")
    if not deployment["deployer"]:
        missing.append("contract creation transaction / deployer")
    if deployment["owner"] is None:
        missing.append("on-chain owner() result")
    if not rpc_url and not os.getenv("BASE_RPC_URL"):
        missing.append("configured Base RPC endpoint")
    risk = _risk_assessment(
        checks, onchain["contract_type"], dex, holders,
        {
            "contract": "AVAILABLE" if onchain["is_contract"] else "MISSING",
            "market": "AVAILABLE" if dex.get("pair_count") else "MISSING",
            "holders": "AVAILABLE" if holders.get("status") == "PASS" else "MISSING",
            "deployer": "AVAILABLE" if deployment.get("deployer") else "MISSING",
            "proxy_authority": (
                "NOT_APPLICABLE" if onchain["contract_type"] != "proxy" else
                "AVAILABLE" if onchain.get("upgrade_authority_status") == "RESOLVED" else
                "MISSING"
            ),
        },
    )
    check_coverage = {"missing": [], "unsupported": [], "not_applicable": []}
    for name, check in checks.items():
        state = check.get("evidence_state")
        if state in {"MISSING", "UNSUPPORTED", "NOT_APPLICABLE"}:
            check_coverage[state.lower()].append(name)
    return {
        "address": checksum, "chain_id": CHAIN_ID,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "contract": onchain, "developer": deployment,
        "security": {"checks": checks, "source": "GoPlus" if token_security else None},
        "market": dex, "holders": holders, "risk": risk, "social": social,
        "decision": risk["decision"], "mode": "PAPER_ONLY",
        "evidence_sources": sorted(set(sources)),
        "check_coverage": check_coverage,
        "missing_evidence": missing, "api_errors": errors,
        "notice": "Read-only intelligence; no score or report proves a token is safe.",
    }
