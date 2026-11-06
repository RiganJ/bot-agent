"""v0.3.3 read-only developer, wallet, social, encoding and contract intelligence.

This module intentionally has no signing or transaction-submission primitives.
All relationships are evidence edges; shared infrastructure alone is never an
ownership claim.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from eth_abi import decode as abi_decode
from web3 import Web3

UNKNOWN = "UNKNOWN"
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.I)
_X_HOSTS = {"x.com", "www.x.com", "twitter.com", "www.twitter.com"}

# Values matching these patterns must not reach persistence, logs, Telegram, or AI.
_SENSITIVE_KEYS = re.compile(
    r"(?i)(private.?key|seed|mnemonic|recovery.?phrase|keystore.?password|"
    r"decrypt(?:ion)?.?(?:key|secret|password)|authorization|api.?key|"
    r"access.?token|refresh.?token|bearer|secret|password)"
)
_MNEMONIC_HINT = re.compile(
    r"(?i)\b(seed phrase|mnemonic|recovery phrase|private key)\b\s*[:=]?\s*.*"
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact_sensitive(value: Any) -> Any:
    """Recursively redact credential-like fields and inline secret material."""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEYS.search(str(key))
            else redact_sensitive(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_sensitive(item) for item in value]
    if not isinstance(value, str):
        return value
    text = _MNEMONIC_HINT.sub("[REDACTED]", value)
    text = re.sub(
        r"(?i)\b(api[_-]?key|token|authorization|bearer|password|secret)"
        r"(\s*[:=]\s*)[^\s,;]+", r"\1\2[REDACTED]", text,
    )
    # 32-byte hex values are ambiguous (tx hashes are public), so redact only when
    # introduced as a private key/secret. The key-name handling above covers JSON.
    return text


def contains_sensitive_material(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_SENSITIVE_KEYS.search(str(k)) or contains_sensitive_material(v)
                   for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(contains_sensitive_material(v) for v in value)
    return bool(isinstance(value, str) and _MNEMONIC_HINT.search(value))


def detect_encryption_format(data: bytes | str) -> dict[str, Any]:
    """Identify public envelope formats without claiming plaintext recovery."""
    raw = data.encode("utf-8", "replace") if isinstance(data, str) else bytes(data)
    text = raw.decode("utf-8", "replace").strip()
    result: dict[str, Any] = {
        "status": UNKNOWN, "format": UNKNOWN, "encrypted": UNKNOWN,
        "plaintext_recovered": False,
        "note": "Format detection reports envelope metadata only.",
    }
    if raw.startswith(b"Salted__"):
        return {**result, "status": "PASS", "format": "OPENSSL_SALTED",
                "encrypted": True, "salt_hex": raw[8:16].hex()}
    if text.startswith("-----BEGIN PGP MESSAGE-----"):
        return {**result, "status": "PASS", "format": "OPENPGP_ARMORED",
                "encrypted": True, "armored": True}
    if text.startswith("age-encryption.org/v1"):
        return {**result, "status": "PASS", "format": "AGE_V1",
                "encrypted": True}
    if text.startswith("gAAAAA"):
        return {**result, "status": "PASS", "format": "FERNET_TOKEN",
                "encrypted": True}
    parts = text.split(".")
    if len(parts) == 5 and all(parts):
        return {**result, "status": "PASS", "format": "JWE_COMPACT",
                "encrypted": True, "segments": 5}
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, dict):
        if {"crypto", "version"}.issubset({str(k).lower() for k in parsed}):
            crypto = parsed.get("crypto") or parsed.get("Crypto") or {}
            return {**result, "status": "PASS", "format": "ETHEREUM_KEYSTORE_JSON",
                    "encrypted": True, "cipher": crypto.get("cipher", UNKNOWN),
                    "kdf": crypto.get("kdf", UNKNOWN),
                    "sensitive": True,
                    "note": "Metadata only; wallet unlocking is prohibited."}
        if {"iv", "ciphertext", "tag"}.issubset({str(k).lower() for k in parsed}):
            return {**result, "status": "PASS", "format": "AEAD_JSON_ENVELOPE",
                    "encrypted": True}
    return result


def _bytes_preview(raw: bytes, limit: int = 96) -> str:
    decoded = raw[:limit].decode("utf-8", "replace")
    return redact_sensitive(decoded)


def decode_abi_calldata(calldata: str, abi: list[dict[str, Any]]) -> dict[str, Any]:
    """Decode calldata only when a caller supplies a matching verified ABI."""
    if not isinstance(calldata, str) or not calldata.startswith("0x"):
        raise ValueError("Calldata must be 0x-prefixed hex")
    try:
        raw = bytes.fromhex(calldata[2:])
    except ValueError as exc:
        raise ValueError("Malformed calldata hex") from exc
    if len(raw) < 4:
        raise ValueError("Calldata is shorter than a function selector")
    selector = raw[:4]
    for entry in abi:
        if entry.get("type") != "function":
            continue
        inputs = entry.get("inputs") or []
        types = [item.get("type") for item in inputs]
        if not all(isinstance(t, str) for t in types):
            continue
        signature = f"{entry.get('name')}({','.join(types)})"
        if Web3.keccak(text=signature)[:4] != selector:
            continue
        try:
            values = abi_decode(types, raw[4:]) if types else ()
        except Exception as exc:
            raise ValueError("ABI arguments could not be decoded") from exc
        arguments = []
        for spec, value in zip(inputs, values):
            if isinstance(value, bytes):
                value = "0x" + value.hex()
            elif isinstance(value, tuple):
                value = list(value)
            arguments.append({"name": spec.get("name") or "", "type": spec["type"],
                              "value": redact_sensitive(value)})
        return {"status": "PASS", "selector": "0x" + selector.hex(),
                "signature": signature, "arguments": arguments,
                "provenance": "caller-supplied ABI"}
    return {"status": UNKNOWN, "selector": "0x" + selector.hex(),
            "signature": UNKNOWN, "arguments": [],
            "note": "No matching function in supplied ABI"}


def decode_abi_event(topics: list[str], data: str,
                     abi: list[dict[str, Any]]) -> dict[str, Any]:
    """Decode an event log using a caller-supplied verified ABI."""
    if not topics or not all(isinstance(topic, str) and topic.startswith("0x")
                             for topic in topics):
        raise ValueError("Event topics must be 0x-prefixed hex")
    if not isinstance(data, str) or not data.startswith("0x"):
        raise ValueError("Event data must be 0x-prefixed hex")
    topic0 = topics[0].lower()
    for entry in abi:
        if entry.get("type") != "event" or entry.get("anonymous"):
            continue
        inputs = entry.get("inputs") or []
        signature = f"{entry.get('name')}({','.join(str(i.get('type')) for i in inputs)})"
        if ("0x" + Web3.keccak(text=signature).hex().removeprefix("0x")).lower() != topic0:
            continue
        indexed = [item for item in inputs if item.get("indexed")]
        plain = [item for item in inputs if not item.get("indexed")]
        if len(topics) - 1 != len(indexed):
            raise ValueError("Indexed topic count does not match ABI")
        try:
            plain_values = abi_decode(
                [item["type"] for item in plain], bytes.fromhex(data[2:])
            ) if plain else ()
        except Exception as exc:
            raise ValueError("Event data could not be ABI decoded") from exc
        indexed_iter = iter(topics[1:])
        plain_iter = iter(plain_values)
        arguments = []
        for item in inputs:
            typ = item["type"]
            if item.get("indexed"):
                topic = next(indexed_iter)
                if typ in {"string", "bytes"} or typ.endswith("]") or typ.startswith("tuple"):
                    value = topic
                    decoded = False
                else:
                    value = abi_decode([typ], bytes.fromhex(topic[2:]))[0]
                    decoded = True
            else:
                value, decoded = next(plain_iter), True
            if isinstance(value, bytes):
                value = "0x" + value.hex()
            arguments.append({"name": item.get("name") or "", "type": typ,
                              "indexed": bool(item.get("indexed")),
                              "decoded": decoded, "value": redact_sensitive(value)})
        return {"status": "PASS", "event": signature, "arguments": arguments,
                "provenance": "caller-supplied ABI"}
    return {"status": UNKNOWN, "event": UNKNOWN, "arguments": [],
            "note": "No matching event in supplied ABI"}


def decode_public_payload(value: str, abi: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Decode public hex/Base64/calldata and identify encrypted envelopes."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Encoded payload is required")
    if contains_sensitive_material(value):
        raise ValueError("Sensitive credentials are not accepted")
    text = value.strip()
    raw: bytes
    encoding: str
    if _HEX_RE.fullmatch(text) and len(text.removeprefix("0x")) % 2 == 0:
        try:
            raw = bytes.fromhex(text.removeprefix("0x"))
        except ValueError as exc:
            raise ValueError("Malformed hex payload") from exc
        encoding = "HEX"
    elif _BASE64_RE.fullmatch(text) and len(text) % 4 == 0:
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Malformed Base64 payload") from exc
        encoding = "BASE64"
    else:
        raw = text.encode("utf-8")
        encoding = "TEXT"
    encryption = detect_encryption_format(raw)
    result: dict[str, Any] = {
        "status": "PASS", "encoding": encoding, "byte_length": len(raw),
        "utf8_preview": _bytes_preview(raw), "encryption": encryption,
        "plaintext_recovered": False,
    }
    if abi is not None and encoding == "HEX" and text.startswith("0x"):
        result["abi"] = decode_abi_calldata(text, abi)
    return redact_sensitive(result)


def extract_social_intelligence(metadata: Any, source: str = "metadata") -> dict[str, Any]:
    """Extract project links with provenance; never invent developer identity."""
    websites: list[dict[str, Any]] = []
    socials: list[dict[str, Any]] = []

    def visit(item: Any, path: str) -> None:
        if isinstance(item, dict):
            for key, val in item.items():
                visit(val, f"{path}.{key}")
        elif isinstance(item, list):
            for index, val in enumerate(item):
                visit(val, f"{path}[{index}]")
        elif isinstance(item, str):
            for match in _URL_RE.findall(item):
                url = match.rstrip(".,);]")
                host = (urlparse(url).hostname or "").lower()
                evidence = {"url": url, "source": source, "path": path,
                            "observed_at": utcnow(), "confidence": 80,
                            "relationship": "PROJECT_METADATA_LINK"}
                if host in _X_HOSTS:
                    socials.append({**evidence, "platform": "X",
                                    "account_type": "PROJECT",
                                    "developer_account": UNKNOWN})
                else:
                    websites.append(evidence)

    visit(metadata, "$metadata")
    def unique(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[str] = set()
        output = []
        for row in rows:
            if row["url"] not in seen:
                seen.add(row["url"])
                output.append(row)
        return output
    websites, socials = unique(websites), unique(socials)
    return {
        "status": "PASS" if websites or socials else UNKNOWN,
        "websites": websites, "social_accounts": socials,
        "developer_accounts": [],
        "developer_relationship_status": UNKNOWN,
        "public_activity": {"status": UNKNOWN,
                            "note": "No legally accessible activity provider was queried."},
        "note": ("Metadata links identify project-facing accounts only; developer "
                 "accounts require separate verified evidence."),
    }


_SELECTORS = {
    "40c10f19": ("mint(address,uint256)", "HIGH"),
    "42966c68": ("burn(uint256)", "INFO"),
    "8456cb59": ("pause()", "MEDIUM"),
    "3f4ba83a": ("unpause()", "INFO"),
    "8da5cb5b": ("owner()", "INFO"),
    "f2fde38b": ("transferOwnership(address)", "MEDIUM"),
    "3659cfe6": ("upgradeTo(address)", "HIGH"),
    "4f1ef286": ("upgradeToAndCall(address,bytes)", "HIGH"),
    "a9059cbb": ("transfer(address,uint256)", "INFO"),
    "23b872dd": ("transferFrom(address,address,uint256)", "INFO"),
}


def inspect_bytecode(code: bytes) -> dict[str, Any]:
    """Conservative static capability indicators; presence is not exploitability."""
    raw = bytes(code)
    hex_code = raw.hex()
    findings = []
    for selector, (signature, severity) in _SELECTORS.items():
        if selector in hex_code:
            findings.append({"capability": signature, "severity": severity,
                             "status": "FAIL" if severity in {"HIGH", "MEDIUM"} else "PASS",
                             "evidence": f"selector 0x{selector} present in runtime bytecode",
                             "certainty": "CAPABILITY_INDICATOR"})
    opaque = []
    if raw and len(raw) < 45:
        opaque.append("very short runtime bytecode")
    delegatecalls = raw.count(b"\xf4")
    if delegatecalls and "3659cfe6" not in hex_code and "4f1ef286" not in hex_code:
        opaque.append("DELEGATECALL present without recognized standard upgrade selector")
    return {
        "status": "PASS" if raw else UNKNOWN, "bytecode_bytes": len(raw),
        "runtime_code_hash": Web3.keccak(raw).hex() if raw else None,
        "capabilities": findings,
        "opaque_patterns": opaque,
        "opaque_assessment": "UNKNOWN" if opaque else "NOT_APPLICABLE",
        "delegatecall_opcode_count": delegatecalls,
        "note": "Obfuscation or encryption is not automatically malicious.",
    }


def build_cluster(nodes: list[str], edges: list[dict[str, Any]]) -> dict[str, Any]:
    """Build an explainable graph without converting infrastructure into identity."""
    clean_nodes = sorted({Web3.to_checksum_address(n) for n in nodes if Web3.is_address(n)})
    clean_edges = []
    for edge in edges:
        left, right = edge.get("from"), edge.get("to")
        if not (Web3.is_address(left) and Web3.is_address(right)):
            continue
        relationship = str(edge.get("relationship") or UNKNOWN).upper()
        shared_only = relationship in {"SHARED_FACTORY", "SHARED_HOOK",
                                       "SHARED_TEMPLATE", "SHARED_INFRASTRUCTURE"}
        clean_edges.append({
            "from": Web3.to_checksum_address(left),
            "to": Web3.to_checksum_address(right),
            "relationship": relationship,
            "evidence": redact_sensitive(edge.get("evidence") or {}),
            "source": edge.get("source") or UNKNOWN,
            "observed_at": edge.get("observed_at") or utcnow(),
            "confidence": max(0, min(int(edge.get("confidence", 0)), 100)),
            "ownership_claim": False,
            "shared_infrastructure_only": shared_only,
        })
    return {
        "status": "PASS" if clean_edges else UNKNOWN,
        "nodes": clean_nodes, "edges": clean_edges,
        "common_ownership": UNKNOWN,
        "note": "Relationships are explainable evidence; shared infrastructure alone does not imply common ownership.",
    }
