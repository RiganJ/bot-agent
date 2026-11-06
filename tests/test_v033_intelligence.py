import base64
import json

from eth_abi import encode as abi_encode
from web3 import Web3

from app import core
from app.intelligence_v033 import (
    build_cluster,
    decode_abi_calldata,
    decode_abi_event,
    decode_public_payload,
    detect_encryption_format,
    extract_social_intelligence,
    inspect_bytecode,
    redact_sensitive,
)


A = "0x0000000000000000000000000000000000000001"
B = "0x0000000000000000000000000000000000000002"
TOKEN = "0x0000000000000000000000000000000000000003"


def test_abi_calldata_decode_with_verified_caller_abi():
    abi = [{"type": "function", "name": "transfer", "inputs": [
        {"name": "to", "type": "address"},
        {"name": "amount", "type": "uint256"},
    ]}]
    selector = Web3.keccak(text="transfer(address,uint256)")[:4]
    calldata = "0x" + (selector + abi_encode(["address", "uint256"], [A, 123])).hex()

    result = decode_abi_calldata(calldata, abi)

    assert result["status"] == "PASS"
    assert result["signature"] == "transfer(address,uint256)"
    assert result["arguments"][1]["value"] == 123


def test_hex_and_base64_payload_decoding():
    assert decode_public_payload("0x68656c6c6f")["utf8_preview"] == "hello"
    encoded = base64.b64encode(b"public metadata").decode()
    result = decode_public_payload(encoded)
    assert result["encoding"] == "BASE64"
    assert result["utf8_preview"] == "public metadata"


def test_event_log_decoding_with_indexed_and_data_arguments():
    abi = [{"type": "event", "name": "Transfer", "anonymous": False, "inputs": [
        {"name": "from", "type": "address", "indexed": True},
        {"name": "to", "type": "address", "indexed": True},
        {"name": "value", "type": "uint256", "indexed": False},
    ]}]
    topic0 = "0x" + Web3.keccak(text="Transfer(address,address,uint256)").hex().removeprefix("0x")
    address_topic = lambda value: "0x" + (b"\x00" * 12 + bytes.fromhex(value[2:])).hex()
    result = decode_abi_event(
        [topic0, address_topic(A), address_topic(B)],
        "0x" + abi_encode(["uint256"], [99]).hex(), abi,
    )
    assert result["status"] == "PASS"
    assert result["arguments"][2]["value"] == 99


def test_encryption_formats_are_metadata_only():
    openssl = detect_encryption_format(b"Salted__12345678ciphertext")
    pgp = detect_encryption_format("-----BEGIN PGP MESSAGE-----\nabc")
    keystore = detect_encryption_format(json.dumps({
        "version": 3, "crypto": {"cipher": "aes-128-ctr", "kdf": "scrypt"},
    }))
    assert openssl["format"] == "OPENSSL_SALTED"
    assert pgp["format"] == "OPENPGP_ARMORED"
    assert keystore["format"] == "ETHEREUM_KEYSTORE_JSON"
    assert not openssl["plaintext_recovered"]
    assert keystore["note"].startswith("Metadata only")


def test_sensitive_redaction_is_recursive_and_blocks_seed_phrase():
    value = {
        "private_key": "0x" + "11" * 32,
        "nested": {"apiKey": "secret-value"},
        "message": "seed phrase: abandon ability able about above absent",
        "public_tx_hash": "0x" + "22" * 32,
    }
    redacted = redact_sensitive(value)
    serialized = json.dumps(redacted)
    assert "secret-value" not in serialized
    assert "abandon" not in serialized
    assert redacted["private_key"] == "[REDACTED]"
    assert redacted["public_tx_hash"] == value["public_tx_hash"]


def test_social_provenance_distinguishes_project_from_developer():
    result = extract_social_intelligence({
        "info": {"websites": [{"url": "https://project.example"}],
                 "socials": [{"url": "https://x.com/project"}]},
    }, "verified explorer metadata")
    assert result["status"] == "PASS"
    assert result["social_accounts"][0]["account_type"] == "PROJECT"
    assert result["social_accounts"][0]["source"] == "verified explorer metadata"
    assert result["developer_accounts"] == []
    assert result["developer_relationship_status"] == "UNKNOWN"


def test_cluster_does_not_infer_ownership_from_shared_factory():
    result = build_cluster([A, B], [{
        "from": A, "to": B, "relationship": "SHARED_FACTORY",
        "source": "factory event", "confidence": 90,
    }])
    assert result["common_ownership"] == "UNKNOWN"
    assert result["edges"][0]["ownership_claim"] is False
    assert result["edges"][0]["shared_infrastructure_only"] is True


def test_static_contract_capabilities_keep_opaque_distinct_from_malicious():
    code = bytes.fromhex("63" + "3659cfe6" + ("00" * 50) + "f4")
    result = inspect_bytecode(code)
    assert result["capabilities"][0]["capability"] == "upgradeTo(address)"
    assert result["opaque_assessment"] == "NOT_APPLICABLE"
    assert "not automatically malicious" in result["note"]


def test_v033_migration_and_relationship_persistence(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "v033.db"))
    report = {
        "address": TOKEN, "analyzed_at": "2026-11-06T00:00:00+00:00",
        "developer": {"deployer": A, "factory": B,
                      "source": "verified explorer creation record",
                      "funding_wallet": {"address": B, "evidence": "public tx"}},
        "contract": {"owner": A, "owner_evidence": "owner()",
                     "static_inspection": {"runtime_code_hash": "0xabc",
                                           "bytecode_bytes": 100}},
        "social": extract_social_intelligence("https://x.com/project", "metadata"),
    }
    core.record_intelligence_evidence(report)
    core.record_intelligence_evidence({
        **report, "address": B,
        "contract": {"static_inspection": {"runtime_code_hash": "0xabc",
                                              "bytecode_bytes": 100}},
        "social": {},
    })

    wallet = core.wallet_summary(A)
    cluster = core.cluster_summary(TOKEN)
    social = core.social_summary(TOKEN)
    with core.db_connect() as con:
        migration = con.execute(
            "SELECT 1 FROM schema_migrations WHERE version=5"
        ).fetchone()

    assert migration == (1,)
    assert wallet["relationships"]
    assert cluster["common_ownership"] == "UNKNOWN"
    assert any(edge["relationship"] == "SHARED_TEMPLATE"
               for edge in cluster["edges"])
    assert social["status"] == "PASS"
