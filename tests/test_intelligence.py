from decimal import Decimal

import requests

from app import intelligence
from app import core
from app.bot import format_analysis


def test_missing_security_data_is_unknown_not_pass():
    checks = intelligence._security_checks(None)

    assert checks
    assert {check["status"] for check in checks.values()} == {"UNKNOWN"}


def test_reported_critical_security_flags_fail():
    checks = intelligence._security_checks({
        "is_honeypot": "1",
        "cannot_sell_all": "0",
        "sell_tax": "0.12",
    })

    assert checks["is_honeypot"]["status"] == "FAIL"
    assert checks["cannot_sell_all"]["status"] == "PASS"
    assert checks["sell_tax"]["status"] == "FAIL"


def test_reported_axis_token_open_source_polarity_regression():
    """Regression for 0x5bE75e3b0aFf5D1A042A5363Ae36AcB1d6d755ea."""
    checks = intelligence._security_checks({
        "is_open_source": "1", "is_proxy": "1", "buy_tax": "0",
        "sell_tax": "0", "is_in_dex": "1",
    })

    assert checks["is_open_source"]["status"] == "PASS"
    assert checks["is_open_source"]["polarity"] == (
        "1=source_available, 0=source_unavailable"
    )
    assert checks["is_honeypot"]["status"] == "UNKNOWN"
    assert checks["is_honeypot"]["evidence_state"] == "UNSUPPORTED"
    assert checks["is_honeypot"]["status"] != "PASS"


def test_each_goplus_boolean_uses_its_documented_polarity():
    risk_fields = (
        "is_honeypot", "cannot_sell_all", "is_blacklisted", "hidden_owner",
        "can_take_back_ownership", "owner_change_balance", "is_mintable",
        "selfdestruct", "transfer_pausable", "slippage_modifiable",
        "personal_slippage_modifiable",
    )
    base = {"is_open_source": "1", "is_in_dex": "1"}
    for field in risk_fields:
        assert intelligence._security_checks({**base, field: "1"})[field]["status"] == "FAIL"
        assert intelligence._security_checks({**base, field: "0"})[field]["status"] == "PASS"
    assert intelligence._security_checks({"is_open_source": "1"})[
        "is_open_source"
    ]["status"] == "PASS"
    assert intelligence._security_checks({"is_open_source": "0"})[
        "is_open_source"
    ]["status"] == "FAIL"


def test_goplus_missing_unsupported_and_not_applicable_are_distinct():
    no_record = intelligence._security_checks(None)
    closed_source = intelligence._security_checks({"is_open_source": "0"})
    no_dex = intelligence._security_checks({
        "is_open_source": "1", "is_in_dex": "0"
    })

    assert no_record["hidden_owner"]["evidence_state"] == "MISSING"
    assert closed_source["hidden_owner"]["evidence_state"] == "UNSUPPORTED"
    assert no_dex["sell_tax"]["evidence_state"] == "NOT_APPLICABLE"
    assert all(item["status"] == "UNKNOWN" for item in (
        no_record["hidden_owner"], closed_source["hidden_owner"],
        no_dex["sell_tax"],
    ))


def test_goplus_mock_response_is_normalized(monkeypatch):
    address = "0x0000000000000000000000000000000000000001"
    token = {"is_honeypot": "0", "sell_tax": "0"}
    monkeypatch.setattr(
        intelligence, "_get_json",
        lambda *_args, **_kwargs: {
            "code": 1, "result": {address: token},
        },
    )
    errors = []

    assert intelligence._fetch_goplus(address, errors) == token
    assert errors == []


def test_goplus_failed_mock_response_is_not_a_pass(monkeypatch):
    address = "0x0000000000000000000000000000000000000001"
    monkeypatch.setattr(
        intelligence, "_get_json",
        lambda *_args, **_kwargs: {"code": 2, "message": "unavailable"},
    )
    errors = []

    token = intelligence._fetch_goplus(address, errors)

    assert token is None
    assert errors
    assert all(
        check["status"] == "UNKNOWN"
        for check in intelligence._security_checks(token).values()
    )


def test_dex_mock_response_filters_to_base(monkeypatch):
    monkeypatch.setattr(
        intelligence, "_get_json",
        lambda *_args, **_kwargs: {
            "pairs": [{"chainId": "base"}, {"chainId": "ethereum"}],
        },
    )
    errors = []

    assert intelligence._fetch_dex(
        "0x0000000000000000000000000000000000000001", errors
    ) == [{"chainId": "base"}]
    assert errors == []


def test_risk_unknowns_cannot_produce_a_safety_decision():
    checks = intelligence._security_checks(None)
    risk = intelligence._risk_assessment(
        checks, "erc20", {"liquidity_usd": None}, {"status": "UNKNOWN"}
    )

    assert risk["decision"] == "WATCHLIST"
    assert risk["safety_proven"] is False
    assert risk["unknown_checks"]
    assert risk["risk_score"] == 0
    assert risk["evidence_confidence"] == 0
    assert risk["assessment"] == "INCONCLUSIVE"


def test_honeypot_triggers_hard_rejection():
    checks = intelligence._security_checks({"is_honeypot": "1"})
    risk = intelligence._risk_assessment(
        checks, "erc20", {}, {"status": "UNKNOWN"}
    )

    assert risk["decision"] == "NO_BUY"
    assert "is_honeypot" in risk["hard_rejections"]


def test_high_tax_is_a_hard_rejection():
    checks = intelligence._security_checks({"sell_tax": "0.10"})
    risk = intelligence._risk_assessment(
        checks, "erc20", {}, {"status": "UNKNOWN"}
    )

    assert checks["sell_tax"]["status"] == "FAIL"
    assert risk["decision"] == "NO_BUY"
    assert "sell_tax" in risk["hard_rejections"]


def test_holder_pool_exclusion_requires_verified_pool_address():
    pool = "0x0000000000000000000000000000000000000001"
    whale = "0x0000000000000000000000000000000000000002"
    token = {"holders": [
        {"address": pool, "is_contract": "1", "percent": "0.70"},
        {"address": whale, "is_contract": "0", "percent": "0.30"},
    ]}

    without_verification = intelligence._holder_concentration(token, set())
    with_verification = intelligence._holder_concentration(token, {pool})

    assert Decimal(without_verification["top_holder_percent"]) == 70
    assert Decimal(with_verification["top_holder_percent"]) == 30
    assert with_verification["verified_pools_excluded"] == 1


def test_inconsistent_holder_shares_are_unknown():
    token = {"holders": [
        {"address": "0x0000000000000000000000000000000000000001",
         "is_contract": "0", "percent": "0.8"},
        {"address": "0x0000000000000000000000000000000000000002",
         "is_contract": "0", "percent": "0.5"},
    ]}

    assert intelligence._holder_concentration(token, set())["status"] == "UNKNOWN"


def test_holder_categories_require_evidence_and_treasury_still_counts():
    burn = "0x000000000000000000000000000000000000dEaD"
    owner = "0x0000000000000000000000000000000000000002"
    unknown = "0x0000000000000000000000000000000000000003"
    token = {"holders": [
        {"address": burn, "is_contract": "0", "percent": "0.40"},
        {"address": owner, "is_contract": "0", "percent": "0.35"},
        {"address": unknown, "is_contract": "1", "tag": "Bridge",
         "percent": "0.25"},
    ]}

    classes = intelligence._classify_holders(
        token, set(), owner=owner
    )
    result = intelligence._holder_concentration(token, classes)

    assert classes[burn.lower()]["classification"] == "burn"
    assert classes[owner.lower()]["classification"] == "treasury"
    assert classes[unknown.lower()]["classification"] == "unclassified"
    assert Decimal(result["top_holder_percent"]) == 35
    assert result["excluded_holders"] == 1


def test_vesting_requires_positive_amount_and_future_unlock(monkeypatch):
    address = "0x0000000000000000000000000000000000000004"
    monkeypatch.setattr(intelligence.time, "time", lambda: 1_000)
    valid = {"holders": [{
        "address": address, "is_locked": "1", "percent": "0.2",
        "locked_detail": [{"amount": "10", "end_time": "2000"}],
    }]}
    expired = {"holders": [{
        "address": address, "is_locked": "1", "percent": "0.2",
        "locked_detail": [{"amount": "10", "end_time": "999"}],
    }]}

    assert intelligence._classify_holders(valid, set())[address][
        "classification"
    ] == "vesting"
    assert intelligence._classify_holders(expired, set())[address][
        "classification"
    ] == "unclassified"


def test_proxy_resolves_eip1967_admin_owner(monkeypatch):
    implementation = "0x0000000000000000000000000000000000000011"
    proxy_admin = "0x0000000000000000000000000000000000000022"
    authority = "0x0000000000000000000000000000000000000033"

    def slot_value(address):
        return bytes.fromhex("00" * 12 + address[2:])

    class Eth:
        def get_storage_at(self, _address, slot):
            if slot == intelligence._IMPLEMENTATION_SLOT:
                return slot_value(implementation)
            if slot == intelligence._ADMIN_SLOT:
                return slot_value(proxy_admin)
            return bytes(32)

        def get_code(self, address):
            return b"code" if address.lower() == proxy_admin.lower() else b""

    class W3:
        eth = Eth()

    monkeypatch.setattr(
        intelligence, "_call",
        lambda _w3, address, signature, _output: authority
        if address.lower() == proxy_admin.lower() and signature == "owner()"
        else None,
    )

    details = intelligence._proxy_details(W3(), proxy_admin, b"not-a-clone")

    assert details["implementation"].lower() == implementation.lower()
    assert details["proxy_admin"].lower() == proxy_admin.lower()
    assert details["upgrade_authority"].lower() == authority.lower()
    assert details["upgrade_authority_status"] == "RESOLVED"


def test_optional_etherscan_v2_key_alias(monkeypatch):
    monkeypatch.delenv("BASESCAN_API_KEY", raising=False)
    monkeypatch.setenv("ETHERSCAN_API_KEY", "v2-key")
    calls = []
    monkeypatch.setattr(
        intelligence, "_get_json",
        lambda _url, params, **_kwargs: calls.append(params) or
        {"status": "1", "result": [{"contractCreator":
          "0x0000000000000000000000000000000000000001"}]},
    )

    creation, transaction = intelligence._fetch_creation(
        "0x0000000000000000000000000000000000000002", []
    )

    assert creation is not None
    assert transaction is None
    assert calls[0]["chainid"] == 8453
    assert calls[0]["apikey"] == "v2-key"


def test_missing_explorer_key_is_not_misreported_as_api_failure(monkeypatch):
    monkeypatch.delenv("BASESCAN_API_KEY", raising=False)
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    errors = []

    assert intelligence._fetch_creation(
        "0x0000000000000000000000000000000000000002", errors
    ) == (None, None)
    assert errors == []


def test_dex_summary_does_not_invent_missing_metrics():
    pairs = [{
        "chainId": "base",
        "baseToken": {"address": "0x0000000000000000000000000000000000000001"},
        "quoteToken": {"address": "0x0000000000000000000000000000000000000002"},
    }]

    summary = intelligence._dex_summary(pairs)

    assert summary["pair_count"] == 1
    assert summary["liquidity_usd"] is None
    assert summary["volume_24h_usd"] is None
    assert "oldest_pair_age_days" not in summary
    assert "activity_24h" not in summary


def test_dex_summary_handles_malformed_optional_sections():
    pair = {
        "chainId": "base",
        "baseToken": {"address": "0x0000000000000000000000000000000000000001"},
        "quoteToken": {"address": "0x0000000000000000000000000000000000000002"},
        "txns": None,
        "priceChange": None,
    }

    assert intelligence._dex_summary([pair])["pair_count"] == 1


def test_dex_summary_reports_available_activity_without_fabrication():
    pair = {
        "chainId": "base",
        "baseToken": {"address": "0x0000000000000000000000000000000000000001"},
        "quoteToken": {"address": "0x0000000000000000000000000000000000000002"},
        "liquidity": {"usd": 1200},
        "volume": {"h24": 340},
        "txns": {"h24": {"buys": 8, "sells": 3}},
        "priceChange": {"h24": "2.5"},
        "pairCreatedAt": 1,
        "pairAddress": "0x0000000000000000000000000000000000000003",
    }

    summary = intelligence._dex_summary([pair])

    assert summary["liquidity_usd"] == "1200"
    assert summary["volume_24h_usd"] == "340"
    assert summary["activity_24h"] == {"buys": 8, "sells": 3}
    assert summary["price_change_24h_percent"] == "2.5"
    assert summary["candidate_pool_addresses"] == [pair["pairAddress"]]


def test_dex_summary_rejects_unrelated_rows_and_separates_v4_pool_ids():
    token = "0x0000000000000000000000000000000000000001"
    quote = "0x4200000000000000000000000000000000000006"
    pool_id = "0x" + "11" * 32
    matching = {
        "chainId": "base", "dexId": "uniswap", "pairAddress": pool_id,
        "baseToken": {"address": token}, "quoteToken": {"address": quote},
        "liquidity": {"usd": "31450000"},
    }
    unrelated = {
        "chainId": "base", "dexId": "uniswap",
        "pairAddress": "0x0000000000000000000000000000000000000003",
        "baseToken": {"address": quote},
        "quoteToken": {"address": "0x0000000000000000000000000000000000000002"},
        "liquidity": {"usd": "999999999"},
    }

    summary = intelligence._dex_summary([matching, unrelated], token)

    assert summary["pair_count"] == 1
    assert summary["liquidity_usd"] == "31450000"
    assert summary["candidate_pool_ids"] == [pool_id]
    assert summary["candidate_pool_addresses"] == []
    assert summary["pair_details"][0]["pair_identity_type"] == "bytes32_pool_id"
    assert summary["pair_details"][0]["requested_token_role"] == "base"
    assert summary["liquidity_scope"] == "single_token_specific_pair"
    assert summary["liquidity_is_aggregated"] is False
    assert summary["liquidity_source_status"] == "PROVIDER_REPORTED_UNVERIFIED"


def test_http_retries_and_redacts_url_from_provider_errors(monkeypatch, caplog):
    calls = []

    class Response:
        status_code = 429
        headers = {}

        def json(self):
            return {"ok": True}

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        if len(calls) == 1:
            return Response()
        Response.status_code = 200
        return Response()

    monkeypatch.setenv("API_MIN_INTERVAL_SECONDS", "0")
    monkeypatch.setattr(intelligence.requests, "get", fake_get)
    monkeypatch.setattr(intelligence.time, "sleep", lambda _: None)
    errors = []

    payload = intelligence._get_json(
        "https://example.test/api?apikey=private",
        source="test-provider",
        errors=errors,
        attempts=2,
    )

    assert payload == {"ok": True}
    assert len(calls) == 2
    assert "private" not in caplog.text
    assert not errors


def test_request_error_does_not_log_authenticated_url(monkeypatch, caplog):
    monkeypatch.setenv("API_MIN_INTERVAL_SECONDS", "0")
    monkeypatch.setattr(
        intelligence.requests, "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            requests.Timeout("https://example.test/?apikey=private")
        ),
    )
    monkeypatch.setattr(intelligence.time, "sleep", lambda _: None)
    errors = []

    result = intelligence._get_json(
        "https://example.test/?apikey=private",
        source="test-provider",
        errors=errors,
        attempts=1,
    )

    assert result is None
    assert "private" not in caplog.text
    assert "private" not in str(errors)


def test_telegram_report_includes_missing_data_and_decision():
    report = {
        "address": "0x0000000000000000000000000000000000000001",
        "decision": "WATCHLIST",
        "contract": {"contract_type": "erc20", "metadata": {"is_erc20": True}},
        "developer": {"deployer": None, "owner": None, "funding_wallet": None},
        "market": {"pair_count": 0},
        "security": {"checks": {"is_honeypot": {"status": "UNKNOWN"}}},
        "holders": {"status": "UNKNOWN"},
        "risk": {"risk_score": 30, "hard_rejections": []},
        "missing_evidence": ["GoPlus token security record"],
        "api_errors": [],
    }

    text = format_analysis(report)

    assert "WATCHLIST" in text
    assert "Developer: UNKNOWN" in text
    assert "Assessment: UNKNOWN" in text
    assert "Liquidity source status: UNKNOWN | Scope: UNKNOWN" in text
    assert "Pool identity: UNKNOWN" in text
    assert "Missing evidence: GoPlus token security record" in text


def test_analyze_report_includes_v4_liquidity_provenance_and_pool_id():
    pool_id = "0x" + "ab" * 32
    report = {
        "address": "0x24873FeF651793140fCb5F05f5Be69B0b51D28Bf",
        "decision": "WATCHLIST",
        "contract": {"contract_type": "erc20", "metadata": {"is_erc20": True}},
        "developer": {}, "holders": {"status": "UNKNOWN"},
        "security": {"checks": {}},
        "market": {
            "liquidity_usd": "31506804.02", "volume_24h_usd": "147697.96",
            "pair_count": 1, "liquidity_source_status": "PROVIDER_REPORTED_UNVERIFIED",
            "liquidity_scope": "single_token_specific_pair",
            "candidate_pool_ids": [pool_id], "verified_pool_addresses": [],
        },
        "risk": {"risk_score": 35, "evidence_confidence": 87,
                 "assessment": "INCONCLUSIVE", "hard_rejections": []},
    }

    text = format_analysis(report)

    assert "Liquidity: $31,506,804.02 | 24h volume: $147,697.96" in text
    assert "Assessment: INCONCLUSIVE" in text
    assert "Liquidity source status: PROVIDER_REPORTED_UNVERIFIED" in text
    assert "Scope: single_token_specific_pair" in text
    assert f"Pool ID: {pool_id}" in text
    assert "Pool contract" not in text


def test_analysis_persists_json_in_existing_sqlite_schema(monkeypatch, tmp_path):
    database = tmp_path / "existing.db"
    monkeypatch.setenv("DATABASE_PATH", str(database))
    with core.db_connect() as connection:
        connection.execute(
            "INSERT INTO analyses(ts, address, data) VALUES (?, ?, ?)",
            ("before", "0xold", '{"legacy":true}'),
        )
        connection.execute(
            "INSERT INTO state(key, value) VALUES (?, ?)",
            ("scanner_enabled", "false"),
        )
    expected = {
        "address": "0x0000000000000000000000000000000000000001",
        "analyzed_at": "2026-01-01T00:00:00+00:00",
        "decision": "WATCHLIST",
        "api_errors": [{"source": "GoPlus", "message": "unavailable"}],
    }
    monkeypatch.setattr(core, "build_analysis", lambda _address, _rpc: expected)

    result = core.inspect_contract(expected["address"])

    assert result == expected
    with core.db_connect() as connection:
        rows = connection.execute(
            "SELECT ts, address, data FROM analyses ORDER BY id"
        ).fetchall()
        state = connection.execute(
            "SELECT value FROM state WHERE key='scanner_enabled'"
        ).fetchone()
    assert rows[0] == ("before", "0xold", '{"legacy":true}')
    assert rows[1][1] == expected["address"]
    assert '"api_errors"' in rows[1][2]
    assert state == ("false",)
