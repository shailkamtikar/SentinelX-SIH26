from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services.email_forensics import (
    compare_routing_identities,
    extract_auth_verdicts,
    extract_domain,
    parse_email_forensics,
)

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_EML_BYTES = (FIXTURES_DIR / "sample.eml").read_bytes()
FORENSICS_EML_BYTES = (FIXTURES_DIR / "sample_with_forensics.eml").read_bytes()


def _upload(filename: str, content: bytes):
    return client.post(
        "/analyze-email",
        files={"file": (filename, content, "message/rfc822")},
    )


def _forensics_from(content: bytes) -> dict:
    response = _upload("sample.eml", content)
    assert response.status_code == 200
    return response.json()["forensics"]


# --- Existing 10-field contract must remain untouched ---------------------


def test_existing_response_fields_unchanged_alongside_forensics():
    data = _upload("sample.eml", SAMPLE_EML_BYTES).json()
    original_fields = {
        "sender",
        "recipient",
        "subject",
        "reply_to",
        "date",
        "message_id",
        "return_path",
        "body",
        "attachments",
        "urls",
    }
    assert original_fields.issubset(data.keys())
    assert "forensics" in data
    assert data["sender"] == "Alice Analyst <alice@example.com>"


# --- Authentication-Results extraction -------------------------------------


def test_correct_spf_dkim_dmarc_extraction():
    forensics = _forensics_from(FORENSICS_EML_BYTES)
    assert forensics["spf_result"] == "fail"
    assert forensics["dkim_result"] == "pass"
    assert forensics["dmarc_result"] == "fail"
    assert forensics["authentication_results_raw"] is not None
    assert "spf=fail" in forensics["authentication_results_raw"]
    assert forensics["authentication_results_raw_all"] == [
        forensics["authentication_results_raw"]
    ]


def test_received_spf_raw_extraction():
    forensics = _forensics_from(FORENSICS_EML_BYTES)
    assert forensics["received_spf_raw"] is not None
    assert "203.0.113.9" in forensics["received_spf_raw"]


def test_missing_received_spf_resolves_to_none():
    forensics = _forensics_from(SAMPLE_EML_BYTES)
    assert forensics["received_spf_raw"] is None


def test_extract_auth_verdicts_case_insensitive():
    assert extract_auth_verdicts("SPF=PASS; DKIM=Fail") == ("pass", "fail", None)


def test_empty_auth_verdict_value_remains_none():
    spf, dkim, dmarc = extract_auth_verdicts("spf=; dkim=pass")
    assert spf is None
    assert dkim == "pass"
    assert dmarc is None


def test_multiple_authentication_results_headers_all_preserved():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Authentication-Results: mx1.example.com; spf=pass\r\n"
        b"Authentication-Results: mx2.example.com; spf=fail\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"body\r\n"
    )
    result = parse_email_forensics(raw)
    assert len(result.authentication_results_raw_all) == 2
    assert "mx1.example.com" in result.authentication_results_raw_all[0]
    assert "mx2.example.com" in result.authentication_results_raw_all[1]
    # Documented prototype behavior: the topmost header drives the verdict.
    assert result.spf_result == "pass"
    assert result.authentication_results_raw == result.authentication_results_raw_all[0]


def test_missing_auth_headers_resolve_to_none():
    forensics = _forensics_from(SAMPLE_EML_BYTES)
    assert forensics["authentication_results_raw"] is None
    assert forensics["spf_result"] is None
    assert forensics["dkim_result"] is None
    assert forensics["dmarc_result"] is None


def test_extract_auth_verdicts_unit():
    assert extract_auth_verdicts(None) == (None, None, None)
    assert extract_auth_verdicts("spf=pass; dkim=fail; dmarc=none") == (
        "pass",
        "fail",
        "none",
    )


# --- Received header extraction --------------------------------------------


def test_received_order_preservation():
    forensics = _forensics_from(FORENSICS_EML_BYTES)
    assert len(forensics["received_chain"]) == 2
    assert "relay-one.test" in forensics["received_chain"][0]
    assert "relay-two.test" in forensics["received_chain"][1]


def test_no_received_headers_returns_empty_list():
    forensics = _forensics_from(SAMPLE_EML_BYTES)
    assert forensics["received_chain"] == []


def test_duplicate_received_headers_preserve_duplicates_and_order():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Received: from a.test by b.test; Mon, 01 Jan 2024 00:00:00 +0000\r\n"
        b"Received: from a.test by b.test; Mon, 01 Jan 2024 00:00:00 +0000\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"body\r\n"
    )
    result = parse_email_forensics(raw)
    # Forensic evidence must not be de-duplicated away — a repeated Received
    # header is itself potentially significant (e.g. a mail loop).
    assert len(result.received_chain) == 2
    assert result.received_chain[0] == result.received_chain[1]


# --- Routing identity comparison --------------------------------------------


def test_routing_mismatch_detection():
    forensics = _forensics_from(FORENSICS_EML_BYTES)
    assert "return_path_domain_mismatch" in forensics["routing_flags"]
    assert "reply_to_domain_mismatch" in forensics["routing_flags"]


def test_consistent_routing_produces_no_flags():
    forensics = _forensics_from(SAMPLE_EML_BYTES)
    assert forensics["routing_flags"] == []


def test_compare_routing_identities_unit():
    assert compare_routing_identities(
        "a@example.com", "a@example.com", "a@example.com"
    ) == []
    assert compare_routing_identities(
        "a@example.com", "a@example.com", "bounce@other.test"
    ) == ["return_path_domain_mismatch"]
    assert compare_routing_identities(None, None, None) == []


def test_extract_domain_unit():
    assert extract_domain("Alice <alice@example.com>") == "example.com"
    assert extract_domain("<bounce@example.com>") == "example.com"
    assert extract_domain(None) is None
    assert extract_domain("not-an-address") is None


def test_extract_domain_ignores_display_name_lookalike_address():
    # A quoted display name containing an email-like string must not be
    # mistaken for the real sending domain — this is a common phishing
    # display-name-spoofing technique.
    spoofed = '"billing@yourbank.com" <attacker@evil-domain.net>'
    assert extract_domain(spoofed) == "evil-domain.net"


def test_extract_domain_multiple_addresses_uses_first_only():
    # Prototype scope: only the first parsed mailbox is considered.
    assert extract_domain("a@x.com, b@y.com") == "x.com"


def test_extract_domain_null_return_path_has_no_domain():
    assert extract_domain("<>") is None


# --- Robustness --------------------------------------------------------------


def test_malformed_bytes_do_not_crash_forensics():
    forensics = _forensics_from(b"\x00\x01not a real email\xffdata")
    assert forensics["authentication_results_raw"] is None
    assert forensics["spf_result"] is None
    assert forensics["dkim_result"] is None
    assert forensics["dmarc_result"] is None
    assert forensics["received_chain"] == []
    assert forensics["routing_flags"] == []


def test_forensics_failure_does_not_break_core_response(monkeypatch):
    def _boom(_raw_bytes: bytes):
        raise RuntimeError("simulated forensics failure")

    monkeypatch.setattr("app.routes.analyze.parse_email_forensics", _boom)

    response = _upload("sample.eml", SAMPLE_EML_BYTES)
    assert response.status_code == 200
    data = response.json()

    # Original 10 fields must still be present and correct.
    assert data["sender"] == "Alice Analyst <alice@example.com>"
    assert data["message_id"] == "<sample-fixture-0001@example.com>"

    # Forensics block is present but degrades to null/empty rather than
    # taking the whole request down.
    assert "forensics" in data
    assert data["forensics"]["authentication_results_raw"] is None
    assert data["forensics"]["spf_result"] is None
    assert data["forensics"]["dkim_result"] is None
    assert data["forensics"]["dmarc_result"] is None
    assert data["forensics"]["received_chain"] == []
    assert data["forensics"]["routing_flags"] == []


def test_parse_email_forensics_directly_on_fixture():
    result = parse_email_forensics(FORENSICS_EML_BYTES)
    assert result.spf_result == "fail"
    assert result.dkim_result == "pass"
    assert result.dmarc_result == "fail"
    assert len(result.received_chain) == 2
    assert set(result.routing_flags) == {
        "return_path_domain_mismatch",
        "reply_to_domain_mismatch",
    }
