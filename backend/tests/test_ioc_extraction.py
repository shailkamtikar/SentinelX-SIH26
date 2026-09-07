from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services.eml_parser import parse_eml_bytes
from app.services.email_forensics import parse_email_forensics
from app.services.ioc_extraction import extract_iocs

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_EML_BYTES = (FIXTURES_DIR / "sample.eml").read_bytes()
FORENSICS_EML_BYTES = (FIXTURES_DIR / "sample_with_forensics.eml").read_bytes()


def _upload(filename: str, content: bytes):
    return client.post(
        "/analyze-email",
        files={"file": (filename, content, "message/rfc822")},
    )


def _iocs_from(content: bytes) -> dict:
    response = _upload("sample.eml", content)
    assert response.status_code == 200
    return response.json()["iocs"]


def _domain_values(iocs: dict) -> set[str]:
    return {d["value"] for d in iocs["domains"]}


def _ip_by_value(iocs: dict, ip_type: str, value: str) -> dict | None:
    for entry in iocs[ip_type]:
        if entry["value"] == value:
            return entry
    return None


# --- 1. sample.eml (clean, consistent) --------------------------------------


def test_sample_eml_domains_from_headers_and_urls():
    iocs = _iocs_from(SAMPLE_EML_BYTES)
    domains = _domain_values(iocs)
    assert "example.com" in domains
    assert "example.org" in domains


def test_sample_eml_has_no_ips():
    iocs = _iocs_from(SAMPLE_EML_BYTES)
    assert iocs["ipv4"] == []
    assert iocs["ipv6"] == []


def test_sample_eml_attachment_sha256_is_correct():
    import hashlib

    iocs = _iocs_from(SAMPLE_EML_BYTES)
    assert len(iocs["attachment_hashes"]) == 1
    entry = iocs["attachment_hashes"][0]
    assert entry["filename"] == "q2-report.csv"
    assert entry["sha256"] == hashlib.sha256(b"Quarter,Revenue\nQ1,1000\nQ2,1500\n").hexdigest()


def test_sample_eml_existing_urls_remain_represented():
    iocs = _iocs_from(SAMPLE_EML_BYTES)
    url_values = {u["value"] for u in iocs["urls"]}
    assert "http://example.com/reports/q2" in url_values
    assert "https://example.org/reports/q2-secure" in url_values


# --- 2. sample_with_forensics.eml -------------------------------------------


def test_forensics_eml_received_chain_ips():
    iocs = _iocs_from(FORENSICS_EML_BYTES)
    entry_one = _ip_by_value(iocs, "ipv4", "198.51.100.5")
    entry_two = _ip_by_value(iocs, "ipv4", "198.51.100.7")
    assert entry_one is not None
    assert entry_two is not None
    assert entry_one["sources"] == ["received_chain"]
    assert entry_two["sources"] == ["received_chain"]
    # 198.51.100.0/24 is RFC 5737 TEST-NET-2 (documentation range), which
    # Python's ipaddress module correctly classifies as non-globally-routable
    # ("private" in the broad stdlib sense used here).
    assert entry_one["private"] is True
    assert entry_two["private"] is True


def test_forensics_eml_received_spf_ip():
    iocs = _iocs_from(FORENSICS_EML_BYTES)
    entry = _ip_by_value(iocs, "ipv4", "203.0.113.9")
    assert entry is not None
    assert entry["sources"] == ["received_spf"]


def test_forensics_eml_domain_provenance():
    iocs = _iocs_from(FORENSICS_EML_BYTES)
    by_value = {d["value"]: d for d in iocs["domains"]}
    assert by_value["example.com"]["sources"] == ["from_header"]
    assert by_value["malicious-example.net"]["sources"] == ["reply_to_header"]
    assert by_value["another-domain.test"]["sources"] == ["return_path_header"]


# --- 3. IPv6 -----------------------------------------------------------------


def test_ipv6_bracketed_in_received_header():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Received: from mail.example.net ([2001:db8::1]) by mx.example.com "
        b"with ESMTPS id abc123; Tue, 10 Jun 2025 14:31:50 +0000\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"body\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    entry = _ip_by_value(report, "ipv6", "2001:db8::1")
    assert entry is not None
    assert entry["sources"] == ["received_chain"]


# --- 4. Multi-source deduplication ------------------------------------------


def test_duplicate_ip_across_sources_is_one_record_with_both_sources():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Received: from a.test (198.51.100.20) by b.test with ESMTP id x; "
        b"Tue, 10 Jun 2025 14:31:50 +0000\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Contact was made from 198.51.100.20 according to logs.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    matches = [e for e in report["ipv4"] if e["value"] == "198.51.100.20"]
    assert len(matches) == 1
    assert set(matches[0]["sources"]) == {"received_chain", "body"}


def test_duplicate_domain_across_sources_is_one_record_with_both_sources():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Visit http://example.com/promo for details.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    matches = [d for d in report["domains"] if d["value"] == "example.com"]
    assert len(matches) == 1
    assert set(matches[0]["sources"]) == {"from_header", "url"}


# --- 5. URL handling ----------------------------------------------------------


def test_url_with_port_path_query_only_hostname_becomes_domain():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Click https://example.com:8443/path?redirect=other-domain.test now.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    domain_values = {d["value"] for d in report["domains"]}
    assert "example.com" in domain_values
    # The query-string value must not be recursively extracted as its own domain.
    assert "other-domain.test" not in domain_values

    url_values = {u["value"] for u in report["urls"]}
    assert any("example.com:8443" in url or "example.com" in url for url in url_values)


def test_url_with_ip_host_is_ip_indicator_not_domain():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Click http://203.0.113.50/payload now.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    assert _ip_by_value(report, "ipv4", "203.0.113.50") is not None
    domain_values = {d["value"] for d in report["domains"]}
    assert "203.0.113.50" not in domain_values


# --- 6. Private/reserved/loopback -------------------------------------------


def test_private_and_loopback_ips_are_extracted_and_flagged():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Received: from internal.local (10.0.0.5) by mx.example.com with "
        b"ESMTP id y; Tue, 10 Jun 2025 14:31:50 +0000\r\n"
        b"Received: from localhost (127.0.0.1) by mx.example.com with ESMTP "
        b"id z; Tue, 10 Jun 2025 14:31:55 +0000\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"body\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    private_entry = _ip_by_value(report, "ipv4", "10.0.0.5")
    loopback_entry = _ip_by_value(report, "ipv4", "127.0.0.1")
    assert private_entry is not None
    assert private_entry["private"] is True
    assert loopback_entry is not None
    assert loopback_entry["private"] is True


# --- 7. Invalid IP candidates -------------------------------------------------


def test_malformed_ip_candidates_are_not_emitted():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Version 999.999.999.999 and build 1.2.3.4.5 and release v2.10.3.44.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    assert report["ipv4"] == []


# --- 8. Email-address domain false positive ----------------------------------


def test_email_address_in_body_does_not_create_body_sourced_domain():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Please contact bob@example.org for help.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    # example.org is not the From/Reply-To/Return-Path domain and appears
    # only inside an email address in the body — it must not be extracted.
    domain_values = {d["value"] for d in report["domains"]}
    assert "example.org" not in domain_values


# --- 9. Empty/malformed parsed input -----------------------------------------


def test_malformed_bytes_do_not_crash_ioc_extraction():
    iocs = _iocs_from(b"\x00\x01not a real email\xffdata")
    assert iocs["ipv4"] == []
    assert iocs["ipv6"] == []
    assert iocs["domains"] == []
    assert iocs["urls"] == []
    assert iocs["attachment_hashes"] == []


def test_ioc_extraction_failure_does_not_break_core_response(monkeypatch):
    def _boom(_parsed, _forensics):
        raise RuntimeError("simulated ioc extraction failure")

    monkeypatch.setattr("app.routes.analyze.extract_iocs", _boom)

    response = _upload("sample.eml", SAMPLE_EML_BYTES)
    assert response.status_code == 200
    data = response.json()

    assert data["sender"] == "Alice Analyst <alice@example.com>"
    assert "forensics" in data
    assert "iocs" in data
    assert data["iocs"]["ipv4"] == []
    assert data["iocs"]["domains"] == []


# --- 10. Structural risk flags (offline, deterministic) ----------------------


def _url_by_value(iocs: dict, value: str) -> dict | None:
    for entry in iocs["urls"]:
        if entry["value"] == value:
            return entry
    return None


def test_ip_literal_url_flag_true_for_ipv4_host():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Click http://203.0.113.77/payload now.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    entry = _url_by_value(report, "http://203.0.113.77/payload")
    assert entry is not None
    assert entry["ip_literal_url"] is True
    assert entry["credential_in_url"] is False
    assert entry["punycode_domain"] is False


def test_ip_literal_url_flag_true_for_ipv6_host():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Click https://[2001:db8::5]/secure now.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    entry = _url_by_value(report, "https://[2001:db8::5]/secure")
    assert entry is not None
    assert entry["ip_literal_url"] is True


def test_ip_literal_url_flag_false_for_domain_host():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Click http://example.com/page now.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    entry = _url_by_value(report, "http://example.com/page")
    assert entry is not None
    assert entry["ip_literal_url"] is False


def test_credential_in_url_flag_true_when_userinfo_present():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Login at http://user:pass@evil.example/account now.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    entry = _url_by_value(report, "http://user:pass@evil.example/account")
    assert entry is not None
    assert entry["credential_in_url"] is True
    assert entry["ip_literal_url"] is False


def test_credential_in_url_flag_false_when_absent():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Click http://example.com/page now.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    entry = _url_by_value(report, "http://example.com/page")
    assert entry is not None
    assert entry["credential_in_url"] is False


def test_punycode_domain_flag_true_for_xn_label_domain():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Reply-To: attacker@xn--80ak6aa92e.com\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"body\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    by_value = {d["value"]: d for d in report["domains"]}
    assert by_value["xn--80ak6aa92e.com"]["punycode_domain"] is True


def test_punycode_domain_flag_false_for_normal_domain():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"body\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    by_value = {d["value"]: d for d in report["domains"]}
    assert by_value["example.com"]["punycode_domain"] is False


def test_punycode_domain_flag_true_on_url_hostname():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Visit http://xn--80ak6aa92e.com/page for details.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    report = extract_iocs(parsed, forensics).to_dict()

    url_entry = _url_by_value(report, "http://xn--80ak6aa92e.com/page")
    assert url_entry is not None
    assert url_entry["punycode_domain"] is True

    domain_by_value = {d["value"]: d for d in report["domains"]}
    assert domain_by_value["xn--80ak6aa92e.com"]["punycode_domain"] is True


def test_malformed_url_structural_flags_do_not_crash_extraction():
    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: test\r\n"
        b"\r\n"
        b"Bad link http://[::1 in this message.\r\n"
    )
    parsed = parse_eml_bytes(raw)
    forensics = parse_email_forensics(raw)
    # parsed.urls contains the unbalanced-bracket string as-is; urlsplit()
    # raises ValueError on it ("Invalid IPv6 URL") — extraction must not crash.
    assert "http://[::1" in parsed.urls

    report = extract_iocs(parsed, forensics).to_dict()

    entry = _url_by_value(report, "http://[::1")
    assert entry is not None
    assert entry["ip_literal_url"] is False
    assert entry["credential_in_url"] is False
    assert entry["punycode_domain"] is False
