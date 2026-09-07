"""Regression tests for the synthetic demo fixture dataset.

Pins the exact deterministic behavior each fixture was designed to
produce (see tests/fixtures/README.md) so the demo dataset can't quietly
drift out of sync with app.services.threat_assessment as the pipeline
evolves. Every assertion here is derived from the deterministic pipeline
itself — nothing is a hand-picked "expected" value beyond what the
fixture's own headers/body are designed to trigger.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"

SAFE_FIXTURES = [
    "clean_quarterly_report.eml",
    "routine_hr_notice.eml",
    "vendor_invoice.eml",
]

SUSPICIOUS_HIGH_FIXTURES = [
    "credential_phishing.eml",
    "finance_bec.eml",
    "executive_impersonation.eml",
    "repeated_infrastructure_1.eml",
    "repeated_infrastructure_2.eml",
    "repeated_artifact.eml",
]

ALL_NEW_FIXTURES = SAFE_FIXTURES + SUSPICIOUS_HIGH_FIXTURES + ["suspicious_attachment.eml"]


def _analyze(filename: str) -> dict:
    raw_bytes = (FIXTURES_DIR / filename).read_bytes()
    response = client.post(
        "/analyze-email",
        files={"file": (filename, raw_bytes, "message/rfc822")},
    )
    assert response.status_code == 200
    return response.json()


def test_every_new_fixture_parses_successfully_via_the_real_route():
    for filename in ALL_NEW_FIXTURES:
        data = _analyze(filename)
        assert data["sender"] is not None
        assert "threat_assessment" in data
        assert "iocs" in data


def test_safe_fixtures_are_low_risk_with_no_reasons():
    for filename in SAFE_FIXTURES:
        data = _analyze(filename)
        assert data["threat_assessment"]["risk_level"] == "LOW", filename
        assert data["threat_assessment"]["reasons"] == [], filename


def test_suspicious_fixtures_reach_high_risk_with_deterministic_reasons():
    for filename in SUSPICIOUS_HIGH_FIXTURES:
        data = _analyze(filename)
        assert data["threat_assessment"]["risk_level"] == "HIGH", filename
        assert len(data["threat_assessment"]["reasons"]) >= 2, filename


def test_suspicious_attachment_fixture_is_medium_via_auth_failure_only():
    data = _analyze("suspicious_attachment.eml")
    assert data["threat_assessment"]["risk_level"] == "MEDIUM"
    assert data["threat_assessment"]["reasons"] == ["SPF result: fail"]


def test_credential_phishing_triggers_structural_url_risk():
    data = _analyze("credential_phishing.eml")
    reasons = data["threat_assessment"]["reasons"]
    assert any("Credentials embedded in URL" in reason for reason in reasons)


def test_finance_bec_triggers_all_three_evidence_categories():
    data = _analyze("finance_bec.eml")
    reasons = data["threat_assessment"]["reasons"]
    assert any("SPF result: fail" in r for r in reasons)
    assert any("DMARC result: fail" in r for r in reasons)
    assert "reply_to_domain_mismatch" in reasons
    assert "return_path_domain_mismatch" in reasons
    assert any("raw IP address" in r for r in reasons)


# --- Deterministic attachment hashing / shared-artifact design -------------


def test_suspicious_attachment_and_repeated_artifact_share_the_same_sha256():
    first = _analyze("suspicious_attachment.eml")
    second = _analyze("repeated_artifact.eml")

    first_hashes = {a["sha256"] for a in first["iocs"]["attachment_hashes"]}
    second_hashes = {a["sha256"] for a in second["iocs"]["attachment_hashes"]}

    assert first_hashes
    assert first_hashes == second_hashes


def test_repeated_infrastructure_fixtures_share_ip_and_domain():
    first = _analyze("repeated_infrastructure_1.eml")
    second = _analyze("repeated_infrastructure_2.eml")

    first_ips = {ip["value"] for ip in first["iocs"]["ipv4"]}
    second_ips = {ip["value"] for ip in second["iocs"]["ipv4"]}
    assert first_ips & second_ips == {"198.51.100.42"}

    first_domains = {d["value"] for d in first["iocs"]["domains"]}
    second_domains = {d["value"] for d in second["iocs"]["domains"]}
    assert "malicious-shared.example.test" in (first_domains & second_domains)


def test_shared_domain_spans_all_three_repeated_fixtures():
    """The repeated domain must appear in all three designed fixtures, not
    just two — a repeated indicator across N emails must show all N."""
    filenames = [
        "repeated_infrastructure_1.eml",
        "repeated_infrastructure_2.eml",
        "repeated_artifact.eml",
    ]
    domain_sets = []
    for filename in filenames:
        data = _analyze(filename)
        domain_sets.append({d["value"] for d in data["iocs"]["domains"]})

    shared = domain_sets[0] & domain_sets[1] & domain_sets[2]
    assert "malicious-shared.example.test" in shared
