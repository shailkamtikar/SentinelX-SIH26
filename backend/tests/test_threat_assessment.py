from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services.eml_parser import parse_eml_bytes
from app.services.email_forensics import ForensicHeaders, parse_email_forensics
from app.services.ioc_extraction import (
    DomainIndicator,
    IOCReport,
    URLIndicator,
    extract_iocs,
)
from app.services.threat_assessment import ThreatAssessment, assess_threat

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_EML_BYTES = (FIXTURES_DIR / "sample.eml").read_bytes()
FORENSICS_EML_BYTES = (FIXTURES_DIR / "sample_with_forensics.eml").read_bytes()


def _upload(filename: str, content: bytes):
    return client.post(
        "/analyze-email",
        files={"file": (filename, content, "message/rfc822")},
    )


def _empty_forensics(**overrides: object) -> ForensicHeaders:
    defaults: dict[str, object] = {
        "authentication_results_raw": None,
        "spf_result": None,
        "dkim_result": None,
        "dmarc_result": None,
    }
    defaults.update(overrides)
    return ForensicHeaders(**defaults)  # type: ignore[arg-type]


# --- 1 & 2. Fixture-driven end-to-end cases -----------------------------------


def test_sample_eml_is_low_risk_with_no_reasons():
    parsed = parse_eml_bytes(SAMPLE_EML_BYTES)
    forensics = parse_email_forensics(SAMPLE_EML_BYTES)
    iocs = extract_iocs(parsed, forensics)

    assessment = assess_threat(forensics, iocs)

    assert assessment.risk_level == "LOW"
    assert assessment.reasons == []


def test_forensics_eml_is_high_risk_from_two_corroborating_categories():
    parsed = parse_eml_bytes(FORENSICS_EML_BYTES)
    forensics = parse_email_forensics(FORENSICS_EML_BYTES)
    iocs = extract_iocs(parsed, forensics)

    assessment = assess_threat(forensics, iocs)

    assert assessment.risk_level == "HIGH"
    # authentication_failure (spf fail, dmarc fail) + routing_identity_mismatch
    assert "SPF result: fail" in assessment.reasons
    assert "DMARC result: fail" in assessment.reasons
    assert set(forensics.routing_flags).issubset(set(assessment.reasons))


# --- 3. Single routing mismatch -----------------------------------------------


def test_single_routing_mismatch_is_medium():
    forensics = _empty_forensics(routing_flags=["reply_to_domain_mismatch"])
    assessment = assess_threat(forensics, IOCReport())

    assert assessment.risk_level == "MEDIUM"
    assert assessment.reasons == ["reply_to_domain_mismatch"]


# --- 4. All-absent evidence ----------------------------------------------------


def test_all_auth_none_no_routing_no_structural_flags_is_low():
    forensics = _empty_forensics()
    assessment = assess_threat(forensics, IOCReport())

    assert assessment.risk_level == "LOW"
    assert assessment.reasons == []


# --- 5-7. Individual authentication mechanisms --------------------------------


def test_spf_fail_alone_is_medium():
    forensics = _empty_forensics(spf_result="fail")
    assessment = assess_threat(forensics, IOCReport())

    assert assessment.risk_level == "MEDIUM"
    assert assessment.reasons == ["SPF result: fail"]


def test_dmarc_fail_alone_is_medium():
    forensics = _empty_forensics(dmarc_result="fail")
    assessment = assess_threat(forensics, IOCReport())

    assert assessment.risk_level == "MEDIUM"
    assert assessment.reasons == ["DMARC result: fail"]


def test_dkim_fail_alone_is_low():
    # DKIM failing alone must NOT activate authentication_failure — mailing
    # lists/forwarding commonly break DKIM signatures without malice.
    forensics = _empty_forensics(dkim_result="fail")
    assessment = assess_threat(forensics, IOCReport())

    assert assessment.risk_level == "LOW"
    assert assessment.reasons == []


# --- 8-10. Individual structural URL/domain flags ------------------------------


def test_credential_in_url_only_is_medium():
    iocs = IOCReport(
        urls=[
            URLIndicator(
                value="http://user:pass@evil.example/account",
                sources=["url"],
                credential_in_url=True,
            )
        ]
    )
    assessment = assess_threat(_empty_forensics(), iocs)

    assert assessment.risk_level == "MEDIUM"
    assert assessment.reasons == [
        "Credentials embedded in URL: http://user:pass@evil.example/account"
    ]


def test_ip_literal_url_only_is_medium():
    iocs = IOCReport(
        urls=[
            URLIndicator(
                value="http://203.0.113.77/payload",
                sources=["url"],
                ip_literal_url=True,
            )
        ]
    )
    assessment = assess_threat(_empty_forensics(), iocs)

    assert assessment.risk_level == "MEDIUM"
    assert assessment.reasons == ["URL hostname is a raw IP address: http://203.0.113.77/payload"]


def test_punycode_domain_only_is_medium():
    iocs = IOCReport(domains=[DomainIndicator(value="xn--80ak6aa92e.com", punycode_domain=True)])
    assessment = assess_threat(_empty_forensics(), iocs)

    assert assessment.risk_level == "MEDIUM"
    assert assessment.reasons == ["Domain uses punycode (IDN) encoding: xn--80ak6aa92e.com"]


# --- 11. Two categories --------------------------------------------------------


def test_two_categories_is_high():
    forensics = _empty_forensics(spf_result="fail", routing_flags=["reply_to_domain_mismatch"])
    assessment = assess_threat(forensics, IOCReport())

    assert assessment.risk_level == "HIGH"
    assert set(assessment.reasons) == {"SPF result: fail", "reply_to_domain_mismatch"}


# --- 12. Malformed/empty evidence does not crash -------------------------------


def test_bare_minimum_evidence_does_not_crash():
    # Only the required fields set, every optional collection left at its
    # dataclass default (empty) — must not raise, must resolve to LOW.
    forensics = _empty_forensics()
    assessment = assess_threat(forensics, IOCReport())

    assert assessment.risk_level == "LOW"
    assert assessment.reasons == []


def test_malformed_bytes_end_to_end_does_not_crash():
    response = _upload("garbage.eml", b"\x00\x01not a real email\xffdata")
    assert response.status_code == 200
    data = response.json()

    assert "threat_assessment" in data
    assert data["threat_assessment"]["risk_level"] == "LOW"
    assert data["threat_assessment"]["reasons"] == []


# --- 13. Forced failure isolation -----------------------------------------------


def test_threat_assessment_failure_does_not_break_core_response(monkeypatch):
    def _boom(_forensics, _iocs):
        raise RuntimeError("simulated threat assessment failure")

    monkeypatch.setattr("app.routes.analyze.assess_threat", _boom)

    response = _upload("sample.eml", SAMPLE_EML_BYTES)
    assert response.status_code == 200
    data = response.json()

    assert data["sender"] == "Alice Analyst <alice@example.com>"
    assert "forensics" in data
    assert "iocs" in data
    assert data["threat_assessment"] == {
        "risk_level": "UNKNOWN",
        "reasons": ["assessment unavailable"],
    }


def test_threat_assessment_return_type_is_dataclass_instance():
    assessment = assess_threat(_empty_forensics(), IOCReport())
    assert isinstance(assessment, ThreatAssessment)
    assert assessment.to_dict() == {"risk_level": "LOW", "reasons": []}
