"""Route-level behaviour for the ai_explanation and evidence fields."""

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services.analysis_store import PersistenceOutcome
from app.services.gemini_explainer import AIExplanation

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_EML_BYTES = (FIXTURES_DIR / "sample.eml").read_bytes()
FORENSICS_EML_BYTES = (FIXTURES_DIR / "sample_with_forensics.eml").read_bytes()

ORIGINAL_FIELDS = [
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
    "forensics",
    "iocs",
    "threat_assessment",
    "enrichment",
]


def _upload(raw_bytes: bytes = SAMPLE_EML_BYTES, filename: str = "sample.eml"):
    return client.post(
        "/analyze-email",
        files={"file": (filename, raw_bytes, "message/rfc822")},
    )


# --- Existing contract is preserved ------------------------------------------


def test_all_pre_existing_response_fields_are_still_present():
    data = _upload().json()
    for field in ORIGINAL_FIELDS:
        assert field in data, f"missing pre-existing field: {field}"


def test_deterministic_assessment_is_unchanged_for_the_forensics_fixture():
    data = _upload(FORENSICS_EML_BYTES, "sample_with_forensics.eml").json()

    assert data["threat_assessment"]["risk_level"] == "HIGH"
    assert data["forensics"]["spf_result"] == "fail"
    assert data["forensics"]["dkim_result"] == "pass"
    assert data["forensics"]["dmarc_result"] == "fail"
    assert len(data["iocs"]["ipv4"]) == 3


# --- ai_explanation ----------------------------------------------------------


def test_ai_explanation_is_null_when_gemini_is_not_configured():
    # conftest strips GEMINI_API_KEY from the environment for every test.
    response = _upload()
    assert response.status_code == 200
    data = response.json()
    assert data["ai_explanation"] is None
    assert data["ai_explanation_status"] == "not_configured"


def test_ai_explanation_is_returned_when_gemini_succeeds(monkeypatch):
    monkeypatch.setattr(
        "app.routes.analyze.explain_analysis",
        lambda _response: AIExplanation(
            summary="Authentication failed.",
            evidence_points=["SPF result: fail"],
            uncertainty="Sender infrastructure ownership is not established.",
            recommended_actions=["Verify via a known-good channel."],
        ),
    )

    data = _upload().json()

    assert data["ai_explanation"] == {
        "summary": "Authentication failed.",
        "evidence_points": ["SPF result: fail"],
        "uncertainty": "Sender infrastructure ownership is not established.",
        "recommended_actions": ["Verify via a known-good channel."],
    }
    # Deterministic assessment remains present and untouched alongside it.
    assert data["threat_assessment"]["risk_level"] == "LOW"
    assert data["ai_explanation_status"] == "ok"


def test_gemini_failure_is_isolated_and_never_returns_500(monkeypatch):
    def _boom(_response):
        raise RuntimeError("simulated Gemini outage")

    monkeypatch.setattr("app.routes.analyze.explain_analysis", _boom)

    response = _upload(FORENSICS_EML_BYTES, "sample_with_forensics.eml")

    assert response.status_code == 200
    data = response.json()
    assert data["ai_explanation"] is None
    # The deterministic pipeline is completely unaffected.
    assert data["threat_assessment"]["risk_level"] == "HIGH"
    assert len(data["iocs"]["ipv4"]) == 3


def test_gemini_failure_while_configured_reports_unavailable_not_not_configured(monkeypatch):
    """The exact bug this suite guards against: a real Gemini failure must
    never be reported as "not configured" when a key IS present — that
    tells the operator to do something (reconfigure) that would not fix
    anything and hides the real problem."""
    monkeypatch.setenv("GEMINI_API_KEY", "configured-but-the-call-still-fails")

    def _boom(_response):
        raise RuntimeError("simulated Gemini outage")

    monkeypatch.setattr("app.routes.analyze.explain_analysis", _boom)

    data = _upload().json()

    assert data["ai_explanation"] is None
    assert data["ai_explanation_status"] == "unavailable"
    # Deterministic pipeline unaffected regardless.
    assert data["threat_assessment"]["risk_level"] == "LOW"


def test_gemini_failure_logs_only_the_exception_type_never_the_message(monkeypatch, caplog):
    monkeypatch.setenv("GEMINI_API_KEY", "should-never-appear-in-logs")

    def _boom(_response):
        raise RuntimeError("secret-looking-detail-should-never-appear-in-logs")

    monkeypatch.setattr("app.routes.analyze.explain_analysis", _boom)

    with caplog.at_level("WARNING"):
        _upload()

    log_text = caplog.text
    assert "RuntimeError" in log_text
    assert "should-never-appear-in-logs" not in log_text
    assert "secret-looking-detail-should-never-appear-in-logs" not in log_text


def test_unusable_model_output_yields_null_rather_than_invented_text(monkeypatch):
    monkeypatch.setattr("app.routes.analyze.explain_analysis", lambda _response: None)

    data = _upload().json()

    assert data["ai_explanation"] is None
    # Key absent in this test (conftest default) — correctly not_configured,
    # not conflated with a genuinely configured-but-unusable-output case.
    assert data["ai_explanation_status"] == "not_configured"


def test_unusable_model_output_while_configured_reports_unavailable(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "configured-but-model-returned-junk")
    monkeypatch.setattr("app.routes.analyze.explain_analysis", lambda _response: None)

    data = _upload().json()

    assert data["ai_explanation"] is None
    assert data["ai_explanation_status"] == "unavailable"


# --- evidence status ---------------------------------------------------------


def test_evidence_reports_the_whole_file_sha256_even_without_supabase():
    data = _upload().json()

    assert data["evidence"]["raw_eml_sha256"] == hashlib.sha256(SAMPLE_EML_BYTES).hexdigest()
    # Nothing was stored: Supabase is unconfigured in tests.
    assert data["evidence"]["raw_eml_stored"] is False


def test_whole_file_hash_differs_from_the_attachment_hash():
    data = _upload().json()

    attachment_sha256 = data["iocs"]["attachment_hashes"][0]["sha256"]
    assert data["evidence"]["raw_eml_sha256"] != attachment_sha256


def test_evidence_reports_stored_only_when_a_path_was_recorded(monkeypatch):
    monkeypatch.setattr(
        "app.routes.analyze.persist_analysis",
        lambda **_kwargs: PersistenceOutcome(
            email_id="email-1",
            raw_eml_sha256="abc",
            raw_eml_storage_path="case-1/email-1.eml",
        ),
    )

    data = _upload().json()

    assert data["evidence"]["raw_eml_stored"] is True
    # The internal object path is never exposed to the client.
    assert "case-1/email-1.eml" not in str(data)


def test_storage_failure_reports_not_stored(monkeypatch):
    monkeypatch.setattr(
        "app.routes.analyze.persist_analysis",
        lambda **_kwargs: PersistenceOutcome(
            email_id="email-1",
            raw_eml_sha256="abc",
            raw_eml_storage_path=None,
            storage_error="bucket_missing",
        ),
    )

    data = _upload().json()

    assert data["evidence"]["raw_eml_stored"] is False


def test_persistence_failure_is_isolated_and_evidence_still_reports_the_hash(monkeypatch):
    def _boom(**_kwargs):
        raise RuntimeError("simulated Supabase outage")

    monkeypatch.setattr("app.routes.analyze.persist_analysis", _boom)

    response = _upload()

    assert response.status_code == 200
    data = response.json()
    assert data["evidence"]["raw_eml_sha256"] == hashlib.sha256(SAMPLE_EML_BYTES).hexdigest()
    assert data["evidence"]["raw_eml_stored"] is False
    assert data["threat_assessment"]["risk_level"] == "LOW"


# --- Secret hygiene ----------------------------------------------------------


def test_no_configuration_secrets_leak_into_logs_on_failure(monkeypatch, caplog):
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key-should-never-be-logged")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "test-supabase-key-should-never-be-logged")

    def _boom(_response):
        raise RuntimeError("outage")

    monkeypatch.setattr("app.routes.analyze.explain_analysis", _boom)
    monkeypatch.setattr("app.routes.analyze.persist_analysis", lambda **_kwargs: None)

    with caplog.at_level("WARNING"):
        _upload()

    assert "test-gemini-key-should-never-be-logged" not in caplog.text
    assert "test-supabase-key-should-never-be-logged" not in caplog.text


def test_no_configuration_secrets_leak_into_the_response(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key-should-never-appear")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "test-supabase-key-should-never-appear")
    monkeypatch.setenv("SUPABASE_URL", "https://test-project.supabase.co")
    # Stub both external stages so credentials being present cannot trigger a
    # real network call from the test suite.
    monkeypatch.setattr("app.routes.analyze.explain_analysis", lambda _response: None)
    monkeypatch.setattr("app.routes.analyze.persist_analysis", lambda **_kwargs: None)

    body = _upload().text

    assert "test-gemini-key-should-never-appear" not in body
    assert "test-supabase-key-should-never-appear" not in body
