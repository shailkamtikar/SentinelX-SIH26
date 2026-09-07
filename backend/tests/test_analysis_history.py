"""GET /analysis-history: authenticated, user-scoped, never trusts the caller.

conftest.py's autouse `_authenticated_by_default` fixture overrides
get_current_user_id for the "authenticated, has history" tests here; the
auth-enforcement tests explicitly remove that override, exactly like
tests/test_auth.py does for /analyze-email.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.analysis_store import persist_analysis
from app.services.auth import get_current_user_id
from tests.fakes import DEFAULT_TEST_USER_ID, FakeSupabaseClient

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_EML_BYTES = (FIXTURES_DIR / "sample.eml").read_bytes()
FORENSICS_EML_BYTES = (FIXTURES_DIR / "sample_with_forensics.eml").read_bytes()


def _analyze(raw_bytes: bytes, filename: str) -> dict:
    response = client.post(
        "/analyze-email",
        files={"file": (filename, raw_bytes, "message/rfc822")},
    )
    assert response.status_code == 200
    return response.json()


# --- Authentication enforcement ---------------------------------------------


def test_missing_authorization_is_rejected():
    app.dependency_overrides.pop(get_current_user_id, None)
    try:
        response = client.get("/analysis-history")
    finally:
        app.dependency_overrides[get_current_user_id] = lambda: DEFAULT_TEST_USER_ID

    assert response.status_code == 401


def test_invalid_token_is_rejected(monkeypatch):
    app.dependency_overrides.pop(get_current_user_id, None)
    monkeypatch.setenv("SUPABASE_URL", "https://test-project.supabase.co")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "test-secret-key")

    class _FakeAuth:
        def get_user(self, _jwt):
            raise RuntimeError("simulated invalid token")

    class _FakeAuthClient:
        auth = _FakeAuth()

    monkeypatch.setattr("app.services.auth._get_client", lambda: _FakeAuthClient())

    try:
        response = client.get(
            "/analysis-history", headers={"Authorization": "Bearer not-a-real-token"}
        )
    finally:
        app.dependency_overrides[get_current_user_id] = lambda: DEFAULT_TEST_USER_ID

    assert response.status_code == 401


# --- Empty / no-case-yet state -----------------------------------------------


def test_user_with_no_prior_analyses_gets_empty_history(monkeypatch):
    fake = FakeSupabaseClient()
    monkeypatch.setattr("app.services.analysis_store._get_client", lambda: fake)

    response = client.get("/analysis-history")

    assert response.status_code == 200
    assert response.json() == {"entries": []}
    # Merely viewing history must never create a case as a side effect.
    assert fake.tables["cases"] == []


# --- Populated history --------------------------------------------------------


def test_history_returns_the_users_own_persisted_analyses(monkeypatch):
    fake = FakeSupabaseClient()
    monkeypatch.setattr("app.services.analysis_store._get_client", lambda: fake)

    # /analyze-email itself persists (via its own internal persist_analysis
    # call) whenever Supabase is configured — no separate manual persist
    # call is needed, and calling one here too would double-insert.
    _analyze(SAMPLE_EML_BYTES, "sample.eml")
    _analyze(FORENSICS_EML_BYTES, "sample_with_forensics.eml")

    history_response = client.get("/analysis-history")

    assert history_response.status_code == 200
    entries = history_response.json()["entries"]
    assert len(entries) == 2
    filenames = {entry["original_filename"] for entry in entries}
    assert filenames == {"sample.eml", "sample_with_forensics.eml"}
    for entry in entries:
        assert "email_id" in entry
        assert "analyzed_at" in entry
        assert "response" in entry
        assert "threat_assessment" in entry["response"]
        assert "iocs" in entry["response"]
        assert "evidence" in entry["response"]
        assert "raw_eml_sha256" in entry["response"]["evidence"]


def test_history_never_includes_raw_eml_bytes(monkeypatch):
    fake = FakeSupabaseClient()
    monkeypatch.setattr("app.services.analysis_store._get_client", lambda: fake)

    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")

    history_response = client.get("/analysis-history")
    serialized = history_response.text

    body_sentence = "Please review the attached quarterly report"
    assert body_sentence in (response["body"] or "")
    # The body text itself is legitimate structured evidence (already part
    # of the normal /analyze-email response) and is expected to appear;
    # what must never appear is the raw multipart/MIME envelope.
    assert "boundary=" not in serialized
    assert "Content-Transfer-Encoding" not in serialized


# --- Cross-user isolation -----------------------------------------------------


def test_user_a_cannot_retrieve_user_bs_history(monkeypatch):
    fake = FakeSupabaseClient()
    monkeypatch.setattr("app.services.analysis_store._get_client", lambda: fake)
    user_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    user_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")
    persist_analysis(
        raw_bytes=SAMPLE_EML_BYTES,
        filename="a.eml",
        response=response,
        user_id=user_a,
        client=fake,
    )
    persist_analysis(
        raw_bytes=SAMPLE_EML_BYTES,
        filename="b.eml",
        response=response,
        user_id=user_b,
        client=fake,
    )

    app.dependency_overrides[get_current_user_id] = lambda: user_a
    try:
        history_a = client.get("/analysis-history").json()["entries"]
    finally:
        app.dependency_overrides[get_current_user_id] = lambda: DEFAULT_TEST_USER_ID

    assert len(history_a) == 1
    assert history_a[0]["original_filename"] == "a.eml"


def test_owner_scoping_comes_only_from_the_verified_token_not_query_params(monkeypatch):
    """The endpoint accepts no filter/owner input at all — a query string
    claiming a different user's id must have zero effect on which
    history comes back; only the verified token's identity matters."""
    fake = FakeSupabaseClient()
    monkeypatch.setattr("app.services.analysis_store._get_client", lambda: fake)
    other_user = "cccccccc-cccc-cccc-cccc-cccccccccccc"

    # Persisted under a different user than the one this test's request
    # will actually authenticate as (DEFAULT_TEST_USER_ID, via conftest's
    # override) — this must never appear in the response below.
    persist_analysis(
        raw_bytes=SAMPLE_EML_BYTES,
        filename="other-user.eml",
        response=_analyze(SAMPLE_EML_BYTES, "unused-for-persistence.eml"),
        user_id=other_user,
        client=fake,
    )

    history_response = client.get(f"/analysis-history?user_id={other_user}&owner_id={other_user}")

    assert history_response.status_code == 200
    entries = history_response.json()["entries"]
    filenames = {entry["original_filename"] for entry in entries}
    # The caller's real (DEFAULT_TEST_USER_ID) history is returned — never
    # "other-user.eml", regardless of what the query string claimed.
    assert "other-user.eml" not in filenames
