"""Authentication enforcement for POST /analyze-email.

conftest.py's autouse `_authenticated_by_default` fixture overrides
get_current_user_id for every other test file in this suite, since most
existing tests exist to exercise the deterministic pipeline, not auth
itself. Every test here explicitly removes that override first, so it
exercises the real dependency exactly as a genuine request would —
including genuinely invalid/expired/forged tokens, never merely decoded
without verification.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.auth import get_current_user_id
from tests.fakes import DEFAULT_TEST_USER_ID

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_EML_BYTES = (FIXTURES_DIR / "sample.eml").read_bytes()


@pytest.fixture(autouse=True)
def _use_real_auth_dependency():
    """Exercise the genuine get_current_user_id, not the suite-wide fake."""
    app.dependency_overrides.pop(get_current_user_id, None)
    yield


class _FakeUser:
    def __init__(self, id_: str):
        self.id = id_


class _FakeUserResponse:
    def __init__(self, user):
        self.user = user


class _FakeAuth:
    """Minimal stand-in for the real Supabase client's `.auth` surface —
    only the one method get_current_user_id actually calls."""

    def __init__(self, *, user_id: str | None = None, raises: Exception | None = None):
        self._user_id = user_id
        self._raises = raises
        self.received_tokens: list[str] = []

    def get_user(self, jwt: str):
        self.received_tokens.append(jwt)
        if self._raises is not None:
            raise self._raises
        if self._user_id is None:
            return _FakeUserResponse(user=None)
        return _FakeUserResponse(user=_FakeUser(self._user_id))


class _FakeAuthClient:
    def __init__(self, **kwargs):
        self.auth = _FakeAuth(**kwargs)


def _upload(headers: dict[str, str] | None = None):
    return client.post(
        "/analyze-email",
        files={"file": ("sample.eml", SAMPLE_EML_BYTES, "message/rfc822")},
        headers=headers or {},
    )


def _configure_supabase(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://test-project.supabase.co")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "test-secret-key")


# --- Missing / malformed header — rejected before any Supabase call --------


def test_missing_authorization_header_is_rejected():
    response = _upload()
    assert response.status_code == 401


def test_malformed_authorization_header_is_rejected():
    response = _upload(headers={"Authorization": "not-a-bearer-token"})
    assert response.status_code == 401


def test_bearer_scheme_with_empty_token_is_rejected():
    response = _upload(headers={"Authorization": "Bearer "})
    assert response.status_code == 401


def test_non_bearer_scheme_is_rejected():
    response = _upload(headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 401


# --- Invalid / expired / unverifiable token ---------------------------------


def test_invalid_token_is_rejected(monkeypatch):
    _configure_supabase(monkeypatch)
    monkeypatch.setattr(
        "app.services.auth._get_client",
        lambda: _FakeAuthClient(raises=RuntimeError("simulated invalid token")),
    )

    response = _upload(headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status_code == 401


def test_expired_or_unverifiable_token_is_rejected(monkeypatch):
    _configure_supabase(monkeypatch)
    # Supabase's own Auth server returning "no user" for this token is
    # exactly what an expired/invalid/unverifiable token looks like.
    monkeypatch.setattr(
        "app.services.auth._get_client",
        lambda: _FakeAuthClient(user_id=None),
    )

    response = _upload(headers={"Authorization": "Bearer expired-token"})

    assert response.status_code == 401


def test_supabase_not_configured_rejects_rather_than_bypassing_auth(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)

    response = _upload(headers={"Authorization": "Bearer some-token"})

    assert response.status_code == 401


def test_auth_failure_never_logs_the_token(monkeypatch, caplog):
    _configure_supabase(monkeypatch)
    monkeypatch.setattr(
        "app.services.auth._get_client",
        lambda: _FakeAuthClient(raises=RuntimeError("simulated invalid token")),
    )

    secret_token = "should-never-appear-in-logs-or-response"
    with caplog.at_level("WARNING"):
        response = _upload(headers={"Authorization": f"Bearer {secret_token}"})

    assert secret_token not in caplog.text
    assert secret_token not in response.text


# --- Valid, verified token ---------------------------------------------------


def test_valid_verified_token_extracts_the_correct_user_uuid_and_reaches_persistence(
    monkeypatch,
):
    _configure_supabase(monkeypatch)
    verified_user_id = "cccccccc-cccc-cccc-cccc-cccccccccccc"
    fake_auth_client = _FakeAuthClient(user_id=verified_user_id)
    monkeypatch.setattr("app.services.auth._get_client", lambda: fake_auth_client)

    captured = {}

    def _capture_persist(**kwargs):
        captured.update(kwargs)
        return None

    monkeypatch.setattr("app.routes.analyze.persist_analysis", _capture_persist)

    response = _upload(headers={"Authorization": "Bearer a-genuinely-valid-token"})

    assert response.status_code == 200
    assert captured["user_id"] == verified_user_id
    # The exact token we sent was the one handed to Supabase for
    # verification — nothing invented, nothing substituted.
    assert fake_auth_client.auth.received_tokens == ["a-genuinely-valid-token"]


def test_response_contract_is_unchanged_for_an_authenticated_request(monkeypatch):
    """Sanity check that authentication enforcement didn't alter the
    existing /analyze-email response shape for a real success path."""
    _configure_supabase(monkeypatch)
    monkeypatch.setattr(
        "app.services.auth._get_client",
        lambda: _FakeAuthClient(user_id=DEFAULT_TEST_USER_ID),
    )
    monkeypatch.setattr("app.routes.analyze.persist_analysis", lambda **_kwargs: None)

    response = _upload(headers={"Authorization": "Bearer a-genuinely-valid-token"})

    assert response.status_code == 200
    data = response.json()
    for field in (
        "sender",
        "recipient",
        "subject",
        "forensics",
        "iocs",
        "threat_assessment",
        "enrichment",
        "ai_explanation",
        "ai_explanation_status",
        "evidence",
    ):
        assert field in data
