import pytest

from app.main import app
from app.services.auth import get_current_user_id
from tests.fakes import DEFAULT_TEST_USER_ID


@pytest.fixture(autouse=True)
def _authenticated_by_default():
    """Every test is authenticated as one fixed fake user, by default.

    POST /analyze-email now requires real authentication (see
    app.services.auth.get_current_user_id), but the vast majority of tests
    in this suite exist to exercise the deterministic pipeline (forensics,
    IOCs, threat assessment, Gemini, persistence) and predate auth
    entirely — they must keep passing without needing a real Supabase
    project or a real JWT. FastAPI's own supported test mechanism —
    dependency_overrides — swaps the dependency for a fixed fake user UUID
    here, for every test, by default.

    tests/test_auth.py explicitly removes this override so it exercises
    the real get_current_user_id logic (missing/malformed/invalid tokens,
    and successful verification) instead.
    """
    app.dependency_overrides[get_current_user_id] = lambda: DEFAULT_TEST_USER_ID
    yield
    app.dependency_overrides.pop(get_current_user_id, None)


@pytest.fixture(autouse=True)
def _no_real_credentials_in_tests(monkeypatch):
    """Keep the test suite hermetic regardless of a local backend/.env.

    Now that app/config.py actually loads backend/.env, any developer
    machine with real credentials in that file would otherwise have every
    test that hits /analyze-email attempt real network calls to a live
    Supabase project or the Gemini API. Tests must never depend on,
    accidentally write to, or spend quota on a real external service.
    Individual tests that need these set to a specific value do so
    themselves via monkeypatch, on top of this baseline.
    """
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
