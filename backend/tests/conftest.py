import pytest


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
