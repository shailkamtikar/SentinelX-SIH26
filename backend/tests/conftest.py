import pytest


@pytest.fixture(autouse=True)
def _no_real_supabase_credentials_in_tests(monkeypatch):
    """Keep the test suite hermetic regardless of a local backend/.env.

    Now that app/config.py actually loads backend/.env, any developer
    machine with real Supabase credentials in that file would otherwise
    have every test that hits /analyze-email attempt a real network call
    to a live Supabase project. Tests must never depend on, or
    accidentally write to, a real external service. Individual tests that
    need SUPABASE_URL/SUPABASE_SECRET_KEY set to a specific value do so
    themselves via monkeypatch, on top of this baseline.
    """
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)
