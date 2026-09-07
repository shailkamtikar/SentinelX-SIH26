"""Focused tests for the dotenv-loading mechanism app/config.py relies on.

These test python-dotenv's `load_dotenv(dotenv_path=..., override=False)`
call with the exact same arguments app/config.py uses, against a temporary
.env file — never the real backend/.env, and never real Supabase
credentials. No test prints or asserts on any actual secret value.
"""

import os

from dotenv import load_dotenv


def test_existing_process_env_var_takes_precedence_over_dotenv_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("SUPABASE_URL=from-dotenv-file\n")
    monkeypatch.setenv("SUPABASE_URL", "already-set-by-process")

    load_dotenv(dotenv_path=env_file, override=False)

    assert os.environ["SUPABASE_URL"] == "already-set-by-process"


def test_dotenv_file_populates_a_missing_env_var(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("SUPABASE_SECRET_KEY=from-dotenv-file-secret\n")
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)

    try:
        load_dotenv(dotenv_path=env_file, override=False)
        assert os.environ["SUPABASE_SECRET_KEY"] == "from-dotenv-file-secret"
    finally:
        # load_dotenv mutates os.environ directly; monkeypatch only tracks
        # changes made through monkeypatch.setenv/delenv, so clean this up
        # explicitly to avoid leaking into other tests.
        monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)


def test_missing_dotenv_file_is_a_graceful_no_op(tmp_path, monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    nonexistent = tmp_path / "does-not-exist" / ".env"

    result = load_dotenv(dotenv_path=nonexistent, override=False)

    assert result is False
    assert "SUPABASE_URL" not in os.environ


# --- Gemini model configuration -----------------------------------------


def test_gemini_model_defaults_when_env_var_is_absent(monkeypatch):
    from app.config import DEFAULT_GEMINI_MODEL, get_settings

    monkeypatch.delenv("GEMINI_MODEL", raising=False)

    assert get_settings().gemini_model == DEFAULT_GEMINI_MODEL


def test_gemini_model_env_var_overrides_the_default(monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("GEMINI_MODEL", "some-other-model")

    assert get_settings().gemini_model == "some-other-model"


def test_gemini_configured_reflects_only_the_api_key(monkeypatch):
    from app.config import get_settings

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert get_settings().gemini_configured is False

    monkeypatch.setenv("GEMINI_API_KEY", "present")
    assert get_settings().gemini_configured is True


# --- CORS allowed origins configuration -----------------------------------


def test_cors_allowed_origins_defaults_to_localhost_only(monkeypatch):
    from app.config import DEFAULT_CORS_ORIGINS, get_settings

    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)

    assert get_settings().cors_allowed_origins == DEFAULT_CORS_ORIGINS
    assert get_settings().cors_allowed_origins == ("http://localhost:3000",)


def test_cors_allowed_origins_env_var_overrides_the_default(monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:3000,https://sentinel-x-sih-26.vercel.app",
    )

    assert get_settings().cors_allowed_origins == (
        "http://localhost:3000",
        "https://sentinel-x-sih-26.vercel.app",
    )


def test_cors_allowed_origins_trims_whitespace_and_drops_empty_entries(monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", " http://localhost:3000 , ,https://example.test ")

    assert get_settings().cors_allowed_origins == ("http://localhost:3000", "https://example.test")


def test_cors_allowed_origins_falls_back_to_default_when_env_var_is_blank(monkeypatch):
    from app.config import DEFAULT_CORS_ORIGINS, get_settings

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "   ,  ,")

    assert get_settings().cors_allowed_origins == DEFAULT_CORS_ORIGINS
