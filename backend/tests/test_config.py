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
