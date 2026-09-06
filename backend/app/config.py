"""Backend configuration loaded from environment variables.

Supabase credentials are entirely optional at import time — the API must
keep serving /analyze-email correctly with zero configuration present.
Persistence built on top of these settings is best-effort and isolated
(see services/analysis_store.py). Values are read fresh from the
environment on every call and are never logged, printed, or included in
any HTTP response.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Load backend/.env (if present) into the process environment, for local
# development only. Resolved relative to this file — not the process's
# current working directory — so it works the same whether the app is
# started from backend/ or elsewhere. override=False (python-dotenv's own
# default, passed explicitly here for clarity) means a real environment
# variable already set on the process always wins over a value in .env.
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env", override=False)


@dataclass(frozen=True)
class Settings:
    supabase_url: str | None
    # Server-only secret (the Supabase "service role"/secret key). Must
    # never be exposed to the frontend or logged.
    supabase_secret_key: str | None

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_secret_key)


def get_settings() -> Settings:
    """Read configuration fresh from the environment on every call.

    Not cached at import time so tests can set/clear environment
    variables per-test without needing to reload this module.
    """
    return Settings(
        supabase_url=os.environ.get("SUPABASE_URL") or None,
        supabase_secret_key=os.environ.get("SUPABASE_SECRET_KEY") or None,
    )
