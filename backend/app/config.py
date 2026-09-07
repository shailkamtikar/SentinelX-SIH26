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


DEFAULT_GEMINI_MODEL = "gemini-3.6-flash"

# Local Next.js dev origin only, unless CORS_ALLOWED_ORIGINS overrides this —
# preserves today's exact behavior when the env var is unset.
DEFAULT_CORS_ORIGINS: tuple[str, ...] = ("http://localhost:3000",)


@dataclass(frozen=True)
class Settings:
    supabase_url: str | None
    # Server-only secret (the Supabase "service role"/secret key). Must
    # never be exposed to the frontend or logged.
    supabase_secret_key: str | None
    # Server-only secret. Optional: the AI explanation stage is skipped
    # entirely when this is absent, and the deterministic assessment
    # remains authoritative either way.
    gemini_api_key: str | None
    gemini_model: str
    # Exact-match browser origins allowed by CORS (app/main.py). Never a
    # wildcard — see CORS_ALLOWED_ORIGINS below.
    cors_allowed_origins: tuple[str, ...]

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_secret_key)

    @property
    def gemini_configured(self) -> bool:
        return bool(self.gemini_api_key)


def _parse_cors_origins(raw: str | None) -> tuple[str, ...]:
    """Comma-separated origins from CORS_ALLOWED_ORIGINS, or the local-dev default.

    Whitespace around each entry is trimmed and empty entries (e.g. from a
    trailing comma) are dropped. An unset or empty env var falls back to
    DEFAULT_CORS_ORIGINS exactly — local dev behavior is unchanged unless
    this is explicitly configured.
    """
    if not raw:
        return DEFAULT_CORS_ORIGINS
    origins = tuple(origin.strip() for origin in raw.split(",") if origin.strip())
    return origins or DEFAULT_CORS_ORIGINS


def get_settings() -> Settings:
    """Read configuration fresh from the environment on every call.

    Not cached at import time so tests can set/clear environment
    variables per-test without needing to reload this module.
    """
    return Settings(
        supabase_url=os.environ.get("SUPABASE_URL") or None,
        supabase_secret_key=os.environ.get("SUPABASE_SECRET_KEY") or None,
        gemini_api_key=os.environ.get("GEMINI_API_KEY") or None,
        gemini_model=os.environ.get("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL,
        cors_allowed_origins=_parse_cors_origins(os.environ.get("CORS_ALLOWED_ORIGINS")),
    )
