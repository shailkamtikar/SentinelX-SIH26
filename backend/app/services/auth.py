"""Verified-identity extraction from the Authorization header.

Every request to an authenticated route depends on get_current_user_id,
which:

* requires a well-formed `Authorization: Bearer <token>` header,
* verifies that token against Supabase's own Auth server by asking it
  "who is this?" (`GoTrue.get_user`) — never by locally decoding the JWT.
  This rejects unsigned, forged, tampered, and expired tokens without this
  backend needing to know the project's signing algorithm or hold a
  separate JWT secret, and works the same whether the project uses
  Supabase's legacy shared secret or newer JWKS-based signing keys.
* returns the verified user's UUID as a plain string.

Every failure mode (missing header, malformed header, invalid token,
expired token, an unreachable/unconfigured Supabase project, or any other
verification error) resolves to the same 401 Unauthorized. The
Authorization header, the token itself, and the provider's raw error text
are never logged or echoed back in a response — only the exception TYPE is
logged, exactly like every other best-effort external call in this
codebase.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

from fastapi import Header, HTTPException, status

from app.config import get_settings

logger = logging.getLogger(__name__)

_INVALID_TOKEN_DETAIL = "Invalid or expired authentication token."


class SupabaseAuthClientLike(Protocol):
    """Minimal client surface this module uses, so tests can inject a fake."""

    @property
    def auth(self) -> Any: ...


def _get_client() -> SupabaseAuthClientLike:
    settings = get_settings()
    if not settings.supabase_configured:
        raise RuntimeError("Supabase is not configured (SUPABASE_URL / SUPABASE_SECRET_KEY missing).")
    # Imported lazily so importing this module never requires the SDK to
    # initialise or credentials to be present.
    from supabase import create_client

    return create_client(settings.supabase_url, settings.supabase_secret_key)


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header.",
        )

    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header must be 'Bearer <token>'.",
        )

    return token


def get_current_user_id(authorization: str | None = Header(default=None)) -> str:
    """FastAPI dependency: the verified Supabase user UUID, or a 401.

    Raising here happens before the route body runs, so an unauthenticated
    or invalid request never reaches file parsing, the forensic pipeline,
    or persistence.
    """
    token = _extract_bearer_token(authorization)

    try:
        client = _get_client()
    except RuntimeError as exc:
        logger.warning("Authentication unavailable: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_TOKEN_DETAIL,
        ) from exc

    try:
        user_response = client.auth.get_user(token)
    except Exception as exc:
        # Exception TYPE only — never the token, never the provider's raw
        # error text, which could echo request/token details.
        logger.warning("Token verification failed: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_TOKEN_DETAIL,
        ) from exc

    user = getattr(user_response, "user", None)
    user_id = getattr(user, "id", None) if user is not None else None
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_TOKEN_DETAIL,
        )

    return str(user_id)
