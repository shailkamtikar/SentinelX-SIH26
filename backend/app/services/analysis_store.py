"""Best-effort persistence of a completed /analyze-email response to Supabase.

This module is intentionally isolated from the rest of the pipeline: it
consumes the already-assembled response dict (never re-parses or
re-normalizes IOCs) and is designed to be called *after* that response is
final. Every function here may raise — callers (routes/analyze.py) are
expected to catch broadly and continue, exactly like every other additive
stage in this pipeline. Persistence failing must never change the API
response or turn a successful analysis into an HTTP error.

No ORM: this talks to Postgres purely through the official `supabase`
Python client's table() query builder.

The raw whole-file SHA-256 computed here is an integrity aid only — it is
NOT a chain-of-custody or tamper-evidence guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from app.config import get_settings
from app.services.evidence_storage import (
    EvidenceBucketMissingError,
    compute_raw_eml_sha256,
    upload_raw_eml,
)

_DEFAULT_CASE_TITLE = "Default Prototype Case"


class SupabaseClientLike(Protocol):
    """The minimal client surface this module actually uses.

    Lets tests pass a small fake/mock instead of a real `supabase-py`
    client, without this module importing test-only types.
    """

    def table(self, name: str) -> Any: ...


def _get_client() -> SupabaseClientLike:
    settings = get_settings()
    if not settings.supabase_configured:
        raise RuntimeError(
            "Supabase is not configured (SUPABASE_URL / SUPABASE_SECRET_KEY missing)."
        )
    # Imported lazily so merely importing this module — or running the
    # existing test suite, which always injects a fake client — never
    # requires network access or a real Supabase project.
    from supabase import create_client

    return create_client(settings.supabase_url, settings.supabase_secret_key)


def _find_case_id_for_user(client: SupabaseClientLike, user_id: str) -> str | None:
    """The id of this user's existing prototype case, or None if they have none yet.

    Read-only — never creates a case. Used by both
    _get_or_create_case_for_user (persistence) and
    get_analysis_history_for_user (read), so merely *viewing* history can
    never conjure a case into existence for a user who has never analyzed
    anything.
    """
    existing = (
        client.table("cases").select("id").eq("owner_id", user_id).limit(1).execute()
    )
    if existing.data:
        return existing.data[0]["id"]
    return None


def _get_or_create_case_for_user(client: SupabaseClientLike, user_id: str) -> str:
    """Return the id of this user's single prototype case, creating it if needed.

    owner_id is always the verified Supabase user UUID passed in by the
    caller (routes/analyze.py, sourced from the authenticated request's
    verified JWT) — never NULL, never supplied by the browser, and never
    shared across users. Still one case per user for this prototype
    milestone: no case-selection UI, no multi-case model.
    """
    existing_case_id = _find_case_id_for_user(client, user_id)
    if existing_case_id is not None:
        return existing_case_id

    created = (
        client.table("cases")
        .insert({"title": _DEFAULT_CASE_TITLE, "owner_id": user_id})
        .execute()
    )
    return created.data[0]["id"]


def _index_by_value(entries: list[dict[str, Any]] | None, field: str) -> dict[str, Any]:
    return {entry["value"]: entry.get(field) for entry in (entries or [])}


def _build_email_row(
    case_id: str,
    filename: str | None,
    raw_eml_sha256: str,
    response: dict[str, Any],
) -> dict[str, Any]:
    forensics = response.get("forensics") or {}
    threat = response.get("threat_assessment") or {}
    return {
        "case_id": case_id,
        "original_filename": filename,
        "sender": response.get("sender"),
        "recipient": response.get("recipient"),
        "subject": response.get("subject"),
        "reply_to": response.get("reply_to"),
        "date_header": response.get("date"),
        "message_id": response.get("message_id"),
        "return_path": response.get("return_path"),
        "body": response.get("body"),
        "spf_result": forensics.get("spf_result"),
        "dkim_result": forensics.get("dkim_result"),
        "dmarc_result": forensics.get("dmarc_result"),
        "authentication_results_raw": forensics.get("authentication_results_raw"),
        "routing_flags": forensics.get("routing_flags") or [],
        "received_chain": forensics.get("received_chain") or [],
        "threat_risk_level": threat.get("risk_level", "UNKNOWN"),
        "threat_reasons": threat.get("reasons") or [],
        # Storage upload is a later milestone — left NULL deliberately.
        "raw_eml_storage_path": None,
        "raw_eml_sha256": raw_eml_sha256,
        "parsed_response": response,
    }


def _build_ip_rows(
    email_id: str, iocs: dict[str, Any], classification_by_value: dict[str, Any]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for family, key in ((4, "ipv4"), (6, "ipv6")):
        for entry in iocs.get(key) or []:
            rows.append(
                {
                    "email_id": email_id,
                    "ip_family": family,
                    "value": entry["value"],
                    "sources": entry.get("sources") or [],
                    "is_private": entry.get("private", False),
                    "enrichment_classification": classification_by_value.get(entry["value"]),
                }
            )
    return rows


def _build_domain_rows(email_id: str, iocs: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "email_id": email_id,
            "value": entry["value"],
            "sources": entry.get("sources") or [],
            "is_punycode": entry.get("punycode_domain", False),
        }
        for entry in iocs.get("domains") or []
    ]


def _build_url_rows(
    email_id: str, iocs: dict[str, Any], shortener_by_value: dict[str, Any]
) -> list[dict[str, Any]]:
    return [
        {
            "email_id": email_id,
            "value": entry["value"],
            "sources": entry.get("sources") or [],
            "is_ip_literal": entry.get("ip_literal_url", False),
            "has_credential": entry.get("credential_in_url", False),
            "is_punycode": entry.get("punycode_domain", False),
            "is_known_shortener": bool(shortener_by_value.get(entry["value"], False)),
        }
        for entry in iocs.get("urls") or []
    ]


def _build_attachment_hash_rows(email_id: str, iocs: dict[str, Any]) -> list[dict[str, Any]]:
    # sha256 is preserved exactly as the pipeline produced it — None stays
    # None (decode failure). Null-never-correlates is enforced by the
    # correlation query/view, not by anything done at insert time here.
    return [
        {
            "email_id": email_id,
            "filename": entry.get("filename"),
            "sha256": entry.get("sha256"),
        }
        for entry in iocs.get("attachment_hashes") or []
    ]


@dataclass
class PersistenceOutcome:
    """What actually happened, so the route can report truthful status."""

    email_id: str
    raw_eml_sha256: str
    # Internal object path inside the PRIVATE bucket, or None when the raw
    # .eml was not stored. Never a public URL.
    raw_eml_storage_path: str | None = None
    # Non-secret marker for why storage did not happen: "bucket_missing"
    # or "upload_failed". None when the upload succeeded.
    storage_error: str | None = None


def _store_raw_eml(
    client: SupabaseClientLike,
    *,
    case_id: str,
    email_id: str,
    raw_bytes: bytes,
) -> tuple[str | None, str | None]:
    """Best-effort upload + path write-back. Returns (path, error_marker).

    Isolated from the rest of persistence on purpose: a Storage outage or
    an unconfigured bucket must not stop the IOC child rows from being
    written, and must never fake a stored state.
    """
    try:
        path = upload_raw_eml(
            client, case_id=case_id, email_id=email_id, raw_bytes=raw_bytes
        )
    except EvidenceBucketMissingError:
        return None, "bucket_missing"
    except Exception:
        return None, "upload_failed"

    try:
        client.table("emails").update({"raw_eml_storage_path": path}).eq(
            "id", email_id
        ).execute()
    except Exception:
        # The object exists but the row could not be pointed at it. Report
        # it as not stored rather than claiming a link that isn't recorded.
        return None, "path_update_failed"

    return path, None


def persist_analysis(
    *,
    raw_bytes: bytes,
    filename: str | None,
    response: dict[str, Any],
    user_id: str,
    client: SupabaseClientLike | None = None,
) -> PersistenceOutcome:
    """Persist one successful /analyze-email response to Supabase.

    Uses the response dict exactly as already assembled — no re-parsing,
    no re-normalization of IOCs. Raises on any failure (missing
    configuration, network error, etc.); the caller is responsible for
    catching broadly so a persistence failure can never change the API
    response or turn a successful analysis into an HTTP error.

    `user_id` must be the verified Supabase user UUID from the
    authenticated request (see app.services.auth.get_current_user_id) —
    never a value supplied by the browser. It becomes cases.owner_id for
    the case this email is filed under; there is no anonymous/shared-case
    fallback.

    Raw .eml upload is a nested best-effort step: it can fail without
    preventing the email row or the IOC child rows from being written.
    """
    resolved_client = client or _get_client()

    case_id = _get_or_create_case_for_user(resolved_client, user_id)
    raw_eml_sha256 = compute_raw_eml_sha256(raw_bytes)

    email_row = _build_email_row(case_id, filename, raw_eml_sha256, response)
    email_result = resolved_client.table("emails").insert(email_row).execute()
    email_id = email_result.data[0]["id"]

    storage_path, storage_error = _store_raw_eml(
        resolved_client, case_id=case_id, email_id=email_id, raw_bytes=raw_bytes
    )

    iocs = response.get("iocs") or {}
    enrichment = response.get("enrichment") or {}
    classification_by_value = _index_by_value(enrichment.get("ip"), "classification")
    shortener_by_value = _index_by_value(enrichment.get("url"), "known_url_shortener")

    ip_rows = _build_ip_rows(email_id, iocs, classification_by_value)
    domain_rows = _build_domain_rows(email_id, iocs)
    url_rows = _build_url_rows(email_id, iocs, shortener_by_value)
    attachment_rows = _build_attachment_hash_rows(email_id, iocs)

    if ip_rows:
        resolved_client.table("ioc_ips").insert(ip_rows).execute()
    if domain_rows:
        resolved_client.table("ioc_domains").insert(domain_rows).execute()
    if url_rows:
        resolved_client.table("ioc_urls").insert(url_rows).execute()
    if attachment_rows:
        resolved_client.table("ioc_attachment_hashes").insert(attachment_rows).execute()

    return PersistenceOutcome(
        email_id=email_id,
        raw_eml_sha256=raw_eml_sha256,
        raw_eml_storage_path=storage_path,
        storage_error=storage_error,
    )


def get_analysis_history_for_user(
    user_id: str, *, client: SupabaseClientLike | None = None
) -> list[dict[str, Any]]:
    """Every previously persisted analysis belonging to this user, oldest first.

    `user_id` must be the verified Supabase user UUID from the
    authenticated request — never a value supplied by the browser. Reads
    are scoped to that user's own case only (see _find_case_id_for_user);
    a user with no prior analyses gets an empty list, not an error, and no
    case is created as a side effect of merely viewing history.

    Each entry reconstructs the same shape /analyze-email itself returns
    (`response`) from the already-persisted `parsed_response` plus the
    row's own hash/storage-path columns for the `evidence` field, which is
    added by the route *after* persistence and so isn't part of the stored
    JSON. Raw .eml bytes are never included — only the boolean/hash
    evidence status, exactly like a live analysis response.
    """
    resolved_client = client or _get_client()

    case_id = _find_case_id_for_user(resolved_client, user_id)
    if case_id is None:
        return []

    result = resolved_client.table("emails").select("*").eq("case_id", case_id).execute()

    entries: list[dict[str, Any]] = []
    for row in result.data or []:
        response = dict(row.get("parsed_response") or {})
        response["evidence"] = {
            "raw_eml_sha256": row.get("raw_eml_sha256"),
            "raw_eml_stored": bool(row.get("raw_eml_storage_path")),
        }
        entries.append(
            {
                "email_id": row.get("id"),
                "original_filename": row.get("original_filename"),
                # None when the table has no such column/value — never
                # invented. The frontend degrades to omitting timestamps.
                "analyzed_at": row.get("created_at"),
                "response": response,
            }
        )

    entries.sort(key=lambda entry: entry.get("analyzed_at") or "")
    return entries
