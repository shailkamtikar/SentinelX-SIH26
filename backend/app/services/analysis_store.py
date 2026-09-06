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

import hashlib
from typing import Any, Protocol

from app.config import get_settings

_DEFAULT_CASE_TITLE = "Default Prototype Case"

# Cached across requests within one process so we don't query/insert a
# case row on every single upload. Reset in tests via monkeypatch.
_cached_default_case_id: str | None = None


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


def _get_or_create_default_case(client: SupabaseClientLike) -> str:
    """Return the id of the single prototype case, creating it if needed.

    Deliberately simple: one shared case for this prototype milestone,
    no auth, no case-selection UI. owner_id stays NULL.
    """
    global _cached_default_case_id
    if _cached_default_case_id is not None:
        return _cached_default_case_id

    existing = client.table("cases").select("id").limit(1).execute()
    if existing.data:
        _cached_default_case_id = existing.data[0]["id"]
        return _cached_default_case_id

    created = (
        client.table("cases").insert({"title": _DEFAULT_CASE_TITLE, "owner_id": None}).execute()
    )
    _cached_default_case_id = created.data[0]["id"]
    return _cached_default_case_id


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


def persist_analysis(
    *,
    raw_bytes: bytes,
    filename: str | None,
    response: dict[str, Any],
    client: SupabaseClientLike | None = None,
) -> None:
    """Persist one successful /analyze-email response to Supabase.

    Uses the response dict exactly as already assembled — no re-parsing,
    no re-normalization of IOCs. Raises on any failure (missing
    configuration, network error, etc.); the caller is responsible for
    catching broadly so a persistence failure can never change the API
    response or turn a successful analysis into an HTTP error.
    """
    resolved_client = client or _get_client()

    case_id = _get_or_create_default_case(resolved_client)
    raw_eml_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    email_row = _build_email_row(case_id, filename, raw_eml_sha256, response)
    email_result = resolved_client.table("emails").insert(email_row).execute()
    email_id = email_result.data[0]["id"]

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
