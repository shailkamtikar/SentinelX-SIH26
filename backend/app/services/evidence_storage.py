"""Private Supabase Storage for the original uploaded .eml bytes.

Deliberately small and isolated: this module knows how to hash the raw
file, where the object belongs, and how to push bytes into the private
`eml-evidence` bucket. Nothing else in the pipeline talks to Storage.

Guarantees and non-guarantees:

* The bucket is expected to already exist and to be PRIVATE. This module
  never creates a bucket and never requests or returns a public URL — the
  only thing it hands back is the internal object path recorded in
  ``emails.raw_eml_storage_path``.
* Raw .eml bytes are uploaded verbatim; they are never written into
  Postgres.
* The whole-file SHA-256 computed here is an integrity aid for the
  investigator. It is NOT blockchain custody, NOT a cryptographic
  chain-of-custody guarantee, and NOT tamper-evidence.

Every function may raise. Callers treat storage as best-effort: a failure
must leave ``raw_eml_storage_path`` NULL rather than fake a stored state.
"""

from __future__ import annotations

import hashlib
from typing import Any, Protocol

# Must already exist in the Supabase project, created manually as PRIVATE.
EVIDENCE_BUCKET = "eml-evidence"

_RFC822_CONTENT_TYPE = "message/rfc822"

# Substrings Supabase Storage uses when the bucket itself is absent. Matched
# case-insensitively against the exception text so a missing bucket can be
# reported as a configuration problem instead of a generic upload failure.
_MISSING_BUCKET_MARKERS = ("bucket not found", "bucket_not_found")


class EvidenceBucketMissingError(RuntimeError):
    """The private `eml-evidence` bucket does not exist yet.

    Signals a one-time manual Supabase configuration step, not a transient
    upload error. This module will never auto-create the bucket, because
    creating it programmatically risks provisioning a public one.
    """


class StorageClientLike(Protocol):
    """The minimal client surface this module actually uses."""

    @property
    def storage(self) -> Any: ...


def compute_raw_eml_sha256(raw_bytes: bytes) -> str:
    """SHA-256 of the ORIGINAL uploaded file, whole-file.

    Separate from, and never to be confused with, the per-attachment
    hashes produced by the parser.
    """
    return hashlib.sha256(raw_bytes).hexdigest()


def build_storage_path(case_id: str, email_id: str) -> str:
    """Object path inside the private bucket: {case_id}/{email_id}.eml"""
    return f"{case_id}/{email_id}.eml"


def _is_missing_bucket(error: Exception) -> bool:
    text = str(error).lower()
    return any(marker in text for marker in _MISSING_BUCKET_MARKERS)


def upload_raw_eml(
    client: StorageClientLike,
    *,
    case_id: str,
    email_id: str,
    raw_bytes: bytes,
) -> str:
    """Upload the original bytes to the private bucket, returning the path.

    Raises EvidenceBucketMissingError when the bucket has not been created
    yet, and re-raises anything else unchanged for the caller to isolate.
    """
    path = build_storage_path(case_id, email_id)

    try:
        client.storage.from_(EVIDENCE_BUCKET).upload(
            path=path,
            file=raw_bytes,
            file_options={"content-type": _RFC822_CONTENT_TYPE, "upsert": "true"},
        )
    except Exception as exc:
        if _is_missing_bucket(exc):
            raise EvidenceBucketMissingError(
                f"Supabase Storage bucket '{EVIDENCE_BUCKET}' does not exist. "
                "Create it manually as a PRIVATE bucket; it is never created automatically."
            ) from exc
        raise

    return path
