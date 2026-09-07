import hashlib

import pytest

from app.services.evidence_storage import (
    EVIDENCE_BUCKET,
    EvidenceBucketMissingError,
    build_storage_path,
    compute_raw_eml_sha256,
    upload_raw_eml,
)
from tests.fakes import FakeSupabaseClient

RAW = b"From: a@example.com\r\nSubject: test\r\n\r\nbody\r\n"


def test_bucket_name_is_the_private_evidence_bucket():
    assert EVIDENCE_BUCKET == "eml-evidence"


def test_storage_path_follows_case_id_email_id_convention():
    assert build_storage_path("case-abc", "email-123") == "case-abc/email-123.eml"


def test_sha256_is_the_whole_file_hash():
    assert compute_raw_eml_sha256(RAW) == hashlib.sha256(RAW).hexdigest()


def test_upload_sends_original_bytes_unchanged_to_the_expected_path():
    fake = FakeSupabaseClient()

    path = upload_raw_eml(fake, case_id="case-1", email_id="email-1", raw_bytes=RAW)

    assert path == "case-1/email-1.eml"
    assert len(fake.uploads) == 1
    upload = fake.uploads[0]
    assert upload["bucket"] == EVIDENCE_BUCKET
    assert upload["path"] == "case-1/email-1.eml"
    # Byte-for-byte identical to what was uploaded by the analyst.
    assert upload["file"] == RAW
    assert upload["file_options"]["content-type"] == "message/rfc822"


def test_missing_bucket_raises_a_distinct_configuration_error():
    fake = FakeSupabaseClient(missing_bucket=True)

    with pytest.raises(EvidenceBucketMissingError) as excinfo:
        upload_raw_eml(fake, case_id="case-1", email_id="email-1", raw_bytes=RAW)

    # The message must point the operator at manual, PRIVATE creation.
    message = str(excinfo.value)
    assert EVIDENCE_BUCKET in message
    assert "PRIVATE" in message
    assert fake.uploads == []


def test_generic_upload_failure_propagates_unchanged():
    fake = FakeSupabaseClient(upload_error=True)

    with pytest.raises(RuntimeError) as excinfo:
        upload_raw_eml(fake, case_id="case-1", email_id="email-1", raw_bytes=RAW)

    # Not misreported as a missing-bucket configuration problem.
    assert not isinstance(excinfo.value, EvidenceBucketMissingError)


def test_module_never_creates_a_bucket_or_requests_a_public_url():
    """The bucket must be created manually as PRIVATE, never from code."""
    from pathlib import Path

    from app.services import evidence_storage

    source = Path(evidence_storage.__file__).read_text(encoding="utf-8")
    for forbidden in ("create_bucket", "get_public_url", "create_signed_url"):
        assert forbidden not in source


def test_upload_is_the_only_storage_operation_performed():
    fake = FakeSupabaseClient()

    upload_raw_eml(fake, case_id="case-1", email_id="email-1", raw_bytes=RAW)

    # Nothing was written to Postgres by the storage layer itself, and no
    # raw bytes leaked into a table.
    assert fake.tables == {}
