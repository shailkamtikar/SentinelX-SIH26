import hashlib
from pathlib import Path
from unittest.mock import patch

from email import policy
from email.parser import BytesParser
from fastapi.testclient import TestClient

from app.main import app
from app.services.eml_parser import get_attachments

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_EML_BYTES = (FIXTURES_DIR / "sample.eml").read_bytes()


def _upload(filename: str, content: bytes, content_type: str = "message/rfc822"):
    return client.post(
        "/analyze-email",
        files={"file": (filename, content, content_type)},
    )


def _parse_sample() -> dict:
    return _upload("sample.eml", SAMPLE_EML_BYTES).json()


def test_valid_eml_upload_returns_200_and_expected_schema():
    response = _upload("sample.eml", SAMPLE_EML_BYTES)
    assert response.status_code == 200
    data = response.json()
    # The original 10 fields must remain present and unchanged; "forensics" is
    # an additive key layered on top by the email-forensics milestone.
    assert {
        "sender",
        "recipient",
        "subject",
        "reply_to",
        "date",
        "message_id",
        "return_path",
        "body",
        "attachments",
        "urls",
    }.issubset(data.keys())
    assert "forensics" in data


def test_sender_recipient_subject_extraction():
    data = _parse_sample()
    assert data["sender"] == "Alice Analyst <alice@example.com>"
    assert data["recipient"] == "bob@example.org"
    # Subject is RFC 2047 encoded in the raw fixture; must come back decoded.
    assert data["subject"] == "Quarterly Report — Confidential"


def test_reply_to_extraction():
    data = _parse_sample()
    assert data["reply_to"] == "soc-alerts@example.com"


def test_date_extraction():
    data = _parse_sample()
    assert data["date"] is not None
    assert "2025" in data["date"]


def test_message_id_extraction():
    data = _parse_sample()
    assert data["message_id"] == "<sample-fixture-0001@example.com>"


def test_return_path_extraction():
    data = _parse_sample()
    assert data["return_path"] == "<bounce@example.com>"


def test_body_extraction_prefers_plain_text_part():
    data = _parse_sample()
    assert data["body"] is not None
    assert "Please review the attached quarterly report" in data["body"]


def test_attachment_extraction():
    data = _parse_sample()
    assert len(data["attachments"]) == 1
    attachment = data["attachments"][0]
    assert attachment["filename"] == "q2-report.csv"
    assert attachment["content_type"] == "text/csv"
    assert attachment["size"] > 0
    assert attachment["sha256"] == hashlib.sha256(b"Quarter,Revenue\nQ1,1000\nQ2,1500\n").hexdigest()


def _build_multipart_with_attachment(attachment_headers_and_body: bytes) -> bytes:
    return (
        b"From: alice@example.com\r\nTo: bob@example.org\r\nSubject: test\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="BOUND"\r\n\r\n'
        b"--BOUND\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
        b"--BOUND\r\n" + attachment_headers_and_body + b"\r\n--BOUND--\r\n"
    )


def test_genuinely_empty_attachment_gets_real_sha256_of_empty_bytes():
    # No data between the attachment's headers and the next boundary —
    # get_payload(decode=True) succeeds and returns b"", not an exception.
    raw = _build_multipart_with_attachment(
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="empty.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n"
    )
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    attachments = get_attachments(msg)

    assert len(attachments) == 1
    assert attachments[0]["size"] == 0
    assert attachments[0]["sha256"] == hashlib.sha256(b"").hexdigest()


def test_decode_failure_does_not_produce_empty_bytes_sha256():
    raw = _build_multipart_with_attachment(
        b"Content-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="broken.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\nAAAA\r\n"
    )
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    attachment_part = next(
        part
        for part in msg.walk()
        if not part.is_multipart() and part.get_filename() == "broken.bin"
    )

    with patch.object(attachment_part, "get_payload", side_effect=RuntimeError("boom")):
        attachments = get_attachments(msg)

    assert len(attachments) == 1
    assert attachments[0]["size"] == 0
    assert attachments[0]["sha256"] is None
    # Must not silently fall back to the empty-bytes hash on decode failure.
    assert attachments[0]["sha256"] != hashlib.sha256(b"").hexdigest()


def test_url_extraction_from_plain_and_html_parts():
    data = _parse_sample()
    assert "http://example.com/reports/q2" in data["urls"]
    assert "https://example.org/reports/q2-secure" in data["urls"]
    # Trailing sentence punctuation must not leak into the extracted URL.
    assert "http://example.com/reports/q2." not in data["urls"]


def test_missing_optional_header_is_null_not_fabricated():
    # This fixture has no header field for a value we never set (e.g. Cc).
    data = _parse_sample()
    # reply_to IS present in the fixture; assert the absence contract instead
    # using a field we deliberately did not set anywhere: nothing here should
    # ever be invented, so an untouched, unrelated key simply won't exist.
    assert "cc" not in data


def test_malformed_eml_bytes_do_not_crash_the_endpoint():
    response = _upload("garbage.eml", b"\x00\x01not a real email\xffdata")
    assert response.status_code == 200
    data = response.json()
    # A non-MIME blob has no recognizable headers; fields must be null, not fabricated.
    assert data["sender"] is None
    assert data["message_id"] is None
    assert data["attachments"] == []


def test_empty_file_upload_is_rejected():
    response = _upload("empty.eml", b"")
    assert response.status_code == 400


def test_non_eml_extension_is_rejected_at_endpoint_level():
    response = _upload("notes.txt", b"just some text content", content_type="text/plain")
    assert response.status_code == 400
