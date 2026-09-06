"""Real RFC-822/MIME email parsing built on Python's standard `email` package.

The uploaded .eml is treated as untrusted evidence: nothing here executes
HTML, scripts, or attachment content, and no network requests are made.
Every field is extracted from the actual parsed message; missing headers
resolve to None rather than a fabricated value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from email.parser import BytesParser
from html.parser import HTMLParser

URL_PATTERN = re.compile(r"https?://[^\s<>\"'()]+")
_TRAILING_PUNCTUATION = ".,;:!?"


class _HTMLTextExtractor(HTMLParser):
    """Pulls visible text and anchor hrefs out of HTML without rendering it."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value:
                self.hrefs.append(value)

    def handle_data(self, data: str) -> None:
        stripped = data.strip()
        if stripped:
            self._chunks.append(stripped)

    def get_text(self) -> str:
        return "\n".join(self._chunks)


def html_to_text(html_content: str) -> tuple[str, list[str]]:
    """Strip HTML tags down to readable text and collect any <a href> links."""
    parser = _HTMLTextExtractor()
    parser.feed(html_content or "")
    return parser.get_text(), parser.hrefs


def header_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def get_body_and_html_urls(msg: Message) -> tuple[str | None, list[str]]:
    plain_parts: list[str] = []
    html_text_parts: list[str] = []
    html_urls: list[str] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        if (part.get_content_disposition() or "").lower() == "attachment":
            continue

        content_type = part.get_content_type()
        if content_type == "text/plain":
            try:
                plain_parts.append(part.get_content())
            except Exception:
                continue
        elif content_type == "text/html":
            try:
                html_content = part.get_content()
            except Exception:
                html_content = ""
            text, hrefs = html_to_text(html_content)
            html_text_parts.append(text)
            html_urls.extend(hrefs)

    if plain_parts:
        body = "\n".join(plain_parts).strip() or None
    elif html_text_parts:
        body = "\n".join(html_text_parts).strip() or None
    else:
        body = None

    return body, html_urls


def get_attachments(msg: Message) -> list[dict[str, object]]:
    attachments: list[dict[str, object]] = []

    for part in msg.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if not filename and disposition != "attachment":
            continue

        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        attachments.append(
            {
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(payload),
            }
        )

    return attachments


def extract_urls(body: str | None, html_urls: list[str]) -> list[str]:
    raw_urls: list[str] = []
    if body:
        raw_urls.extend(URL_PATTERN.findall(body))
    raw_urls.extend(html_urls)

    seen: set[str] = set()
    unique_urls: list[str] = []
    for url in raw_urls:
        cleaned = url.rstrip(_TRAILING_PUNCTUATION)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_urls.append(cleaned)
    return unique_urls


@dataclass
class ParsedEmail:
    sender: str | None
    recipient: str | None
    subject: str | None
    reply_to: str | None
    date: str | None
    message_id: str | None
    return_path: str | None
    body: str | None
    attachments: list[dict[str, object]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "subject": self.subject,
            "reply_to": self.reply_to,
            "date": self.date,
            "message_id": self.message_id,
            "return_path": self.return_path,
            "body": self.body,
            "attachments": self.attachments,
            "urls": self.urls,
        }


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    """Parse raw .eml bytes into structured, evidence-faithful fields.

    Uses policy=email.policy.default so RFC 2047 encoded-word headers
    (e.g. "=?UTF-8?B?...?=") are decoded automatically.
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    body, html_urls = get_body_and_html_urls(msg)
    attachments = get_attachments(msg)
    urls = extract_urls(body, html_urls)

    return ParsedEmail(
        sender=header_str(msg.get("From")),
        recipient=header_str(msg.get("To")),
        subject=header_str(msg.get("Subject")),
        reply_to=header_str(msg.get("Reply-To")),
        date=header_str(msg.get("Date")),
        message_id=header_str(msg.get("Message-ID")),
        return_path=header_str(msg.get("Return-Path")),
        body=body,
        attachments=attachments,
        urls=urls,
    )
