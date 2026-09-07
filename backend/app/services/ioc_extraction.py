"""Deterministic IOC (indicator of compromise) extraction.

Consumes the already-produced ParsedEmail and ForensicHeaders results —
it never touches raw bytes, never runs its own email parse, and makes no
network calls of any kind (no DNS, no WHOIS/RDAP, no GeoIP, no reputation
or threat-intelligence lookups). Every indicator is either an IP address,
a domain, a URL, or an attachment hash observed directly in the already-
extracted evidence; nothing here assigns a verdict, a score, or a
location/attribution to anything.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.services.eml_parser import ParsedEmail
from app.services.email_forensics import ForensicHeaders, extract_domain

# Fast candidate finder only — every match is validated by ipaddress.ip_address()
# before being trusted, so this does not need to be a strict IP grammar.
_IPV4_CANDIDATE_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6_CANDIDATE_PATTERN = re.compile(r"\[?([0-9A-Fa-f:]{2,39})\]?")

_TRAILING_DOT = "."


def _classify_ip(value: str) -> tuple[str, bool] | None:
    """Validate and classify a candidate IP string.

    Returns (kind, is_private) where kind is "ipv4" or "ipv6", or None if
    the candidate is not a valid IP address at all.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None

    is_private = addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    kind = "ipv4" if addr.version == 4 else "ipv6"
    return kind, is_private


def _find_ipv4_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for match in _IPV4_CANDIDATE_PATTERN.finditer(text):
        start, end = match.start(), match.end()
        # Reject matches that are actually a 4-octet slice of a longer
        # dotted-numeric chain (e.g. "1.2.3.4.5") rather than a standalone
        # address — \b alone doesn't catch this since "." isn't a word char.
        if start > 0 and text[start - 1] == ".":
            continue
        if end < len(text) and text[end] == "." and end + 1 < len(text) and text[end + 1].isdigit():
            continue
        candidates.append(match.group(0))
    return candidates


def _find_ip_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    candidates.extend(_find_ipv4_candidates(text))
    for match in _IPV6_CANDIDATE_PATTERN.finditer(text):
        candidate = match.group(1)
        # A bare run of digits/colons that happens to have no colon at all is
        # not an IPv6 candidate (it would just be noise); require at least
        # one colon so this pattern doesn't overlap with the IPv4 finder.
        if ":" in candidate:
            candidates.append(candidate)
    return candidates


def _normalize_domain(hostname: str | None) -> str | None:
    if not hostname:
        return None
    normalized = hostname.strip().lower()
    if normalized.endswith(_TRAILING_DOT):
        normalized = normalized[:-1]
    return normalized or None


def _is_punycode_hostname(hostname: str | None) -> bool:
    """Structural fact only: at least one label is IDN ACE-encoded (xn--).

    Not a maliciousness signal by itself — plenty of legitimate
    internationalized domains use punycode.
    """
    if not hostname:
        return False
    return any(label.startswith("xn--") for label in hostname.split("."))


def _safe_urlsplit_hostname(url: str) -> str | None:
    """hostname from urlsplit(), or None if the URL's syntax is unparsable.

    urlsplit() raises ValueError on some malformed strings (e.g. an
    unbalanced IPv6-literal bracket like "http://[::1"). A single
    malformed URL in a hostile/malformed email must not crash extraction
    for every other indicator, so this degrades to "no hostname" instead.
    """
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _url_structural_flags(url: str) -> tuple[bool, bool, bool]:
    """Return (ip_literal_url, credential_in_url, punycode_domain) for a URL.

    Purely structural observations about the URL's own syntax — never
    raises, since a malformed URL must not crash IOC extraction; an
    unparsable URL simply yields all-False flags.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False, False, False
    hostname = parts.hostname
    ip_literal = hostname is not None and _classify_ip(hostname) is not None
    credential = parts.username is not None
    punycode = _is_punycode_hostname(hostname)
    return ip_literal, credential, punycode


@dataclass
class IPIndicator:
    value: str
    sources: list[str] = field(default_factory=list)
    private: bool = False

    def to_dict(self) -> dict[str, object]:
        return {"value": self.value, "sources": self.sources, "private": self.private}


@dataclass
class DomainIndicator:
    value: str
    sources: list[str] = field(default_factory=list)
    punycode_domain: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "sources": self.sources,
            "punycode_domain": self.punycode_domain,
        }


@dataclass
class URLIndicator:
    value: str
    sources: list[str] = field(default_factory=list)
    ip_literal_url: bool = False
    credential_in_url: bool = False
    punycode_domain: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "sources": self.sources,
            "ip_literal_url": self.ip_literal_url,
            "credential_in_url": self.credential_in_url,
            "punycode_domain": self.punycode_domain,
        }


@dataclass
class AttachmentHashIndicator:
    filename: str | None
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {"filename": self.filename, "sha256": self.sha256}


@dataclass
class IOCReport:
    ipv4: list[IPIndicator] = field(default_factory=list)
    ipv6: list[IPIndicator] = field(default_factory=list)
    domains: list[DomainIndicator] = field(default_factory=list)
    urls: list[URLIndicator] = field(default_factory=list)
    attachment_hashes: list[AttachmentHashIndicator] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "ipv4": [ioc.to_dict() for ioc in self.ipv4],
            "ipv6": [ioc.to_dict() for ioc in self.ipv6],
            "domains": [ioc.to_dict() for ioc in self.domains],
            "urls": [ioc.to_dict() for ioc in self.urls],
            "attachment_hashes": [ioc.to_dict() for ioc in self.attachment_hashes],
        }


def extract_iocs(parsed: ParsedEmail, forensics: ForensicHeaders) -> IOCReport:
    """Extract IPv4/IPv6/domain/URL/attachment-hash indicators.

    Pure function over already-produced structured results — no raw bytes,
    no re-parsing, no network calls. IP addresses found in Received/
    Received-SPF headers are recorded with their originating source label
    only; nothing here interprets a Received-header IP as an attacker's
    location — that determination would require path analysis this
    milestone deliberately does not attempt.
    """
    ipv4_map: dict[str, IPIndicator] = {}
    ipv6_map: dict[str, IPIndicator] = {}
    domain_map: dict[str, DomainIndicator] = {}

    def add_ip(candidate: str, source: str) -> None:
        classified = _classify_ip(candidate)
        if classified is None:
            return
        kind, is_private = classified
        normalized = str(ipaddress.ip_address(candidate))
        target = ipv4_map if kind == "ipv4" else ipv6_map
        if normalized in target:
            if source not in target[normalized].sources:
                target[normalized].sources.append(source)
        else:
            target[normalized] = IPIndicator(
                value=normalized, sources=[source], private=is_private
            )

    def add_domain(hostname: str | None, source: str) -> None:
        normalized = _normalize_domain(hostname)
        if not normalized:
            return
        if normalized in domain_map:
            if source not in domain_map[normalized].sources:
                domain_map[normalized].sources.append(source)
        else:
            domain_map[normalized] = DomainIndicator(
                value=normalized,
                sources=[source],
                punycode_domain=_is_punycode_hostname(normalized),
            )

    # --- IP extraction -----------------------------------------------------

    if parsed.body:
        for candidate in _find_ip_candidates(parsed.body):
            add_ip(candidate, "body")

    for hop in forensics.received_chain:
        for candidate in _find_ip_candidates(hop):
            add_ip(candidate, "received_chain")

    if forensics.received_spf_raw:
        for candidate in _find_ip_candidates(forensics.received_spf_raw):
            add_ip(candidate, "received_spf")

    for url in parsed.urls:
        hostname = _safe_urlsplit_hostname(url)
        if hostname:
            classified = _classify_ip(hostname)
            if classified is not None:
                add_ip(hostname, "url")

    # --- Domain extraction ---------------------------------------------------

    add_domain(extract_domain(parsed.sender), "from_header")
    add_domain(extract_domain(parsed.reply_to), "reply_to_header")
    add_domain(extract_domain(parsed.return_path), "return_path_header")

    for url in parsed.urls:
        hostname = _safe_urlsplit_hostname(url)
        # A URL host that is itself a valid IP is an IP indicator, not a
        # domain indicator — don't double-count it under both types.
        if hostname and _classify_ip(hostname) is None:
            add_domain(hostname, "url")

    # --- URL indicators (reuse parsed.urls verbatim; no second regex) -------

    url_indicators = []
    for url in parsed.urls:
        ip_literal, credential, punycode = _url_structural_flags(url)
        url_indicators.append(
            URLIndicator(
                value=url,
                sources=["url"],
                ip_literal_url=ip_literal,
                credential_in_url=credential,
                punycode_domain=punycode,
            )
        )

    # --- Attachment hashes (read already-computed sha256, never re-hash) ---

    attachment_hashes = [
        AttachmentHashIndicator(
            filename=attachment.get("filename"),  # type: ignore[arg-type]
            sha256=attachment["sha256"],  # type: ignore[index]
        )
        for attachment in parsed.attachments
        if "sha256" in attachment
    ]

    return IOCReport(
        ipv4=list(ipv4_map.values()),
        ipv6=list(ipv6_map.values()),
        domains=list(domain_map.values()),
        urls=url_indicators,
        attachment_hashes=attachment_hashes,
    )
