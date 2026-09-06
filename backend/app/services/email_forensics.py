"""Email authentication and routing-identity forensics.

Reads Authentication-Results and Received headers directly from the
parsed message. Nothing here performs live DNS lookups, calls external
services, or invents a verdict when a header is absent — missing
signals resolve to None/[] exactly like the rest of the evidence
pipeline in eml_parser.py.

Routing "flags" are neutral descriptive observations (domain mismatches
between From/Reply-To/Return-Path), never a threat verdict or a
numeric score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser

# RFC 8601 Authentication-Results tokens look like "spf=pass", "dkim=fail", etc.
_AUTH_RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)

# Bare-domain extraction from an address header's "@domain" portion.
_DOMAIN_PATTERN = re.compile(r"@([A-Za-z0-9.-]+)")


def header_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def extract_domain(address_header: str | None) -> str | None:
    """Best-effort bare-domain extraction from a From/Reply-To/Return-Path value."""
    if not address_header:
        return None
    match = _DOMAIN_PATTERN.search(address_header)
    if not match:
        return None
    return match.group(1).lower()


def extract_auth_verdicts(
    authentication_results_raw: str | None,
) -> tuple[str | None, str | None, str | None]:
    """Pull spf/dkim/dmarc verdicts out of a raw Authentication-Results header.

    Returns (spf_result, dkim_result, dmarc_result). Any mechanism not
    present in the header resolves to None — never guessed.
    """
    if not authentication_results_raw:
        return None, None, None

    verdicts: dict[str, str] = {}
    for match in _AUTH_RESULT_PATTERN.finditer(authentication_results_raw):
        mechanism = match.group(1).lower()
        result = match.group(2).lower()
        verdicts.setdefault(mechanism, result)

    return verdicts.get("spf"), verdicts.get("dkim"), verdicts.get("dmarc")


def compare_routing_identities(
    sender: str | None,
    reply_to: str | None,
    return_path: str | None,
) -> list[str]:
    """Flag domain mismatches between From/Reply-To/Return-Path.

    These are neutral observations, not threat verdicts. A flag is only
    raised when both domains being compared are actually present —
    missing data is never treated as a mismatch.
    """
    flags: list[str] = []

    from_domain = extract_domain(sender)
    reply_to_domain = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)

    if from_domain and return_path_domain and from_domain != return_path_domain:
        flags.append("return_path_domain_mismatch")

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        flags.append("reply_to_domain_mismatch")

    return flags


@dataclass
class ForensicHeaders:
    authentication_results_raw: str | None
    spf_result: str | None
    dkim_result: str | None
    dmarc_result: str | None
    received_chain: list[str] = field(default_factory=list)
    routing_flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "authentication_results_raw": self.authentication_results_raw,
            "spf_result": self.spf_result,
            "dkim_result": self.dkim_result,
            "dmarc_result": self.dmarc_result,
            "received_chain": self.received_chain,
            "routing_flags": self.routing_flags,
        }


def parse_email_forensics(raw_bytes: bytes) -> ForensicHeaders:
    """Extract authentication and routing-identity forensics from raw .eml bytes.

    Parses the same raw bytes independently of eml_parser.parse_eml_bytes so
    this module stays fully decoupled from — and never mutates — the
    existing evidence-extraction response.
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    authentication_results_raw = header_str(msg.get("Authentication-Results"))
    spf_result, dkim_result, dmarc_result = extract_auth_verdicts(authentication_results_raw)

    received_chain = [str(value).strip() for value in (msg.get_all("Received") or [])]

    routing_flags = compare_routing_identities(
        sender=header_str(msg.get("From")),
        reply_to=header_str(msg.get("Reply-To")),
        return_path=header_str(msg.get("Return-Path")),
    )

    return ForensicHeaders(
        authentication_results_raw=authentication_results_raw,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
        received_chain=received_chain,
        routing_flags=routing_flags,
    )
