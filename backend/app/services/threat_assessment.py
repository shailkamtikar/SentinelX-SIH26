"""Deterministic, evidence-based threat assessment.

Consumes the already-produced ForensicHeaders and IOCReport results — no
raw-bytes reparsing, no network calls (no DNS, no WHOIS/RDAP, no GeoIP, no
reputation or threat-intelligence lookups), no machine learning. Every
reason string is a direct citation of a specific field already present in
the forensics/IOC evidence; nothing here is guessed or invented.

Three independent evidence categories are evaluated, and the risk level is
simply the count of categories that are true — not a weighted score:

  0 categories -> LOW
  1 category   -> MEDIUM
  2-3 categories -> HIGH

This intentionally means a single weak signal alone can never reach HIGH,
and a missing/absent signal (None) is never treated as a failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.services.email_forensics import ForensicHeaders
from app.services.ioc_extraction import IOCReport

_RISK_LEVEL_BY_CATEGORY_COUNT = {
    0: "LOW",
    1: "MEDIUM",
    2: "HIGH",
    3: "HIGH",
}


@dataclass
class ThreatAssessment:
    risk_level: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {"risk_level": self.risk_level, "reasons": self.reasons}


def _authentication_failure_reasons(forensics: ForensicHeaders) -> list[str]:
    """True only on an explicit "fail" verdict — never on an absent header.

    DKIM failing alone does not activate this category: benign mailing-list
    relaying/forwarding commonly breaks DKIM signatures without indicating
    anything suspicious, so it is not treated as a standalone red flag here.
    """
    reasons: list[str] = []
    if forensics.spf_result == "fail":
        reasons.append("SPF result: fail")
    if forensics.dmarc_result == "fail":
        reasons.append("DMARC result: fail")
    return reasons


def _routing_identity_mismatch_reasons(forensics: ForensicHeaders) -> list[str]:
    return list(forensics.routing_flags)


def _structural_url_risk_reasons(iocs: IOCReport) -> list[str]:
    reasons: list[str] = []
    for url in iocs.urls:
        if url.ip_literal_url:
            reasons.append(f"URL hostname is a raw IP address: {url.value}")
        if url.credential_in_url:
            reasons.append(f"Credentials embedded in URL: {url.value}")
        if url.punycode_domain:
            reasons.append(f"URL hostname uses punycode (IDN) encoding: {url.value}")
    for domain in iocs.domains:
        if domain.punycode_domain:
            reasons.append(f"Domain uses punycode (IDN) encoding: {domain.value}")
    return reasons


def assess_threat(forensics: ForensicHeaders, iocs: IOCReport) -> ThreatAssessment:
    """Evaluate the three evidence categories and derive a risk level.

    Pure function over already-produced structured results. Never raises
    for any combination of empty/None evidence — every category simply
    contributes zero reasons when its evidence is absent.
    """
    category_reasons = [
        _authentication_failure_reasons(forensics),
        _routing_identity_mismatch_reasons(forensics),
        _structural_url_risk_reasons(iocs),
    ]

    category_count = sum(1 for reasons in category_reasons if reasons)
    risk_level = _RISK_LEVEL_BY_CATEGORY_COUNT[category_count]

    reasons = [reason for reasons in category_reasons for reason in reasons]

    return ThreatAssessment(risk_level=risk_level, reasons=reasons)
