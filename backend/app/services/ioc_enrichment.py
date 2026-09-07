"""Deterministic, offline IOC enrichment.

Consumes an already-produced IOCReport — no raw-bytes reparsing, no
network calls of any kind (no DNS, no WHOIS/RDAP, no GeoIP, no reputation
or threat-intelligence lookups), no external services, no API keys, no
environment variables. Every classification is derived purely from the
IP address's own bits (via the stdlib `ipaddress` module) or from a small
static, bundled hostname list — nothing here is fetched, guessed, or
invented at request time.

Classifications are factual/provenance statements about address-space or
service usage (e.g. "this is an RFC 1918 private address", "this URL uses
a known link-shortening service") — never a threat verdict. A private,
reserved, documentation-range, or shortened-link classification is NOT,
by itself, any indication of malicious intent, and nothing here computes
or contributes to a risk score. See threat_assessment.py for the
(separate, unaffected) deterministic risk engine.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.services.ioc_extraction import IOCReport

# --- IPv4 special-purpose ranges not already exposed as a single stdlib
# attribute (RFC 5737 documentation ranges, RFC 1918 private ranges, and
# RFC 6598 shared/CGNAT address space) -----------------------------------

_IPV4_DOCUMENTATION_NETWORKS: tuple[tuple[ipaddress.IPv4Network, str], ...] = (
    (ipaddress.ip_network("192.0.2.0/24"), "RFC 5737 documentation range (TEST-NET-1)"),
    (ipaddress.ip_network("198.51.100.0/24"), "RFC 5737 documentation range (TEST-NET-2)"),
    (ipaddress.ip_network("203.0.113.0/24"), "RFC 5737 documentation range (TEST-NET-3)"),
)

_IPV4_RFC1918_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

_IPV4_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")

# --- IPv6 special-purpose ranges not already exposed as a single stdlib
# attribute (RFC 4193 Unique Local Addresses, RFC 3849 documentation) ----

_IPV6_ULA_NETWORK = ipaddress.ip_network("fc00::/7")
_IPV6_DOCUMENTATION_NETWORK = ipaddress.ip_network("2001:db8::/32")

# Non-exhaustive, hand-maintained list of well-known URL-shortening
# service hostnames. Presence in this list is a NEUTRAL structural fact
# about the service a URL uses — shorteners are ordinary, legitimate
# infrastructure used constantly for entirely benign purposes (marketing,
# social media, SMS character limits, etc.) and are NOT, by themselves,
# any indication of malicious intent. This list is manually curated, will
# inevitably drift out of date, and is not a reputation or intelligence
# feed of any kind — it is not fetched or updated automatically.
KNOWN_URL_SHORTENER_HOSTNAMES: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "tiny.cc",
        "rb.gy",
        "bl.ink",
        "lnkd.in",
        "s.id",
    }
)


def _classify_ipv4(addr: ipaddress.IPv4Address) -> str:
    if addr.is_unspecified:
        return "Unspecified address (RFC 791)"
    if addr.is_loopback:
        return "Loopback (RFC 5735)"
    if addr.is_link_local:
        return "Link-local (RFC 3927)"
    for network, label in _IPV4_DOCUMENTATION_NETWORKS:
        if addr in network:
            return label
    for network in _IPV4_RFC1918_NETWORKS:
        if addr in network:
            return "RFC 1918 private address space"
    if addr in _IPV4_SHARED_ADDRESS_SPACE:
        return "Shared address space / CGNAT (RFC 6598)"
    if addr.is_multicast:
        return "Multicast (RFC 5771)"
    if addr.is_reserved:
        return "Reserved (IANA special-purpose registry)"
    if addr.is_private:
        return "Private / non-globally-routable"
    return "Public / globally routable"


def _classify_ipv6(addr: ipaddress.IPv6Address) -> str:
    if addr.is_unspecified:
        return "Unspecified address (RFC 4291)"
    if addr.is_loopback:
        return "Loopback (RFC 4291)"
    if addr.is_link_local:
        return "Link-local (RFC 4291)"
    if addr in _IPV6_ULA_NETWORK:
        return "Unique local address / ULA (RFC 4193)"
    if addr in _IPV6_DOCUMENTATION_NETWORK:
        return "RFC 3849 documentation range"
    if addr.is_multicast:
        return "Multicast (RFC 4291)"
    if addr.is_reserved:
        return "Reserved (IANA special-purpose registry)"
    if addr.is_private:
        return "Private / non-globally-routable"
    return "Public / globally routable"


def _classify_ip(value: str) -> str | None:
    """Classify an IP's address-space provenance, or None if invalid.

    Never raises — a malformed value simply yields no classification
    rather than crashing enrichment for every other indicator.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return _classify_ipv4(addr)
    return _classify_ipv6(addr)


def _safe_hostname(url: str) -> str | None:
    """hostname from urlsplit(), or None if the URL's syntax is unparsable.

    A single malformed URL must not crash enrichment for every other
    indicator.
    """
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


@dataclass
class IPEnrichment:
    value: str
    classification: str

    def to_dict(self) -> dict[str, object]:
        return {"value": self.value, "classification": self.classification}


@dataclass
class URLEnrichment:
    value: str
    known_url_shortener: bool = True

    def to_dict(self) -> dict[str, object]:
        return {"value": self.value, "known_url_shortener": self.known_url_shortener}


@dataclass
class EnrichmentReport:
    ip: list[IPEnrichment] = field(default_factory=list)
    url: list[URLEnrichment] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "ip": [entry.to_dict() for entry in self.ip],
            "url": [entry.to_dict() for entry in self.url],
        }


def enrich_iocs(iocs: IOCReport) -> EnrichmentReport:
    """Derive offline, deterministic enrichment for already-extracted IOCs.

    Pure function over an already-produced IOCReport — no raw bytes, no
    re-parsing, no network calls. Produces one IP entry per extracted
    IPv4/IPv6 indicator (in the order given; no additional deduplication
    beyond what IOCReport itself already guarantees), and a URL entry
    only for URLs whose hostname matches a known shortener service.
    """
    ip_entries: list[IPEnrichment] = []
    for indicator in (*iocs.ipv4, *iocs.ipv6):
        classification = _classify_ip(indicator.value)
        if classification is not None:
            ip_entries.append(IPEnrichment(value=indicator.value, classification=classification))

    url_entries: list[URLEnrichment] = []
    for indicator in iocs.urls:
        hostname = _safe_hostname(indicator.value)
        if hostname and hostname.lower() in KNOWN_URL_SHORTENER_HOSTNAMES:
            url_entries.append(URLEnrichment(value=indicator.value))

    return EnrichmentReport(ip=ip_entries, url=url_entries)
