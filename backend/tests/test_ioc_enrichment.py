from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services.eml_parser import parse_eml_bytes
from app.services.email_forensics import parse_email_forensics
from app.services.ioc_enrichment import EnrichmentReport, enrich_iocs
from app.services.ioc_extraction import IOCReport, IPIndicator, URLIndicator, extract_iocs

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_EML_BYTES = (FIXTURES_DIR / "sample.eml").read_bytes()
FORENSICS_EML_BYTES = (FIXTURES_DIR / "sample_with_forensics.eml").read_bytes()


def _upload(filename: str, content: bytes):
    return client.post(
        "/analyze-email",
        files={"file": (filename, content, "message/rfc822")},
    )


def _classification_by_value(enrichment: EnrichmentReport) -> dict[str, str]:
    return {entry.value: entry.classification for entry in enrichment.ip}


# --- 1. sample.eml -> empty enrichment ----------------------------------------


def test_sample_eml_has_empty_enrichment():
    parsed = parse_eml_bytes(SAMPLE_EML_BYTES)
    forensics = parse_email_forensics(SAMPLE_EML_BYTES)
    iocs = extract_iocs(parsed, forensics)

    enrichment = enrich_iocs(iocs)

    assert enrichment.ip == []
    assert enrichment.url == []


def test_sample_eml_end_to_end_response_has_empty_enrichment():
    response = _upload("sample.eml", SAMPLE_EML_BYTES)
    assert response.status_code == 200
    data = response.json()

    assert data["enrichment"] == {"ip": [], "url": []}


# --- 2. sample_with_forensics.eml -> correct RFC 5737 classifications --------


def test_forensics_eml_ips_get_correct_documentation_range_classification():
    parsed = parse_eml_bytes(FORENSICS_EML_BYTES)
    forensics = parse_email_forensics(FORENSICS_EML_BYTES)
    iocs = extract_iocs(parsed, forensics)

    enrichment = enrich_iocs(iocs)
    by_value = _classification_by_value(enrichment)

    assert by_value["198.51.100.5"] == "RFC 5737 documentation range (TEST-NET-2)"
    assert by_value["198.51.100.7"] == "RFC 5737 documentation range (TEST-NET-2)"
    assert by_value["203.0.113.9"] == "RFC 5737 documentation range (TEST-NET-3)"


# --- 3-9. Individual IP classification cases -----------------------------------


def test_rfc1918_private_ip_classification():
    iocs = IOCReport(ipv4=[IPIndicator(value="10.0.0.5", sources=["body"], private=True)])
    enrichment = enrich_iocs(iocs)

    assert _classification_by_value(enrichment)["10.0.0.5"] == "RFC 1918 private address space"


def test_loopback_ip_classification():
    iocs = IOCReport(ipv4=[IPIndicator(value="127.0.0.1", sources=["body"], private=True)])
    enrichment = enrich_iocs(iocs)

    assert _classification_by_value(enrichment)["127.0.0.1"] == "Loopback (RFC 5735)"


def test_link_local_ip_classification():
    iocs = IOCReport(ipv4=[IPIndicator(value="169.254.10.20", sources=["body"], private=True)])
    enrichment = enrich_iocs(iocs)

    assert _classification_by_value(enrichment)["169.254.10.20"] == "Link-local (RFC 3927)"


def test_public_ip_classification():
    iocs = IOCReport(ipv4=[IPIndicator(value="8.8.8.8", sources=["body"], private=False)])
    enrichment = enrich_iocs(iocs)

    assert _classification_by_value(enrichment)["8.8.8.8"] == "Public / globally routable"


def test_ipv6_loopback_classification():
    iocs = IOCReport(ipv6=[IPIndicator(value="::1", sources=["body"], private=True)])
    enrichment = enrich_iocs(iocs)

    assert _classification_by_value(enrichment)["::1"] == "Loopback (RFC 4291)"


def test_ipv6_documentation_range_classification():
    iocs = IOCReport(ipv6=[IPIndicator(value="2001:db8::1", sources=["body"], private=True)])
    enrichment = enrich_iocs(iocs)

    assert (
        _classification_by_value(enrichment)["2001:db8::1"] == "RFC 3849 documentation range"
    )


def test_ipv6_ula_classification():
    iocs = IOCReport(ipv6=[IPIndicator(value="fd12:3456:789a::1", sources=["body"], private=True)])
    enrichment = enrich_iocs(iocs)

    assert (
        _classification_by_value(enrichment)["fd12:3456:789a::1"]
        == "Unique local address / ULA (RFC 4193)"
    )


# --- 10. Known shortener --------------------------------------------------------


def test_known_url_shortener_is_flagged():
    iocs = IOCReport(urls=[URLIndicator(value="http://bit.ly/promo123", sources=["url"])])
    enrichment = enrich_iocs(iocs)

    assert len(enrichment.url) == 1
    assert enrichment.url[0].value == "http://bit.ly/promo123"
    assert enrichment.url[0].known_url_shortener is True


def test_known_url_shortener_is_case_insensitive():
    iocs = IOCReport(urls=[URLIndicator(value="http://BIT.LY/promo123", sources=["url"])])
    enrichment = enrich_iocs(iocs)

    assert len(enrichment.url) == 1
    assert enrichment.url[0].known_url_shortener is True


# --- 11. Unlisted domain --------------------------------------------------------


def test_unlisted_domain_url_is_not_flagged():
    iocs = IOCReport(urls=[URLIndicator(value="http://example.com/page", sources=["url"])])
    enrichment = enrich_iocs(iocs)

    assert enrichment.url == []


# --- 12. Malformed/empty IOCReport ----------------------------------------------


def test_empty_ioc_report_produces_empty_enrichment():
    enrichment = enrich_iocs(IOCReport())

    assert enrichment.ip == []
    assert enrichment.url == []


def test_malformed_ip_value_in_report_is_skipped_not_crashed():
    iocs = IOCReport(ipv4=[IPIndicator(value="not-an-ip", sources=["body"], private=False)])
    enrichment = enrich_iocs(iocs)

    assert enrichment.ip == []


def test_malformed_url_in_report_does_not_crash():
    # Unbalanced IPv6-literal bracket — urlsplit() raises ValueError on this.
    iocs = IOCReport(urls=[URLIndicator(value="http://[::1", sources=["url"])])
    enrichment = enrich_iocs(iocs)

    assert enrichment.url == []


def test_malformed_bytes_end_to_end_does_not_crash():
    response = _upload("garbage.eml", b"\x00\x01not a real email\xffdata")
    assert response.status_code == 200
    data = response.json()

    assert data["enrichment"] == {"ip": [], "url": []}


# --- 13. Duplicate inputs -------------------------------------------------------


def test_duplicate_ip_entries_each_produce_their_own_enrichment_row():
    iocs = IOCReport(
        ipv4=[
            IPIndicator(value="10.0.0.5", sources=["body"], private=True),
            IPIndicator(value="10.0.0.5", sources=["received_chain"], private=True),
        ]
    )
    enrichment = enrich_iocs(iocs)

    assert len(enrichment.ip) == 2
    assert all(entry.value == "10.0.0.5" for entry in enrichment.ip)
    assert all(entry.classification == "RFC 1918 private address space" for entry in enrichment.ip)


# --- 14. Isolation: enrichment failure never breaks iocs/threat_assessment -----


def test_enrichment_failure_falls_back_and_does_not_alter_iocs_or_threat_assessment(
    monkeypatch,
):
    baseline = _upload("sample.eml", SAMPLE_EML_BYTES).json()

    def _boom(_iocs):
        raise RuntimeError("simulated enrichment failure")

    monkeypatch.setattr("app.routes.analyze.enrich_iocs", _boom)

    response = _upload("sample.eml", SAMPLE_EML_BYTES)
    assert response.status_code == 200
    data = response.json()

    assert data["enrichment"] == {"ip": [], "url": []}
    assert data["iocs"] == baseline["iocs"]
    assert data["threat_assessment"] == baseline["threat_assessment"]


def test_enrich_iocs_never_raises_for_a_variety_of_malformed_report_shapes():
    reports = [
        IOCReport(),
        IOCReport(ipv4=[IPIndicator(value="999.999.999.999", sources=[], private=False)]),
        IOCReport(ipv6=[IPIndicator(value="not-ipv6-either", sources=[], private=False)]),
        IOCReport(urls=[URLIndicator(value="", sources=[])]),
        IOCReport(urls=[URLIndicator(value="not a url at all", sources=[])]),
    ]
    for report in reports:
        enrich_iocs(report)  # must not raise
