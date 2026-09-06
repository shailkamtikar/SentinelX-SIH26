from collections import defaultdict
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import analysis_store
from app.services.analysis_store import persist_analysis

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_EML_BYTES = (FIXTURES_DIR / "sample.eml").read_bytes()
FORENSICS_EML_BYTES = (FIXTURES_DIR / "sample_with_forensics.eml").read_bytes()


# --- A tiny fake Supabase client — just enough of the table()/select()/
# insert()/limit()/execute() surface that analysis_store.py actually uses.


class _FakeResult:
    def __init__(self, data):
        self.data = data


class _FakeTable:
    def __init__(self, store: "_FakeSupabaseClient", name: str):
        self._store = store
        self._name = name
        self._pending_insert = None

    def select(self, *_args, **_kwargs):
        return self

    def limit(self, _n):
        return self

    def insert(self, row_or_rows):
        self._pending_insert = row_or_rows
        return self

    def execute(self):
        if self._pending_insert is not None:
            rows = (
                self._pending_insert
                if isinstance(self._pending_insert, list)
                else [self._pending_insert]
            )
            inserted = []
            for row in rows:
                stored = dict(row)
                stored.setdefault("id", f"{self._name}-{len(self._store.tables[self._name]) + 1}")
                self._store.tables[self._name].append(stored)
                inserted.append(stored)
            self._pending_insert = None
            return _FakeResult(inserted)
        return _FakeResult(list(self._store.tables[self._name]))


class _FakeSupabaseClient:
    def __init__(self):
        self.tables: dict[str, list[dict]] = defaultdict(list)

    def table(self, name: str) -> _FakeTable:
        return _FakeTable(self, name)


@pytest.fixture(autouse=True)
def _reset_default_case_cache(monkeypatch):
    # persist_analysis caches the default case id at module level across
    # calls — reset it for every test so tests don't leak state into
    # each other.
    monkeypatch.setattr(analysis_store, "_cached_default_case_id", None)


def _analyze(raw_bytes: bytes, filename: str) -> dict:
    response = client.post(
        "/analyze-email",
        files={"file": (filename, raw_bytes, "message/rfc822")},
    )
    assert response.status_code == 200
    return response.json()


# --- Default case creation -----------------------------------------------


def test_creates_default_case_once_across_multiple_calls():
    fake = _FakeSupabaseClient()
    response_1 = _analyze(SAMPLE_EML_BYTES, "sample.eml")
    response_2 = _analyze(SAMPLE_EML_BYTES, "sample.eml")

    persist_analysis(raw_bytes=SAMPLE_EML_BYTES, filename="a.eml", response=response_1, client=fake)
    persist_analysis(raw_bytes=SAMPLE_EML_BYTES, filename="b.eml", response=response_2, client=fake)

    assert len(fake.tables["cases"]) == 1
    assert fake.tables["cases"][0]["title"] == "Default Prototype Case"
    assert fake.tables["cases"][0]["owner_id"] is None
    assert len(fake.tables["emails"]) == 2
    assert fake.tables["emails"][0]["case_id"] == fake.tables["emails"][1]["case_id"]


# --- Email row field mapping -----------------------------------------------


def test_email_row_maps_header_forensics_and_threat_fields():
    fake = _FakeSupabaseClient()
    response = _analyze(FORENSICS_EML_BYTES, "sample_with_forensics.eml")

    persist_analysis(
        raw_bytes=FORENSICS_EML_BYTES,
        filename="sample_with_forensics.eml",
        response=response,
        client=fake,
    )

    row = fake.tables["emails"][0]
    assert row["original_filename"] == "sample_with_forensics.eml"
    assert row["sender"] == response["sender"]
    assert row["reply_to"] == response["reply_to"]
    assert row["return_path"] == response["return_path"]
    assert row["date_header"] == response["date"]
    assert row["spf_result"] == "fail"
    assert row["dkim_result"] == "pass"
    assert row["dmarc_result"] == "fail"
    assert row["authentication_results_raw"] == response["forensics"]["authentication_results_raw"]
    assert row["routing_flags"] == response["forensics"]["routing_flags"]
    assert row["received_chain"] == response["forensics"]["received_chain"]
    assert row["threat_risk_level"] == "HIGH"
    assert row["threat_reasons"] == response["threat_assessment"]["reasons"]
    assert row["raw_eml_storage_path"] is None
    assert row["parsed_response"] == response


def test_raw_eml_sha256_is_whole_file_hash_not_attachment_hash():
    import hashlib

    fake = _FakeSupabaseClient()
    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")

    persist_analysis(raw_bytes=SAMPLE_EML_BYTES, filename="sample.eml", response=response, client=fake)

    expected = hashlib.sha256(SAMPLE_EML_BYTES).hexdigest()
    row = fake.tables["emails"][0]
    assert row["raw_eml_sha256"] == expected
    # Must not be confused with the (unrelated) attachment SHA-256.
    attachment_sha256 = response["iocs"]["attachment_hashes"][0]["sha256"]
    assert row["raw_eml_sha256"] != attachment_sha256


# --- IOC child rows ----------------------------------------------------------


def test_ip_domain_url_attachment_rows_created_with_enrichment_joined():
    fake = _FakeSupabaseClient()
    response = _analyze(FORENSICS_EML_BYTES, "sample_with_forensics.eml")

    persist_analysis(
        raw_bytes=FORENSICS_EML_BYTES,
        filename="sample_with_forensics.eml",
        response=response,
        client=fake,
    )

    ip_rows = fake.tables["ioc_ips"]
    assert len(ip_rows) == 3
    assert all(row["ip_family"] == 4 for row in ip_rows)
    by_value = {row["value"]: row for row in ip_rows}
    assert by_value["198.51.100.5"]["enrichment_classification"] == "RFC 5737 documentation range (TEST-NET-2)"
    assert by_value["203.0.113.9"]["enrichment_classification"] == "RFC 5737 documentation range (TEST-NET-3)"

    domain_rows = fake.tables["ioc_domains"]
    domain_values = {row["value"] for row in domain_rows}
    assert domain_values == {"example.com", "malicious-example.net", "another-domain.test"}

    # sample_with_forensics.eml has no URLs or attachments.
    assert fake.tables["ioc_urls"] == []
    assert fake.tables["ioc_attachment_hashes"] == []


def test_url_rows_include_structural_and_enrichment_flags():
    fake = _FakeSupabaseClient()
    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")

    persist_analysis(raw_bytes=SAMPLE_EML_BYTES, filename="sample.eml", response=response, client=fake)

    url_rows = {row["value"]: row for row in fake.tables["ioc_urls"]}
    assert "http://example.com/reports/q2" in url_rows
    row = url_rows["http://example.com/reports/q2"]
    assert row["is_ip_literal"] is False
    assert row["has_credential"] is False
    assert row["is_known_shortener"] is False


def test_attachment_hash_row_preserves_non_null_sha256():
    fake = _FakeSupabaseClient()
    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")

    persist_analysis(raw_bytes=SAMPLE_EML_BYTES, filename="sample.eml", response=response, client=fake)

    rows = fake.tables["ioc_attachment_hashes"]
    assert len(rows) == 1
    assert rows[0]["filename"] == "q2-report.csv"
    assert rows[0]["sha256"] == response["iocs"]["attachment_hashes"][0]["sha256"]
    assert rows[0]["sha256"] is not None


def test_attachment_hash_row_preserves_null_when_decode_failed():
    fake = _FakeSupabaseClient()
    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")
    # Simulate a decode failure exactly like eml_parser.py produces: a
    # real filename with sha256 explicitly None — must be persisted as
    # None, never coerced or dropped, and never allowed to "match" another
    # null via any correlation semantics (enforced at the query layer, not
    # here — this test only proves the null survives storage as null).
    response["iocs"]["attachment_hashes"] = [{"filename": "broken.bin", "sha256": None}]

    persist_analysis(raw_bytes=SAMPLE_EML_BYTES, filename="sample.eml", response=response, client=fake)

    rows = fake.tables["ioc_attachment_hashes"]
    assert len(rows) == 1
    assert rows[0]["filename"] == "broken.bin"
    assert rows[0]["sha256"] is None


def test_empty_iocs_insert_no_child_rows():
    fake = _FakeSupabaseClient()
    response = _analyze(FORENSICS_EML_BYTES, "sample_with_forensics.eml")
    response["iocs"] = {
        "ipv4": [],
        "ipv6": [],
        "domains": [],
        "urls": [],
        "attachment_hashes": [],
    }

    persist_analysis(
        raw_bytes=FORENSICS_EML_BYTES,
        filename="sample_with_forensics.eml",
        response=response,
        client=fake,
    )

    assert fake.tables["ioc_ips"] == []
    assert fake.tables["ioc_domains"] == []
    assert fake.tables["ioc_urls"] == []
    assert fake.tables["ioc_attachment_hashes"] == []
    # The email row itself is still persisted even with no IOCs.
    assert len(fake.tables["emails"]) == 1


# --- Configuration / failure behavior ---------------------------------------


def test_persist_analysis_raises_when_supabase_not_configured(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)
    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")

    with pytest.raises(RuntimeError):
        persist_analysis(raw_bytes=SAMPLE_EML_BYTES, filename="sample.eml", response=response)


def test_route_persistence_failure_does_not_change_response(monkeypatch):
    def _boom(**_kwargs):
        raise RuntimeError("simulated Supabase outage")

    monkeypatch.setattr("app.routes.analyze.persist_analysis", _boom)

    response = client.post(
        "/analyze-email",
        files={"file": ("sample.eml", SAMPLE_EML_BYTES, "message/rfc822")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["sender"] == "Alice Analyst <alice@example.com>"
    assert "iocs" in data
    assert "threat_assessment" in data
    assert "enrichment" in data


def test_route_calls_persist_analysis_with_raw_bytes_filename_and_response():
    captured = {}

    def _capture(*, raw_bytes, filename, response):
        captured["raw_bytes"] = raw_bytes
        captured["filename"] = filename
        captured["response"] = response

    import app.routes.analyze as analyze_route

    original = analyze_route.persist_analysis
    analyze_route.persist_analysis = _capture
    try:
        response = client.post(
            "/analyze-email",
            files={"file": ("sample.eml", SAMPLE_EML_BYTES, "message/rfc822")},
        )
    finally:
        analyze_route.persist_analysis = original

    assert response.status_code == 200
    assert captured["raw_bytes"] == SAMPLE_EML_BYTES
    assert captured["filename"] == "sample.eml"
    assert captured["response"] == response.json()
