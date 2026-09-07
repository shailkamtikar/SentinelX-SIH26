# SentinelX fixture dataset

All fixtures are synthetic. Every domain/IP/identity uses reserved,
documentation-only, or clearly fake values (`.test` TLDs, RFC 5737
TEST-NET IPv4 ranges `198.51.100.0/24`/`203.0.113.0/24`) — nothing here
resolves or belongs to a real organization. No fixture claims a
"confirmed attack" or "known attacker"; risk levels below are exactly
what `app.services.threat_assessment.assess_threat` computes
deterministically from each fixture's headers — nothing is hand-labeled.

## Pre-existing fixtures (unchanged)

| File | Purpose |
|---|---|
| `sample.eml` | Baseline clean parse: attachment, HTML+plain body, one benign URL. |
| `sample_with_forensics.eml` | SPF fail / DKIM pass / DMARC fail plus both routing-mismatch flags — the original forensics/threat-assessment fixture. |

## New fixtures (this milestone)

### Safe — deterministic risk: LOW (0 evidence categories)

| File | Why it's LOW |
|---|---|
| `clean_quarterly_report.eml` | SPF/DKIM/DMARC all pass, Reply-To/Return-Path match the From domain, plain `https://` URL with no credentials/IP-literal/punycode. |
| `routine_hr_notice.eml` | Same clean pattern, no URLs at all. |
| `vendor_invoice.eml` | Ordinary vendor correspondence, all identities consistent, one plain support URL. |

### Suspicious

| File | Deterministic categories triggered | Result | Shared IOCs |
|---|---|---|---|
| `credential_phishing.eml` | Auth failure (SPF+DMARC fail) + structural URL risk (credentials embedded in the URL) | **HIGH** | — |
| `finance_bec.eml` | Auth failure + routing mismatch (Reply-To **and** Return-Path both differ from From) + structural URL risk (IP-literal URL, `203.0.113.77`) | **HIGH** | — |
| `executive_impersonation.eml` | Auth failure + routing mismatch (Return-Path domain differs from the impersonated executive's From domain) | **HIGH** | — |
| `suspicious_attachment.eml` | Auth failure only (SPF fail) | **MEDIUM** | Attachment SHA-256 shared with `repeated_artifact.eml` |
| `repeated_infrastructure_1.eml` | Auth failure + routing mismatch (Reply-To → `malicious-shared.example.test`) | **HIGH** | IPv4 `198.51.100.42` (Received header) and domain `malicious-shared.example.test` shared with `repeated_infrastructure_2.eml` |
| `repeated_infrastructure_2.eml` | Same as above, different pretext/sender | **HIGH** | Same shared IPv4 + domain as `repeated_infrastructure_1.eml` |
| `repeated_artifact.eml` | Auth failure + routing mismatch (same shared domain) | **HIGH** | Domain `malicious-shared.example.test` — the **third** email sharing it (with `repeated_infrastructure_1.eml` and `_2.eml`); attachment SHA-256 shared with `suspicious_attachment.eml` |

`suspicious_attachment.eml` and `repeated_artifact.eml` carry byte-identical
attachment payloads (a short synthetic placeholder, never executable
content) so their SHA-256 hashes match exactly — this is what the
correlation panel is expected to surface as a repeated artifact.

### Intended demo narrative

1. Upload a safe fixture → **LOW**, "No deterministic risk indicators."
2. Upload `finance_bec.eml` → **HIGH**, with all three evidence categories
   populated (SPF/DMARC fail, Reply-To/Return-Path mismatch, IP-literal
   URL) — the clearest single-email "why" story.
3. Upload `repeated_infrastructure_1.eml` then `repeated_infrastructure_2.eml`
   → Correlation shows IPv4 `198.51.100.42` and domain
   `malicious-shared.example.test` observed in 2 emails.
4. Upload `repeated_artifact.eml` → the shared domain now shows **3**
   emails, and the attachment SHA-256 now shows 2 emails (with
   `suspicious_attachment.eml`, uploaded at any point).

A repeated indicator is reported as an **observation** ("observed in N
emails", "investigation lead") — never as a confirmed campaign or a
known-malicious verdict, since no real threat-intelligence source is
implemented here.
