# SentinelX — AI-Powered Email Threat Intelligence & Digital Forensics

**AI-powered email threat detection, geolocation, and forensic intelligence platform.**

SentinelX is a cybersecurity project developed for **Smart India Hackathon 2026 (SIH26106)** under the **Blockchain & Cybersecurity** theme. It aims to transform suspicious email analysis into a structured investigation workflow by combining email forensics, machine learning, threat intelligence, infrastructure correlation, and generative AI.

Instead of merely flagging an email as malicious, SentinelX is designed to help investigators understand **why an email is suspicious, which indicators are associated with it, what infrastructure may be involved, and what actions should be taken next.**

> **Team:** Git_Happens
> **Team ID:** EFB71A
> **Problem Statement:** SIH26106 — AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform
> **Institution:** Vishwakarma Institute of Technology, Pune

---

## Table of Contents

* [Overview](#overview)
* [Problem Statement](#problem-statement)
* [Proposed Solution](#proposed-solution)
* [Key Features](#key-features)
* [Technical Workflow](#technical-workflow)
* [Architecture](#architecture)
* [Technology Stack](#technology-stack)
* [Threat Detection Capabilities](#threat-detection-capabilities)
* [Forensic Intelligence](#forensic-intelligence)
* [Use Cases](#use-cases)
* [Security and Responsible Use](#security-and-responsible-use)
* [Future Roadmap](#future-roadmap)
* [Team](#team)

---

## Overview

Email remains one of the most common channels for phishing, business email compromise (BEC), impersonation, credential theft, and social engineering.

Traditional email security tools often focus on classifying messages as spam or malicious. However, investigating sophisticated email threats can require correlating information across message headers, authentication records, sender infrastructure, URLs, domains, IP addresses, and known threat indicators.

**SentinelX proposes a unified forensic intelligence workflow** that combines these signals to support more informed security investigations.

The platform follows a structured pipeline:

**Ingest → Analyze → Enrich → Correlate → Explain → Report**

The goal is to make email investigations more explainable, evidence-driven, and actionable.

---

## Problem Statement

**SIH26106 — AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform**

The challenge focuses on improving the investigation of malicious emails through intelligent threat detection, forensic analysis, infrastructure intelligence, and explainable reporting.

Key challenges include:

* Detecting phishing, impersonation, fraud, and business email compromise.
* Identifying suspicious sender information and email-routing anomalies.
* Validating email authentication mechanisms.
* Extracting and investigating indicators of compromise (IOCs).
* Connecting related email, domain, IP, and URL indicators.
* Estimating the probable origin of suspicious infrastructure.
* Generating investigation reports backed by observable evidence.

SentinelX addresses these challenges through a modular email threat intelligence and forensic analysis approach.

---

## Proposed Solution

SentinelX is designed around eight analytical stages.

### 1. Email Ingestion

Accept and parse email evidence for investigation.

Planned capabilities include:

* Parsing `.eml` files.
* Extracting sender, recipient, subject, timestamps, and message headers.
* Processing message bodies and attachments.
* Preserving original evidence.
* Computing cryptographic hashes to support integrity verification.

### 2. Email Security Forensics

Analyze email metadata and authentication information to identify potential spoofing and routing anomalies.

The analysis focuses on:

* SPF — Sender Policy Framework.
* DKIM — DomainKeys Identified Mail.
* DMARC — Domain-based Message Authentication, Reporting, and Conformance.
* Received-header chains and relay paths.
* Sender-domain inconsistencies.
* Suspicious routing patterns.

Authentication failures are treated as investigative signals rather than automatic proof of malicious activity.

### 3. AI-Powered Threat Detection

Use machine learning and natural language processing to identify suspicious message characteristics.

Target threat categories include:

* Phishing.
* Business email compromise (BEC).
* Sender impersonation.
* Financial fraud.
* Social engineering.
* Suspicious requests for credentials or sensitive information.

The objective is to combine message content with technical evidence instead of relying exclusively on suspicious keywords.

### 4. IOC Extraction and Threat Intelligence

Extract indicators of compromise from email content and related metadata.

Examples include:

* IP addresses.
* Domains and subdomains.
* URLs.
* File hashes.
* Suspicious sender identities.

These indicators can be enriched with relevant intelligence sources, including DNS records, RDAP/WHOIS information, IP reputation, and geolocation databases.

Enrichment results provide additional investigative context for determining whether an indicator warrants further analysis.

### 5. Graph-Based Threat Correlation

Represent relationships between email artifacts and infrastructure to help identify potentially related threats.

The proposed correlation model connects:

`Email ↔ Sender ↔ Domain ↔ IP ↔ URL ↔ Campaign`

This relationship-based approach can help investigators identify recurring infrastructure, shared indicators, and potential links between suspicious messages.

### 6. Infrastructure Geolocation

Analyze available network and domain intelligence to estimate the geographic location associated with suspicious infrastructure.

Potential enrichment signals include:

* IP geolocation.
* Network ownership information.
* Domain registration information.
* DNS resolution data.
* Relationships between infrastructure indicators.

Geolocation results are estimates, not proof of an attacker's physical location or identity. VPNs, proxies, cloud infrastructure, and compromised systems can obscure the actual source.

### 7. Retrieval-Augmented Generation (RAG) and GenAI

Use retrieval-augmented generation to provide investigation context grounded in relevant cybersecurity knowledge and available evidence.

Potential outputs include:

* Explanations of suspicious email indicators.
* Contextual analysis of authentication failures.
* Summaries of related infrastructure.
* Evidence-grounded investigation insights.
* Recommended investigation steps.

Generative AI is intended to assist analysts, not replace evidence verification or human judgment.

### 8. Forensic Report Generation

Consolidate investigation findings into a structured report.

The proposed report includes:

* Overall risk assessment.
* Evidence supporting the assessment.
* Extracted indicators of compromise.
* Email authentication and routing findings.
* Related infrastructure and graph relationships.
* Geolocation context and confidence.
* Recommended defensive actions.

The objective is to make investigation results easier to understand, review, and communicate.

---

## Key Features

| Capability                     | Description                                                                         |
| ------------------------------ | ----------------------------------------------------------------------------------- |
| Email forensics                | Analyze email headers, content, and routing information.                            |
| Authentication analysis        | Examine SPF, DKIM, and DMARC results.                                               |
| ML/NLP threat detection        | Identify suspicious patterns associated with phishing, BEC, and social engineering. |
| IOC extraction                 | Identify IP addresses, domains, URLs, and file hashes.                              |
| Threat intelligence enrichment | Add reputation, DNS, registration, and geolocation context.                         |
| Graph correlation              | Connect related email and infrastructure indicators.                                |
| Infrastructure geolocation     | Estimate the geographic context of network infrastructure.                          |
| RAG-assisted investigation     | Generate context-aware explanations grounded in retrieved information.              |
| Forensic reporting             | Organize findings, evidence, risk assessments, and recommended actions.             |

*Feature availability depends on the current implementation of each module.*

---

## Technical Workflow

A typical investigation is designed to follow this sequence:

```text
              Suspicious Email
                     |
                     v
              Email Ingestion
                     |
                     v
          Header and Content Parsing
                     |
                     v
             Security Forensics
          SPF / DKIM / DMARC / Relay
                     |
                     v
            ML / NLP Threat Analysis
                     |
                     v
               IOC Extraction
                     |
                     v
          Threat Intelligence Enrichment
                     |
                     v
             Graph Correlation
                     |
                     v
          Geolocation and Attribution
                     |
                     v
             RAG / GenAI Analysis
                     |
                     v
             Forensic Report
```

This modular workflow separates evidence collection from analysis and interpretation, making individual components easier to test and improve.

---

## Architecture

SentinelX is organized conceptually into the following layers.

### Input Layer

Responsible for receiving email evidence and extracting relevant artifacts.

**Responsibilities:**

* Email file ingestion.
* Header and body parsing.
* Attachment metadata extraction.
* Evidence preservation and hashing.

### Analysis Layer

Responsible for examining email characteristics and identifying suspicious behavior.

**Responsibilities:**

* Authentication analysis.
* Routing and spoofing investigation.
* ML/NLP-based threat assessment.
* Indicator extraction.

### Intelligence Layer

Responsible for enriching indicators and identifying relationships.

**Responsibilities:**

* DNS and domain intelligence.
* IP reputation and geolocation.
* IOC correlation.
* Relationship and campaign analysis.

### AI Investigation Layer

Responsible for contextualizing evidence and producing analyst-oriented explanations.

**Responsibilities:**

* Retrieval of relevant cybersecurity knowledge.
* Evidence-grounded analysis.
* Investigation summaries.
* Recommended next steps.

### Reporting Layer

Responsible for presenting investigation findings.

**Responsibilities:**

* Risk assessment.
* Evidence summaries.
* IOC listings.
* Related infrastructure.
* Recommended defensive actions.

---

## Technology Stack

The platform's proposed technical approach incorporates the following areas.

| Area                        | Technologies / Concepts                                                |
| --------------------------- | ---------------------------------------------------------------------- |
| Programming and processing  | Python-based email and security analysis                               |
| Machine learning            | ML-based threat classification                                         |
| Natural language processing | Email content and social-engineering analysis                          |
| Email authentication        | SPF, DKIM, DMARC                                                       |
| Threat intelligence         | DNS, RDAP/WHOIS, IP reputation, GeoIP                                  |
| Graph analysis              | Relationship-based IOC correlation                                     |
| Generative AI               | Retrieval-Augmented Generation (RAG)                                   |
| Digital forensics           | Evidence preservation, cryptographic hashing, structured reporting     |
| Security research           | MITRE ATT&CK phishing techniques and relevant email-security standards |

The exact framework, database, model, and deployment choices should be documented as they are confirmed in the repository.

---

## Threat Detection Capabilities

SentinelX focuses on investigation of several email-based threats.

### Phishing

Analyze suspicious links, message content, sender details, and authentication signals to identify potential attempts to obtain credentials or sensitive information.

### Business Email Compromise

Investigate messages involving unusual financial requests, impersonation, changes to payment instructions, or suspicious business communications.

### Email Spoofing

Examine sender identities, authentication results, and routing information for inconsistencies that may indicate spoofing.

### Social Engineering

Analyze message language and context for suspicious requests, urgency, impersonation, and attempts to manipulate recipients.

### Infrastructure-Based Threat Investigation

Connect extracted indicators with available network and domain intelligence to provide additional context for investigating suspicious emails.

---

## Forensic Intelligence

SentinelX emphasizes **evidence-backed investigation rather than unexplained classification**.

A useful investigation should distinguish among:

1. **Observed evidence** — information directly extracted from an email or intelligence source.
2. **Analytical findings** — conclusions derived from authentication results, content analysis, or infrastructure relationships.
3. **AI-generated interpretation** — contextual explanations based on retrieved information and available evidence.
4. **Recommended actions** — suggested steps for validating and responding to a potential threat.

Keeping these categories distinct helps reduce unsupported conclusions and makes findings easier to review.

---

## Use Cases

Potential applications include:

* Security operations center (SOC) investigations.
* Phishing incident triage.
* Business email compromise investigations.
* Email spoofing and authentication analysis.
* Threat intelligence enrichment.
* Infrastructure relationship analysis.
* Digital forensic evidence summarization.
* Security awareness and research.

---

## Security and Responsible Use

SentinelX is intended for defensive cybersecurity research, authorized email investigations, and security analysis.

Important considerations include:

* Preserve original evidence and document transformations.
* Protect sensitive email content, credentials, and personal information.
* Treat threat intelligence results as contextual evidence, not absolute proof.
* Validate AI-generated findings against source evidence.
* Avoid attributing malicious activity to individuals based solely on IP geolocation.
* Use appropriate access controls when storing forensic artifacts.
* Follow applicable privacy requirements and authorization boundaries.

---

## Future Roadmap

Potential areas for further development include:

* Improved phishing and BEC detection models.
* Additional threat intelligence integrations.
* Expanded graph-based campaign correlation.
* Enhanced forensic visualization.
* More comprehensive investigation reports.
* Evaluation against labeled email threat datasets.
* Detection performance benchmarking.
* Analyst feedback and investigation workflow improvements.

These items represent potential future enhancements rather than claims about existing functionality.

---

## Team

**Team Git_Happens**

Developed for Smart India Hackathon 2026.

* **Team ID:** EFB71A
* **Problem Statement ID:** SIH26106
* **Theme:** Blockchain & Cybersecurity
* **Institution:** Vishwakarma Institute of Technology, Pune

---

## Research References

The proposed approach draws on established cybersecurity standards and threat-analysis frameworks.

* [MITRE ATT&CK — Phishing (T1566)](https://attack.mitre.org/techniques/T1566/)
* [MITRE ATT&CK — Phishing for Information (T1598)](https://attack.mitre.org/techniques/T1598/)
* [RFC 7208 — Sender Policy Framework (SPF)](https://www.rfc-editor.org/rfc/rfc7208)
* [RFC 6376 — DomainKeys Identified Mail (DKIM)](https://www.rfc-editor.org/rfc/rfc6376)
* [RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489)

---

## Contributing

Contributions, technical feedback, and suggestions for improving defensive email threat analysis are welcome.

If contributing to the project:

1. Create a feature branch.
2. Keep changes focused and documented.
3. Add tests for new analysis functionality.
4. Avoid committing credentials, private keys, or sensitive email evidence.
5. Document known limitations and assumptions.

---

## Disclaimer

SentinelX is a cybersecurity project intended for research, education, and authorized defensive use. Its findings should be interpreted in context and verified against available evidence. Risk assessments, geolocation results, and AI-generated explanations are not guarantees of malicious activity or definitive attribution.

**SentinelX — From suspicious emails to evidence-driven threat intelligence.**

