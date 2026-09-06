"use client";

import { useState, type ReactNode } from "react";

import type {
  AttachmentHashIndicator,
  DomainIndicator,
  IPIndicator,
  ParsedEmail,
  ThreatAssessment,
  URLIndicator,
} from "../lib/analyzeEmail";

// Full literal class strings per key (not fragment-interpolated) so
// Tailwind's static scanner can find them — reuses only existing tokens.
const RISK_LEVEL_STYLES: Record<
  ThreatAssessment["risk_level"],
  { border: string; bg: string; text: string; dot: string }
> = {
  LOW: {
    border: "border-verified/30",
    bg: "bg-verified/5",
    text: "text-verified",
    dot: "bg-verified",
  },
  MEDIUM: {
    border: "border-warning/30",
    bg: "bg-warning/5",
    text: "text-warning",
    dot: "bg-warning",
  },
  HIGH: {
    border: "border-critical/30",
    bg: "bg-critical/5",
    text: "text-critical",
    dot: "bg-critical",
  },
  UNKNOWN: {
    border: "border-neutral/30",
    bg: "bg-neutral/5",
    text: "text-neutral",
    dot: "bg-neutral",
  },
};

/** Standard evidence card. One consistent container treatment everywhere. */
function Section({
  title,
  meta,
  children,
  className = "",
}: {
  title: string;
  meta?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-card border border-border-structural/50 bg-surface-container p-5 sm:p-6 ${className}`}
    >
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h3 className="text-[11px] font-medium uppercase tracking-[0.16em] text-text-dim">
          {title}
        </h3>
        {meta}
      </div>
      <div className="mt-4">{children}</div>
    </section>
  );
}

function CountMeta({ count }: { count: number }) {
  return <span className="text-[11px] text-text-dim">{count}</span>;
}

function Field({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-[10px] uppercase tracking-[0.16em] text-text-dim">{label}</dt>
      <dd className="break-words font-mono text-[12px] leading-5 text-text-secondary">
        {value ?? "—"}
      </dd>
    </div>
  );
}

/** Recessed data well — replaces the previous per-row bordered boxes. */
function EvidenceRow({ text }: { text: string }) {
  return (
    <li className="break-all rounded-control bg-surface-lowest/70 px-3.5 py-2.5 font-mono text-[12px] leading-5 text-text-secondary">
      {text}
    </li>
  );
}

function AuthTile({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="rounded-control bg-surface-lowest/70 px-4 py-3">
      <p className="text-[10px] uppercase tracking-[0.16em] text-text-dim">{label}</p>
      <p
        className={`mt-1.5 font-mono text-[13px] leading-5 ${
          value ? "text-text-secondary" : "text-text-dim"
        }`}
      >
        {value ?? "Not present in analyzed email."}
      </p>
    </div>
  );
}

function SourceTag({ sources }: { sources: string[] }) {
  if (sources.length === 0) return null;
  return (
    <span className="shrink-0 text-[10px] uppercase tracking-wider text-text-dim">
      {sources.join(", ")}
    </span>
  );
}

// Structural facts only, never a maliciousness verdict — same neutral
// visual language as the IP classification badge below.
function FlagBadge({ label }: { label: string }) {
  return (
    <span className="rounded-control bg-surface-high px-2 py-0.5 text-[10px] uppercase tracking-wider text-neutral">
      {label}
    </span>
  );
}

function IndicatorRow({ children }: { children: ReactNode }) {
  return (
    <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-control bg-surface-lowest/70 px-3.5 py-2.5">
      {children}
    </li>
  );
}

function IPIndicatorRow({
  entry,
  classification,
}: {
  entry: IPIndicator;
  classification?: string;
}) {
  return (
    <IndicatorRow>
      <span className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[12px] text-text-secondary">{entry.value}</span>
        {entry.private && (
          <span className="rounded-control bg-surface-high px-2 py-0.5 text-[10px] uppercase tracking-wider text-neutral">
            {/* Falls back to the generic "Private" label when offline
                enrichment is unavailable — the row must still degrade
                gracefully. */}
            {classification ?? "Private"}
          </span>
        )}
      </span>
      <SourceTag sources={entry.sources} />
    </IndicatorRow>
  );
}

function DomainIndicatorRow({ entry }: { entry: DomainIndicator }) {
  return (
    <IndicatorRow>
      <span className="flex flex-wrap items-center gap-2">
        <span className="break-all font-mono text-[12px] text-text-secondary">{entry.value}</span>
        {entry.punycode_domain && <FlagBadge label="Punycode" />}
      </span>
      <SourceTag sources={entry.sources} />
    </IndicatorRow>
  );
}

function URLIndicatorRow({
  entry,
  isKnownShortener,
}: {
  entry: URLIndicator;
  isKnownShortener?: boolean;
}) {
  return (
    <IndicatorRow>
      <span className="flex flex-wrap items-center gap-2">
        <span className="break-all font-mono text-[12px] text-sky">{entry.value}</span>
        {entry.ip_literal_url && <FlagBadge label="IP literal" />}
        {entry.credential_in_url && <FlagBadge label="Credentials in URL" />}
        {entry.punycode_domain && <FlagBadge label="Punycode" />}
        {isKnownShortener && <FlagBadge label="Known URL shortener" />}
      </span>
      <SourceTag sources={entry.sources} />
    </IndicatorRow>
  );
}

function AttachmentHashRow({ entry }: { entry: AttachmentHashIndicator }) {
  return (
    <IndicatorRow>
      <span className="font-mono text-[12px] text-text-secondary">
        {entry.filename ?? "(unnamed)"}
      </span>
      <span className="break-all font-mono text-[11px] text-text-dim">
        {entry.sha256 ?? "Hash unavailable"}
      </span>
    </IndicatorRow>
  );
}

function IOCGroup<T>({
  label,
  entries,
  emptyText,
  renderRow,
}: {
  label: string;
  entries: T[];
  emptyText: string;
  renderRow: (entry: T, index: number) => ReactNode;
}) {
  return (
    <div>
      <div className="flex items-baseline gap-2">
        <h4 className="text-[12px] font-medium text-text-secondary">{label}</h4>
        <span className="text-[11px] text-text-dim">{entries.length}</span>
      </div>
      {entries.length === 0 ? (
        <p className="mt-2 text-[12px] text-text-dim">{emptyText}</p>
      ) : (
        <ul className="mt-2.5 flex flex-col gap-1.5">
          {entries.map((entry, index) => renderRow(entry, index))}
        </ul>
      )}
    </div>
  );
}

function ThreatAssessmentCard({ assessment }: { assessment: ThreatAssessment }) {
  const styles = RISK_LEVEL_STYLES[assessment.risk_level];

  return (
    <section className={`rounded-card border ${styles.border} ${styles.bg} p-5 sm:p-6`}>
      <h3 className="text-[11px] font-medium uppercase tracking-[0.16em] text-text-dim">
        Threat assessment
      </h3>

      <div className="mt-3 flex flex-wrap items-center gap-x-3.5 gap-y-2">
        <span className={`h-2.5 w-2.5 rounded-full ${styles.dot}`} />
        <span className={`text-3xl font-semibold tracking-tight ${styles.text}`}>
          {assessment.risk_level}
        </span>
      </div>

      {assessment.reasons.length === 0 ? (
        <p className="mt-4 text-[13px] leading-6 text-text-dim">
          No risk indicators found in extracted evidence.
        </p>
      ) : (
        <ul className="mt-4 flex flex-col gap-2">
          {assessment.reasons.map((reason, index) => (
            <li
              key={index}
              className="flex items-start gap-2.5 text-[13px] leading-6 text-text-secondary"
            >
              <span className={`mt-2.5 h-1 w-1 shrink-0 rounded-full ${styles.dot}`} />
              {reason}
            </li>
          ))}
        </ul>
      )}

      <p className="mt-5 text-[11px] leading-5 text-text-dim">
        Deterministic, evidence-based assessment — not machine learning or reputation
        intelligence.
      </p>
    </section>
  );
}

export default function AnalysisResult({ result }: { result: ParsedEmail }) {
  // Captured once when this evidence view is rendered — a real,
  // client-generated timestamp, not a server or cryptographic one.
  const [generatedAt] = useState(() => new Date());

  // Offline enrichment is joined back onto the existing IOC rows by value
  // rather than reshaping iocs itself — see ioc_enrichment.py.
  const ipClassificationByValue = new Map(
    result.enrichment.ip.map((entry) => [entry.value, entry.classification]),
  );
  const knownShortenerUrls = new Set(
    result.enrichment.url.filter((entry) => entry.known_url_shortener).map((entry) => entry.value),
  );

  return (
    <div className="print-report mt-7 flex flex-col gap-4 print:mt-0 print:gap-5">
      {/* Print-only letterhead — hidden on screen, shown only in the
          exported/printed Evidence Summary. */}
      <div className="hidden print:block">
        <p className="text-lg font-bold text-text-primary">SentinelX</p>
        <p className="text-sm font-semibold text-text-secondary">Forensic Evidence Summary</p>
        <p className="mt-1.5 font-mono text-[10px] text-text-dim">
          Generated locally in the browser: {generatedAt.toLocaleString()}
        </p>
        <p className="font-mono text-[9px] text-text-dim">
          Deterministic, evidence-based export. Not a cryptographically verified, tamper-evident,
          or chain-of-custody record.
        </p>
      </div>

      {/* Result status */}
      <div className="print:hidden flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className="h-2 w-2 rounded-full bg-verified" />
          <span className="text-[13px] font-medium text-text-primary">Analysis complete</span>
        </div>
        <span className="text-[10px] uppercase tracking-[0.18em] text-text-dim">
          Parsed evidence
        </span>
      </div>

      {/* 1. Investigation overview */}
      <Section title="Investigation overview">
        <dl className="grid grid-cols-1 gap-x-8 gap-y-4 sm:grid-cols-2">
          <Field label="Sender" value={result.sender} />
          <Field label="Recipient" value={result.recipient} />
          <Field label="Subject" value={result.subject} />
          <Field label="Reply-To" value={result.reply_to} />
          <Field label="Date" value={result.date} />
          <Field label="Message-ID" value={result.message_id} />
          <Field label="Return-Path" value={result.return_path} />
        </dl>
      </Section>

      {/* 2. Threat assessment — the focal point */}
      <ThreatAssessmentCard assessment={result.threat_assessment} />

      {/* 3. Authentication evidence */}
      <Section title="Email authentication">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <AuthTile label="SPF" value={result.forensics.spf_result} />
          <AuthTile label="DKIM" value={result.forensics.dkim_result} />
          <AuthTile label="DMARC" value={result.forensics.dmarc_result} />
        </div>

        <p className="mt-5 text-[10px] uppercase tracking-[0.16em] text-text-dim">
          Raw Authentication-Results header
        </p>
        <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap break-words rounded-control bg-surface-lowest/70 px-4 py-3 font-mono text-[12px] leading-5 text-text-secondary">
          {result.forensics.authentication_results_raw ?? "Not present in analyzed email."}
        </pre>

        {result.forensics.authentication_results_raw_all.length > 1 && (
          <details className="mt-3 rounded-control bg-surface-lowest/70 px-4 py-3">
            <summary className="cursor-pointer text-[12px] text-text-dim">
              {result.forensics.authentication_results_raw_all.length} Authentication-Results
              headers found — view all
            </summary>
            <ul className="mt-3 flex flex-col gap-1.5">
              {result.forensics.authentication_results_raw_all.map((raw, index) => (
                <EvidenceRow key={index} text={raw} />
              ))}
            </ul>
          </details>
        )}
      </Section>

      {/* 4. Routing evidence */}
      <Section title="Routing & delivery path">
        <div>
          <div className="flex items-baseline gap-2">
            <h4 className="text-[12px] font-medium text-text-secondary">Received chain</h4>
            <CountMeta count={result.forensics.received_chain.length} />
          </div>
          {result.forensics.received_chain.length === 0 ? (
            <p className="mt-2 text-[12px] text-text-dim">No Received headers found.</p>
          ) : (
            <ul className="mt-2.5 flex flex-col gap-1.5">
              {result.forensics.received_chain.map((hop, index) => (
                <EvidenceRow key={index} text={hop} />
              ))}
            </ul>
          )}
        </div>

        <div className="mt-6">
          <div className="flex items-baseline gap-2">
            <h4 className="text-[12px] font-medium text-text-secondary">Routing flags</h4>
            <CountMeta count={result.forensics.routing_flags.length} />
          </div>
          {result.forensics.routing_flags.length === 0 ? (
            <p className="mt-2 text-[12px] text-text-dim">No routing inconsistencies detected.</p>
          ) : (
            <ul className="mt-2.5 flex flex-col gap-1.5">
              {result.forensics.routing_flags.map((flag) => (
                <li
                  key={flag}
                  className="flex items-center gap-2.5 rounded-control border border-warning/30 bg-warning/5 px-3.5 py-2.5 font-mono text-[12px] text-warning"
                >
                  <span className="h-1 w-1 shrink-0 rounded-full bg-warning" />
                  {flag}
                </li>
              ))}
            </ul>
          )}
        </div>
      </Section>

      {/* 5. Indicators of compromise */}
      <Section title="Indicators of compromise">
        <div className="flex flex-col gap-6">
          <IOCGroup
            label="IPv4 addresses"
            entries={result.iocs.ipv4}
            emptyText="No IPv4 indicators found."
            renderRow={(entry) => (
              <IPIndicatorRow
                key={entry.value}
                entry={entry}
                classification={ipClassificationByValue.get(entry.value)}
              />
            )}
          />

          <IOCGroup
            label="IPv6 addresses"
            entries={result.iocs.ipv6}
            emptyText="No IPv6 indicators found."
            renderRow={(entry) => (
              <IPIndicatorRow
                key={entry.value}
                entry={entry}
                classification={ipClassificationByValue.get(entry.value)}
              />
            )}
          />

          <IOCGroup
            label="Domains"
            entries={result.iocs.domains}
            emptyText="No domain indicators found."
            renderRow={(entry) => <DomainIndicatorRow key={entry.value} entry={entry} />}
          />

          <IOCGroup
            label="URLs"
            entries={result.iocs.urls}
            emptyText="No URL indicators found."
            renderRow={(entry) => (
              <URLIndicatorRow
                key={entry.value}
                entry={entry}
                isKnownShortener={knownShortenerUrls.has(entry.value)}
              />
            )}
          />

          <IOCGroup
            label="Attachment hashes (SHA-256)"
            entries={result.iocs.attachment_hashes}
            emptyText="No attachment hashes found."
            renderRow={(entry, index) => (
              <AttachmentHashRow key={`${entry.filename ?? "unnamed"}-${index}`} entry={entry} />
            )}
          />
        </div>
      </Section>

      {/* 6. Raw message evidence */}
      <Section title="Message content">
        <div>
          <h4 className="text-[12px] font-medium text-text-secondary">Body</h4>
          <pre className="mt-2.5 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-control bg-surface-lowest/70 px-4 py-3 font-mono text-[12px] leading-5 text-text-secondary">
            {result.body ?? "— No body content found —"}
          </pre>
        </div>

        <div className="mt-6">
          <div className="flex items-baseline gap-2">
            <h4 className="text-[12px] font-medium text-text-secondary">Attachments</h4>
            <CountMeta count={result.attachments.length} />
          </div>
          {result.attachments.length === 0 ? (
            <p className="mt-2 text-[12px] text-text-dim">No attachments found.</p>
          ) : (
            <ul className="mt-2.5 flex flex-col gap-1.5">
              {result.attachments.map((attachment, index) => (
                <li
                  key={`${attachment.filename ?? "unnamed"}-${index}`}
                  className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 rounded-control bg-surface-lowest/70 px-3.5 py-2.5"
                >
                  <span className="font-mono text-[12px] text-text-secondary">
                    {attachment.filename ?? "(unnamed)"}
                  </span>
                  <span className="font-mono text-[11px] text-text-dim">
                    {attachment.content_type} · {attachment.size} B
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="mt-6">
          <div className="flex items-baseline gap-2">
            <h4 className="text-[12px] font-medium text-text-secondary">Extracted URLs</h4>
            <CountMeta count={result.urls.length} />
          </div>
          {result.urls.length === 0 ? (
            <p className="mt-2 text-[12px] text-text-dim">No URLs found.</p>
          ) : (
            <ul className="mt-2.5 flex flex-col gap-1.5">
              {result.urls.map((url) => (
                <li
                  key={url}
                  className="break-all rounded-control bg-surface-lowest/70 px-3.5 py-2.5 font-mono text-[12px] leading-5 text-sky"
                >
                  {url}
                </li>
              ))}
            </ul>
          )}
        </div>
      </Section>

      {/* 7. Evidence / report action */}
      <section className="print:hidden rounded-card border border-border-structural/50 bg-surface-container p-5 sm:p-6">
        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-4">
          <div className="min-w-0">
            <h3 className="text-[13px] font-medium text-text-primary">Evidence Summary</h3>
            <p className="mt-1.5 max-w-lg text-[12px] leading-5 text-text-dim">
              Produces a printable forensic summary of this analysis, generated locally in the
              browser. Not a cryptographically verified, tamper-evident, or chain-of-custody
              record.
            </p>
          </div>
          <button
            type="button"
            onClick={() => window.print()}
            className="shrink-0 rounded-control border border-cyan/40 bg-cyan/10 px-5 py-2.5 text-[12px] font-semibold uppercase tracking-[0.12em] text-cyan transition-colors hover:bg-cyan/20"
          >
            Export Evidence Summary
          </button>
        </div>
      </section>
    </div>
  );
}
