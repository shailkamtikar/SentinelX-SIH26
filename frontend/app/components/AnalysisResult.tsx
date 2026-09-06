import type { ReactNode } from "react";

import type {
  AttachmentHashIndicator,
  DomainIndicator,
  IPIndicator,
  ParsedEmail,
  URLIndicator,
} from "../lib/analyzeEmail";

function Field({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="font-mono text-[9px] uppercase tracking-widest text-text-dim">{label}</dt>
      <dd className="break-words font-mono text-[11px] text-text-secondary">{value ?? "—"}</dd>
    </div>
  );
}

function EvidenceRow({ text }: { text: string }) {
  return (
    <li className="break-all rounded-sm border border-border-structural bg-surface-container px-3 py-1.5 font-mono text-[11px] text-text-secondary">
      {text}
    </li>
  );
}

function SourceTag({ sources }: { sources: string[] }) {
  if (sources.length === 0) return null;
  return (
    <span className="ml-2 shrink-0 font-mono text-[9px] uppercase tracking-wide text-text-dim">
      {sources.join(", ")}
    </span>
  );
}

// Structural facts only, never a maliciousness verdict — same neutral
// visual language as the IP "Private" badge below.
function FlagBadge({ label }: { label: string }) {
  return (
    <span className="rounded-sm border border-neutral/40 px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-widest text-neutral">
      {label}
    </span>
  );
}

function IPIndicatorRow({ entry }: { entry: IPIndicator }) {
  return (
    <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-sm border border-border-structural bg-surface-container px-3 py-2 font-mono text-[11px]">
      <span className="mr-2 flex items-center gap-2 text-text-secondary">
        <span>{entry.value}</span>
        {entry.private && (
          <span className="rounded-sm border border-neutral/40 px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-widest text-neutral">
            Private
          </span>
        )}
      </span>
      <SourceTag sources={entry.sources} />
    </li>
  );
}

function DomainIndicatorRow({ entry }: { entry: DomainIndicator }) {
  return (
    <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-sm border border-border-structural bg-surface-container px-3 py-2 font-mono text-[11px]">
      <span className="mr-2 flex flex-wrap items-center gap-2">
        <span className="break-all text-text-secondary">{entry.value}</span>
        {entry.punycode_domain && <FlagBadge label="Punycode" />}
      </span>
      <SourceTag sources={entry.sources} />
    </li>
  );
}

function URLIndicatorRow({ entry }: { entry: URLIndicator }) {
  return (
    <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-sm border border-border-structural bg-surface-container px-3 py-2 font-mono text-[11px]">
      <span className="mr-2 flex flex-wrap items-center gap-2">
        <span className="break-all text-sky">{entry.value}</span>
        {entry.ip_literal_url && <FlagBadge label="IP literal" />}
        {entry.credential_in_url && <FlagBadge label="Credentials in URL" />}
        {entry.punycode_domain && <FlagBadge label="Punycode" />}
      </span>
      <SourceTag sources={entry.sources} />
    </li>
  );
}

function AttachmentHashRow({ entry }: { entry: AttachmentHashIndicator }) {
  return (
    <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-0.5 rounded-sm border border-border-structural bg-surface-container px-3 py-2 font-mono text-[11px]">
      <span className="text-text-secondary">{entry.filename ?? "(unnamed)"}</span>
      <span className="break-all text-text-dim">{entry.sha256 ?? "Hash unavailable"}</span>
    </li>
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
    <div className="mt-3 first:mt-0">
      <p className="font-mono text-[9px] uppercase tracking-widest text-text-dim">
        {label} ({entries.length})
      </p>
      {entries.length === 0 ? (
        <p className="mt-1.5 font-mono text-[11px] text-text-dim">{emptyText}</p>
      ) : (
        <ul className="mt-1.5 flex flex-col gap-1.5">
          {entries.map((entry, index) => renderRow(entry, index))}
        </ul>
      )}
    </div>
  );
}

export default function AnalysisResult({ result }: { result: ParsedEmail }) {
  return (
    <div className="mt-4 rounded-sm border border-border-structural bg-surface-lowest">
      <div className="flex items-center justify-between border-b border-border-structural px-4 py-2.5">
        <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-verified">
          Parsed Evidence
        </span>
        <span className="font-mono text-[8px] uppercase tracking-widest text-verified">
          Analysis Complete
        </span>
      </div>

      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 px-4 py-4 sm:grid-cols-2">
        <Field label="Sender" value={result.sender} />
        <Field label="Recipient" value={result.recipient} />
        <Field label="Subject" value={result.subject} />
        <Field label="Reply-To" value={result.reply_to} />
        <Field label="Date" value={result.date} />
        <Field label="Message-ID" value={result.message_id} />
        <Field label="Return-Path" value={result.return_path} />
      </dl>

      <div className="border-t border-border-structural px-4 py-3.5">
        <p className="font-mono text-[9px] uppercase tracking-widest text-text-dim">Body</p>
        <pre className="mt-1.5 max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-sm border border-border-structural bg-surface-container px-3 py-2 font-mono text-[11px] leading-5 text-text-secondary">
          {result.body ?? "— No body content found —"}
        </pre>
      </div>

      <div className="border-t border-border-structural px-4 py-3.5">
        <p className="font-mono text-[9px] uppercase tracking-widest text-text-dim">
          Attachments ({result.attachments.length})
        </p>
        {result.attachments.length === 0 ? (
          <p className="mt-1.5 font-mono text-[11px] text-text-dim">No attachments found.</p>
        ) : (
          <ul className="mt-1.5 flex flex-col gap-1.5">
            {result.attachments.map((attachment, index) => (
              <li
                key={`${attachment.filename ?? "unnamed"}-${index}`}
                className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-0.5 rounded-sm border border-border-structural bg-surface-container px-3 py-2 font-mono text-[11px]"
              >
                <span className="text-text-secondary">
                  {attachment.filename ?? "(unnamed)"}
                </span>
                <span className="text-text-dim">
                  {attachment.content_type} · {attachment.size} B
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="border-t border-border-structural px-4 py-3.5">
        <p className="font-mono text-[9px] uppercase tracking-widest text-text-dim">
          URLs ({result.urls.length})
        </p>
        {result.urls.length === 0 ? (
          <p className="mt-1.5 font-mono text-[11px] text-text-dim">No URLs found.</p>
        ) : (
          <ul className="mt-1.5 flex flex-col gap-1">
            {result.urls.map((url) => (
              <li
                key={url}
                className="break-all rounded-sm border border-border-structural bg-surface-container px-3 py-1.5 font-mono text-[11px] text-sky"
              >
                {url}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="border-t border-border-structural px-4 py-3.5">
        <p className="font-mono text-[9px] uppercase tracking-widest text-text-dim">
          Authentication Results
        </p>

        <dl className="mt-2 grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-3">
          <Field
            label="SPF"
            value={result.forensics.spf_result ?? "Not present in analyzed email."}
          />
          <Field
            label="DKIM"
            value={result.forensics.dkim_result ?? "Not present in analyzed email."}
          />
          <Field
            label="DMARC"
            value={result.forensics.dmarc_result ?? "Not present in analyzed email."}
          />
        </dl>

        <p className="mt-3 font-mono text-[9px] uppercase tracking-widest text-text-dim">
          Raw Authentication-Results Header
        </p>
        <pre className="mt-1.5 max-h-32 overflow-auto whitespace-pre-wrap break-words rounded-sm border border-border-structural bg-surface-container px-3 py-2 font-mono text-[11px] leading-5 text-text-secondary">
          {result.forensics.authentication_results_raw ?? "Not present in analyzed email."}
        </pre>

        {result.forensics.authentication_results_raw_all.length > 1 && (
          <details className="mt-2 rounded-sm border border-border-structural bg-surface-container px-3 py-2">
            <summary className="cursor-pointer font-mono text-[10px] uppercase tracking-widest text-text-dim">
              {result.forensics.authentication_results_raw_all.length} Authentication-Results
              headers found — view all
            </summary>
            <ul className="mt-2 flex flex-col gap-1.5">
              {result.forensics.authentication_results_raw_all.map((raw, index) => (
                <EvidenceRow key={index} text={raw} />
              ))}
            </ul>
          </details>
        )}
      </div>

      <div className="border-t border-border-structural px-4 py-3.5">
        <p className="font-mono text-[9px] uppercase tracking-widest text-text-dim">
          Received Chain ({result.forensics.received_chain.length})
        </p>
        {result.forensics.received_chain.length === 0 ? (
          <p className="mt-1.5 font-mono text-[11px] text-text-dim">No Received headers found.</p>
        ) : (
          <ul className="mt-1.5 flex flex-col gap-1.5">
            {result.forensics.received_chain.map((hop, index) => (
              <EvidenceRow key={index} text={hop} />
            ))}
          </ul>
        )}
      </div>

      <div className="border-t border-border-structural px-4 py-3.5">
        <p className="font-mono text-[9px] uppercase tracking-widest text-text-dim">
          Routing Flags ({result.forensics.routing_flags.length})
        </p>
        {result.forensics.routing_flags.length === 0 ? (
          <p className="mt-1.5 font-mono text-[11px] text-text-dim">
            No routing inconsistencies detected.
          </p>
        ) : (
          <ul className="mt-1.5 flex flex-col gap-1.5">
            {result.forensics.routing_flags.map((flag) => (
              <li
                key={flag}
                className="rounded-sm border border-warning/40 bg-warning/10 px-3 py-1.5 font-mono text-[11px] text-warning"
              >
                {flag}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="border-t border-border-structural px-4 py-3.5">
        <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-cyan">
          Indicators of Compromise
        </p>

        <IOCGroup
          label="IPv4"
          entries={result.iocs.ipv4}
          emptyText="No IPv4 indicators found."
          renderRow={(entry) => <IPIndicatorRow key={entry.value} entry={entry} />}
        />

        <IOCGroup
          label="IPv6"
          entries={result.iocs.ipv6}
          emptyText="No IPv6 indicators found."
          renderRow={(entry) => <IPIndicatorRow key={entry.value} entry={entry} />}
        />

        <IOCGroup
          label="Domains"
          entries={result.iocs.domains}
          emptyText="No domain indicators found."
          renderRow={(entry) => <DomainIndicatorRow key={entry.value} entry={entry} />}
        />

        <IOCGroup
          label="URL Indicators"
          entries={result.iocs.urls}
          emptyText="No URL indicators found."
          renderRow={(entry) => <URLIndicatorRow key={entry.value} entry={entry} />}
        />

        <IOCGroup
          label="Attachment SHA-256"
          entries={result.iocs.attachment_hashes}
          emptyText="No attachment hashes found."
          renderRow={(entry, index) => (
            <AttachmentHashRow key={`${entry.filename ?? "unnamed"}-${index}`} entry={entry} />
          )}
        />
      </div>
    </div>
  );
}
