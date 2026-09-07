import type { AnalyzedEmail, SharedIndicator } from "../lib/correlateIocs";

type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";

function uniqueValues(history: AnalyzedEmail[], pick: (email: AnalyzedEmail) => string[]): number {
  const values = new Set<string>();
  for (const email of history) {
    for (const value of pick(email)) {
      values.add(value);
    }
  }
  return values.size;
}

function countByRisk(history: AnalyzedEmail[]): Record<RiskLevel, number> {
  const counts: Record<RiskLevel, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, UNKNOWN: 0 };
  for (const email of history) {
    const level = email.result.threat_assessment?.risk_level ?? "UNKNOWN";
    counts[level] = (counts[level] ?? 0) + 1;
  }
  return counts;
}

/** Deterministic "what happened" narrative — no Gemini, no invented values. */
function buildNarrative(history: AnalyzedEmail[], sharedIndicators: SharedIndicator[]): string {
  const counts = countByRisk(history);
  const riskParts: string[] = [];
  if (counts.HIGH > 0) riskParts.push(`${counts.HIGH} high risk`);
  if (counts.MEDIUM > 0) riskParts.push(`${counts.MEDIUM} medium risk`);
  if (counts.LOW > 0) riskParts.push(`${counts.LOW} low risk`);
  if (counts.UNKNOWN > 0) riskParts.push(`${counts.UNKNOWN} unassessed`);

  const emailWord = history.length === 1 ? "email" : "emails";
  let sentence = `${history.length} ${emailWord} analyzed.`;
  if (riskParts.length > 0) {
    sentence += ` ${riskParts.join(", ")}.`;
  }

  const authFailureCount = history.filter((email) =>
    (email.result.threat_assessment?.reasons ?? []).some(
      (reason) => reason.startsWith("SPF result: fail") || reason.startsWith("DMARC result: fail"),
    ),
  ).length;
  if (authFailureCount > 0) {
    sentence += ` Authentication failures were observed in ${authFailureCount} of the analyzed ${
      authFailureCount === 1 ? "message" : "messages"
    }.`;
  }

  const infrastructureIndicators = sharedIndicators.filter(
    (indicator) => indicator.type === "IPv4" || indicator.type === "IPv6" || indicator.type === "Domain",
  );
  const attachmentIndicators = sharedIndicators.filter(
    (indicator) => indicator.type === "Attachment SHA-256",
  );

  for (const indicator of infrastructureIndicators.slice(0, 2)) {
    sentence += ` ${indicator.value} appeared across ${indicator.emailLabels.length} emails.`;
  }
  if (attachmentIndicators.length > 0) {
    const top = attachmentIndicators[0];
    sentence += ` The same attachment artifact appeared in ${top.emailLabels.length} emails.`;
  }

  return sentence;
}

const WHY_THIS_MATTERS = [
  "Authentication failures weaken confidence in the claimed sender identity.",
  "Repeated infrastructure across multiple analyzed emails is an investigation lead.",
  "Suspicious URL structures (embedded credentials, IP-literal hosts, punycode) warrant inspection.",
  "Repeated attachment hashes may indicate reuse of the same artifact across messages.",
];

const RECOMMENDED_ACTIONS = [
  "Inspect any repeated infrastructure (IPs, domains, URLs) for a common source.",
  "Compare timestamps across related messages for a delivery pattern.",
  "Validate sender identity through a known-good, independent channel.",
  "Review shared attachments for reuse across multiple messages.",
  "Independently verify suspicious URLs before visiting them.",
  "Confirm external reputation through your own tooling before blocking any infrastructure.",
];

function SummaryStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col gap-1">
      <p className="text-[10px] uppercase tracking-[0.16em] text-text-dim">{label}</p>
      <p className="font-mono text-[20px] font-semibold text-text-primary">{value}</p>
    </div>
  );
}

export default function InvestigationSummary({
  history,
  sharedIndicators,
}: {
  history: AnalyzedEmail[];
  sharedIndicators: SharedIndicator[];
}) {
  return (
    <section className="print-report print:break-inside-avoid rounded-panel border border-border-structural/60 bg-surface-lowest p-5 sm:p-7">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className="text-[11px] font-medium uppercase tracking-[0.16em] text-text-dim">
          Investigation summary
        </h2>
        <span className="text-[11px] text-text-dim">
          {history.length === 0 ? "No evidence yet" : `${history.length} emails analyzed`}
        </span>
      </div>

      {history.length === 0 ? (
        <p className="mt-4 text-[13px] leading-6 text-text-dim">
          No persisted investigation evidence yet.
        </p>
      ) : (
        <>
          {(() => {
            const counts = countByRisk(history);
            const uniqueIpv4 = uniqueValues(history, (e) => (e.result.iocs?.ipv4 ?? []).map((i) => i.value));
            const uniqueIpv6 = uniqueValues(history, (e) => (e.result.iocs?.ipv6 ?? []).map((i) => i.value));
            const uniqueDomains = uniqueValues(history, (e) =>
              (e.result.iocs?.domains ?? []).map((d) => d.value),
            );
            const uniqueUrls = uniqueValues(history, (e) => (e.result.iocs?.urls ?? []).map((u) => u.value));
            const uniqueAttachmentHashes = uniqueValues(history, (e) =>
              (e.result.iocs?.attachment_hashes ?? [])
                .map((a) => a.sha256)
                .filter((sha256): sha256 is string => sha256 !== null),
            );

            return (
              <div className="mt-4 grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3 lg:grid-cols-5">
                <SummaryStat label="Emails analyzed" value={history.length} />
                <SummaryStat label="Low risk" value={counts.LOW} />
                <SummaryStat label="Medium risk" value={counts.MEDIUM} />
                <SummaryStat label="High risk" value={counts.HIGH} />
                <SummaryStat label="Repeated indicators" value={sharedIndicators.length} />
                <SummaryStat label="Unique IPv4" value={uniqueIpv4} />
                <SummaryStat label="Unique IPv6" value={uniqueIpv6} />
                <SummaryStat label="Unique domains" value={uniqueDomains} />
                <SummaryStat label="Unique URLs" value={uniqueUrls} />
                <SummaryStat label="Unique attachment hashes" value={uniqueAttachmentHashes} />
              </div>
            );
          })()}

          {(() => {
            const timestamps = history
              .map((email) => email.analyzedAt)
              .filter((value): value is string => Boolean(value))
              .sort();
            if (timestamps.length === 0) return null;
            const first = timestamps[0];
            const latest = timestamps[timestamps.length - 1];
            return (
              <div className="mt-4 flex flex-wrap gap-x-8 gap-y-2 border-t border-border-structural/50 pt-4">
                <div className="flex flex-col gap-1">
                  <p className="text-[10px] uppercase tracking-[0.16em] text-text-dim">
                    First analyzed
                  </p>
                  <p className="font-mono text-[12px] text-text-secondary">{first}</p>
                </div>
                <div className="flex flex-col gap-1">
                  <p className="text-[10px] uppercase tracking-[0.16em] text-text-dim">
                    Latest analyzed
                  </p>
                  <p className="font-mono text-[12px] text-text-secondary">{latest}</p>
                </div>
              </div>
            );
          })()}

          <div className="mt-6 border-t border-border-structural/50 pt-5">
            <h3 className="text-[12px] font-medium text-text-secondary">What happened?</h3>
            <p className="mt-2 text-[13px] leading-6 text-text-secondary">
              {buildNarrative(history, sharedIndicators)}
            </p>
          </div>

          <div className="mt-5">
            <h3 className="text-[12px] font-medium text-text-secondary">Why this matters</h3>
            <ul className="mt-2.5 flex flex-col gap-1.5">
              {WHY_THIS_MATTERS.map((item) => (
                <li key={item} className="flex items-start gap-2.5 text-[12px] leading-6 text-text-dim">
                  <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-text-dim" />
                  {item}
                </li>
              ))}
            </ul>
          </div>

          <div className="mt-5">
            <h3 className="text-[12px] font-medium text-text-secondary">Recommended analyst actions</h3>
            <ul className="mt-2.5 flex flex-col gap-1.5">
              {RECOMMENDED_ACTIONS.map((item) => (
                <li key={item} className="flex items-start gap-2.5 text-[12px] leading-6 text-text-dim">
                  <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-cyan/70" />
                  {item}
                </li>
              ))}
            </ul>
          </div>

          <p className="mt-5 text-[11px] leading-5 text-text-dim">
            Deterministic summary computed from already-analyzed evidence — not machine learning,
            not live threat intelligence, and not a verdict beyond what each email&apos;s own
            deterministic assessment already states.
          </p>
        </>
      )}
    </section>
  );
}
