import type { ReactNode } from "react";

import { computeSharedIOCs, type AnalyzedEmail, type SharedIndicator } from "../lib/correlateIocs";

function SharedIndicatorRow({ indicator }: { indicator: SharedIndicator }) {
  return (
    <li className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-sm border border-border-structural bg-surface-container px-3 py-2 font-mono text-[11px]">
      <span className="mr-2 flex flex-wrap items-center gap-2">
        <span className="rounded-sm border border-cyan/40 px-1.5 py-0.5 font-mono text-[8px] uppercase tracking-widest text-cyan">
          {indicator.type}
        </span>
        <span className="break-all text-text-secondary">{indicator.value}</span>
      </span>
      <span className="font-mono text-[9px] uppercase tracking-wide text-text-dim">
        Observed in {indicator.emailLabels.join(", ")} ({indicator.emailLabels.length} emails)
      </span>
    </li>
  );
}

function CorrelationSection({ children }: { children: ReactNode }) {
  return (
    <div className="print:hidden rounded-sm border border-border-structural bg-surface-lowest">
      {children}
    </div>
  );
}

function CorrelationHeader({ statusLabel }: { statusLabel: string }) {
  return (
    <div className="flex items-center justify-between border-b border-border-structural px-4 py-2.5">
      <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-cyan">
        Stage 04 — Correlate
      </span>
      <span className="font-mono text-[8px] uppercase tracking-widest text-text-dim">
        {statusLabel}
      </span>
    </div>
  );
}

export default function CorrelationPanel({ history }: { history: AnalyzedEmail[] }) {
  if (history.length === 0) {
    return null;
  }

  if (history.length === 1) {
    return (
      <CorrelationSection>
        <CorrelationHeader statusLabel="1 Email Analyzed" />
        <div className="px-4 py-3.5">
          <p className="font-mono text-[11px] text-text-dim">
            Analyze at least 2 emails to identify shared indicators.
          </p>
        </div>
      </CorrelationSection>
    );
  }

  const sharedIndicators = computeSharedIOCs(history);

  return (
    <CorrelationSection>
      <CorrelationHeader statusLabel={`${history.length} Emails Analyzed`} />
      <div className="px-4 py-3.5">
        <p className="font-mono text-[9px] uppercase tracking-widest text-text-dim">
          Shared Indicators ({sharedIndicators.length})
        </p>
        {sharedIndicators.length === 0 ? (
          <p className="mt-1.5 font-mono text-[11px] text-text-dim">
            No shared IOC values were observed across the analyzed emails.
          </p>
        ) : (
          <ul className="mt-1.5 flex flex-col gap-1.5">
            {sharedIndicators.map((indicator) => (
              <SharedIndicatorRow
                key={`${indicator.type}-${indicator.value}`}
                indicator={indicator}
              />
            ))}
          </ul>
        )}
        <p className="mt-3 font-mono text-[9px] uppercase tracking-wide text-text-dim">
          Observation only — indicates the same value appeared in multiple analyzed emails, not a
          confirmed relationship, shared campaign, or malicious infrastructure.
        </p>
      </div>
    </CorrelationSection>
  );
}
