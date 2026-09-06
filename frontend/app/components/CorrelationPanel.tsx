import type { ReactNode } from "react";

import { computeSharedIOCs, type AnalyzedEmail, type SharedIndicator } from "../lib/correlateIocs";

function SharedIndicatorCard({ indicator }: { indicator: SharedIndicator }) {
  return (
    <li className="rounded-card bg-surface-container p-4 sm:p-5">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="rounded-control bg-cyan/15 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-cyan">
          {indicator.type}
        </span>
        <span className="break-all font-mono text-[13px] text-text-primary">
          {indicator.value}
        </span>
      </div>
      <p className="mt-2.5 text-[12px] leading-5 text-text-dim">
        Seen in {indicator.emailLabels.join(", ")} · {indicator.emailLabels.length} emails
      </p>
    </li>
  );
}

function CorrelationSection({
  statusLabel,
  children,
}: {
  statusLabel: string;
  children: ReactNode;
}) {
  return (
    <section className="print:hidden rounded-panel border border-border-structural/60 bg-surface-lowest p-5 sm:p-7">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className="text-[11px] font-medium uppercase tracking-[0.16em] text-text-dim">
          Correlation
        </h2>
        <span className="text-[11px] text-text-dim">{statusLabel}</span>
      </div>
      <div className="mt-4">{children}</div>
    </section>
  );
}

export default function CorrelationPanel({ history }: { history: AnalyzedEmail[] }) {
  if (history.length === 0) {
    return null;
  }

  if (history.length === 1) {
    return (
      <CorrelationSection statusLabel="1 email analyzed">
        <p className="text-[13px] leading-6 text-text-dim">
          Analyze at least 2 emails to identify shared indicators.
        </p>
      </CorrelationSection>
    );
  }

  const sharedIndicators = computeSharedIOCs(history);

  return (
    <CorrelationSection statusLabel={`${history.length} emails analyzed`}>
      {sharedIndicators.length === 0 ? (
        <p className="text-[13px] leading-6 text-text-dim">
          No shared IOC values were observed across the analyzed emails.
        </p>
      ) : (
        <>
          <div className="flex items-baseline gap-2">
            <h3 className="text-[14px] font-semibold tracking-tight text-text-primary">
              Shared indicators detected
            </h3>
            <span className="text-[11px] text-text-dim">{sharedIndicators.length}</span>
          </div>
          <ul className="mt-3.5 flex flex-col gap-2.5">
            {sharedIndicators.map((indicator) => (
              <SharedIndicatorCard
                key={`${indicator.type}-${indicator.value}`}
                indicator={indicator}
              />
            ))}
          </ul>
        </>
      )}

      <p className="mt-5 text-[11px] leading-5 text-text-dim">
        Observation only — indicates the same value appeared in multiple analyzed emails, not a
        confirmed relationship, shared campaign, or malicious infrastructure.
      </p>
    </CorrelationSection>
  );
}
