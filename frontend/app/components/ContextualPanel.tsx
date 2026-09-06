import type { SVGProps } from "react";

type PanelItem = {
  title: string;
  status: "PENDING" | "LOCKED";
  note: string;
};

const ITEMS: PanelItem[] = [
  {
    title: "Chain of Custody",
    status: "LOCKED",
    note: "Available once INGEST is finalized and ANALYZE is connected.",
  },
  {
    title: "Auth Results — SPF / DKIM / DMARC",
    status: "PENDING",
    note: "Requires the ANALYZE stage to be connected.",
  },
  {
    title: "Threat Indicators",
    status: "PENDING",
    note: "Requires the ENRICH stage to be connected.",
  },
  {
    title: "MITRE ATT&CK Mapping",
    status: "LOCKED",
    note: "Requires the CORRELATE stage to be connected.",
  },
];

export default function ContextualPanel() {
  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-sm border border-border-structural bg-surface-container-alt p-4">
        <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-text-dim">
          Contextual Panel
        </p>
        <h3 className="mt-1 text-sm font-semibold text-text-primary">
          Downstream Analysis
        </h3>
        <p className="mt-1 text-xs leading-5 text-text-dim">
          These panels populate automatically as later pipeline stages are wired to a backend.
          Nothing below reflects real analysis.
        </p>
      </div>

      {ITEMS.map((item) => (
        <div
          key={item.title}
          className="rounded-sm border border-border-structural bg-surface-lowest p-4 opacity-80"
        >
          <div className="flex items-start justify-between gap-2">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-text-secondary">
              {item.title}
            </h4>
            <span className="flex items-center gap-1 shrink-0">
              {item.status === "LOCKED" && <LockIcon className="h-3 w-3 text-neutral" />}
              <span className="font-mono text-[8px] uppercase tracking-widest text-neutral">
                {item.status}
              </span>
            </span>
          </div>
          <p className="mt-2 font-mono text-[10px] leading-4 text-text-dim">{item.note}</p>
        </div>
      ))}
    </div>
  );
}

function LockIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} {...props}>
      <rect x="4.5" y="10.5" width="15" height="9.5" rx="1" />
      <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    </svg>
  );
}
