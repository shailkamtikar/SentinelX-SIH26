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
    // The local Evidence Summary export exists, but tamper-evident custody
    // logging does not — keep this note accurate about what is missing.
    note: "Custody logging is not yet implemented.",
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
      <div className="rounded-card border border-border-structural/60 bg-surface-lowest p-5">
        <p className="text-[10px] uppercase tracking-[0.18em] text-text-dim">Contextual panel</p>
        <h3 className="mt-2 text-[15px] font-semibold tracking-tight text-text-primary">
          Downstream analysis
        </h3>
        <p className="mt-2 text-[12px] leading-5 text-text-dim">
          These panels populate automatically as later pipeline stages are wired to a backend.
          Nothing below reflects real analysis.
        </p>
      </div>

      {ITEMS.map((item) => (
        <div
          key={item.title}
          className="rounded-card border border-border-structural/50 bg-surface-lowest/60 p-5"
        >
          <div className="flex items-start justify-between gap-3">
            <h4 className="text-[13px] font-medium text-text-secondary">{item.title}</h4>
            <span className="flex shrink-0 items-center gap-1.5 text-[10px] uppercase tracking-wider text-neutral">
              {item.status === "LOCKED" && <LockIcon className="h-3 w-3" />}
              {item.status}
            </span>
          </div>
          <p className="mt-2.5 text-[12px] leading-5 text-text-dim">{item.note}</p>
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
