import type { SVGProps } from "react";

type NavStage = {
  code: string;
  label: string;
  status: "ACTIVE" | "QUEUED" | "PENDING" | "LOCKED";
};

const NAV_STAGES: NavStage[] = [
  { code: "01", label: "Ingest", status: "ACTIVE" },
  { code: "02", label: "Analyze", status: "ACTIVE" },
  { code: "03", label: "Enrich", status: "ACTIVE" },
  { code: "04", label: "Correlate", status: "ACTIVE" },
  { code: "05", label: "Explain", status: "ACTIVE" },
  { code: "06", label: "Report", status: "ACTIVE" },
];

const AGENTS = [
  { name: "Parser Agent", state: "OFFLINE" },
  { name: "Enrichment Agent", state: "OFFLINE" },
  { name: "Correlation Agent", state: "OFFLINE" },
];

function statusDotClass(status: NavStage["status"]) {
  switch (status) {
    case "ACTIVE":
      return "bg-cyan";
    case "QUEUED":
      return "bg-sky/70";
    case "LOCKED":
      return "bg-neutral/60";
    default:
      return "bg-text-dim/50";
  }
}

export default function Sidebar() {
  return (
    <aside className="hidden lg:fixed lg:inset-y-0 lg:left-0 lg:z-20 lg:flex lg:w-72 lg:flex-col lg:border-r lg:border-border-structural/60 lg:bg-surface-lowest print:hidden">
      {/* Branding */}
      <div className="flex h-16 shrink-0 items-center gap-2.5 px-6">
        <span className="flex h-7 w-7 items-center justify-center rounded-control bg-cyan/15 text-[11px] font-bold text-cyan">
          X
        </span>
        <div className="leading-tight">
          <p className="text-sm font-semibold tracking-tight text-text-primary">
            SENTINEL<span className="text-cyan">X</span>
          </p>
          <p className="text-[10px] uppercase tracking-[0.18em] text-text-dim">DFIR Core</p>
        </div>
      </div>

      <div className="flex flex-1 flex-col gap-6 overflow-y-auto px-4 pb-4 pt-1">
        {/* System + case context, grouped into one calm card instead of two
            separately bordered strips */}
        <div className="rounded-card bg-surface-container/60 p-4">
          <div className="flex items-center gap-2.5">
            <span className="h-2 w-2 rounded-full bg-verified" />
            <span className="text-[12px] font-medium text-text-secondary">System operational</span>
          </div>
          <div className="mt-3.5 border-t border-border-structural/60 pt-3.5">
            <p className="text-[10px] uppercase tracking-[0.18em] text-text-dim">Active case</p>
            <p className="mt-1.5 text-[12px] text-text-secondary">No case loaded</p>
            <p className="mt-0.5 text-[11px] leading-4 text-text-dim">
              Case management not yet connected.
            </p>
          </div>
        </div>

        {/* Investigation pipeline */}
        <nav>
          <p className="px-2 text-[10px] uppercase tracking-[0.18em] text-text-dim">
            Investigation pipeline
          </p>
          <ul className="mt-2.5 flex flex-col gap-1">
            {NAV_STAGES.map((stage) => {
              const isActive = stage.status === "ACTIVE";
              const isLocked = stage.status === "LOCKED";
              return (
                <li key={stage.code}>
                  <div
                    aria-disabled={!isActive}
                    className={`flex items-center gap-3 rounded-control px-3 py-2.5 ${
                      isActive ? "bg-surface-container" : ""
                    }`}
                  >
                    <span
                      className={`w-5 shrink-0 font-mono text-[11px] ${
                        isActive ? "text-cyan" : "text-text-dim"
                      }`}
                    >
                      {stage.code}
                    </span>
                    <span
                      className={`flex-1 text-[13px] ${
                        isActive ? "font-medium text-text-primary" : "text-text-dim"
                      }`}
                    >
                      {stage.label}
                    </span>
                    <span className="flex shrink-0 items-center gap-1.5">
                      {isLocked && <LockIcon className="h-3 w-3 text-neutral" />}
                      <span className={`h-1.5 w-1.5 rounded-full ${statusDotClass(stage.status)}`} />
                      <span className="text-[10px] uppercase tracking-wider text-text-dim">
                        {stage.status}
                      </span>
                    </span>
                  </div>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* Agent status */}
        <div>
          <p className="px-2 text-[10px] uppercase tracking-[0.18em] text-text-dim">Agent status</p>
          <ul className="mt-2.5 flex flex-col gap-2 px-2">
            {AGENTS.map((agent) => (
              <li key={agent.name} className="flex items-center justify-between gap-3">
                <span className="text-[12px] text-text-secondary">{agent.name}</span>
                <span className="text-[10px] uppercase tracking-wider text-text-dim">
                  {agent.state}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Analyst profile */}
      <div className="flex shrink-0 items-center gap-2.5 border-t border-border-structural/60 px-6 py-4">
        <span className="flex h-8 w-8 items-center justify-center rounded-control bg-surface-container text-[11px] font-medium text-text-secondary">
          LA
        </span>
        <div className="leading-tight">
          <p className="text-[12px] font-medium text-text-secondary">Local Analyst</p>
          <p className="text-[10px] uppercase tracking-wider text-text-dim">Local session</p>
        </div>
      </div>
    </aside>
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
