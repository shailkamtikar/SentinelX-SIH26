import type { SVGProps } from "react";

type NavStage = {
  code: string;
  label: string;
  status: "ACTIVE" | "QUEUED" | "PENDING" | "LOCKED";
};

const NAV_STAGES: NavStage[] = [
  { code: "01", label: "Ingest", status: "ACTIVE" },
  { code: "02", label: "Analyze", status: "QUEUED" },
  { code: "03", label: "Enrich", status: "PENDING" },
  { code: "04", label: "Correlate", status: "PENDING" },
  { code: "05", label: "Explain", status: "PENDING" },
  { code: "06", label: "Report", status: "LOCKED" },
];

const AGENTS = [
  { name: "Parser Agent", state: "OFFLINE" },
  { name: "Enrichment Agent", state: "OFFLINE" },
  { name: "Correlation Agent", state: "OFFLINE" },
];

function statusColorClass(status: NavStage["status"]) {
  switch (status) {
    case "ACTIVE":
      return "text-cyan";
    case "QUEUED":
      return "text-sky";
    case "LOCKED":
      return "text-neutral";
    default:
      return "text-text-dim";
  }
}

export default function Sidebar() {
  return (
    <aside className="hidden lg:fixed lg:inset-y-0 lg:left-0 lg:z-20 lg:flex lg:w-72 lg:flex-col lg:border-r lg:border-border-structural lg:bg-surface-lowest">
      {/* Branding */}
      <div className="flex h-16 shrink-0 items-center gap-2 border-b border-border-structural px-5">
        <span className="flex h-6 w-6 items-center justify-center rounded-sm border border-cyan/40 text-[10px] font-bold text-cyan">
          X
        </span>
        <div className="leading-tight">
          <p className="text-sm font-bold tracking-tight text-text-primary">
            SENTINEL<span className="text-cyan">X</span>
          </p>
          <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-text-dim">
            DFIR-CORE
          </p>
        </div>
      </div>

      <div className="flex flex-1 flex-col overflow-y-auto">
        {/* System status */}
        <div className="border-b border-border-structural px-5 py-4">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-verified opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-verified" />
            </span>
            <span className="font-mono text-[10px] uppercase tracking-[0.15em] text-text-secondary">
              System Operational
            </span>
          </div>
        </div>

        {/* Active case */}
        <div className="border-b border-border-structural px-5 py-4">
          <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-text-dim">
            Active Case
          </p>
          <p className="mt-2 rounded-sm border border-border-structural bg-surface-container px-2.5 py-2 font-mono text-[11px] text-text-dim">
            NO CASE LOADED
            <span className="mt-1 block text-text-dim/70">
              Case management not yet connected.
            </span>
          </p>
        </div>

        {/* Forensic navigation */}
        <nav className="border-b border-border-structural px-3 py-4">
          <p className="px-2 font-mono text-[9px] uppercase tracking-[0.2em] text-text-dim">
            Investigation Pipeline
          </p>
          <ul className="mt-2 flex flex-col gap-0.5">
            {NAV_STAGES.map((stage) => {
              const isActive = stage.status === "ACTIVE";
              const isLocked = stage.status === "LOCKED";
              return (
                <li key={stage.code}>
                  <div
                    aria-disabled={!isActive}
                    className={`flex items-center justify-between rounded-sm px-2 py-2 ${
                      isActive
                        ? "border border-border-focused bg-surface-container"
                        : "border border-transparent"
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      <span
                        className={`font-mono text-[10px] ${isActive ? "text-cyan" : "text-text-dim"}`}
                      >
                        {stage.code}
                      </span>
                      <span
                        className={`text-xs font-medium ${
                          isActive ? "text-text-primary" : "text-text-dim"
                        }`}
                      >
                        {stage.label}
                      </span>
                    </span>
                    <span className="flex items-center gap-1">
                      {isLocked && <LockIcon className="h-3 w-3 text-neutral" />}
                      <span
                        className={`font-mono text-[8px] uppercase tracking-widest ${statusColorClass(stage.status)}`}
                      >
                        {stage.status}
                      </span>
                    </span>
                  </div>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* Operational / agent status */}
        <div className="border-b border-border-structural px-5 py-4">
          <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-text-dim">
            Agent Status
          </p>
          <ul className="mt-2 flex flex-col gap-1.5">
            {AGENTS.map((agent) => (
              <li
                key={agent.name}
                className="flex items-center justify-between font-mono text-[10px]"
              >
                <span className="text-text-secondary">{agent.name}</span>
                <span className="text-text-dim">{agent.state}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Analyst profile */}
      <div className="flex shrink-0 items-center gap-2 border-t border-border-structural px-5 py-4">
        <span className="flex h-7 w-7 items-center justify-center rounded-sm border border-border-structural bg-surface-container font-mono text-[10px] text-text-dim">
          LA
        </span>
        <div className="leading-tight">
          <p className="text-xs font-medium text-text-secondary">Local Analyst</p>
          <p className="font-mono text-[9px] uppercase tracking-widest text-text-dim">
            Local Session
          </p>
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
