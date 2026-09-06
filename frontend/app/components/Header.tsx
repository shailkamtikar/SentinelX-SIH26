import type { SVGProps } from "react";

export default function Header() {
  return (
    <header className="sticky top-0 z-10 flex h-16 shrink-0 items-center gap-4 border-b border-border-structural bg-surface-lowest/95 px-5 backdrop-blur-sm lg:px-8">
      {/* Forensic breadcrumbs */}
      <div className="flex min-w-0 items-center gap-2 font-mono text-[11px] uppercase tracking-[0.15em] text-text-dim">
        <span className="lg:hidden font-bold text-cyan">SENTINELX</span>
        <span className="hidden lg:inline">SentinelX</span>
        <ChevronIcon className="h-3 w-3 shrink-0" />
        <span className="truncate text-text-secondary">Evidence Ingestion</span>
      </div>

      {/* IOC / search affordance */}
      <div className="hidden flex-1 justify-center md:flex">
        <div className="flex w-full max-w-sm items-center gap-2 rounded-sm border border-border-structural bg-surface-container px-3 py-1.5 opacity-60">
          <SearchIcon className="h-3.5 w-3.5 text-text-dim" />
          <input
            type="text"
            disabled
            placeholder="SEARCH IOC — UNAVAILABLE"
            className="w-full bg-transparent font-mono text-[11px] uppercase tracking-wide text-text-dim placeholder:text-text-dim focus:outline-none"
          />
        </div>
      </div>

      {/* Buffer / session status + profile control */}
      <div className="ml-auto flex shrink-0 items-center gap-4">
        <div className="hidden items-center gap-1.5 sm:flex">
          <span className="h-1.5 w-1.5 rounded-full bg-neutral" />
          <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
            Local Session
          </span>
        </div>
        <span className="hidden h-5 w-px bg-border-structural sm:block" />
        <span className="flex h-8 w-8 items-center justify-center rounded-sm border border-border-structural bg-surface-container font-mono text-[10px] text-text-dim">
          LA
        </span>
      </div>
    </header>
  );
}

function ChevronIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} {...props}>
      <path strokeLinecap="round" strokeLinejoin="round" d="m9 6 6 6-6 6" />
    </svg>
  );
}

function SearchIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} {...props}>
      <circle cx="11" cy="11" r="6.5" />
      <path strokeLinecap="round" d="m20 20-3.5-3.5" />
    </svg>
  );
}
