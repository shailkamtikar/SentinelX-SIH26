"use client";

import type { SVGProps } from "react";

import { useAuthSession } from "../lib/AuthSessionProvider";

/** First one or two letters of the email's local part, uppercased — never
 * a fabricated name, and never invented when signed out. */
function initialsFromEmail(email: string): string {
  const localPart = email.split("@")[0] ?? "";
  const letters = localPart.replace(/[^a-zA-Z]/g, "");
  return (letters.slice(0, 2) || email.slice(0, 2)).toUpperCase();
}

export default function Header() {
  const { session } = useAuthSession();
  const avatarLabel = session?.user?.email ? initialsFromEmail(session.user.email) : "—";

  return (
    <header className="sticky top-0 z-10 flex h-16 shrink-0 items-center gap-5 border-b border-border-structural/60 bg-canvas/85 px-5 backdrop-blur-md lg:px-10">
      {/* Investigation context */}
      <div className="flex min-w-0 items-center gap-2.5">
        <span className="text-sm font-semibold tracking-tight text-text-primary lg:hidden">
          SENTINEL<span className="text-cyan">X</span>
        </span>
        <span className="hidden text-[13px] text-text-dim lg:inline">SentinelX</span>
        <ChevronIcon className="hidden h-3 w-3 shrink-0 text-text-dim/60 lg:block" />
        <span className="truncate text-[13px] font-medium text-text-secondary">
          Evidence Ingestion
        </span>
      </div>

      {/* IOC search — present but honestly unavailable until wired to a backend */}
      <div className="hidden flex-1 justify-center md:flex">
        <div className="flex w-full max-w-sm items-center gap-2.5 rounded-control border border-border-structural/70 bg-surface-lowest/60 px-3.5 py-2">
          <SearchIcon className="h-3.5 w-3.5 shrink-0 text-text-dim/70" />
          <input
            type="text"
            disabled
            placeholder="Search indicators — not yet available"
            className="w-full bg-transparent text-[12px] text-text-dim placeholder:text-text-dim/70 focus:outline-none"
          />
        </div>
      </div>

      {/* Session status + analyst */}
      <div className="ml-auto flex shrink-0 items-center gap-4">
        <div className="hidden items-center gap-2 sm:flex">
          <span className="h-1.5 w-1.5 rounded-full bg-verified/80" />
          <span className="text-[12px] text-text-dim">Local session</span>
        </div>
        <span className="flex h-8 w-8 items-center justify-center rounded-control bg-surface-container text-[11px] font-medium text-text-secondary">
          {avatarLabel}
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
