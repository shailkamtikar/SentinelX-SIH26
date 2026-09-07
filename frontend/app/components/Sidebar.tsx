"use client";

import Link from "next/link";
import { useState } from "react";

import { useAuthSession } from "../lib/AuthSessionProvider";

const AGENTS = [
  { name: "Parser Agent", state: "OFFLINE" },
  { name: "Enrichment Agent", state: "OFFLINE" },
  { name: "Correlation Agent", state: "OFFLINE" },
];

export default function Sidebar() {
  const { session, loading, signingOut, signOut } = useAuthSession();
  const [logoutError, setLogoutError] = useState<string | null>(null);

  const handleLogout = async () => {
    setLogoutError(null);
    const { error } = await signOut();
    if (error) {
      setLogoutError(error);
    }
  };

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

      {/* Authenticated user / session state — reflects the real Supabase
          session truthfully; no identity is shown or invented when signed
          out. */}
      <div className="flex shrink-0 flex-col gap-2 border-t border-border-structural/60 px-6 py-4">
        {loading ? (
          <p className="text-[12px] text-text-dim">Checking session…</p>
        ) : session?.user?.email ? (
          <>
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0 leading-tight">
                <p className="truncate text-[12px] font-medium text-text-secondary">
                  {session.user.email}
                </p>
                <p className="text-[10px] uppercase tracking-wider text-text-dim">Signed in</p>
              </div>
              <button
                type="button"
                onClick={handleLogout}
                disabled={signingOut}
                className="transition-soft shrink-0 rounded-control border border-border-structural px-2.5 py-1.5 text-[11px] font-medium text-text-secondary transition-colors hover:border-critical/40 hover:text-critical focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan/60 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {signingOut ? "Signing out…" : "Log out"}
              </button>
            </div>
            {logoutError && <p className="text-[11px] text-critical">{logoutError}</p>}
          </>
        ) : (
          <div className="flex items-center justify-between gap-3">
            <p className="text-[12px] text-text-dim">Not signed in</p>
            <Link
              href="/login"
              className="transition-soft shrink-0 text-[11px] font-medium text-cyan transition-colors hover:text-cyan-light focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan/60"
            >
              Log in
            </Link>
          </div>
        )}
      </div>
    </aside>
  );
}
