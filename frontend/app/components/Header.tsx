"use client";

import { useEffect, useRef, useState, type SVGProps } from "react";

import { useAuthSession } from "../lib/AuthSessionProvider";

/** First one or two letters of the email's local part, uppercased — never
 * a fabricated name, and never invented when signed out. */
function initialsFromEmail(email: string): string {
  const localPart = email.split("@")[0] ?? "";
  const letters = localPart.replace(/[^a-zA-Z]/g, "");
  return (letters.slice(0, 2) || email.slice(0, 2)).toUpperCase();
}

/**
 * Top-right account control. Reads session state from the existing
 * AuthSessionProvider only — no second auth context, no manual storage,
 * no token handling. The only logout call is the shared signOut(); this
 * component never implements its own sign-out request.
 *
 * A lightweight popover, not a full ARIA menu-authoring-practices widget:
 * with a single actionable item ("Log out") a roving-tabindex menu would
 * add complexity with no real benefit. The trigger and the log-out action
 * are both native <button>s, so focusability and Enter/Space activation
 * come from the browser for free; only the outside-click and Escape
 * dismissal are handled explicitly.
 */
function AccountMenu() {
  const { session, signingOut, signOut } = useAuthSession();
  const [isOpen, setIsOpen] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const email = session?.user?.email ?? null;
  const avatarLabel = email ? initialsFromEmail(email) : "—";

  useEffect(() => {
    if (!isOpen) return;

    const handlePointerDown = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsOpen(false);
      }
    };

    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen]);

  const toggleOpen = () => {
    setLogoutError(null);
    setIsOpen((open) => !open);
  };

  const handleLogout = async () => {
    setLogoutError(null);
    const { error } = await signOut();
    if (error) {
      // Failed: stay open (and on this page) so the error is visible,
      // exactly like the existing Sidebar logout control.
      setLogoutError(error);
      return;
    }
    // Succeeded: AuthSessionProvider itself navigates to /login.
    setIsOpen(false);
  };

  if (!email) {
    // Defensive only — AuthGate normally keeps a signed-out visitor off
    // this page entirely. Never invents an identity if this ever renders
    // while signed out.
    return (
      <div className="flex items-center gap-2.5">
        <span className="flex h-8 w-8 items-center justify-center rounded-control bg-surface-container text-[11px] font-medium text-text-dim">
          —
        </span>
        <span className="hidden text-[12px] text-text-dim sm:inline">Not signed in</span>
      </div>
    );
  }

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={toggleOpen}
        aria-haspopup="menu"
        aria-expanded={isOpen}
        aria-controls="account-menu"
        className="flex items-center gap-2.5 rounded-control border border-transparent px-2 py-1.5 transition-colors hover:border-border-structural hover:bg-surface-container/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan/60"
      >
        <span className="hidden items-center gap-2 sm:flex">
          <span className="h-1.5 w-1.5 rounded-full bg-verified/80" />
          <span className="text-[12px] text-text-dim">Signed in</span>
        </span>
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-control bg-surface-container text-[11px] font-medium text-text-secondary">
          {avatarLabel}
        </span>
      </button>

      {isOpen && (
        <div
          id="account-menu"
          role="menu"
          aria-label="Account"
          className="absolute right-0 top-full z-20 mt-2 w-64 max-w-[calc(100vw-2rem)] rounded-card border border-border-structural/60 bg-surface-lowest p-3 shadow-lg"
        >
          <div className="flex items-center gap-2.5 px-1 pb-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-control bg-surface-container text-[12px] font-medium text-text-secondary">
              {avatarLabel}
            </span>
            <div className="min-w-0 leading-tight">
              <p className="truncate text-[12px] font-medium text-text-primary" title={email}>
                {email}
              </p>
              <p className="mt-0.5 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-text-dim">
                <span className="h-1.5 w-1.5 rounded-full bg-verified/80" />
                Signed in
              </p>
            </div>
          </div>

          <div className="border-t border-border-structural/60 pt-2">
            <button
              type="button"
              role="menuitem"
              onClick={handleLogout}
              disabled={signingOut}
              className="flex w-full items-center justify-center rounded-control px-3 py-2 text-[12px] font-medium text-text-secondary transition-colors hover:bg-critical/10 hover:text-critical focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan/60 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {signingOut ? "Signing out…" : "Log out"}
            </button>
            {logoutError && <p className="mt-2 px-1 text-[11px] text-critical">{logoutError}</p>}
          </div>
        </div>
      )}
    </div>
  );
}

export default function Header() {
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

      {/* Account control */}
      <div className="ml-auto flex shrink-0 items-center">
        <AccountMenu />
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
