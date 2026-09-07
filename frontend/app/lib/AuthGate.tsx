"use client";

import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";

import { useAuthSession } from "./AuthSessionProvider";

/**
 * Gates rendering of `children` on the current Supabase session, redirecting
 * away when the session doesn't match what a route requires.
 *
 * - `requireSession={true}`  (the dashboard, `/`): redirect to /login when
 *   signed out.
 * - `requireSession={false}` (the login page, `/login`): redirect to /
 *   when a session already exists.
 *
 * This is a client-side check only. The current Supabase setup stores the
 * session in browser storage (via @supabase/supabase-js), not cookies, so
 * Next.js middleware/server components have no visibility into it without
 * migrating to a cookie-based session (@supabase/ssr) — a materially
 * larger change than this milestone calls for. The real security boundary
 * for email analysis remains the backend's verified-JWT check
 * (app.services.auth.get_current_user_id); this component is UX routing,
 * not a security control.
 *
 * While the initial session check is pending, or while a redirect is about
 * to fire, `children` is never mounted — only a minimal neutral
 * placeholder is shown — so the dashboard's real content (or the login
 * form) never flashes for the wrong auth state.
 */
export function AuthGate({
  requireSession,
  redirectTo,
  children,
}: {
  requireSession: boolean;
  redirectTo: string;
  children: ReactNode;
}) {
  const router = useRouter();
  const { session, loading } = useAuthSession();

  const hasSession = Boolean(session);
  const shouldRedirect = !loading && hasSession !== requireSession;

  useEffect(() => {
    if (shouldRedirect) {
      router.replace(redirectTo);
    }
  }, [shouldRedirect, redirectTo, router]);

  if (loading || shouldRedirect) {
    return (
      <div className="flex min-h-screen flex-1 items-center justify-center bg-canvas">
        <p className="text-[12px] text-text-dim">Checking session…</p>
      </div>
    );
  }

  return <>{children}</>;
}
