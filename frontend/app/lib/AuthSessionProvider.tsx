"use client";

import type { Session } from "@supabase/supabase-js";
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

import { getSupabaseClient, isSupabaseConfigured } from "./supabaseClient";

type AuthSessionContextValue = {
  /** null while loading, and null (truthfully) when signed out. */
  session: Session | null;
  /** True only until the initial session check resolves. */
  loading: boolean;
  /** True while a signOut() call is in flight. */
  signingOut: boolean;
  /** Resolves with a safe, user-facing error message, or null on success. */
  signOut: () => Promise<{ error: string | null }>;
};

const AuthSessionContext = createContext<AuthSessionContextValue | null>(null);

/**
 * Shares one Supabase auth session across the app (Sidebar, Header, and
 * anything else that needs it) instead of duplicating session-fetching and
 * onAuthStateChange wiring in each component.
 *
 * Deliberately does nothing beyond exposing session state and signOut:
 * no route protection, no redirect on sign-in/out (Milestone 3), no
 * backend calls, no token exposure — access/refresh tokens are never read
 * out of `session` here or passed anywhere.
 */
export function AuthSessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  // Known synchronously and truthfully at first render — no session check
  // will ever run if Supabase isn't configured, so there is nothing to
  // wait for. Avoids a setState call directly inside the effect body below.
  const [loading, setLoading] = useState(() => isSupabaseConfigured());

  const [signingOut, setSigningOut] = useState(false);

  useEffect(() => {
    if (!isSupabaseConfigured()) {
      return;
    }

    const client = getSupabaseClient();
    let isMounted = true;

    client.auth.getSession().then(({ data }) => {
      if (isMounted) {
        setSession(data.session);
        setLoading(false);
      }
    });

    const {
      data: { subscription },
    } = client.auth.onAuthStateChange((_event, nextSession) => {
      if (isMounted) {
        setSession(nextSession);
      }
    });

    return () => {
      isMounted = false;
      subscription.unsubscribe();
    };
  }, []);

  const signOut = async (): Promise<{ error: string | null }> => {
    let client;
    try {
      client = getSupabaseClient();
    } catch {
      return { error: "Authentication is not configured." };
    }

    setSigningOut(true);
    const { error } = await client.auth.signOut();
    setSigningOut(false);

    return { error: error ? error.message : null };
  };

  return (
    <AuthSessionContext.Provider value={{ session, loading, signingOut, signOut }}>
      {children}
    </AuthSessionContext.Provider>
  );
}

export function useAuthSession(): AuthSessionContextValue {
  const context = useContext(AuthSessionContext);
  if (!context) {
    throw new Error("useAuthSession must be used within an AuthSessionProvider");
  }
  return context;
}
