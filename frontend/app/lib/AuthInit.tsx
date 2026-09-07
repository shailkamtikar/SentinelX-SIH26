"use client";

import { useEffect } from "react";

import { getSupabaseClient } from "./supabaseClient";

/**
 * Constructs the Supabase browser client once, on initial app load.
 *
 * Renders no UI. Supabase Auth JS's GoTrueClient automatically detects and
 * consumes an authentication URL fragment
 * (#access_token=...&refresh_token=...) — left by an email-confirmation or
 * magic-link redirect — and establishes the browser session from it, but
 * only at the moment a client is actually constructed on the page. Outside
 * of this, getSupabaseClient() is only ever called lazily from the login
 * page's submit handler, so a confirmation redirect landing anywhere else
 * (e.g. the dashboard) left that fragment sitting unprocessed in the
 * address bar. Mounting this once at the root layout ensures a client
 * always exists on load, letting Supabase's own URL/session handling run —
 * nothing here parses tokens or touches window.location itself.
 *
 * Supabase configuration is optional at this milestone (see
 * supabaseClient.ts) — a missing/unset env var must not disrupt the
 * dashboard, so construction failures are swallowed rather than thrown.
 */
export default function AuthInit() {
  useEffect(() => {
    try {
      getSupabaseClient();
    } catch {
      // Supabase not configured yet — auth is optional at this milestone.
    }
  }, []);

  return null;
}
