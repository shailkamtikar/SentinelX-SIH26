import { createClient, type SupabaseClient } from "@supabase/supabase-js";

/**
 * Browser-side Supabase client, authentication only (Milestone 1).
 *
 * Uses the public anon key exclusively — this file must never import or
 * reference the service-role/secret key, which stays backend-only (see
 * backend/app/config.py). The anon key is safe to ship to the browser: it
 * has no elevated privileges and every table it can reach is still subject
 * to Supabase's Row Level Security.
 *
 * No database tables are read or written through this client yet — it
 * exists solely to drive supabase.auth (signup/login/logout/session).
 *
 * The client is created lazily, on first actual use, rather than at module
 * import time: Next.js evaluates client-component modules once during
 * static prerendering, and a missing/unset env var must not break `next
 * build` for the whole app — it should only surface truthfully when a
 * caller actually tries to sign in or sign up in the browser.
 */

/** Pure, synchronous env check — no client construction, no side effects. */
export function isSupabaseConfigured(): boolean {
  return Boolean(process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);
}

let cachedClient: SupabaseClient | null = null;

export function getSupabaseClient(): SupabaseClient {
  if (cachedClient) {
    return cachedClient;
  }

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    throw new Error(
      "Missing NEXT_PUBLIC_SUPABASE_URL or NEXT_PUBLIC_SUPABASE_ANON_KEY. " +
        "Copy frontend/.env.example to frontend/.env.local and fill in your " +
        "Supabase project's URL and anon (public) key.",
    );
  }

  cachedClient = createClient(supabaseUrl, supabaseAnonKey);
  return cachedClient;
}
