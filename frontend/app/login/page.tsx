"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import { AuthGate } from "../lib/AuthGate";
import { getSupabaseClient } from "../lib/supabaseClient";

type Mode = "login" | "signup";
type FormState = "idle" | "submitting";

export default function LoginPage() {
  const router = useRouter();

  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [formState, setFormState] = useState<FormState>("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);

  const switchMode = (next: Mode) => {
    if (next === mode) return;
    setMode(next);
    setErrorMessage(null);
    setInfoMessage(null);
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setErrorMessage(null);
    setInfoMessage(null);

    const trimmedEmail = email.trim();
    if (!trimmedEmail || !password) {
      setErrorMessage("Email and password are both required.");
      return;
    }

    setFormState("submitting");

    let client;
    try {
      client = getSupabaseClient();
    } catch (clientError) {
      setFormState("idle");
      setErrorMessage(
        clientError instanceof Error
          ? clientError.message
          : "Supabase is not configured.",
      );
      return;
    }

    if (mode === "login") {
      const { error } = await client.auth.signInWithPassword({
        email: trimmedEmail,
        password,
      });

      setFormState("idle");

      if (error) {
        setErrorMessage(error.message);
        return;
      }

      router.push("/");
      return;
    }

    // Sign up. Supabase returns a user but no session when email
    // confirmation is required — that is a truthful "check your inbox"
    // state, not a failure and not an immediately authenticated session.
    const { data, error } = await client.auth.signUp({
      email: trimmedEmail,
      password,
    });

    setFormState("idle");

    if (error) {
      setErrorMessage(error.message);
      return;
    }

    if (data.session) {
      router.push("/");
      return;
    }

    setInfoMessage(
      "Account created. Check your inbox to confirm your email address before logging in.",
    );
    setMode("login");
  };

  return (
    <AuthGate requireSession={false} redirectTo="/">
      <div className="flex min-h-full flex-1 items-center justify-center bg-canvas px-5 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex flex-col items-center gap-2 text-center">
            <span className="flex h-10 w-10 items-center justify-center rounded-control bg-cyan/15 text-[13px] font-bold text-cyan">
              X
            </span>
            <p className="text-[15px] font-semibold tracking-tight text-text-primary">
              SENTINEL<span className="text-cyan">X</span>
            </p>
            <p className="text-[11px] uppercase tracking-[0.18em] text-text-dim">DFIR Core</p>
          </div>

          <div className="rounded-panel border border-border-structural/60 bg-surface-lowest p-6 sm:p-7">
            <div className="mb-6 grid grid-cols-2 gap-1 rounded-control bg-surface-container/60 p-1">
              <button
                type="button"
                onClick={() => switchMode("login")}
                aria-pressed={mode === "login"}
                className={`rounded-control py-2 text-[12px] font-medium uppercase tracking-wider transition-colors ${
                  mode === "login"
                    ? "bg-cyan/15 text-cyan"
                    : "text-text-dim hover:text-text-secondary"
                }`}
              >
                Log In
              </button>
              <button
                type="button"
                onClick={() => switchMode("signup")}
                aria-pressed={mode === "signup"}
                className={`rounded-control py-2 text-[12px] font-medium uppercase tracking-wider transition-colors ${
                  mode === "signup"
                    ? "bg-cyan/15 text-cyan"
                    : "text-text-dim hover:text-text-secondary"
                }`}
              >
                Sign Up
              </button>
            </div>

            <h1 className="text-[17px] font-semibold tracking-tight text-text-primary">
              {mode === "login" ? "Log in to your account" : "Create an account"}
            </h1>
            <p className="mt-1.5 text-[12px] leading-5 text-text-dim">
              {mode === "login"
                ? "Access the SentinelX forensic console."
                : "Email and password authentication only — no other sign-up method is enabled."}
            </p>

            <form className="mt-6 flex flex-col gap-4" onSubmit={handleSubmit} noValidate>
              <label className="flex flex-col gap-1.5">
                <span className="text-[10px] uppercase tracking-[0.16em] text-text-dim">Email</span>
                <input
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  className="rounded-control border border-border-structural bg-surface-container/60 px-3.5 py-2.5 text-[13px] text-text-primary placeholder:text-text-dim focus:border-border-focused focus:outline-none"
                  placeholder="you@example.com"
                />
              </label>

              <label className="flex flex-col gap-1.5">
                <span className="text-[10px] uppercase tracking-[0.16em] text-text-dim">
                  Password
                </span>
                <input
                  type="password"
                  autoComplete={mode === "login" ? "current-password" : "new-password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  className="rounded-control border border-border-structural bg-surface-container/60 px-3.5 py-2.5 text-[13px] text-text-primary placeholder:text-text-dim focus:border-border-focused focus:outline-none"
                  placeholder="••••••••"
                />
              </label>

              {errorMessage && (
                <p
                  className="rounded-control border border-critical/40 bg-critical/10 px-3.5 py-2.5 font-mono text-[12px] leading-5 text-critical"
                  role="alert"
                >
                  {errorMessage}
                </p>
              )}

              {infoMessage && (
                <p className="rounded-control border border-verified/30 bg-verified/5 px-3.5 py-2.5 text-[12px] leading-5 text-verified">
                  {infoMessage}
                </p>
              )}

              <button
                type="submit"
                disabled={formState === "submitting"}
                className="mt-2 flex w-full items-center justify-center rounded-control bg-cyan px-4 py-3 text-[13px] font-semibold uppercase tracking-[0.12em] text-canvas-deep transition-colors hover:bg-cyan-light disabled:cursor-not-allowed disabled:bg-surface-high disabled:text-text-dim"
              >
                {formState === "submitting"
                  ? mode === "login"
                    ? "Logging in…"
                    : "Creating account…"
                  : mode === "login"
                    ? "Log In"
                    : "Sign Up"}
              </button>
            </form>

            <p className="mt-5 text-center text-[12px] text-text-dim">
              {mode === "login" ? (
                <>
                  Need an account?{" "}
                  <button
                    type="button"
                    onClick={() => switchMode("signup")}
                    className="font-medium text-cyan hover:text-cyan-light"
                  >
                    Sign up
                  </button>
                </>
              ) : (
                <>
                  Already have an account?{" "}
                  <button
                    type="button"
                    onClick={() => switchMode("login")}
                    className="font-medium text-cyan hover:text-cyan-light"
                  >
                    Log in
                  </button>
                </>
              )}
            </p>
          </div>
        </div>
      </div>
    </AuthGate>
  );
}
