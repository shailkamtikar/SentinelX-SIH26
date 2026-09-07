"use client";

import {
  useCallback,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
  type SVGProps,
} from "react";

import { analyzeEmail, AnalyzeEmailError, type ParsedEmail } from "../lib/analyzeEmail";
import { useAuthSession } from "../lib/AuthSessionProvider";
import AnalysisResult from "./AnalysisResult";

type Status = "empty" | "selected" | "invalid";
type AnalysisState = "idle" | "loading" | "success" | "error";

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatTimestamp(epochMs: number): string {
  return new Date(epochMs).toISOString().replace("T", " ").replace("Z", " UTC");
}

function isEmlFile(file: File): boolean {
  return file.name.toLowerCase().endsWith(".eml");
}

export default function EmailUploadCard({
  onAnalysisComplete,
}: {
  onAnalysisComplete?: (result: ParsedEmail) => void;
}) {
  const { session } = useAuthSession();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<Status>("empty");
  const [isDragging, setIsDragging] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [analysisState, setAnalysisState] = useState<AnalysisState>("idle");
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<ParsedEmail | null>(null);

  const acceptFile = useCallback((candidate: File | undefined) => {
    if (!candidate) return;

    if (!isEmlFile(candidate)) {
      setFile(null);
      setStatus("invalid");
      setErrorMessage(
        `REJECTED: "${candidate.name}" — .eml file required.`,
      );
      setAnalysisState("idle");
      setAnalysisError(null);
      setAnalysisResult(null);
      return;
    }

    setFile(candidate);
    setStatus("selected");
    setErrorMessage(null);
    setAnalysisState("idle");
    setAnalysisError(null);
    setAnalysisResult(null);
  }, []);

  const handleInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    acceptFile(event.target.files?.[0]);
    event.target.value = "";
  };

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    acceptFile(event.dataTransfer.files?.[0]);
  };

  const handleDragOver = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
  };

  const handleRemove = () => {
    setFile(null);
    setStatus("empty");
    setErrorMessage(null);
    setAnalysisState("idle");
    setAnalysisError(null);
    setAnalysisResult(null);
  };

  const handleBrowseClick = () => {
    inputRef.current?.click();
  };

  const handleAnalyzeClick = async () => {
    if (!file || status !== "selected" || analysisState === "loading") return;

    // Fails closed: an unresolved session (still loading) is treated the
    // same as signed-out — analysis is never submitted, and the email is
    // never added to local correlation history, unless a session is
    // actually confirmed present.
    if (!session) {
      setAnalysisError("Sign in required to analyze email evidence.");
      setAnalysisState("error");
      return;
    }

    setAnalysisState("loading");
    setAnalysisError(null);
    setAnalysisResult(null);

    try {
      const result = await analyzeEmail(file, session.access_token);
      setAnalysisResult(result);
      setAnalysisState("success");
      onAnalysisComplete?.(result);
    } catch (error) {
      const message =
        error instanceof AnalyzeEmailError
          ? error.message
          : "Unexpected error while contacting the analysis backend.";
      setAnalysisError(message);
      setAnalysisState("error");
    }
  };

  return (
    <div className="rounded-panel border border-border-structural/60 bg-surface-lowest p-5 sm:p-7 print:rounded-none print:border-0 print:bg-transparent print:p-0">
      {/* Stage header */}
      <div className="print:hidden flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.18em] text-cyan">Stage 01 — Ingest</p>
          <h3 className="mt-2 text-[17px] font-semibold tracking-tight text-text-primary">
            New Evidence Ingestion
          </h3>
        </div>
        <span className="shrink-0 rounded-control bg-cyan/15 px-2.5 py-1 text-[10px] font-medium uppercase tracking-wider text-cyan">
          Active
        </span>
      </div>

      <div className="print:hidden mt-6">
        {/* Ingestion drop zone */}
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={handleBrowseClick}
          role="button"
          tabIndex={0}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              handleBrowseClick();
            }
          }}
          className={`flex cursor-pointer flex-col items-center justify-center gap-4 rounded-card border border-dashed px-6 py-16 text-center transition-colors ${
            isDragging
              ? "border-cyan/70 bg-cyan/5"
              : status === "invalid"
                ? "border-critical/50 bg-critical/5"
                : "border-border-structural bg-surface-container/40 hover:border-border-focused hover:bg-surface-container/70"
          }`}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".eml"
            className="hidden"
            onChange={handleInputChange}
          />

          <span
            className={`flex h-12 w-12 items-center justify-center rounded-card ${
              isDragging || status === "selected"
                ? "bg-cyan/15 text-cyan"
                : "bg-surface-container text-text-dim"
            }`}
          >
            <UploadIcon className="h-6 w-6" />
          </span>

          <div>
            <p className="text-[15px] font-medium text-text-primary">Drop .eml evidence file</p>
            <p className="mt-1.5 text-[12px] text-text-dim">
              or click to browse — .eml files only
            </p>
          </div>
        </div>

        {status === "invalid" && errorMessage && (
          <p
            className="mt-4 rounded-control border border-critical/40 bg-critical/10 px-4 py-3 font-mono text-[12px] text-critical"
            role="alert"
          >
            {errorMessage}
          </p>
        )}

        {status === "selected" && file && (
          <div className="mt-5 rounded-card bg-surface-container p-5">
            <div className="flex items-center justify-between gap-3">
              <span className="text-[10px] uppercase tracking-[0.18em] text-text-dim">
                Evidence metadata
              </span>
              <button
                type="button"
                onClick={handleRemove}
                className="flex items-center gap-1.5 rounded-control px-2 py-1 text-[11px] text-text-dim transition-colors hover:bg-surface-high hover:text-critical"
                aria-label="Remove selected file"
              >
                <CloseIcon className="h-3 w-3" />
                Remove
              </button>
            </div>
            <dl className="mt-4 grid grid-cols-1 gap-x-8 gap-y-4 sm:grid-cols-2">
              <MetaRow label="File name" value={file.name} truncate />
              <MetaRow label="File size" value={formatFileSize(file.size)} />
              <MetaRow label="MIME type" value={file.type || "UNKNOWN"} />
              <MetaRow label="Last modified" value={formatTimestamp(file.lastModified)} />
              <MetaRow label="SHA-256" value="PENDING — not returned by backend" dim />
              <MetaRow
                label="Ingestion status"
                value={analysisState === "success" ? "ANALYZED" : "STAGED"}
                accent
              />
            </dl>
          </div>
        )}

        <button
          type="button"
          disabled={status !== "selected" || analysisState === "loading"}
          onClick={handleAnalyzeClick}
          className="mt-6 flex w-full items-center justify-center rounded-control bg-cyan px-4 py-3.5 text-[13px] font-semibold uppercase tracking-[0.12em] text-canvas-deep transition-colors hover:bg-cyan-light disabled:cursor-not-allowed disabled:bg-surface-high disabled:text-text-dim"
        >
          {analysisState === "loading" ? "Analyzing…" : "Analyze Email"}
        </button>

        {analysisState === "loading" && (
          <p className="mt-4 rounded-control bg-surface-container px-4 py-3 font-mono text-[12px] leading-5 text-text-dim">
            <span className="text-cyan">{"> "}</span>
            Sending evidence to the analysis backend…
          </p>
        )}

        {analysisState === "error" && analysisError && (
          <p
            className="mt-4 rounded-control border border-critical/40 bg-critical/10 px-4 py-3 font-mono text-[12px] text-critical"
            role="alert"
          >
            ANALYSIS FAILED: {analysisError}
          </p>
        )}
      </div>

      {analysisState === "success" && analysisResult && <AnalysisResult result={analysisResult} />}
    </div>
  );
}

function MetaRow({
  label,
  value,
  dim = false,
  accent = false,
  truncate = false,
}: {
  label: string;
  value: string;
  dim?: boolean;
  accent?: boolean;
  truncate?: boolean;
}) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-[10px] uppercase tracking-[0.16em] text-text-dim">{label}</dt>
      <dd
        className={`min-w-0 font-mono text-[12px] ${truncate ? "truncate" : "break-words"} ${
          accent ? "text-cyan" : dim ? "text-text-dim" : "text-text-secondary"
        }`}
      >
        {value}
      </dd>
    </div>
  );
}

function UploadIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} {...props}>
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M12 16.5V4.5m0 0L7 9.5m5-5 5 5M4.5 16.5v2A2.25 2.25 0 0 0 6.75 20.75h10.5A2.25 2.25 0 0 0 19.5 18.5v-2"
      />
    </svg>
  );
}

function CloseIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} {...props}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
    </svg>
  );
}
