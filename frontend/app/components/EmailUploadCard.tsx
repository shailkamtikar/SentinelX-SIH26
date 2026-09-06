"use client";

import {
  useCallback,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
  type SVGProps,
} from "react";

type Status = "empty" | "selected" | "invalid";

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

export default function EmailUploadCard() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<Status>("empty");
  const [isDragging, setIsDragging] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [analyzeRequested, setAnalyzeRequested] = useState(false);

  const acceptFile = useCallback((candidate: File | undefined) => {
    if (!candidate) return;

    if (!isEmlFile(candidate)) {
      setFile(null);
      setStatus("invalid");
      setErrorMessage(
        `REJECTED: "${candidate.name}" — .eml file required.`,
      );
      setAnalyzeRequested(false);
      return;
    }

    setFile(candidate);
    setStatus("selected");
    setErrorMessage(null);
    setAnalyzeRequested(false);
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
    setAnalyzeRequested(false);
  };

  const handleBrowseClick = () => {
    inputRef.current?.click();
  };

  const handleAnalyzeClick = () => {
    setAnalyzeRequested(true);
  };

  const dropzoneAccent =
    isDragging || status === "selected"
      ? "text-cyan"
      : status === "invalid"
        ? "text-critical"
        : "text-border-structural";

  return (
    <div className="rounded-sm border border-border-structural bg-surface-container">
      {/* Console header */}
      <div className="flex items-center justify-between border-b border-border-structural px-5 py-4">
        <div>
          <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-cyan">
            Stage 01 — Ingest
          </p>
          <h3 className="mt-1 text-base font-semibold text-text-primary">
            New Evidence Ingestion
          </h3>
        </div>
        <span className="rounded-sm border border-cyan/40 px-2 py-1 font-mono text-[9px] uppercase tracking-widest text-cyan">
          Active
        </span>
      </div>

      <div className="p-5 sm:p-6">
        {/* Ingestion drop zone with datum corner markers */}
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
          className={`relative flex cursor-pointer flex-col items-center justify-center gap-3 border border-dashed px-6 py-14 text-center transition-colors ${
            isDragging
              ? "border-cyan bg-surface-high"
              : status === "invalid"
                ? "border-critical/60 bg-surface-low"
                : "border-border-structural bg-surface-low hover:border-border-focused"
          }`}
        >
          <span className={`${dropzoneAccent}`}>
            <span className="datum-corner datum-corner--tl" />
            <span className="datum-corner datum-corner--tr" />
            <span className="datum-corner datum-corner--bl" />
            <span className="datum-corner datum-corner--br" />
          </span>

          <input
            ref={inputRef}
            type="file"
            accept=".eml"
            className="hidden"
            onChange={handleInputChange}
          />

          <UploadIcon className="h-8 w-8 text-text-dim" />

          <div>
            <p className="font-mono text-xs uppercase tracking-wide text-text-primary">
              Drop .eml Evidence File
            </p>
            <p className="mt-1.5 font-mono text-[10px] uppercase tracking-widest text-text-dim">
              Or Click To Browse — .eml Only
            </p>
          </div>
        </div>

        {status === "invalid" && errorMessage && (
          <p
            className="mt-3 rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 font-mono text-[11px] text-critical"
            role="alert"
          >
            {errorMessage}
          </p>
        )}

        {status === "selected" && file && (
          <div className="mt-4 rounded-sm border border-border-structural bg-surface-lowest">
            <div className="flex items-center justify-between border-b border-border-structural px-4 py-2.5">
              <span className="font-mono text-[9px] uppercase tracking-[0.2em] text-text-dim">
                Evidence Metadata
              </span>
              <button
                type="button"
                onClick={handleRemove}
                className="flex items-center gap-1 rounded-sm px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-text-dim transition-colors hover:text-critical"
                aria-label="Remove selected file"
              >
                <CloseIcon className="h-3 w-3" />
                Remove
              </button>
            </div>
            <dl className="grid grid-cols-1 gap-x-6 gap-y-2 px-4 py-3.5 font-mono text-[11px] sm:grid-cols-2">
              <MetaRow label="File Name" value={file.name} truncate />
              <MetaRow label="File Size" value={formatFileSize(file.size)} />
              <MetaRow label="MIME Type" value={file.type || "UNKNOWN"} />
              <MetaRow label="Last Modified" value={formatTimestamp(file.lastModified)} />
              <MetaRow label="SHA-256" value="PENDING — backend not connected" dim />
              <MetaRow label="Ingestion Status" value="STAGED" accent />
            </dl>
          </div>
        )}

        <button
          type="button"
          disabled={status !== "selected"}
          onClick={handleAnalyzeClick}
          className="mt-5 flex w-full items-center justify-center rounded-sm bg-cyan px-4 py-3 font-mono text-xs font-semibold uppercase tracking-widest text-canvas-deep transition-colors hover:bg-cyan-light disabled:cursor-not-allowed disabled:bg-surface-high disabled:text-text-dim"
        >
          Analyze Email
        </button>

        {analyzeRequested && (
          <p className="mt-3 rounded-sm border border-border-structural bg-surface-lowest px-3 py-2 font-mono text-[10px] leading-4 text-text-dim">
            <span className="text-cyan">{"> "}</span>
            Analysis pipeline not connected. This action is wired and awaiting backend
            integration.
          </p>
        )}
      </div>
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
    <div className="flex items-baseline justify-between gap-3 sm:flex-col sm:items-start sm:gap-0.5">
      <dt className="shrink-0 uppercase tracking-widest text-text-dim">{label}</dt>
      <dd
        className={`min-w-0 ${truncate ? "truncate" : ""} ${
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
