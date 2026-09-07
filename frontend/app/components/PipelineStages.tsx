/**
 * Truthful, state-driven pipeline visualization. INGEST → ANALYZE → ENRICH →
 * CORRELATE → EXPLAIN → REPORT are SentinelX's real stages, but the backend
 * currently runs parsing, forensics, IOC extraction, threat assessment,
 * enrichment, and the Gemini explanation inside ONE HTTP request
 * (POST /analyze-email) — there is no streaming, polling, or per-stage
 * signal to observe. So ANALYZE is the single stage shown as actively
 * processing for the duration of that request; ENRICH and EXPLAIN are
 * shown as "included" in that same request rather than lit up on a
 * fabricated timer. CORRELATE only reflects a real condition (2+ analyzed
 * emails in session/persisted history) and REPORT only reflects whether a
 * result actually exists to export — see the "correlated"/"analyzed" cases
 * in deriveStatuses below.
 */
export type PipelineStage = "idle" | "ingest-staged" | "analyzing" | "analyzed" | "correlated";

type StageId = "ingest" | "analyze" | "enrich" | "correlate" | "explain" | "report";
type StageVisual = "pending" | "active" | "included" | "completed" | "available";

const STAGE_DEFS: { id: StageId; code: string; label: string }[] = [
  { id: "ingest", code: "01", label: "Ingest" },
  { id: "analyze", code: "02", label: "Analyze" },
  { id: "enrich", code: "03", label: "Enrich" },
  { id: "correlate", code: "04", label: "Correlate" },
  { id: "explain", code: "05", label: "Explain" },
  { id: "report", code: "06", label: "Report" },
];

const STATUS_TEXT: Record<StageId, Partial<Record<StageVisual, string>>> = {
  ingest: { pending: "Pending", active: "Staged", completed: "Complete" },
  analyze: { pending: "Pending", active: "Processing", completed: "Complete" },
  enrich: { pending: "Pending", included: "Included", completed: "Complete" },
  correlate: { pending: "Pending", completed: "Observed" },
  explain: { pending: "Pending", included: "Included", completed: "Complete" },
  report: { pending: "Pending", available: "Available" },
};

const ALL_PENDING: Record<StageId, StageVisual> = {
  ingest: "pending",
  analyze: "pending",
  enrich: "pending",
  correlate: "pending",
  explain: "pending",
  report: "pending",
};

function deriveStatuses(stage: PipelineStage): Record<StageId, StageVisual> {
  switch (stage) {
    case "idle":
      return ALL_PENDING;
    case "ingest-staged":
      return { ...ALL_PENDING, ingest: "active" };
    case "analyzing":
      return {
        ingest: "completed",
        analyze: "active",
        enrich: "included",
        correlate: "pending",
        explain: "included",
        report: "pending",
      };
    case "analyzed":
      return {
        ingest: "completed",
        analyze: "completed",
        enrich: "completed",
        correlate: "pending",
        explain: "completed",
        report: "available",
      };
    case "correlated":
      return {
        ingest: "completed",
        analyze: "completed",
        enrich: "completed",
        correlate: "completed",
        explain: "completed",
        report: "available",
      };
  }
}

function stageClasses(visual: StageVisual) {
  switch (visual) {
    case "active":
      return { marker: "bg-cyan/15 text-cyan", label: "text-text-primary", dot: "bg-cyan" };
    case "included":
      return { marker: "bg-cyan/8 text-cyan/70", label: "text-text-dim", dot: "bg-cyan/40" };
    case "completed":
      return { marker: "bg-verified/10 text-verified", label: "text-text-secondary", dot: "bg-verified/70" };
    case "available":
      return { marker: "bg-surface-container text-cyan-light", label: "text-text-secondary", dot: "bg-cyan/50" };
    default:
      return { marker: "bg-surface-container text-text-dim", label: "text-text-dim", dot: "bg-text-dim/40" };
  }
}

export default function PipelineStages({ stage }: { stage: PipelineStage }) {
  const statuses = deriveStatuses(stage);

  return (
    <div className="w-full overflow-x-auto rounded-panel border border-border-structural/60 bg-surface-lowest px-5 py-5 print:hidden sm:px-7 sm:py-6">
      <ol className="flex min-w-max items-center">
        {STAGE_DEFS.map((def, index) => {
          const visual = statuses[def.id];
          const classes = stageClasses(visual);
          const statusText = STATUS_TEXT[def.id][visual] ?? "Pending";
          // Only ANALYZE gets the ambient pulse — the one stage that is
          // genuinely "processing, duration unknown" right now. INGEST gets
          // a steady (non-animated) glow when staged: it's current, but
          // nothing about it is actively in progress.
          const isPulsingActive = visual === "active" && def.id === "analyze";
          const isSteadyActive = visual === "active" && def.id !== "analyze";

          return (
            <li key={def.id} className="flex items-center">
              <div className="flex items-center gap-3">
                <span
                  className={`transition-soft flex h-9 w-9 shrink-0 items-center justify-center rounded-control font-mono text-[12px] transition-colors ${classes.marker} ${
                    isPulsingActive ? "pipeline-stage-pulse" : isSteadyActive ? "pipeline-stage-glow" : ""
                  }`}
                >
                  {def.code}
                </span>
                <div className="leading-tight">
                  <p className={`transition-soft text-[13px] font-medium transition-colors ${classes.label}`}>
                    {def.label}
                  </p>
                  <p className="mt-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-text-dim">
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${classes.dot} ${isPulsingActive ? "pipeline-dot-pulse" : ""}`}
                    />
                    {statusText}
                  </p>
                </div>
              </div>
              {index < STAGE_DEFS.length - 1 && (
                <span className="mx-4 h-px w-8 shrink-0 bg-border-structural sm:mx-5 sm:w-12" aria-hidden />
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
