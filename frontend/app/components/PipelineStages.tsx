import type { SVGProps } from "react";

type Stage = {
  code: string;
  label: string;
  status: "ACTIVE" | "QUEUED" | "PENDING" | "LOCKED";
};

const STAGES: Stage[] = [
  { code: "01", label: "Ingest", status: "ACTIVE" },
  { code: "02", label: "Analyze", status: "ACTIVE" },
  { code: "03", label: "Enrich", status: "ACTIVE" },
  { code: "04", label: "Correlate", status: "ACTIVE" },
  { code: "05", label: "Explain", status: "ACTIVE" },
  { code: "06", label: "Report", status: "ACTIVE" },
];

function stageClasses(status: Stage["status"]) {
  switch (status) {
    case "ACTIVE":
      return {
        marker: "bg-cyan/15 text-cyan",
        label: "text-text-primary",
        dot: "bg-cyan",
      };
    case "QUEUED":
      return {
        marker: "bg-surface-container text-sky/80",
        label: "text-text-secondary",
        dot: "bg-sky/70",
      };
    case "LOCKED":
      return {
        marker: "bg-surface-container text-neutral",
        label: "text-text-dim",
        dot: "bg-neutral/60",
      };
    default:
      return {
        marker: "bg-surface-container text-text-dim",
        label: "text-text-dim",
        dot: "bg-text-dim/50",
      };
  }
}

export default function PipelineStages() {
  return (
    <div className="w-full overflow-x-auto rounded-panel border border-border-structural/60 bg-surface-lowest px-5 py-5 print:hidden sm:px-7 sm:py-6">
      <ol className="flex min-w-max items-center">
        {STAGES.map((stage, index) => {
          const classes = stageClasses(stage.status);
          const isLocked = stage.status === "LOCKED";
          return (
            <li key={stage.code} className="flex items-center">
              <div className="flex items-center gap-3">
                <span
                  className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-control font-mono text-[12px] ${classes.marker}`}
                >
                  {stage.code}
                </span>
                <div className="leading-tight">
                  <p className={`text-[13px] font-medium ${classes.label}`}>{stage.label}</p>
                  <p className="mt-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-text-dim">
                    {isLocked ? (
                      <LockIcon className="h-2.5 w-2.5 text-neutral" />
                    ) : (
                      <span className={`h-1.5 w-1.5 rounded-full ${classes.dot}`} />
                    )}
                    {stage.status}
                  </p>
                </div>
              </div>
              {index < STAGES.length - 1 && (
                <span
                  className="mx-4 h-px w-8 shrink-0 bg-border-structural sm:mx-5 sm:w-12"
                  aria-hidden
                />
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function LockIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} {...props}>
      <rect x="4.5" y="10.5" width="15" height="9.5" rx="1" />
      <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    </svg>
  );
}
