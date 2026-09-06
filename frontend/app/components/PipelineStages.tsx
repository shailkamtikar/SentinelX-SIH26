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
  { code: "04", label: "Correlate", status: "PENDING" },
  { code: "05", label: "Explain", status: "ACTIVE" },
  { code: "06", label: "Report", status: "LOCKED" },
];

function stageClasses(status: Stage["status"]) {
  switch (status) {
    case "ACTIVE":
      return {
        wrap: "border-cyan/50 bg-surface-container",
        code: "text-cyan",
        label: "text-text-primary",
        badge: "text-cyan",
      };
    case "QUEUED":
      return {
        wrap: "border-border-structural bg-surface-lowest",
        code: "text-sky/80",
        label: "text-text-secondary",
        badge: "text-sky/80",
      };
    case "LOCKED":
      return {
        wrap: "border-border-structural bg-surface-lowest opacity-60",
        code: "text-neutral",
        label: "text-text-dim",
        badge: "text-neutral",
      };
    default:
      return {
        wrap: "border-border-structural bg-surface-lowest opacity-80",
        code: "text-text-dim",
        label: "text-text-dim",
        badge: "text-text-dim",
      };
  }
}

export default function PipelineStages() {
  return (
    <div className="w-full overflow-x-auto">
      <ol className="flex min-w-max items-stretch gap-2">
        {STAGES.map((stage, index) => {
          const classes = stageClasses(stage.status);
          const isActive = stage.status === "ACTIVE";
          return (
            <li key={stage.code} className="flex items-center gap-2">
              <div
                className={`flex min-w-[132px] flex-col gap-1.5 rounded-sm border px-3.5 py-2.5 ${classes.wrap}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className={`font-mono text-[11px] ${classes.code}`}>{stage.code}</span>
                  {isActive && (
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan opacity-60" />
                      <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-cyan" />
                    </span>
                  )}
                  {stage.status === "LOCKED" && (
                    <LockIcon className="h-3 w-3 text-neutral" />
                  )}
                </div>
                <span className={`text-xs font-semibold uppercase tracking-wide ${classes.label}`}>
                  {stage.label}
                </span>
                <span className={`font-mono text-[9px] uppercase tracking-widest ${classes.badge}`}>
                  {stage.status}
                </span>
              </div>
              {index < STAGES.length - 1 && (
                <span className="h-px w-4 shrink-0 bg-border-structural" aria-hidden />
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
