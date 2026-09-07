import type { AnalyzedEmail, SharedIndicator } from "../lib/correlateIocs";

const ROW_HEIGHT = 40;
const TOP_PADDING = 24;
const EMAIL_X = 90;
const INDICATOR_X = 430;
const VIEW_WIDTH = 520;

function truncate(value: string, max = 26): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

/**
 * OBSERVED RELATIONSHIPS — a lightweight bipartite diagram: each analyzed
 * email that shares at least one indicator with another email, connected
 * by a line to each shared indicator it was observed carrying. Purely a
 * visual restatement of the same exact-match correlation data already
 * shown in the Correlation section — no new inference, no attribution,
 * no invented nodes. Plain inline SVG; no charting/graph dependency.
 */
export default function ObservedRelationships({
  history,
  sharedIndicators,
}: {
  history: AnalyzedEmail[];
  sharedIndicators: SharedIndicator[];
}) {
  const involvedLabels = Array.from(new Set(sharedIndicators.flatMap((i) => i.emailLabels))).sort(
    (a, b) => history.findIndex((e) => e.label === a) - history.findIndex((e) => e.label === b),
  );

  const height = Math.max(involvedLabels.length, sharedIndicators.length, 1) * ROW_HEIGHT + TOP_PADDING * 2;

  const emailY = new Map(
    involvedLabels.map((label, index) => [
      label,
      TOP_PADDING + (index + 0.5) * ((height - TOP_PADDING * 2) / involvedLabels.length),
    ]),
  );
  const indicatorY = new Map(
    sharedIndicators.map((indicator, index) => [
      `${indicator.type}:${indicator.value}`,
      TOP_PADDING + (index + 0.5) * ((height - TOP_PADDING * 2) / sharedIndicators.length),
    ]),
  );

  return (
    // SVG fill/stroke colors aren't covered by the .print-report override
    // (that rule targets background-color/color/border-color, not SVG
    // paint properties), so this diagram is screen-only rather than risk
    // printing illegibly on white paper — Part 10's report scope
    // (investigation summary, threat assessment, repeated indicators,
    // analyst actions) doesn't require the diagram itself.
    <section className="print:hidden rounded-panel border border-border-structural/60 bg-surface-lowest p-5 sm:p-7">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className="text-[11px] font-medium uppercase tracking-[0.16em] text-text-dim">
          Observed relationships
        </h2>
        <span className="text-[11px] text-text-dim">
          {sharedIndicators.length === 0 ? "No repeated indicators" : `${sharedIndicators.length} repeated`}
        </span>
      </div>

      {sharedIndicators.length === 0 ? (
        <p className="mt-4 text-[13px] leading-6 text-text-dim">
          No repeated relationships observed yet — analyze at least two emails that share an
          indicator to see them here.
        </p>
      ) : (
        <>
          <div className="mt-4 overflow-x-auto">
            <svg
              viewBox={`0 0 ${VIEW_WIDTH} ${height}`}
              width="100%"
              height={height}
              role="img"
              aria-label="Diagram connecting analyzed emails to the repeated indicators they share"
            >
              {sharedIndicators.map((indicator) =>
                indicator.emailLabels.map((label) => {
                  const y1 = emailY.get(label);
                  const y2 = indicatorY.get(`${indicator.type}:${indicator.value}`);
                  if (y1 === undefined || y2 === undefined) return null;
                  return (
                    <line
                      key={`${indicator.type}-${indicator.value}-${label}`}
                      x1={EMAIL_X + 60}
                      y1={y1}
                      x2={INDICATOR_X - 90}
                      y2={y2}
                      stroke="var(--color-border-focused)"
                      strokeWidth={1}
                    />
                  );
                }),
              )}

              {involvedLabels.map((label) => {
                const y = emailY.get(label) ?? 0;
                return (
                  <g key={label}>
                    <rect
                      x={EMAIL_X - 55}
                      y={y - 13}
                      width={110}
                      height={26}
                      rx={7}
                      fill="var(--color-surface-container)"
                      stroke="var(--color-border-structural)"
                    />
                    <text
                      x={EMAIL_X}
                      y={y + 4}
                      textAnchor="middle"
                      fontSize="10"
                      fill="var(--color-text-secondary)"
                    >
                      <title>{label}</title>
                      {truncate(label, 16)}
                    </text>
                  </g>
                );
              })}

              {sharedIndicators.map((indicator) => {
                const key = `${indicator.type}:${indicator.value}`;
                const y = indicatorY.get(key) ?? 0;
                return (
                  <g key={key}>
                    <rect
                      x={INDICATOR_X - 85}
                      y={y - 13}
                      width={170}
                      height={26}
                      rx={7}
                      fill="var(--color-surface-container)"
                      stroke="var(--color-cyan)"
                    />
                    <text x={INDICATOR_X} y={y + 4} textAnchor="middle" fontSize="10" fill="var(--color-cyan)">
                      <title>
                        {indicator.type}: {indicator.value}
                      </title>
                      {indicator.type}: {truncate(indicator.value, 18)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          <p className="mt-4 text-[11px] leading-5 text-text-dim">
            Lines indicate the same indicator value observed across multiple analyzed emails — an
            investigation lead, not a confirmed relationship, campaign, or malicious infrastructure.
          </p>
        </>
      )}
    </section>
  );
}
