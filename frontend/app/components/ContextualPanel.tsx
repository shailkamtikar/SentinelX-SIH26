type PanelItem = {
  title: string;
  note: string;
};

const ITEMS: PanelItem[] = [
  {
    title: "Chain of Custody",
    // The local Evidence Summary export exists, but tamper-evident custody
    // logging does not — keep this note accurate about what is missing.
    note: "Custody logging is not yet implemented.",
  },
  {
    title: "MITRE ATT&CK Mapping",
    note: "Requires the CORRELATE stage to be connected.",
  },
];

export default function ContextualPanel() {
  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-card border border-border-structural/60 bg-surface-lowest p-5">
        <p className="text-[10px] uppercase tracking-[0.18em] text-text-dim">Contextual panel</p>
        <h3 className="mt-2 text-[15px] font-semibold tracking-tight text-text-primary">
          Downstream analysis
        </h3>
        <p className="mt-2 text-[12px] leading-5 text-text-dim">
          These panels populate automatically as later pipeline stages are wired to a backend.
          Nothing below reflects real analysis.
        </p>
      </div>

      {/* Deliberately quieter than the live pipeline: plain text rows, no
          card-per-item, no LOCKED badge — this is a roadmap list, not a
          set of investigation stages, and should never visually compete
          with PipelineStages for attention. */}
      <div className="rounded-card border border-border-structural/40 bg-surface-lowest/40 p-5">
        <p className="text-[10px] uppercase tracking-[0.18em] text-text-dim">Future capabilities</p>
        <ul className="mt-3 flex flex-col divide-y divide-border-structural/40">
          {ITEMS.map((item) => (
            <li key={item.title} className="flex flex-col gap-1 py-3 first:pt-0 last:pb-0">
              <div className="flex items-baseline justify-between gap-3">
                <p className="text-[12.5px] font-medium text-text-dim">{item.title}</p>
                <span className="shrink-0 text-[10px] uppercase tracking-wider text-neutral/80">
                  Not yet available
                </span>
              </div>
              <p className="text-[11.5px] leading-5 text-text-dim/80">{item.note}</p>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
