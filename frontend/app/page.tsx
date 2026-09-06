"use client";

import { useCallback, useState } from "react";

import CorrelationPanel from "./components/CorrelationPanel";
import ContextualPanel from "./components/ContextualPanel";
import EmailUploadCard from "./components/EmailUploadCard";
import Header from "./components/Header";
import PipelineStages from "./components/PipelineStages";
import Sidebar from "./components/Sidebar";
import type { ParsedEmail } from "./lib/analyzeEmail";
import type { AnalyzedEmail } from "./lib/correlateIocs";

export default function Home() {
  // Successful-analysis history for this browser session only — no
  // persistence, no identifiers beyond a sequential display label.
  const [history, setHistory] = useState<AnalyzedEmail[]>([]);

  const handleAnalysisComplete = useCallback((result: ParsedEmail) => {
    setHistory((previous) => [...previous, { label: `Email ${previous.length + 1}`, result }]);
  }, []);

  return (
    <div className="min-h-screen bg-canvas">
      <Sidebar />

      <div className="flex flex-col print:pl-0 lg:pl-72">
        <div className="print:hidden">
          <Header />
        </div>

        <main className="flex-1 px-5 py-6 sm:px-8 sm:py-8 lg:px-10 lg:py-10">
          <div className="mx-auto flex max-w-[1800px] flex-col gap-7">
            <div className="print:hidden">
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-text-dim">
                Forensic Console / Evidence Ingestion
              </p>
              <h2 className="mt-2 text-2xl font-semibold tracking-tight text-text-primary">
                New Evidence Ingestion
              </h2>
              <p className="mt-1.5 max-w-2xl text-sm leading-6 text-text-secondary">
                Upload raw email evidence to begin the investigation pipeline. Ingest, Analyze,
                Enrich, and the deterministic Explain stage are connected and operational. A
                local Evidence Summary export is available for a completed analysis, and local,
                session-based IOC correlation runs automatically across successfully analyzed
                emails.
              </p>
            </div>

            <PipelineStages />

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
              <div className="xl:col-span-8">
                <EmailUploadCard onAnalysisComplete={handleAnalysisComplete} />
              </div>
              <div className="print:hidden xl:col-span-4">
                <ContextualPanel />
              </div>
            </div>

            <CorrelationPanel history={history} />
          </div>
        </main>
      </div>
    </div>
  );
}
