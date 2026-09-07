"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import CorrelationPanel from "./components/CorrelationPanel";
import ContextualPanel from "./components/ContextualPanel";
import EmailUploadCard, { type UploadStage } from "./components/EmailUploadCard";
import Header from "./components/Header";
import InvestigationSummary from "./components/InvestigationSummary";
import ObservedRelationships from "./components/ObservedRelationships";
import PipelineStages from "./components/PipelineStages";
import Sidebar from "./components/Sidebar";
import { fetchAnalysisHistory } from "./lib/analysisHistory";
import type { ParsedEmail } from "./lib/analyzeEmail";
import { AuthGate } from "./lib/AuthGate";
import { useAuthSession } from "./lib/AuthSessionProvider";
import { computeSharedIOCs, type AnalyzedEmail } from "./lib/correlateIocs";

export default function Home() {
  const { session } = useAuthSession();

  // Seeded once from the authenticated user's persisted history (Supabase),
  // then appended to locally as new uploads succeed this session — so a
  // refresh doesn't lose prior investigation context, and a live upload
  // still renders immediately without waiting on a round trip.
  const [history, setHistory] = useState<AnalyzedEmail[]>([]);
  const historySeeded = useRef(false);

  // The upload/analysis lifecycle as truthfully reported by EmailUploadCard
  // itself (see UploadStage there) — "correlated" below is the only value
  // derived here, from the one additional real condition the upload card
  // has no visibility into: whether 2+ emails exist in history.
  const [uploadStage, setUploadStage] = useState<UploadStage>("idle");
  const pipelineStage = uploadStage === "analyzed" && history.length >= 2 ? "correlated" : uploadStage;

  useEffect(() => {
    if (!session || historySeeded.current) return;
    historySeeded.current = true;

    fetchAnalysisHistory(session.access_token).then((entries) => {
      setHistory((previous) => {
        // A live upload already happened before this fetch resolved —
        // don't clobber it. This is a deliberate, simple choice over a
        // full merge: the common case (fetch resolves before a human
        // finishes picking and uploading a file) is handled correctly,
        // and the rare race never shows stale or duplicated data.
        if (previous.length > 0) return previous;
        return entries.map((entry, index) => ({
          label: entry.original_filename ?? `Email ${index + 1}`,
          result: entry.response,
          analyzedAt: entry.analyzed_at,
        }));
      });
    });
  }, [session]);

  const handleAnalysisComplete = useCallback((result: ParsedEmail, filename: string) => {
    setHistory((previous) => [
      ...previous,
      { label: filename || `Email ${previous.length + 1}`, result, analyzedAt: null },
    ]);
  }, []);

  const sharedIndicators = computeSharedIOCs(history);

  return (
    <AuthGate requireSession redirectTo="/login">
      <div className="min-h-screen bg-canvas">
        <Sidebar />

        <div className="flex flex-col print:pl-0 lg:pl-72">
          <div className="print:hidden">
            <Header />
          </div>

          <main className="flex-1 px-5 py-7 sm:px-8 sm:py-9 lg:px-12 lg:py-10">
            <div className="mx-auto flex max-w-[1600px] flex-col gap-8">
              <div className="print:hidden">
                <p className="text-[10px] uppercase tracking-[0.18em] text-text-dim">
                  Forensic console / Evidence ingestion
                </p>
                <h2 className="mt-2.5 text-[26px] font-semibold leading-tight tracking-tight text-text-primary">
                  New Evidence Ingestion
                </h2>
                <p className="mt-3 max-w-3xl text-[13px] leading-6 text-text-secondary">
                  Upload raw email evidence to begin the investigation pipeline. Ingest, Analyze,
                  Enrich, and the deterministic Explain stage are connected and operational. A
                  local Evidence Summary export is available for a completed analysis, and local,
                  session-based IOC correlation runs automatically across successfully analyzed
                  emails.
                </p>
              </div>

              <PipelineStages stage={pipelineStage} />

              <div className="grid grid-cols-1 gap-6 xl:grid-cols-12 xl:gap-8">
                <div className="xl:col-span-8">
                  <EmailUploadCard
                    onAnalysisComplete={handleAnalysisComplete}
                    onStageChange={setUploadStage}
                  />
                </div>
                <div className="print:hidden xl:col-span-4">
                  <ContextualPanel />
                </div>
              </div>

              <InvestigationSummary history={history} sharedIndicators={sharedIndicators} />

              <CorrelationPanel history={history} />

              <ObservedRelationships history={history} sharedIndicators={sharedIndicators} />
            </div>
          </main>
        </div>
      </div>
    </AuthGate>
  );
}
