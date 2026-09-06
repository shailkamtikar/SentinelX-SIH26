import ContextualPanel from "./components/ContextualPanel";
import EmailUploadCard from "./components/EmailUploadCard";
import Header from "./components/Header";
import PipelineStages from "./components/PipelineStages";
import Sidebar from "./components/Sidebar";

export default function Home() {
  return (
    <div className="min-h-screen bg-canvas">
      <Sidebar />

      <div className="flex flex-col lg:pl-72">
        <Header />

        <main className="flex-1 px-5 py-6 sm:px-8 sm:py-8 lg:px-10 lg:py-10">
          <div className="mx-auto flex max-w-[1800px] flex-col gap-7">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-text-dim">
                Forensic Console / Evidence Ingestion
              </p>
              <h2 className="mt-2 text-2xl font-semibold tracking-tight text-text-primary">
                New Evidence Ingestion
              </h2>
              <p className="mt-1.5 max-w-2xl text-sm leading-6 text-text-secondary">
                Upload raw email evidence to begin the investigation pipeline. Ingest, Analyze,
                Enrich, and the deterministic Explain stage are connected and operational.
                Correlate and Report remain pending and are not yet implemented.
              </p>
            </div>

            <PipelineStages />

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
              <div className="xl:col-span-8">
                <EmailUploadCard />
              </div>
              <div className="xl:col-span-4">
                <ContextualPanel />
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
