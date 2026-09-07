import type { ParsedEmail } from "./analyzeEmail";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

/**
 * One previously persisted analysis, in exactly the same shape
 * `/analyze-email` itself returns (see backend
 * app.services.analysis_store.get_analysis_history_for_user) — so the
 * existing AnalysisResult/CorrelationPanel rendering logic works
 * identically for a live upload and a history entry with no new types.
 */
export type AnalysisHistoryEntry = {
  email_id: string | null;
  original_filename: string | null;
  analyzed_at: string | null;
  response: ParsedEmail;
};

/**
 * Fetches the authenticated user's own persisted analysis history.
 *
 * Best-effort, like the rest of this app's optional stages: any failure
 * (network error, non-2xx, unreadable body) degrades to an empty list
 * rather than throwing — a history-fetch problem must never block the
 * live upload/analyze workflow, which keeps working normally regardless.
 */
export async function fetchAnalysisHistory(accessToken: string): Promise<AnalysisHistoryEntry[]> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/analysis-history`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  } catch {
    return [];
  }

  if (!response.ok) {
    return [];
  }

  try {
    const data = (await response.json()) as { entries?: AnalysisHistoryEntry[] };
    return data.entries ?? [];
  } catch {
    return [];
  }
}
