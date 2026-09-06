const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export type Attachment = {
  filename: string | null;
  content_type: string;
  size: number;
};

export type Forensics = {
  authentication_results_raw: string | null;
  authentication_results_raw_all: string[];
  spf_result: string | null;
  dkim_result: string | null;
  dmarc_result: string | null;
  received_chain: string[];
  routing_flags: string[];
};

export type IPIndicator = {
  value: string;
  sources: string[];
  private: boolean;
};

export type DomainIndicator = {
  value: string;
  sources: string[];
  punycode_domain: boolean;
};

export type URLIndicator = {
  value: string;
  sources: string[];
  ip_literal_url: boolean;
  credential_in_url: boolean;
  punycode_domain: boolean;
};

export type AttachmentHashIndicator = {
  filename: string | null;
  sha256: string | null;
};

export type IOCs = {
  ipv4: IPIndicator[];
  ipv6: IPIndicator[];
  domains: DomainIndicator[];
  urls: URLIndicator[];
  attachment_hashes: AttachmentHashIndicator[];
};

export type ThreatAssessment = {
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";
  reasons: string[];
};

export type IPEnrichment = {
  value: string;
  classification: string;
};

export type URLEnrichment = {
  value: string;
  known_url_shortener: boolean;
};

export type Enrichment = {
  ip: IPEnrichment[];
  url: URLEnrichment[];
};

/**
 * Optional, evidence-grounded explanation produced by the Gemini stage.
 * Null whenever the stage is unconfigured, fails, or returns unusable
 * output — the deterministic threat_assessment stays authoritative.
 */
export type AIExplanation = {
  summary: string;
  evidence_points: string[];
  uncertainty: string;
  recommended_actions: string[];
};

/**
 * Why ai_explanation is (or isn't) present:
 * - "ok"             — an explanation was produced
 * - "not_configured" — GEMINI_API_KEY is not set server-side
 * - "unavailable"    — configured, but the call failed or returned
 *                       unusable output
 */
export type AIExplanationStatus = "ok" | "not_configured" | "unavailable";

/** Truthful evidence-handling status. Never a public storage URL. */
export type EvidenceStatus = {
  raw_eml_sha256: string | null;
  raw_eml_stored: boolean;
};

export type ParsedEmail = {
  sender: string | null;
  recipient: string | null;
  subject: string | null;
  reply_to: string | null;
  date: string | null;
  message_id: string | null;
  return_path: string | null;
  body: string | null;
  attachments: Attachment[];
  urls: string[];
  forensics: Forensics;
  iocs: IOCs;
  threat_assessment: ThreatAssessment;
  enrichment: Enrichment;
  ai_explanation: AIExplanation | null;
  ai_explanation_status: AIExplanationStatus;
  evidence: EvidenceStatus | null;
};

export class AnalyzeEmailError extends Error {}

/**
 * Uploads a real .eml file to the SentinelX backend and returns the parsed,
 * structured evidence fields. Never fabricates data — a network failure or
 * non-2xx response always surfaces as a thrown AnalyzeEmailError instead of
 * a fallback result.
 */
export async function analyzeEmail(file: File): Promise<ParsedEmail> {
  const formData = new FormData();
  formData.append("file", file);

  let response: Response;
  try {
    // No explicit Content-Type header: the browser sets the multipart
    // boundary itself when given a FormData body.
    response = await fetch(`${API_BASE_URL}/analyze-email`, {
      method: "POST",
      body: formData,
    });
  } catch {
    throw new AnalyzeEmailError(
      `Could not reach the analysis backend at ${API_BASE_URL}. Is it running?`,
    );
  }

  if (!response.ok) {
    let detail: string | undefined;
    try {
      const errorBody: unknown = await response.json();
      if (
        errorBody &&
        typeof errorBody === "object" &&
        "detail" in errorBody &&
        typeof (errorBody as { detail: unknown }).detail === "string"
      ) {
        detail = (errorBody as { detail: string }).detail;
      }
    } catch {
      // Response body wasn't JSON — fall through to the generic message below.
    }
    throw new AnalyzeEmailError(detail ?? `Analysis failed (HTTP ${response.status}).`);
  }

  try {
    return (await response.json()) as ParsedEmail;
  } catch {
    throw new AnalyzeEmailError("Backend returned an unreadable response.");
  }
}
