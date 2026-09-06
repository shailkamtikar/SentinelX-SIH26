const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export type Attachment = {
  filename: string | null;
  content_type: string;
  size: number;
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
