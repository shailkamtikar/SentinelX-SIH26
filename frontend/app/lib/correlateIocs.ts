import type { ParsedEmail } from "./analyzeEmail";

/**
 * A single successfully analyzed email retained in browser-session memory.
 * `label` is a sequential, session-local display name only — never an
 * identifier, case ID, or UUID.
 */
export type AnalyzedEmail = {
  label: string;
  result: ParsedEmail;
};

export type SharedIndicatorType = "IPv4" | "IPv6" | "Domain" | "URL" | "Attachment SHA-256";

/**
 * An IOC value observed in two or more successfully analyzed emails.
 * This is an observation, not a verdict: it says nothing about whether the
 * emails are related, malicious, or part of a campaign.
 */
export type SharedIndicator = {
  type: SharedIndicatorType;
  value: string;
  emailLabels: string[];
};

/**
 * For one IOC category, find every value that appears in at least two
 * distinct analyzed emails. Repeated appearances of the same value within
 * a single email are collapsed via `Set` before cross-email comparison,
 * so they can never inflate a single email into multiple "matches".
 */
function findSharedValues(
  history: AnalyzedEmail[],
  type: SharedIndicatorType,
  extractValues: (email: AnalyzedEmail) => string[],
): SharedIndicator[] {
  const emailLabelsByValue = new Map<string, Set<string>>();

  for (const email of history) {
    const uniqueValuesInThisEmail = new Set(extractValues(email));
    for (const value of uniqueValuesInThisEmail) {
      const labels = emailLabelsByValue.get(value) ?? new Set<string>();
      labels.add(email.label);
      emailLabelsByValue.set(value, labels);
    }
  }

  const shared: SharedIndicator[] = [];
  for (const [value, labels] of emailLabelsByValue) {
    if (labels.size >= 2) {
      shared.push({ type, value, emailLabels: Array.from(labels) });
    }
  }
  return shared;
}

/**
 * Deterministic, offline correlation over already-extracted IOC values from
 * successfully analyzed emails only. No network calls, no DNS/GeoIP/
 * reputation lookups, no host-level or fuzzy matching — exact equality on
 * the same normalized values the backend already returns.
 */
export function computeSharedIOCs(history: AnalyzedEmail[]): SharedIndicator[] {
  return [
    ...findSharedValues(history, "IPv4", (email) =>
      (email.result.iocs?.ipv4 ?? []).map((entry) => entry.value),
    ),
    ...findSharedValues(history, "IPv6", (email) =>
      (email.result.iocs?.ipv6 ?? []).map((entry) => entry.value),
    ),
    ...findSharedValues(history, "Domain", (email) =>
      (email.result.iocs?.domains ?? []).map((entry) => entry.value),
    ),
    ...findSharedValues(history, "URL", (email) =>
      (email.result.iocs?.urls ?? []).map((entry) => entry.value),
    ),
    ...findSharedValues(history, "Attachment SHA-256", (email) =>
      (email.result.iocs?.attachment_hashes ?? [])
        .map((entry) => entry.sha256)
        .filter((sha256): sha256 is string => sha256 !== null),
    ),
  ];
}
