"""Optional Gemini-powered explanation of an already-completed analysis.

Strictly additive and strictly subordinate to the deterministic pipeline:

* The deterministic threat assessment (services/threat_assessment.py) stays
  authoritative. Nothing here can change, override, or re-rank it.
* Only structured evidence SentinelX already produced is sent. The raw
  .eml is never uploaded to Gemini, and neither is the decoded message
  body — the model explains findings, it does not re-analyse the message.
* When no API key is configured, when the API fails, or when the model
  returns anything that is not the expected JSON shape, this returns None.
  There is deliberately no fallback text: an unavailable explanation is
  reported as unavailable rather than invented.

The API key is read from the environment via app.config and is never
logged, echoed, or included in any response.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.config import get_settings

SYSTEM_INSTRUCTION = (
    "You are explaining an email forensic analysis. Use ONLY the supplied evidence. "
    "Do not invent facts. Distinguish observed evidence from inference. Do not claim "
    "maliciousness unless the supplied deterministic assessment supports that "
    "conclusion. If evidence is insufficient, say so."
)

_RESPONSE_FORMAT_INSTRUCTION = (
    "Return a single JSON object with exactly these keys:\n"
    '  "summary": a short paragraph (2-4 sentences) explaining what the evidence shows.\n'
    '  "evidence_points": an array of short strings, each citing a specific supplied '
    "observation.\n"
    '  "uncertainty": a short string describing what the evidence does NOT establish.\n'
    '  "recommended_actions": an array of short, practical analyst next steps.\n'
    "Be concise. Do not add any other keys or any prose outside the JSON object."
)

# Keep the payload demo-sized and bound the blast radius of a chatty model.
_MAX_LIST_ITEMS = 8
_MAX_SUMMARY_CHARS = 1200
_MAX_ITEM_CHARS = 400


@dataclass
class AIExplanation:
    summary: str
    evidence_points: list[str] = field(default_factory=list)
    uncertainty: str = ""
    recommended_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "summary": self.summary,
            "evidence_points": self.evidence_points,
            "uncertainty": self.uncertainty,
            "recommended_actions": self.recommended_actions,
        }


class GeminiClientLike(Protocol):
    """Minimal surface used here, so tests can inject a small fake."""

    @property
    def models(self) -> Any: ...


def _cap_items(items: Any, *, limit: int = _MAX_LIST_ITEMS) -> list[Any]:
    """Bound list length sent to the model as evidence.

    A real uploaded email can carry far more received-chain hops or IOCs
    than the small fixtures used to size max_output_tokens. An unbounded
    prompt can grow large enough to consume the model's mandatory
    "thinking" token budget and re-trigger the same finish_reason=MAX_TOKENS
    truncation that budget was raised to fix — just at a larger input size.
    """
    if not isinstance(items, list):
        return []
    return items[:limit]


def _cap_text(value: Any, *, limit: int = _MAX_ITEM_CHARS) -> Any:
    if isinstance(value, str):
        return value[:limit]
    return value


def build_evidence_payload(response: dict[str, Any]) -> dict[str, Any]:
    """Structured evidence subset sent to the model.

    Explicitly excludes the raw .eml and the decoded body: the model is
    asked to explain extracted findings, not to re-read the message.
    """
    forensics = response.get("forensics") or {}
    threat = response.get("threat_assessment") or {}
    iocs = response.get("iocs") or {}
    enrichment = response.get("enrichment") or {}

    return {
        "identity": {
            "sender": response.get("sender"),
            "recipient": response.get("recipient"),
            "subject": response.get("subject"),
            "reply_to": response.get("reply_to"),
            "return_path": response.get("return_path"),
        },
        "authentication": {
            "spf": forensics.get("spf_result"),
            "dkim": forensics.get("dkim_result"),
            "dmarc": forensics.get("dmarc_result"),
            "authentication_results_raw": forensics.get("authentication_results_raw"),
        },
        "routing": {
            "routing_flags": _cap_items(forensics.get("routing_flags") or []),
            "received_chain": [
                _cap_text(hop) for hop in _cap_items(forensics.get("received_chain") or [])
            ],
        },
        "indicators": {
            "ipv4": _cap_items(iocs.get("ipv4") or []),
            "ipv6": _cap_items(iocs.get("ipv6") or []),
            "domains": _cap_items(iocs.get("domains") or []),
            "urls": _cap_items(iocs.get("urls") or []),
            "attachment_hashes": _cap_items(iocs.get("attachment_hashes") or []),
        },
        "indicator_enrichment": {
            key: (_cap_items(value) if isinstance(value, list) else value)
            for key, value in enrichment.items()
        },
        "deterministic_assessment": {
            "risk_level": threat.get("risk_level"),
            "reasons": threat.get("reasons") or [],
            "note": (
                "This deterministic, rule-based assessment is authoritative. "
                "Do not contradict or override it."
            ),
        },
    }


def build_prompt(response: dict[str, Any]) -> str:
    payload = build_evidence_payload(response)
    return (
        "Explain the following email forensic analysis evidence.\n\n"
        f"{_RESPONSE_FORMAT_INSTRUCTION}\n\n"
        "EVIDENCE (JSON):\n"
        f"{json.dumps(payload, indent=2, default=str)}"
    )


def _clean_text(value: Any, *, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()[:limit]


def _clean_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for entry in value:
        text = _clean_text(entry, limit=_MAX_ITEM_CHARS)
        if text:
            items.append(text)
        if len(items) >= _MAX_LIST_ITEMS:
            break
    return items


def parse_explanation(text: str | None) -> AIExplanation | None:
    """Validate model output, returning None for anything unusable.

    Malformed output is rejected outright — never patched up into
    plausible-looking text.
    """
    if not text or not text.strip():
        return None

    stripped = text.strip()
    # Tolerate a ```json fenced block, which some models emit even when
    # asked for raw JSON. Anything else unexpected is rejected below.
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        if stripped.lower().startswith("json"):
            stripped = stripped[4:]
        stripped = stripped.strip()

    try:
        data = json.loads(stripped)
    except (ValueError, TypeError):
        return None

    if not isinstance(data, dict):
        return None

    summary = _clean_text(data.get("summary"), limit=_MAX_SUMMARY_CHARS)
    if not summary:
        # Without a summary there is no explanation worth showing.
        return None

    return AIExplanation(
        summary=summary,
        evidence_points=_clean_list(data.get("evidence_points")),
        uncertainty=_clean_text(data.get("uncertainty"), limit=_MAX_ITEM_CHARS),
        recommended_actions=_clean_list(data.get("recommended_actions")),
    )


def _get_client() -> GeminiClientLike:
    settings = get_settings()
    # Imported lazily so importing this module never requires the SDK to
    # initialise or a key to be present.
    from google import genai

    return genai.Client(api_key=settings.gemini_api_key)


def explain_analysis(
    response: dict[str, Any],
    *,
    client: GeminiClientLike | None = None,
) -> AIExplanation | None:
    """Produce an evidence-grounded explanation, or None if unavailable.

    Returns None when Gemini is not configured or when the model returns
    unusable output. Transport/API errors are raised for the caller to
    isolate, exactly like every other best-effort stage.
    """
    settings = get_settings()
    if client is None and not settings.gemini_configured:
        return None

    resolved_client = client or _get_client()

    result = resolved_client.models.generate_content(
        model=settings.gemini_model,
        contents=build_prompt(response),
        config={
            "system_instruction": SYSTEM_INSTRUCTION,
            "response_mime_type": "application/json",
            "temperature": 0.2,
            # Current "thinking" models spend part of this budget on
            # internal reasoning before producing any visible output, and
            # that reasoning is mandatory here — thinking_budget=0 is
            # rejected by the API for this model family (400
            # INVALID_ARGUMENT). 900 was verified live to leave too little
            # room: the model hit finish_reason=MAX_TOKENS after ~860
            # thinking tokens, truncating the JSON mid-string before
            # parse_explanation ever saw a complete object. 3072 was
            # verified live against this milestone's real, larger evidence
            # payload (3 IPv4 IOCs + enrichment) to finish with
            # finish_reason=STOP and ~940 tokens of headroom to spare.
            "max_output_tokens": 3072,
        },
    )

    return parse_explanation(getattr(result, "text", None))
