import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.gemini_explainer import (
    SYSTEM_INSTRUCTION,
    build_evidence_payload,
    build_prompt,
    explain_analysis,
    parse_explanation,
)

client = TestClient(app)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_EML_BYTES = (FIXTURES_DIR / "sample.eml").read_bytes()
FORENSICS_EML_BYTES = (FIXTURES_DIR / "sample_with_forensics.eml").read_bytes()

VALID_MODEL_JSON = json.dumps(
    {
        "summary": "SPF and DMARC failed and the reply address does not match the sender domain.",
        "evidence_points": ["SPF result: fail", "DMARC result: fail"],
        "uncertainty": "The evidence does not establish who operates the sending infrastructure.",
        "recommended_actions": ["Verify the sender through a known-good channel."],
    }
)


class _FakeModels:
    def __init__(self, text=None, error=None):
        self._text = text
        self._error = error
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error

        class _Result:
            text = self._text

        return _Result()


class _FakeGeminiClient:
    def __init__(self, text=None, error=None):
        self.models = _FakeModels(text=text, error=error)


def _analyze(raw_bytes: bytes, filename: str) -> dict:
    response = client.post(
        "/analyze-email",
        files={"file": (filename, raw_bytes, "message/rfc822")},
    )
    assert response.status_code == 200
    return response.json()


# --- Availability ------------------------------------------------------------


def test_returns_none_when_no_api_key_is_configured(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")

    # No key, no client injected: unavailable, and no invented text.
    assert explain_analysis(response) is None


def test_returns_structured_explanation_on_a_valid_model_response():
    response = _analyze(FORENSICS_EML_BYTES, "sample_with_forensics.eml")
    fake = _FakeGeminiClient(text=VALID_MODEL_JSON)

    explanation = explain_analysis(response, client=fake)

    assert explanation is not None
    assert explanation.summary.startswith("SPF and DMARC failed")
    assert explanation.evidence_points == ["SPF result: fail", "DMARC result: fail"]
    assert "does not establish" in explanation.uncertainty
    assert len(explanation.recommended_actions) == 1
    assert set(explanation.to_dict()) == {
        "summary",
        "evidence_points",
        "uncertainty",
        "recommended_actions",
    }


def test_api_failure_propagates_for_the_route_to_isolate():
    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")
    fake = _FakeGeminiClient(error=RuntimeError("simulated Gemini outage"))

    with pytest.raises(RuntimeError):
        explain_analysis(response, client=fake)


# --- Malformed output is rejected, never patched up --------------------------


@pytest.mark.parametrize(
    "text",
    [
        None,
        "",
        "   ",
        "not json at all",
        "[1, 2, 3]",
        json.dumps({"evidence_points": ["x"]}),  # no summary
        json.dumps({"summary": ""}),  # empty summary
        json.dumps({"summary": 42}),  # wrong type
    ],
)
def test_malformed_output_is_rejected(text):
    assert parse_explanation(text) is None


def test_fenced_json_block_is_tolerated():
    explanation = parse_explanation(f"```json\n{VALID_MODEL_JSON}\n```")
    assert explanation is not None
    assert explanation.summary.startswith("SPF and DMARC failed")


def test_non_string_list_entries_are_dropped_not_stringified():
    explanation = parse_explanation(
        json.dumps({"summary": "ok", "evidence_points": ["good", 5, None, {"a": 1}]})
    )
    assert explanation is not None
    assert explanation.evidence_points == ["good"]


def test_malformed_output_through_explain_analysis_returns_none():
    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")
    fake = _FakeGeminiClient(text="}{ not json")

    assert explain_analysis(response, client=fake) is None


# --- Prompt content ----------------------------------------------------------


def test_system_instruction_states_the_required_grounding_rules():
    for required in [
        "Use ONLY the supplied evidence",
        "Do not invent facts",
        "Distinguish observed evidence from inference",
        "Do not claim maliciousness",
        "If evidence is insufficient, say so",
    ]:
        assert required in SYSTEM_INSTRUCTION


def test_prompt_carries_the_supplied_evidence():
    response = _analyze(FORENSICS_EML_BYTES, "sample_with_forensics.eml")
    prompt = build_prompt(response)

    # Real observed evidence from this fixture must reach the model.
    assert "fail" in prompt
    assert "198.51.100.5" in prompt
    assert "malicious-example.net" in prompt
    assert "reply_to_domain_mismatch" in prompt
    assert "HIGH" in prompt


def test_deterministic_assessment_is_marked_authoritative_in_the_payload():
    response = _analyze(FORENSICS_EML_BYTES, "sample_with_forensics.eml")
    payload = build_evidence_payload(response)

    assert payload["deterministic_assessment"]["risk_level"] == "HIGH"
    note = payload["deterministic_assessment"]["note"]
    assert "authoritative" in note
    assert "Do not contradict or override it." in note


def test_raw_eml_and_message_body_are_never_sent_to_the_model():
    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")
    payload = build_evidence_payload(response)
    prompt = build_prompt(response)

    assert "body" not in payload
    # A distinctive sentence from the fixture body must not leave the host.
    body_sentence = "Please review the attached quarterly report"
    assert body_sentence in (response["body"] or "")
    assert body_sentence not in prompt
    # And obviously none of the raw .eml headers/boundaries.
    assert "MIME-Version" not in prompt


def test_model_call_uses_configured_model_and_json_output(monkeypatch):
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test-model")
    response = _analyze(SAMPLE_EML_BYTES, "sample.eml")
    fake = _FakeGeminiClient(text=VALID_MODEL_JSON)

    explain_analysis(response, client=fake)

    call = fake.models.calls[0]
    assert call["model"] == "gemini-test-model"
    assert call["config"]["response_mime_type"] == "application/json"
    assert call["config"]["system_instruction"] == SYSTEM_INSTRUCTION


# --- Regression: MAX_TOKENS truncation (thinking-token budget) --------------


def test_truncated_json_from_a_max_tokens_cutoff_is_rejected_not_repaired():
    """Reproduces the exact failure mode observed live: the model's
    "thinking" tokens consumed nearly the whole max_output_tokens budget,
    finish_reason was MAX_TOKENS, and result.text was valid-looking JSON
    cut off mid-string. parse_explanation must reject this outright — it
    must never guess at or repair a truncated object."""
    truncated_text = (
        '{\n  "summary": "The provided evidence shows a basic email header '
        'record between alice@example.com and bob@example.org with a subject of'
    )

    assert parse_explanation(truncated_text) is None


def test_max_output_tokens_leaves_headroom_beyond_the_previous_insufficient_value():
    """The previous budget (900) was verified live to be consumed almost
    entirely by mandatory model "thinking" tokens, truncating the visible
    JSON before it could complete. This pins the fix at the config level
    without depending on real Gemini output shape."""
    response = _analyze(FORENSICS_EML_BYTES, "sample_with_forensics.eml")
    fake = _FakeGeminiClient(text=VALID_MODEL_JSON)

    explain_analysis(response, client=fake)

    call = fake.models.calls[0]
    # 900 was verified live to be insufficient for this model's mandatory
    # thinking-token overhead; the fixed value must comfortably clear it.
    assert call["config"]["max_output_tokens"] >= 2048
