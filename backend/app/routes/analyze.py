import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

from app.config import get_settings
from app.services.analysis_store import persist_analysis
from app.services.auth import get_current_user_id
from app.services.eml_parser import parse_eml_bytes
from app.services.email_forensics import ForensicHeaders, parse_email_forensics
from app.services.evidence_storage import compute_raw_eml_sha256
from app.services.gemini_explainer import explain_analysis
from app.services.ioc_enrichment import EnrichmentReport, enrich_iocs
from app.services.ioc_extraction import IOCReport, extract_iocs
from app.services.threat_assessment import ThreatAssessment, assess_threat

logger = logging.getLogger(__name__)

router = APIRouter()

# Guard against pathological uploads; evidence files are typically small.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


@router.post("/analyze-email")
async def analyze_email(
    file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id),
) -> dict[str, object]:
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .eml files are accepted.",
        )

    raw_bytes = await file.read()

    if not raw_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )

    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Uploaded file exceeds the maximum allowed size.",
        )

    try:
        parsed = parse_eml_bytes(raw_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unable to parse email: the file is not a valid RFC-822/MIME message.",
        ) from exc

    # Forensics is an additive, best-effort layer: a failure here must never
    # take down an otherwise-successful core parse. Fall back to an empty
    # forensic structure rather than fabricating anything.
    try:
        forensics = parse_email_forensics(raw_bytes)
    except Exception:
        forensics = ForensicHeaders(
            authentication_results_raw=None,
            spf_result=None,
            dkim_result=None,
            dmarc_result=None,
        )

    # IOC extraction is likewise additive and best-effort: it must never
    # take down an otherwise-successful core parse.
    try:
        iocs = extract_iocs(parsed, forensics)
    except Exception:
        iocs = IOCReport()

    # Threat assessment is likewise additive and best-effort: it must never
    # take down an otherwise-successful core parse. UNKNOWN (rather than a
    # normal LOW/MEDIUM/HIGH) makes an assessment failure distinguishable
    # from an email that was actually assessed and found low-risk.
    try:
        assessment = assess_threat(forensics, iocs)
    except Exception:
        assessment = ThreatAssessment(risk_level="UNKNOWN", reasons=["assessment unavailable"])

    # IOC enrichment is likewise additive and best-effort: it must never
    # take down an otherwise-successful core parse, and a failure here must
    # never alter the already-computed iocs or threat_assessment responses.
    try:
        enrichment = enrich_iocs(iocs)
    except Exception:
        enrichment = EnrichmentReport()

    response = parsed.to_dict()
    response["forensics"] = forensics.to_dict()
    response["iocs"] = iocs.to_dict()
    response["threat_assessment"] = assessment.to_dict()
    response["enrichment"] = enrichment.to_dict()

    # Optional AI explanation. Strictly subordinate to the deterministic
    # assessment above and strictly best-effort: no key, an API failure or
    # unusable model output all resolve to null rather than invented text.
    # Added before persistence so it is captured in emails.parsed_response.
    #
    # ai_explanation_status distinguishes *why* ai_explanation is null so
    # the frontend never tells an operator to "configure GEMINI_API_KEY"
    # when it already is configured:
    #   "ok"             — an explanation was produced
    #   "not_configured" — GEMINI_API_KEY is not set
    #   "unavailable"    — configured, but the call failed or the model
    #                      returned unusable output
    try:
        explanation = explain_analysis(response)
        ai_explanation_status = "ok" if explanation else None
    except Exception as exc:
        explanation = None
        ai_explanation_status = None
        # Exception TYPE only — never str(exc), which could echo request
        # details or provider error text. Never the API key.
        logger.warning("Gemini explanation unavailable: %s", type(exc).__name__)

    if ai_explanation_status is None:
        # explain_analysis returned None cleanly (no exception): either
        # Gemini was never configured, or it was configured but the model
        # returned unusable output.
        ai_explanation_status = "not_configured" if not get_settings().gemini_configured else "unavailable"

    response["ai_explanation"] = explanation.to_dict() if explanation else None
    response["ai_explanation_status"] = ai_explanation_status

    # Persistence to Supabase happens only after the response above is
    # fully assembled, and is additive/best-effort like every stage above:
    # a database or network failure must never change this response or
    # turn a successful analysis into an HTTP error.
    outcome = None
    try:
        outcome = persist_analysis(
            raw_bytes=raw_bytes,
            filename=file.filename,
            response=response,
            user_id=user_id,
        )
    except Exception:
        pass

    # Truthful evidence status. The whole-file hash is computed locally and
    # is therefore always available, independently of Supabase. Storage is
    # reported as stored only when an object path was actually recorded —
    # and the internal path itself is never exposed to the client.
    response["evidence"] = {
        "raw_eml_sha256": compute_raw_eml_sha256(raw_bytes),
        "raw_eml_stored": bool(outcome and outcome.raw_eml_storage_path),
    }

    return response
