from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.services.eml_parser import parse_eml_bytes
from app.services.email_forensics import ForensicHeaders, parse_email_forensics
from app.services.ioc_enrichment import EnrichmentReport, enrich_iocs
from app.services.ioc_extraction import IOCReport, extract_iocs
from app.services.threat_assessment import ThreatAssessment, assess_threat

router = APIRouter()

# Guard against pathological uploads; evidence files are typically small.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


@router.post("/analyze-email")
async def analyze_email(file: UploadFile = File(...)) -> dict[str, object]:
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
    return response
