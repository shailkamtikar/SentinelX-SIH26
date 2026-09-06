from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.services.eml_parser import parse_eml_bytes
from app.services.email_forensics import parse_email_forensics

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
        forensics = parse_email_forensics(raw_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unable to parse email: the file is not a valid RFC-822/MIME message.",
        ) from exc

    response = parsed.to_dict()
    response["forensics"] = forensics.to_dict()
    return response
