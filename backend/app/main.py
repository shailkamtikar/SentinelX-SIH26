from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routes import analyze, health

app = FastAPI(
    title="SentinelX Backend",
    description="Step 1: real .eml ingestion and structured parsing.",
    version="0.1.0",
)

# Exact-match allowed origins only, never a wildcard — see
# Settings.cors_allowed_origins / CORS_ALLOWED_ORIGINS in app/config.py.
# Defaults to the local Next.js dev origin when that env var is unset, so
# local development behavior is unchanged from before this was configurable.
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(get_settings().cors_allowed_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(analyze.router)
