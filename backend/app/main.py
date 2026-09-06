from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import analyze, health

app = FastAPI(
    title="SentinelX Backend",
    description="Step 1: real .eml ingestion and structured parsing.",
    version="0.1.0",
)

# Development CORS: only the known local Next.js origin, no wildcard.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(analyze.router)
