"""
CipherSight — Quantum-Proof Cryptographic Scanner.

FastAPI application entry point with CORS, router registration,
static file serving, and lifecycle management.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import init_db
from app.routers import scans, assets, cbom, certificates, ws, crypto_assets, source_scan, graph, risk, migration, remediation

# CRITICAL: Import all models so Base.metadata knows about them
# before init_db() calls create_all(). Without this, no tables are created.
import app.models  # noqa: F401 — triggers models/__init__.py imports

# Setup logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown events."""
    logger.info("🚀 CipherSight starting up...")
    # Create database tables
    await init_db()
    # Ensure artifacts directory exists
    os.makedirs(settings.ARTIFACTS_DIR, exist_ok=True)
    logger.info("✅ Database initialized, artifacts directory ready")
    yield
    logger.info("🛑 CipherSight shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Quantum-Proof Cryptographic Scanner and CBOM Generator. "
        "Scans public-facing assets to assess Post-Quantum Cryptography readiness "
        "and generates CycloneDX Cryptographic Bill of Materials."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(scans.router)
app.include_router(assets.router)
app.include_router(cbom.router)
app.include_router(certificates.router)
app.include_router(ws.router)
app.include_router(crypto_assets.router)
app.include_router(source_scan.router)
app.include_router(graph.router)
app.include_router(risk.router)
app.include_router(migration.router)
app.include_router(remediation.router)

# Mount artifacts directory for badge/QR serving
if os.path.exists(settings.ARTIFACTS_DIR):
    app.mount(
        "/artifacts",
        StaticFiles(directory=settings.ARTIFACTS_DIR),
        name="artifacts",
    )


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
