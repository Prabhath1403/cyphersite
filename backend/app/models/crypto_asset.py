"""Canonical CryptoAsset model for unified cryptographic findings.

Every scanner (network, source-code, binary, container, dependency)
must convert its findings into CryptoAsset records so that downstream
consumers (CBOM generator, risk engine, Mosca analysis, PQC recommender,
migration planner) work against a single representation.
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, String, Integer, Float, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.database import Base


# ---------------------------------------------------------------------------
# Asset-type and source-type constants
# ---------------------------------------------------------------------------
# These are stored as plain strings in the database (project convention).
# Python-side validation is done via Pydantic schemas.

CRYPTO_ASSET_TYPES = (
    "algorithm",
    "key",
    "certificate",
    "protocol",
    "library",
    "dependency",
    "hsm",
    "cloud_service",
    "source_code_usage",
    "binary_usage",
    "container_usage",
    "network_endpoint",
)

CRYPTO_SOURCE_TYPES = (
    "network",
    "source_code",
    "binary",
    "container",
    "dependency",
    "manual",
)


class CryptoAsset(Base):
    """Canonical representation of a cryptographic finding.

    Flexible enough to capture discoveries from any scanner type.
    Nullable fields accommodate the varying information each scanner provides.
    """

    __tablename__ = "crypto_assets"

    # ── Identity ──────────────────────────────────────────────────────────
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id"),
        nullable=False,
        index=True,
    )
    asset_type = Column(String(30), nullable=False, index=True)
    # algorithm | key | certificate | protocol | library | dependency
    # hsm | cloud_service | source_code_usage | binary_usage
    # container_usage | network_endpoint

    source_type = Column(String(20), nullable=False, index=True)
    # network | source_code | binary | container | dependency | manual

    name = Column(String(500), nullable=False)
    version = Column(String(100), nullable=True)

    # ── Cryptographic properties ──────────────────────────────────────────
    algorithm = Column(String(100), nullable=True)
    algorithm_family = Column(String(50), nullable=True)
    key_size = Column(Integer, nullable=True)
    key_type = Column(String(50), nullable=True)
    hash_algorithm = Column(String(50), nullable=True)
    key_exchange = Column(String(100), nullable=True)
    cipher_suite = Column(String(200), nullable=True)
    protocol = Column(String(50), nullable=True)

    # ── Library properties ────────────────────────────────────────────────
    library = Column(String(200), nullable=True)
    library_version = Column(String(100), nullable=True)

    # ── Source-code provenance ────────────────────────────────────────────
    source_location = Column(String(500), nullable=True)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    function_name = Column(String(200), nullable=True)
    language = Column(String(50), nullable=True)

    # ── Network information ───────────────────────────────────────────────
    hostname = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)
    port = Column(Integer, nullable=True)

    # ── Security / PQC ────────────────────────────────────────────────────
    pqc_status = Column(String(20), nullable=True, index=True)
    # QUANTUM_SAFE | HYBRID_READY | VULNERABLE | UNKNOWN
    risk_score = Column(Float, nullable=True, index=True)  # 0.0 – 100.0
    vulnerabilities = Column(JSONB, nullable=True)  # list of strings
    recommendations = Column(JSONB, nullable=True)  # list of strings

    # ── Future business-risk fields (data model only) ─────────────────────
    business_criticality = Column(String(20), nullable=True)
    # critical | high | medium | low
    data_sensitivity = Column(String(20), nullable=True)
    # top_secret | secret | confidential | public
    data_lifetime_years = Column(Integer, nullable=True)
    migration_time_months = Column(Integer, nullable=True)

    # ── Metadata ──────────────────────────────────────────────────────────
    details = Column(JSONB, nullable=True)  # scanner-specific extra data
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # ── Relationships ─────────────────────────────────────────────────────
    scan = relationship("ScanJob", back_populates="crypto_assets")

    def __repr__(self) -> str:
        return (
            f"<CryptoAsset {self.asset_type}/{self.source_type} "
            f"name={self.name!r} pqc={self.pqc_status}>"
        )
