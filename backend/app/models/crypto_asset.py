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

    # ── Extended crypto properties (unified platform) ─────────────────────
    primitive = Column(String(30), nullable=True)
    # symmetric | asymmetric | hash | mac | kdf | protocol | signature
    mode = Column(String(30), nullable=True)       # GCM | CBC | CTR | CFB | ECB | etc.
    padding = Column(String(30), nullable=True)     # PKCS7 | OAEP | PSS | PKCS1v15 | etc.
    usage = Column(String(50), nullable=True)
    # encryption | signing | key_exchange | hashing | authentication | tls | jwt | etc.

    # ── Library properties ────────────────────────────────────────────────
    library = Column(String(200), nullable=True)
    library_version = Column(String(100), nullable=True)

    # ── Source-code provenance ────────────────────────────────────────────
    repository = Column(String(500), nullable=True)   # repo URL or identifier
    source_location = Column(String(500), nullable=True)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    function_name = Column(String(200), nullable=True)
    language = Column(String(50), nullable=True)

    # ── Network information ───────────────────────────────────────────────
    hostname = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)
    port = Column(Integer, nullable=True)

    # ── Detection confidence ──────────────────────────────────────────────
    confidence = Column(Float, nullable=True)  # 0.0 – 1.0
    evidence = Column(JSONB, nullable=True)    # structured evidence payload

    # ── Security / PQC ────────────────────────────────────────────────────
    pqc_status = Column(String(20), nullable=True, index=True)
    # QUANTUM_SAFE | HYBRID_READY | VULNERABLE | UNKNOWN
    quantum_status = Column(String(30), nullable=True)
    # vulnerable | reduced_security_margin | safe | unknown
    risk_score = Column(Float, nullable=True, index=True)  # 0.0 – 100.0
    risk_level = Column(String(10), nullable=True)
    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    vulnerabilities = Column(JSONB, nullable=True)  # list of strings
    recommendations = Column(JSONB, nullable=True)  # list of strings

    # ── Sensitivity inference ─────────────────────────────────────────────
    sensitivity = Column(String(30), nullable=True)
    # government_id | financial | medical | authentication | pii | general | unknown
    sensitivity_confidence = Column(Float, nullable=True)  # 0.0 – 1.0

    # ── Business-risk fields ──────────────────────────────────────────────
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


# Type alias — new platform code can use CryptoFinding for clarity
# while the database model remains CryptoAsset for backward compatibility.
CryptoFinding = CryptoAsset
