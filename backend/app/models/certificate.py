"""PQC Certificate database model."""

import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class PQCCertificate(Base):
    """Represents a PQC readiness certificate for a quantum-safe asset."""

    __tablename__ = "pqc_certificates"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False, unique=True)
    cert_id = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True, nullable=False)
    status = Column(String(30), nullable=False)  # FULLY_QUANTUM_SAFE, PQC_READY
    algorithms_verified = Column(JSONB, nullable=False, default=list)
    fingerprint = Column(String(128), nullable=False)  # SHA-256 hex digest
    issued_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    valid_until = Column(DateTime, nullable=False)
    badge_svg_path = Column(String(500), nullable=True)
    badge_png_path = Column(String(500), nullable=True)
    qr_path = Column(String(500), nullable=True)

    # Relationships
    asset = relationship("Asset", back_populates="pqc_certificate")

    def __repr__(self):
        return f"<PQCCertificate {self.cert_id} status={self.status}>"
