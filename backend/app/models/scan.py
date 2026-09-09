"""Scan job database model."""

import uuid
from datetime import datetime

from sqlalchemy import Column, String, Integer, DateTime, Text, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


class ScanJob(Base):
    """Represents a scan job submitted by a user."""

    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target = Column(String(500), nullable=False, index=True)
    status = Column(
        String(20),
        nullable=False,
        default="queued",
        index=True,
    )  # queued, running, completed, failed
    scan_depth = Column(String(10), nullable=False, default="quick")  # quick, full
    scan_type = Column(String(50), nullable=False, default="network")  # network, source, container, binary
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    total_assets = Column(Integer, default=0)
    quantum_safe_count = Column(Integer, default=0)
    vulnerable_count = Column(Integer, default=0)
    hybrid_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    # Relationships
    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    cbom_records = relationship("CBOMRecord", back_populates="scan", cascade="all, delete-orphan")
    crypto_assets = relationship("CryptoAsset", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanJob {self.id} target={self.target} status={self.status}>"
