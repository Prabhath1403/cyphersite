"""CBOM record database model."""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


class CBOMRecord(Base):
    """Stores generated CycloneDX CBOM document for a scan."""

    __tablename__ = "cbom_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False, index=True, unique=True)
    cyclonedx_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("ScanJob", back_populates="cbom_records")

    def __repr__(self):
        return f"<CBOMRecord scan_id={self.scan_id}>"
