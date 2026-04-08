"""Asset database model for discovered cryptographic endpoints."""

import uuid
from datetime import datetime

from sqlalchemy import Column, String, Integer, DateTime, Text, Float, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.database import Base


class Asset(Base):
    """Represents a discovered cryptographic endpoint/asset."""

    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False, index=True)
    hostname = Column(String(500), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    port = Column(Integer, nullable=False, default=443)
    service_type = Column(String(20), nullable=False, default="web_server")
    # web_server, api, vpn, mail, ldap, other

    # TLS fingerprint data
    tls_versions = Column(JSONB, nullable=True)  # List of TLS versions
    cipher_suites = Column(JSONB, nullable=True)  # List of cipher suite details
    certificate = Column(JSONB, nullable=True)  # Certificate details
    key_exchange = Column(String(100), nullable=True)
    cert_chain_length = Column(Integer, nullable=True)
    hsts_enabled = Column(String(10), nullable=True)
    ocsp_stapling = Column(String(10), nullable=True)

    # PQC assessment
    pqc_status = Column(String(20), nullable=True)  # QUANTUM_SAFE, HYBRID_READY, VULNERABLE
    risk_score = Column(Float, nullable=True)  # 0-100
    vulnerabilities = Column(JSONB, nullable=True)  # List of vulnerability descriptions
    recommendations = Column(JSONB, nullable=True)  # List of remediation steps

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("ScanJob", back_populates="assets")
    pqc_certificate = relationship("PQCCertificate", back_populates="asset", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Asset {self.hostname}:{self.port} pqc={self.pqc_status}>"
