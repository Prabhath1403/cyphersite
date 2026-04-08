"""Pydantic schemas for asset data."""

from datetime import datetime
from typing import Optional, List, Any, Dict
from uuid import UUID

from pydantic import BaseModel


class AssetSummary(BaseModel):
    """Summary view of a discovered asset."""
    id: UUID
    scan_id: UUID
    hostname: str
    ip_address: Optional[str] = None
    port: int
    service_type: str
    pqc_status: Optional[str] = None
    risk_score: Optional[float] = None
    created_at: datetime

    class Config:
        from_attributes = True


class TLSFingerprint(BaseModel):
    """Detailed TLS fingerprint data."""
    tls_versions: Optional[List[str]] = None
    cipher_suites: Optional[List[Dict[str, Any]]] = None
    certificate: Optional[Dict[str, Any]] = None
    key_exchange: Optional[str] = None
    cert_chain_length: Optional[int] = None
    hsts_enabled: Optional[str] = None
    ocsp_stapling: Optional[str] = None


class PQCAssessment(BaseModel):
    """PQC assessment details."""
    pqc_status: Optional[str] = None
    risk_score: Optional[float] = None
    vulnerabilities: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None


class AssetDetail(BaseModel):
    """Full asset detail including TLS fingerprint and PQC assessment."""
    id: UUID
    scan_id: UUID
    hostname: str
    ip_address: Optional[str] = None
    port: int
    service_type: str
    tls_fingerprint: TLSFingerprint
    pqc_assessment: PQCAssessment
    created_at: datetime

    class Config:
        from_attributes = True


class AssetListResponse(BaseModel):
    """Response for listing assets."""
    assets: List[AssetSummary]
    total: int
