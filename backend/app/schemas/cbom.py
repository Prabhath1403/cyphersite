"""Pydantic schemas for CBOM data."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

from pydantic import BaseModel


class CBOMResponse(BaseModel):
    """Response schema for CBOM data."""
    id: UUID
    scan_id: UUID
    created_at: datetime
    cyclonedx_json: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class CertificateResponse(BaseModel):
    """Response schema for PQC certificate data."""
    id: UUID
    asset_id: UUID
    cert_id: UUID
    status: str
    algorithms_verified: List[str]
    fingerprint: str
    issued_at: datetime
    valid_until: datetime
    badge_svg_url: Optional[str] = None
    badge_png_url: Optional[str] = None
    qr_url: Optional[str] = None

    class Config:
        from_attributes = True


class CertificateVerifyResponse(BaseModel):
    """Public certificate verification response."""
    cert_id: UUID
    status: str
    asset_hostname: str
    algorithms_verified: List[str]
    fingerprint: str
    issued_at: datetime
    valid_until: datetime
    is_valid: bool
