"""Pydantic schemas for scan operations."""

from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.core.scanner.discovery import normalize_target_input


class ScanCreate(BaseModel):
    """Schema for creating a new scan job."""
    target: str = Field(..., description="Target domain, IP, or CIDR range", min_length=1, max_length=500)
    scan_depth: str = Field(default="quick", description="Scan depth: 'quick' or 'full'", pattern="^(quick|full)$")

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        """Normalize target to a scanable host/IP representation."""
        return normalize_target_input(value)


class SourceScanCreate(BaseModel):
    """Schema for submitting a source code scan."""
    path: str = Field(..., description="Local directory path, file path, or Git repository URL", min_length=1)
    repository: Optional[str] = Field(None, description="Repository identifier or display name")
    scan_depth: str = Field(default="standard", description="Scan depth: quick, standard, deep")


class ScanStatusResponse(BaseModel):
    """Schema for scan creation response."""
    scan_id: UUID
    status: str


class ScanSummary(BaseModel):
    """Summary view of a scan job."""
    id: UUID
    target: str
    status: str
    scan_depth: str
    scan_type: str = "network"
    created_at: datetime
    completed_at: Optional[datetime] = None
    total_assets: int = 0
    quantum_safe_count: int = 0
    vulnerable_count: int = 0
    hybrid_count: int = 0
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Response for listing scans."""
    scans: List[ScanSummary]
    total: int


class DashboardStats(BaseModel):
    """Dashboard overview statistics."""
    total_scans: int
    total_assets: int
    quantum_safe_pct: float
    vulnerable_count: int
    recent_scans: List[ScanSummary]
