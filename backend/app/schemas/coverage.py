"""Schemas for coverage and confidence reporting."""

from typing import List, Dict, Optional, Any
from uuid import UUID
from pydantic import BaseModel, Field


class ConfidenceDistributionSchema(BaseModel):
    average_confidence: float = Field(..., description="Mean confidence score (0.0 to 1.0)")
    high_count: int = Field(..., description="Findings with confidence >= 0.8")
    medium_count: int = Field(..., description="Findings with 0.5 <= confidence < 0.8")
    low_count: int = Field(..., description="Findings with confidence < 0.5")


class LanguageCoverageSchema(BaseModel):
    language: str
    files_count: int
    supported: bool
    scanner: Optional[str] = None


class CoverageReportResponse(BaseModel):
    scan_id: Optional[str] = None
    target: str
    scan_type: str = "source"
    files_discovered: int
    files_scanned: int
    files_skipped: int
    coverage_pct: float
    coverage_tier: str  # FULL, HIGH, PARTIAL, LOW
    languages: List[LanguageCoverageSchema] = []
    confidence: ConfidenceDistributionSchema
    primitive_breakdown: Dict[str, int] = {}
    library_breakdown: Dict[str, int] = {}
    total_findings: int
    errors: List[str] = []
    warnings: List[str] = []

    class Config:
        from_attributes = True
