"""Pydantic schemas for AI Cryptographic Explanation Agent."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AIExplainFindingRequest(BaseModel):
    """Request payload for finding-level explanation."""
    finding_id: Optional[str] = Field(None, description="UUID of the CryptoAsset finding if stored in database")
    finding_data: Optional[Dict[str, Any]] = Field(None, description="Raw finding dictionary if explaining in-memory finding")
    target_audience: Optional[str] = Field("developer", description="developer | executive | auditor")
    use_llm: bool = Field(False, description="Whether to attempt LLM augmentation if provider is configured")


class AIExplainScanRequest(BaseModel):
    """Request payload for scan-level summary explanation."""
    scan_id: str = Field(..., description="UUID of the scan job")
    use_llm: bool = Field(False, description="Whether to attempt LLM augmentation if provider is configured")


class AIQueryRequest(BaseModel):
    """Request payload for cryptographic query / Q&A."""
    query: str = Field(..., description="Natural language question about cryptography, PQC, or scan findings")
    scan_id: Optional[str] = Field(None, description="Optional scan ID context")
    finding_id: Optional[str] = Field(None, description="Optional finding ID context")
    use_llm: bool = Field(False, description="Whether to attempt LLM augmentation if provider is configured")


class TheoreticalFoundation(BaseModel):
    attack_algorithm: str
    mathematical_basis: str
    quantum_complexity: str
    qubits_required_estimate: str


class HNDLRisk(BaseModel):
    hndl_exposure: str
    threat_description: str
    confidentiality_impact: str


class RegulatoryImplications(BaseModel):
    cnsa_deadline: str
    nist_standard: str
    compliance_summary: str


class TailoredRemediation(BaseModel):
    recommended_replacement: str
    target_standard: str
    migration_urgency: str
    code_snippet: str
    configuration_changes: str


class AIExplanationResponse(BaseModel):
    """Full AI explanation for a single finding."""
    finding_id: Optional[str] = None
    algorithm: str
    primitive: Optional[str] = None
    key_size: Optional[int] = None
    quantum_status: str
    quantum_vulnerability_summary: str
    theoretical_foundation: TheoreticalFoundation
    harvest_now_decrypt_later_risk: HNDLRisk
    regulatory_implications: RegulatoryImplications
    tailored_remediation: TailoredRemediation
    confidence_score: float
    engine: str


class AIScanSummaryResponse(BaseModel):
    """Scan-wide executive AI summary."""
    scan_id: str
    total_findings: int
    vulnerable_findings_count: int
    quantum_safe_count: int
    executive_summary: str
    quantum_readiness_posture: str
    primary_quantum_vectors: List[str]
    recommended_priority_actions: List[str]
    engine: str


class AIQueryResponse(BaseModel):
    """Answer to a free-form question about cryptography and PQC."""
    query: str
    answer: str
    references: List[str]
    engine: str
