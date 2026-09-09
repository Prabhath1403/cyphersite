"""
Quantum Risk and Mosca Theorem API Router.
"""

from uuid import UUID
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import ScanJob
from app.models.crypto_asset import CryptoAsset
from app.core.risk import QuantumRiskEngine

router = APIRouter(prefix="/api/risk", tags=["risk"])


class RiskEvaluationRequest(BaseModel):
    algorithm: str = Field(..., description="Cryptographic algorithm name (e.g. RSA-2048, ML-KEM-768)")
    sensitivity: str = Field(default="MEDIUM", description="Data sensitivity level (CRITICAL, HIGH, MEDIUM, LOW)")
    is_public: bool = Field(default=False, description="Whether endpoint/usage is internet-facing")
    shelf_life_years: float = Field(default=5.0, description="Years data must remain secure (X)")
    migration_years: float = Field(default=2.0, description="Years required to migrate system (Y)")
    q_day_years: float = Field(default=8.0, description="Estimated years until Q-Day (Z)")


@router.post("/evaluate")
async def evaluate_algorithm_risk(request: RiskEvaluationRequest):
    """
    Evaluate multi-factor quantum risk and Mosca's theorem for a specific algorithm.
    """
    result = QuantumRiskEngine.evaluate_asset_risk(
        algorithm=request.algorithm,
        sensitivity=request.sensitivity,
        is_public=request.is_public,
        shelf_life_years=request.shelf_life_years,
        migration_years=request.migration_years,
        q_day_years=request.q_day_years,
    )
    return {
        "algorithm": result.algorithm,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "pqc_status": result.pqc_status,
        "quantum_break_method": result.quantum_break_method,
        "quantum_complexity": result.quantum_complexity,
        "recommended_replacement": result.recommended_replacement,
        "risk_factors": result.risk_factors,
        "regulatory_deadlines": result.regulatory_deadlines,
        "mosca": result.mosca.__dict__ if result.mosca else None,
    }


@router.get("/scan/{scan_id}")
async def get_scan_risk_profile(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate an aggregated post-quantum risk profile and Mosca theorem analysis
    for all cryptographic assets discovered in a scan.
    """
    scan_result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_res = await db.execute(
        select(CryptoAsset).where(CryptoAsset.scan_id == scan_id)
    )
    findings = findings_res.scalars().all()

    evaluated_assets = []
    mosca_violations = 0
    max_risk = 0.0

    for f in findings:
        eval_res = QuantumRiskEngine.evaluate_asset_risk(
            algorithm=f.algorithm or f.name,
            sensitivity=f.sensitivity or "MEDIUM",
            is_public=(f.source_type == "network"),
        )
        if eval_res.mosca and eval_res.mosca.is_violated:
            mosca_violations += 1
        if eval_res.risk_score > max_risk:
            max_risk = eval_res.risk_score

        evaluated_assets.append({
            "id": str(f.id),
            "name": f.name,
            "algorithm": eval_res.algorithm,
            "risk_score": eval_res.risk_score,
            "risk_level": eval_res.risk_level,
            "pqc_status": eval_res.pqc_status,
            "recommended_replacement": eval_res.recommended_replacement,
            "mosca_violated": eval_res.mosca.is_violated if eval_res.mosca else False,
        })

    return {
        "scan_id": str(scan_id),
        "target": scan.target,
        "total_assets": len(findings),
        "max_risk_score": max_risk,
        "mosca_violations_count": mosca_violations,
        "portfolio_posture": "COMPROMISED" if mosca_violations > 0 else "MANAGEABLE",
        "assets": evaluated_assets,
    }
