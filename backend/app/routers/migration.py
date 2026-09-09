"""
Cryptographic Migration Recommender Router.
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
from app.core.migration import MigrationRecommender

router = APIRouter(prefix="/api/migration", tags=["migration"])


class AdHocRecommendRequest(BaseModel):
    algorithm: str = Field(..., description="Algorithm name to migrate (e.g. RSA-2048, AES-128)")
    usage: Optional[str] = Field(default="digital_signature", description="Usage context")
    sensitivity: Optional[str] = Field(default="HIGH", description="Data sensitivity level")
    source_type: Optional[str] = Field(default="source_code", description="Finding source type")
    risk_score: Optional[float] = Field(default=80.0, description="Risk score")


@router.get("/plan/{scan_id}")
async def get_scan_migration_plan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate an actionable, prioritized post-quantum migration plan for all
    findings discovered in a scan job.
    """
    scan_result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_res = await db.execute(
        select(CryptoAsset).where(CryptoAsset.scan_id == scan_id)
    )
    findings = findings_res.scalars().all()

    actions = MigrationRecommender.generate_plan_for_findings(findings)

    total_hours = sum(a.estimated_effort_hours for a in actions)
    p0_count = sum(1 for a in actions if a.priority == "P0_CRITICAL")
    p1_count = sum(1 for a in actions if a.priority == "P1_HIGH")

    return {
        "scan_id": str(scan_id),
        "target": scan.target,
        "total_actions": len(actions),
        "total_estimated_effort_hours": total_hours,
        "p0_critical_count": p0_count,
        "p1_high_count": p1_count,
        "actions": [a.__dict__ for a in actions],
    }


@router.post("/recommend")
async def recommend_ad_hoc(request: AdHocRecommendRequest):
    """
    Generate an immediate post-quantum migration recommendation and code snippet.
    """
    action = MigrationRecommender.recommend_for_finding({
        "name": request.algorithm,
        "algorithm": request.algorithm,
        "usage": request.usage,
        "sensitivity": request.sensitivity,
        "source_type": request.source_type,
        "risk_score": request.risk_score,
    })
    return action.__dict__
