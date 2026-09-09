"""
Cryptographic Dependency Graph Router.
"""

from uuid import UUID
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import ScanJob
from app.models.crypto_asset import CryptoAsset
from app.core.graph import GraphEngine

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("/{scan_id}")
async def get_scan_graph(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate and retrieve the cryptographic topology and dependency graph
    for a specific scan job.
    """
    scan_result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_res = await db.execute(
        select(CryptoAsset).where(CryptoAsset.scan_id == scan_id)
    )
    findings = findings_res.scalars().all()

    graph = GraphEngine.build_graph(
        findings=findings,
        target_name=scan.target,
        scan_id=str(scan.id),
    )
    return graph.to_dict()


@router.get("")
async def get_enterprise_graph(
    limit: int = 150,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate and retrieve an aggregated enterprise-wide cryptographic graph
    across recent scans.
    """
    findings_res = await db.execute(
        select(CryptoAsset)
        .order_by(desc(CryptoAsset.created_at))
        .limit(limit)
    )
    findings = findings_res.scalars().all()

    graph = GraphEngine.build_graph(
        findings=findings,
        target_name="Enterprise Portfolio",
    )
    return graph.to_dict()
