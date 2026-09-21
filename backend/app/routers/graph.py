"""
Cryptographic Dependency Graph Router.
"""

from uuid import UUID
from typing import Optional, List, Dict, Any

from app.core.auth.security import get_current_active_user
from app.models.user import User

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
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user),
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
    # Sync to Neo4j in background (non-blocking, non-fatal)
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, GraphEngine.sync_to_neo4j, graph)
    except Exception:
        pass

    return graph.to_dict()


@router.get("")
async def get_enterprise_graph(
    scan_id: Optional[UUID] = None,
    scope: Optional[str] = "latest",
    limit: int = 150,
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_active_user),
):
    """
    Generate and retrieve a clean, single-project cryptographic graph.
    Defaults to the latest scan job so different scans are never mashed together.
    """
    import asyncio

    # 1. If explicit scan_id requested, return that scan's graph
    if scan_id:
        return await get_scan_graph(scan_id=scan_id, db=db, current_user=current_user)

    # 2. If scope is latest (default), find the most recent scan
    if scope != "all":
        recent_scan_res = await db.execute(
            select(ScanJob).order_by(desc(ScanJob.created_at)).limit(1)
        )
        recent_scan = recent_scan_res.scalar_one_or_none()
        if recent_scan:
            return await get_scan_graph(scan_id=recent_scan.id, db=db, current_user=current_user)

    # 3. Fallback or scope == "all"
    findings_res = await db.execute(
        select(CryptoAsset)
        .order_by(desc(CryptoAsset.created_at))
        .limit(limit)
    )
    findings = findings_res.scalars().all()

    if not findings:
        return {
            "nodes": [],
            "edges": [],
            "summary": {"total_nodes": 0, "total_edges": 0, "node_types": {}, "critical_chains_count": 0},
            "critical_chains": [],
        }

    graph = GraphEngine.build_graph(
        findings=findings,
        target_name="Recent Target",
    )
    try:
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, GraphEngine.sync_to_neo4j, graph)
    except Exception:
        pass

    return graph.to_dict()

@router.get('/neo4j/health')
async def neo4j_health():
    """Check Neo4j database connectivity."""
    from app.core.graph.neo4j_client import check_neo4j_health
    return check_neo4j_health()

@router.get('/neo4j/{scan_id}')
async def get_neo4j_graph(scan_id: UUID):
    """Retrieve a graph directly from Neo4j persistent storage."""
    from app.core.graph.neo4j_client import query_graph_from_neo4j
    from fastapi import HTTPException
    result = query_graph_from_neo4j(str(scan_id))
    if result is None:
        raise HTTPException(
            status_code=503,
            detail='Neo4j is unavailable or graph not found. Use /api/graph/{scan_id} for PostgreSQL-based graphs.'
        )
    return result
