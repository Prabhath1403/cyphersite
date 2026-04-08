"""
Scans router — handles scan job creation and retrieval.
"""

import logging
from datetime import datetime, timedelta
from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.schemas.scan import (
    ScanCreate, ScanStatusResponse, ScanSummary,
    ScanListResponse, DashboardStats,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])

STALE_QUEUE_TIMEOUT = timedelta(minutes=2)
STALE_QUEUE_ERROR = (
    "Scan was queued but not picked up by the worker in time. "
    "Please run the scan again. If this keeps happening, check Celery worker health."
)


async def expire_stale_queued_scans(db: AsyncSession) -> int:
    """
    Mark stale queued scans as failed so they don't appear stuck forever.

    Returns:
        Number of scan jobs updated.
    """
    cutoff = datetime.utcnow() - STALE_QUEUE_TIMEOUT
    result = await db.execute(
        select(ScanJob).where(
            ScanJob.status == "queued",
            ScanJob.created_at < cutoff,
        )
    )
    stale_scans = result.scalars().all()
    now = datetime.utcnow()

    for scan in stale_scans:
        scan.status = "failed"
        scan.completed_at = now
        if not scan.error_message:
            scan.error_message = STALE_QUEUE_ERROR

    if stale_scans:
        logger.warning(
            "Marked %d stale queued scan(s) as failed",
            len(stale_scans),
        )

    return len(stale_scans)


@router.post("", response_model=ScanStatusResponse)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)):
    """
    Create a new scan job and queue it for processing.

    Args:
        payload: Scan creation payload with target and depth.
        db: Database session.

    Returns:
        Scan ID and initial status.
    """
    scan = ScanJob(
        target=payload.target,
        scan_depth=payload.scan_depth,
        status="queued",
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Queue Celery task
    try:
        from app.tasks.scan_tasks import run_full_scan
        run_full_scan.delay(str(scan.id), payload.target, payload.scan_depth)
        logger.info(f"Scan {scan.id} queued for target: {payload.target}")
    except Exception as e:
        logger.error(f"Failed to queue scan task: {e}")
        scan.status = "failed"
        scan.error_message = f"Task queue error: {str(e)}"

    return ScanStatusResponse(scan_id=scan.id, status=scan.status)


@router.get("", response_model=ScanListResponse)
async def list_scans(
    limit: int = Query(default=20, le=100),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """
    List all scan jobs with pagination.

    Args:
        limit: Maximum number of results.
        offset: Result offset.
        db: Database session.

    Returns:
        Paginated list of scan summaries.
    """
    await expire_stale_queued_scans(db)

    count_result = await db.execute(select(func.count(ScanJob.id)))
    total = count_result.scalar()

    result = await db.execute(
        select(ScanJob)
        .order_by(desc(ScanJob.created_at))
        .limit(limit)
        .offset(offset)
    )
    scans = result.scalars().all()

    return ScanListResponse(
        scans=[ScanSummary.model_validate(s) for s in scans],
        total=total,
    )


@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """
    Get dashboard overview statistics.

    Returns:
        Aggregate statistics across all scans.
    """
    await expire_stale_queued_scans(db)

    # Total scans
    scan_count = await db.execute(select(func.count(ScanJob.id)))
    total_scans = scan_count.scalar() or 0

    # Total assets
    asset_count = await db.execute(select(func.count(Asset.id)))
    total_assets = asset_count.scalar() or 0

    # Quantum safe percentage
    qs_count = await db.execute(
        select(func.count(Asset.id))
        .where(Asset.pqc_status == "QUANTUM_SAFE")
    )
    quantum_safe = qs_count.scalar() or 0
    quantum_safe_pct = (quantum_safe / max(total_assets, 1)) * 100

    # Vulnerable count
    vuln_count = await db.execute(
        select(func.count(Asset.id))
        .where(Asset.pqc_status == "VULNERABLE")
    )
    vulnerable = vuln_count.scalar() or 0

    # Recent scans
    recent_result = await db.execute(
        select(ScanJob).order_by(desc(ScanJob.created_at)).limit(10)
    )
    recent_scans = recent_result.scalars().all()

    return DashboardStats(
        total_scans=total_scans,
        total_assets=total_assets,
        quantum_safe_pct=round(quantum_safe_pct, 1),
        vulnerable_count=vulnerable,
        recent_scans=[ScanSummary.model_validate(s) for s in recent_scans],
    )


@router.get("/{scan_id}", response_model=ScanSummary)
async def get_scan(scan_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Get details for a specific scan job.

    Args:
        scan_id: UUID of the scan.
        db: Database session.

    Returns:
        Scan summary with status and results.
    """
    await expire_stale_queued_scans(db)

    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanSummary.model_validate(scan)
