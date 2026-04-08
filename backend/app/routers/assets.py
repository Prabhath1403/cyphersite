"""
Assets router — handles asset listing and detail views.
"""

import logging
from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.asset import Asset
from app.schemas.asset import (
    AssetSummary, AssetDetail, AssetListResponse,
    TLSFingerprint, PQCAssessment,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("", response_model=AssetListResponse)
async def list_assets(
    scan_id: Optional[UUID] = Query(default=None),
    pqc_status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """
    List assets with optional filtering by scan ID and PQC status.

    Args:
        scan_id: Optional scan ID filter.
        pqc_status: Optional PQC status filter.
        limit: Maximum results.
        offset: Result offset.
        db: Database session.

    Returns:
        Paginated list of asset summaries.
    """
    query = select(Asset)
    count_query = select(func.count(Asset.id))

    if scan_id:
        query = query.where(Asset.scan_id == scan_id)
        count_query = count_query.where(Asset.scan_id == scan_id)

    if pqc_status:
        query = query.where(Asset.pqc_status == pqc_status)
        count_query = count_query.where(Asset.pqc_status == pqc_status)

    count_result = await db.execute(count_query)
    total = count_result.scalar()

    result = await db.execute(
        query.order_by(desc(Asset.created_at))
        .limit(limit)
        .offset(offset)
    )
    assets = result.scalars().all()

    return AssetListResponse(
        assets=[AssetSummary.model_validate(a) for a in assets],
        total=total,
    )


@router.get("/{asset_id}", response_model=AssetDetail)
async def get_asset_detail(asset_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Get full details for an asset including TLS fingerprint and PQC assessment.

    Args:
        asset_id: UUID of the asset.
        db: Database session.

    Returns:
        Full asset detail with TLS and PQC data.
    """
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    return AssetDetail(
        id=asset.id,
        scan_id=asset.scan_id,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
        port=asset.port,
        service_type=asset.service_type,
        tls_fingerprint=TLSFingerprint(
            tls_versions=asset.tls_versions,
            cipher_suites=asset.cipher_suites,
            certificate=asset.certificate,
            key_exchange=asset.key_exchange,
            cert_chain_length=asset.cert_chain_length,
            hsts_enabled=asset.hsts_enabled,
            ocsp_stapling=asset.ocsp_stapling,
        ),
        pqc_assessment=PQCAssessment(
            pqc_status=asset.pqc_status,
            risk_score=asset.risk_score,
            vulnerabilities=asset.vulnerabilities,
            recommendations=asset.recommendations,
        ),
        created_at=asset.created_at,
    )
