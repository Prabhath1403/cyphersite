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
from app.models.crypto_asset import CryptoAsset
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

    # If no network assets found and scan_id provided, check CryptoAsset table
    if total == 0 and scan_id:
        ca_query = select(CryptoAsset).where(CryptoAsset.scan_id == scan_id)
        ca_count_query = select(func.count(CryptoAsset.id)).where(CryptoAsset.scan_id == scan_id)
        if pqc_status:
            ca_query = ca_query.where(CryptoAsset.pqc_status == pqc_status)
            ca_count_query = ca_count_query.where(CryptoAsset.pqc_status == pqc_status)
        ca_count_res = await db.execute(ca_count_query)
        total = ca_count_res.scalar() or 0

        ca_result = await db.execute(
            ca_query.order_by(desc(CryptoAsset.risk_score))
            .limit(limit)
            .offset(offset)
        )
        ca_items = ca_result.scalars().all()
        summaries = [
            AssetSummary(
                id=c.id,
                scan_id=c.scan_id,
                hostname=c.file_path or c.hostname or c.name,
                ip_address=c.ip_address,
                port=c.line_number or c.port or 0,
                service_type=c.source_type or c.asset_type or "source_code",
                pqc_status=c.pqc_status,
                risk_score=c.risk_score,
                created_at=c.created_at,
            )
            for c in ca_items
        ]
        return AssetListResponse(assets=summaries, total=total)

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
        # Check CryptoAsset table
        ca_res = await db.execute(select(CryptoAsset).where(CryptoAsset.id == asset_id))
        ca = ca_res.scalar_one_or_none()
        if not ca:
            raise HTTPException(status_code=404, detail="Asset not found")

        cipher_list = []
        if ca.cipher_suite or ca.algorithm:
            cipher_list.append({"name": ca.cipher_suite or ca.algorithm, "encryption": ca.algorithm or ""})

        return AssetDetail(
            id=ca.id,
            scan_id=ca.scan_id,
            hostname=ca.file_path or ca.hostname or ca.name,
            ip_address=ca.ip_address,
            port=ca.line_number or ca.port or 0,
            service_type=ca.source_type or ca.asset_type or "source_code",
            tls_fingerprint=TLSFingerprint(
                tls_versions=[ca.protocol] if ca.protocol else [],
                cipher_suites=cipher_list,
                certificate={"signature_algorithm": ca.algorithm, "key_size": ca.key_size} if ca.key_size else {},
                key_exchange=ca.key_exchange or ca.usage,
            ),
            pqc_assessment=PQCAssessment(
                pqc_status=ca.pqc_status,
                risk_score=ca.risk_score,
                vulnerabilities=ca.vulnerabilities or [],
                recommendations=ca.recommendations or [],
            ),
            created_at=ca.created_at,
        )

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
