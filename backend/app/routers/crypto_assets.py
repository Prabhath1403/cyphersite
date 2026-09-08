"""CryptoAsset router — CRUD and listing of canonical cryptographic findings."""

import logging
from uuid import UUID
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.crypto_asset import CryptoAsset, CRYPTO_ASSET_TYPES, CRYPTO_SOURCE_TYPES
from app.models.scan import ScanJob
from app.schemas.crypto_asset import (
    CryptoAssetCreate,
    CryptoAssetResponse,
    CryptoAssetListResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/crypto-assets", tags=["crypto-assets"])


@router.get("", response_model=CryptoAssetListResponse)
async def list_crypto_assets(
    scan_id: Optional[UUID] = Query(default=None),
    asset_type: Optional[str] = Query(default=None),
    source_type: Optional[str] = Query(default=None),
    pqc_status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """
    List crypto assets with optional filtering.

    Supports filtering by scan_id, asset_type, source_type, and pqc_status.
    Results are paginated with limit/offset.
    """
    # Validate enum filter values
    if asset_type and asset_type not in CRYPTO_ASSET_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid asset_type '{asset_type}'. Must be one of: {', '.join(CRYPTO_ASSET_TYPES)}",
        )
    if source_type and source_type not in CRYPTO_SOURCE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid source_type '{source_type}'. Must be one of: {', '.join(CRYPTO_SOURCE_TYPES)}",
        )

    # Validate scan_id exists if provided
    if scan_id:
        scan_result = await db.execute(
            select(ScanJob.id).where(ScanJob.id == scan_id)
        )
        if not scan_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Scan not found")

    query = select(CryptoAsset)
    count_query = select(func.count(CryptoAsset.id))

    if scan_id:
        query = query.where(CryptoAsset.scan_id == scan_id)
        count_query = count_query.where(CryptoAsset.scan_id == scan_id)
    if asset_type:
        query = query.where(CryptoAsset.asset_type == asset_type)
        count_query = count_query.where(CryptoAsset.asset_type == asset_type)
    if source_type:
        query = query.where(CryptoAsset.source_type == source_type)
        count_query = count_query.where(CryptoAsset.source_type == source_type)
    if pqc_status:
        query = query.where(CryptoAsset.pqc_status == pqc_status)
        count_query = count_query.where(CryptoAsset.pqc_status == pqc_status)

    count_result = await db.execute(count_query)
    total = count_result.scalar()

    result = await db.execute(
        query.order_by(desc(CryptoAsset.created_at))
        .limit(limit)
        .offset(offset)
    )
    assets = result.scalars().all()

    return CryptoAssetListResponse(
        assets=[CryptoAssetResponse.model_validate(a) for a in assets],
        total=total,
    )


@router.get("/{asset_id}", response_model=CryptoAssetResponse)
async def get_crypto_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a single crypto asset by ID."""
    result = await db.execute(
        select(CryptoAsset).where(CryptoAsset.id == asset_id)
    )
    asset = result.scalar_one_or_none()

    if not asset:
        raise HTTPException(status_code=404, detail="Crypto asset not found")

    return CryptoAssetResponse.model_validate(asset)


@router.post("", response_model=CryptoAssetResponse, status_code=201)
async def create_crypto_asset(
    payload: CryptoAssetCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new crypto asset.

    Validates that the referenced scan_id exists before persisting.
    """
    # Verify scan exists
    scan_result = await db.execute(
        select(ScanJob.id).where(ScanJob.id == payload.scan_id)
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    asset = CryptoAsset(
        scan_id=payload.scan_id,
        asset_type=payload.asset_type.value,
        source_type=payload.source_type.value,
        name=payload.name,
        version=payload.version,
        algorithm=payload.algorithm,
        algorithm_family=payload.algorithm_family,
        key_size=payload.key_size,
        key_type=payload.key_type,
        hash_algorithm=payload.hash_algorithm,
        key_exchange=payload.key_exchange,
        cipher_suite=payload.cipher_suite,
        protocol=payload.protocol,
        library=payload.library,
        library_version=payload.library_version,
        source_location=payload.source_location,
        file_path=payload.file_path,
        line_number=payload.line_number,
        function_name=payload.function_name,
        language=payload.language,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        port=payload.port,
        pqc_status=payload.pqc_status,
        risk_score=payload.risk_score,
        vulnerabilities=payload.vulnerabilities,
        recommendations=payload.recommendations,
        business_criticality=payload.business_criticality,
        data_sensitivity=payload.data_sensitivity,
        data_lifetime_years=payload.data_lifetime_years,
        migration_time_months=payload.migration_time_months,
        details=payload.details,
    )
    db.add(asset)
    await db.flush()
    await db.refresh(asset)

    return CryptoAssetResponse.model_validate(asset)
