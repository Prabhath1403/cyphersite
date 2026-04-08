"""
Certificates router — handles PQC certificate retrieval and verification.
"""

import logging
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.certificate import PQCCertificate
from app.models.asset import Asset
from app.schemas.cbom import CertificateResponse, CertificateVerifyResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/certificates", tags=["certificates"])


@router.get("/verify/{cert_id}", response_model=CertificateVerifyResponse)
async def verify_certificate(cert_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Public certificate verification endpoint.

    Verifies certificate integrity and validity period.

    Args:
        cert_id: Certificate UUID.
        db: Database session.

    Returns:
        Certificate verification result.
    """
    result = await db.execute(
        select(PQCCertificate)
        .where(PQCCertificate.cert_id == cert_id)
        .options(selectinload(PQCCertificate.asset))
    )
    cert = result.scalar_one_or_none()

    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")

    is_valid = datetime.utcnow() < cert.valid_until

    return CertificateVerifyResponse(
        cert_id=cert.cert_id,
        status=cert.status,
        asset_hostname=cert.asset.hostname if cert.asset else "unknown",
        algorithms_verified=cert.algorithms_verified or [],
        fingerprint=cert.fingerprint,
        issued_at=cert.issued_at,
        valid_until=cert.valid_until,
        is_valid=is_valid,
    )


@router.get("/{asset_id}", response_model=CertificateResponse)
async def get_certificate(asset_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Get PQC certificate for an asset.

    Args:
        asset_id: UUID of the asset.
        db: Database session.

    Returns:
        Certificate data with badge URLs.
    """
    result = await db.execute(
        select(PQCCertificate).where(PQCCertificate.asset_id == asset_id)
    )
    cert = result.scalar_one_or_none()

    if not cert:
        raise HTTPException(status_code=404, detail="No certificate found for this asset")

    return CertificateResponse(
        id=cert.id,
        asset_id=cert.asset_id,
        cert_id=cert.cert_id,
        status=cert.status,
        algorithms_verified=cert.algorithms_verified or [],
        fingerprint=cert.fingerprint,
        issued_at=cert.issued_at,
        valid_until=cert.valid_until,
        badge_svg_url=f"/artifacts/certs/{asset_id}/badge.svg" if cert.badge_svg_path else None,
        badge_png_url=f"/artifacts/certs/{asset_id}/badge.png" if cert.badge_png_path else None,
        qr_url=f"/artifacts/certs/{asset_id}/qr.png" if cert.qr_path else None,
    )


@router.get("/{asset_id}/badge")
async def get_badge(asset_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Get the PQC badge image for an asset.

    Args:
        asset_id: UUID of the asset.
        db: Database session.

    Returns:
        SVG badge file.
    """
    result = await db.execute(
        select(PQCCertificate).where(PQCCertificate.asset_id == asset_id)
    )
    cert = result.scalar_one_or_none()

    if not cert or not cert.badge_svg_path:
        raise HTTPException(status_code=404, detail="Badge not found")

    return FileResponse(cert.badge_svg_path, media_type="image/svg+xml")


@router.get("/{asset_id}/qr")
async def get_qr_code(asset_id: UUID, db: AsyncSession = Depends(get_db)):
    """
    Get the QR code image for an asset's certificate.

    Args:
        asset_id: UUID of the asset.
        db: Database session.

    Returns:
        PNG QR code file.
    """
    result = await db.execute(
        select(PQCCertificate).where(PQCCertificate.asset_id == asset_id)
    )
    cert = result.scalar_one_or_none()

    if not cert or not cert.qr_path:
        raise HTTPException(status_code=404, detail="QR code not found")

    return FileResponse(cert.qr_path, media_type="image/png")
