"""
Source code scanning router — handles source repository scanning,
result retrieval, and CBOM generation.
"""

import json
import logging
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import ScanJob
from app.models.crypto_asset import CryptoAsset
from app.models.cbom import CBOMRecord
from app.schemas.scan import SourceScanCreate, ContainerScanCreate, BinaryScanCreate, ScanSummary
from app.schemas.crypto_asset import CryptoAssetResponse
from app.schemas.coverage import CoverageReportResponse
from app.core.source_scanner import ScanTarget
from app.core.source_scanner.python_scanner import PythonScanner
from app.core.cbom.builder import build_cbom, cbom_to_json_string

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["source-scan"])


class SourceScanDetailResponse(BaseModel):
    """Detailed response for a scan job including findings."""
    id: UUID
    target: str
    status: str
    scan_type: str
    scan_depth: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    total_assets: int = 0
    quantum_safe_count: int = 0
    hybrid_count: int = 0
    vulnerable_count: int = 0
    error_message: Optional[str] = None
    findings: List[CryptoAssetResponse] = []

    class Config:
        from_attributes = True


@router.post("/source", response_model=SourceScanDetailResponse)
async def submit_source_scan(
    request: SourceScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Scan a Python source code repository or directory for cryptographic usages.

    Accepts:
    - A local filesystem path (e.g., ``/path/to/project`` or ``./src``)
    - A Git repository URL (e.g., ``https://github.com/org/repo.git``)

    Discovers crypto APIs, evaluates NIST PQC readiness, saves canonical
    CryptoAsset findings, and generates a CycloneDX 1.5 CBOM.
    """
    target_str = request.path.strip()
    is_git_url = target_str.startswith(("http://", "https://", "git@")) or target_str.endswith(".git")

    # Create initial scan job record
    scan = ScanJob(
        target=target_str,
        scan_type="source",
        scan_depth=request.scan_depth,
        status="running",
    )
    db.add(scan)
    await db.flush()

    temp_dir = None
    scan_path = target_str
    repo_name = request.repository or (Path(target_str).name if not is_git_url else target_str.split("/")[-1].replace(".git", ""))

    try:
        if is_git_url:
            temp_dir = tempfile.mkdtemp(prefix="ciphersight_git_")
            scan_path = temp_dir
            logger.info("Cloning Git repository %s into %s", target_str, temp_dir)
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", target_str, temp_dir],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to clone Git repository: {e}",
                )
        else:
            resolved_path = Path(target_str).resolve()
            if not resolved_path.exists():
                raise HTTPException(
                    status_code=400,
                    detail=f"Local path does not exist: {target_str}",
                )
            scan_path = str(resolved_path)

        # Execute Python source scanner
        scanner = PythonScanner()
        scan_target = ScanTarget(
            path=scan_path,
            scan_type="source",
            language="python",
            depth=request.scan_depth,
            repository=repo_name,
        )
        scan_result = scanner.scan(scan_target)

        # Convert findings to CryptoAsset ORM records
        created_assets: List[CryptoAsset] = []
        qs_count = 0
        hybrid_count = 0
        vuln_count = 0

        for f in scan_result.findings:
            orm_kwargs = f.to_orm_kwargs()
            # If path was in a temp directory, strip temp dir prefix for cleaner provenance
            if temp_dir and orm_kwargs.get("file_path"):
                rel_path = str(Path(orm_kwargs["file_path"]).relative_to(Path(temp_dir)))
                orm_kwargs["file_path"] = rel_path
                if orm_kwargs.get("source_location"):
                    orm_kwargs["source_location"] = rel_path

            crypto_asset = CryptoAsset(
                scan_id=scan.id,
                **orm_kwargs,
            )
            db.add(crypto_asset)
            created_assets.append(crypto_asset)

            # Update count metrics
            pqc = (f.pqc_status or "").upper()
            if pqc == "QUANTUM_SAFE":
                qs_count += 1
            elif pqc == "HYBRID_READY":
                hybrid_count += 1
            elif pqc == "VULNERABLE":
                vuln_count += 1
            else:
                vuln_count += 1

        # Build and persist CycloneDX CBOM
        cbom = build_cbom(
            scan_id=str(scan.id),
            target=target_str,
            assets=scan_result.findings,
        )
        cbom_json = cbom_to_json_string(cbom)
        cbom_record = CBOMRecord(
            scan_id=scan.id,
            cyclonedx_json=cbom_json,
        )
        db.add(cbom_record)

        # Update ScanJob summary
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.total_assets = len(created_assets)
        scan.quantum_safe_count = qs_count
        scan.hybrid_count = hybrid_count
        scan.vulnerable_count = vuln_count

        await db.commit()
        await db.refresh(scan)

        return SourceScanDetailResponse(
            id=scan.id,
            target=scan.target,
            status=scan.status,
            scan_type=scan.scan_type,
            scan_depth=scan.scan_depth,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            total_assets=scan.total_assets,
            quantum_safe_count=scan.quantum_safe_count,
            hybrid_count=scan.hybrid_count,
            vulnerable_count=scan.vulnerable_count,
            error_message=scan.error_message,
            findings=[CryptoAssetResponse.model_validate(a) for a in created_assets],
        )

    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        logger.exception("Error executing source scan: %s", exc)
        scan.status = "failed"
        scan.error_message = str(exc)
        scan.completed_at = datetime.utcnow()
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Source scan failed: {exc}")

    finally:
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/container", response_model=SourceScanDetailResponse)
async def submit_container_scan(
    request: ContainerScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Scan a container image (tarball, rootfs directory, or Docker image tag)
    for cryptographic libraries, installed packages, and TLS certificates.
    """
    from app.core.container_scanner import ContainerScanner

    target_str = request.image.strip()
    scan = ScanJob(
        target=target_str,
        scan_type="container",
        scan_depth=request.scan_depth,
        status="running",
    )
    db.add(scan)
    await db.flush()

    try:
        scanner = ContainerScanner()
        scan_target = ScanTarget(
            path=target_str,
            scan_type="container",
            depth=request.scan_depth,
            repository=request.repository,
        )
        scan_result = scanner.scan(scan_target)

        created_assets: List[CryptoAsset] = []
        qs_count = 0
        hybrid_count = 0
        vuln_count = 0

        for f in scan_result.findings:
            orm_kwargs = f.to_orm_kwargs()
            crypto_asset = CryptoAsset(
                scan_id=scan.id,
                **orm_kwargs,
            )
            db.add(crypto_asset)
            created_assets.append(crypto_asset)

            pqc = (f.pqc_status or "").upper()
            if pqc == "QUANTUM_SAFE":
                qs_count += 1
            elif pqc == "HYBRID_READY":
                hybrid_count += 1
            elif pqc == "VULNERABLE":
                vuln_count += 1
            else:
                vuln_count += 1

        # Build and persist CycloneDX CBOM
        cbom = build_cbom(
            scan_id=str(scan.id),
            target=target_str,
            assets=scan_result.findings,
        )
        cbom_json = cbom_to_json_string(cbom)
        cbom_record = CBOMRecord(
            scan_id=scan.id,
            cyclonedx_json=cbom_json,
        )
        db.add(cbom_record)

        # Update ScanJob
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.total_assets = len(created_assets)
        scan.quantum_safe_count = qs_count
        scan.hybrid_count = hybrid_count
        scan.vulnerable_count = vuln_count
        if scan_result.errors:
            scan.error_message = "; ".join(scan_result.errors[:3])

        await db.commit()
        await db.refresh(scan)

        return SourceScanDetailResponse(
            id=scan.id,
            target=scan.target,
            status=scan.status,
            scan_type=scan.scan_type,
            scan_depth=scan.scan_depth,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            total_assets=scan.total_assets,
            quantum_safe_count=scan.quantum_safe_count,
            hybrid_count=scan.hybrid_count,
            vulnerable_count=scan.vulnerable_count,
            error_message=scan.error_message,
            findings=[CryptoAssetResponse.model_validate(a) for a in created_assets],
        )

    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        logger.exception("Error executing container scan: %s", exc)
        scan.status = "failed"
        scan.error_message = str(exc)
        scan.completed_at = datetime.utcnow()
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Container scan failed: {exc}")


@router.post("/binary", response_model=SourceScanDetailResponse)
async def submit_binary_scan(
    request: BinaryScanCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Scan compiled binaries, shared libraries, or executables (ELF, PE, Mach-O)
    for cryptographic symbols, embedded constants, and quantum vulnerabilities.
    """
    from app.core.binary_scanner import BinaryScanner

    target_str = request.path.strip()
    scan = ScanJob(
        target=target_str,
        scan_type="binary",
        scan_depth=request.scan_depth,
        status="running",
    )
    db.add(scan)
    await db.flush()

    try:
        scanner = BinaryScanner()
        scan_target = ScanTarget(
            path=target_str,
            scan_type="binary",
            depth=request.scan_depth,
            repository=request.repository,
        )
        scan_result = scanner.scan(scan_target)

        created_assets: List[CryptoAsset] = []
        qs_count = 0
        hybrid_count = 0
        vuln_count = 0

        for f in scan_result.findings:
            orm_kwargs = f.to_orm_kwargs()
            crypto_asset = CryptoAsset(
                scan_id=scan.id,
                **orm_kwargs,
            )
            db.add(crypto_asset)
            created_assets.append(crypto_asset)

            pqc = (f.pqc_status or "").upper()
            if pqc == "QUANTUM_SAFE":
                qs_count += 1
            elif pqc == "HYBRID_READY":
                hybrid_count += 1
            elif pqc == "VULNERABLE":
                vuln_count += 1
            else:
                vuln_count += 1

        # Build and persist CycloneDX CBOM
        cbom = build_cbom(
            scan_id=str(scan.id),
            target=target_str,
            assets=scan_result.findings,
        )
        cbom_json = cbom_to_json_string(cbom)
        cbom_record = CBOMRecord(
            scan_id=scan.id,
            cyclonedx_json=cbom_json,
        )
        db.add(cbom_record)

        # Update ScanJob
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        scan.total_assets = len(created_assets)
        scan.quantum_safe_count = qs_count
        scan.hybrid_count = hybrid_count
        scan.vulnerable_count = vuln_count
        if scan_result.errors:
            scan.error_message = "; ".join(scan_result.errors[:3])

        await db.commit()
        await db.refresh(scan)

        return SourceScanDetailResponse(
            id=scan.id,
            target=scan.target,
            status=scan.status,
            scan_type=scan.scan_type,
            scan_depth=scan.scan_depth,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            total_assets=scan.total_assets,
            quantum_safe_count=scan.quantum_safe_count,
            hybrid_count=scan.hybrid_count,
            vulnerable_count=scan.vulnerable_count,
            error_message=scan.error_message,
            findings=[CryptoAssetResponse.model_validate(a) for a in created_assets],
        )

    except HTTPException:
        await db.rollback()
        raise
    except Exception as exc:
        logger.exception("Error executing binary scan: %s", exc)
        scan.status = "failed"
        scan.error_message = str(exc)
        scan.completed_at = datetime.utcnow()
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Binary scan failed: {exc}")


@router.get("/{scan_id}", response_model=SourceScanDetailResponse)
async def get_scan_details(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed results for any scan job by ID, including all findings.
    """
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(
        select(CryptoAsset)
        .where(CryptoAsset.scan_id == scan_id)
        .order_by(desc(CryptoAsset.risk_score))
    )
    findings = findings_result.scalars().all()

    return SourceScanDetailResponse(
        id=scan.id,
        target=scan.target,
        status=scan.status,
        scan_type=scan.scan_type or "network",
        scan_depth=scan.scan_depth,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        total_assets=scan.total_assets,
        quantum_safe_count=scan.quantum_safe_count,
        hybrid_count=scan.hybrid_count,
        vulnerable_count=scan.vulnerable_count,
        error_message=scan.error_message,
        findings=[CryptoAssetResponse.model_validate(f) for f in findings],
    )


@router.get("/{scan_id}/cbom")
async def get_scan_cbom(
    scan_id: UUID,
    format: str = Query(default="json", pattern="^(json|cyclonedx)$"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get the CycloneDX CBOM document for a specific scan.
    """
    result = await db.execute(
        select(CBOMRecord).where(CBOMRecord.scan_id == scan_id)
    )
    cbom_record = result.scalar_one_or_none()

    if not cbom_record:
        raise HTTPException(status_code=404, detail="CBOM not found for this scan")

    cbom_data = json.loads(cbom_record.cyclonedx_json)
    return JSONResponse(
        content=cbom_data,
        headers={
            "Content-Disposition": f"attachment; filename=cbom_{scan_id}.json"
        },
    )


@router.get("/{scan_id}/coverage", response_model=CoverageReportResponse)
async def get_scan_coverage(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Get coverage and confidence statistics for a scan.

    Tracks files discovered, scanned, and skipped; languages detected;
    and confidence distribution across all cryptographic findings.
    """
    from app.core.coverage.reporter import build_coverage_report

    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(
        select(CryptoAsset).where(CryptoAsset.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()

    report = build_coverage_report(
        scan_id=str(scan.id),
        target=scan.target,
        scan_type=scan.scan_type or "source",
        findings=findings,
        target_path=scan.target,
    )
    return CoverageReportResponse(**report.to_dict())
