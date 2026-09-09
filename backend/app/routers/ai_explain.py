"""
AI Cryptographic Explanation and Post-Quantum Advisory Router.
"""

from uuid import UUID
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import ScanJob
from app.models.crypto_asset import CryptoAsset
from app.core.ai.explainer import AIExplanationAgent
from app.schemas.ai import (
    AIExplainFindingRequest,
    AIExplainScanRequest,
    AIQueryRequest,
    AIExplanationResponse,
    AIScanSummaryResponse,
    AIQueryResponse,
)

router = APIRouter(prefix="/api/ai", tags=["ai"])
agent = AIExplanationAgent()


@router.post("/explain", response_model=AIExplanationResponse)
async def explain_finding(
    request: AIExplainFindingRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate an in-depth, scientifically rigorous explanation of quantum vulnerability,
    Shor/Grover algorithmic mechanics, HNDL risk, and tailored remediation.
    """
    finding_dict: Dict[str, Any] = {}

    if request.finding_id:
        try:
            fid = UUID(request.finding_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid finding UUID")

        res = await db.execute(select(CryptoAsset).where(CryptoAsset.id == fid))
        asset = res.scalar_one_or_none()
        if not asset:
            raise HTTPException(status_code=404, detail="Crypto asset finding not found")

        finding_dict = {
            "id": str(asset.id),
            "name": asset.name,
            "algorithm": asset.algorithm,
            "key_size": asset.key_size,
            "primitive": asset.primitive,
            "quantum_status": asset.quantum_status or asset.pqc_status,
            "sensitivity": asset.sensitivity,
            "source_type": asset.source_type,
            "file_path": asset.file_path,
            "usage": asset.usage,
        }
    elif request.finding_data:
        finding_dict = request.finding_data
    else:
        raise HTTPException(
            status_code=400,
            detail="Either finding_id or finding_data must be provided in the request body",
        )

    explanation = await agent.explain_finding(
        finding_dict,
        target_audience=request.target_audience or "developer",
        use_llm=request.use_llm,
    )
    return explanation


@router.get("/finding/{finding_id}", response_model=AIExplanationResponse)
async def explain_finding_by_id(
    finding_id: UUID,
    audience: str = Query("developer", pattern="^(developer|executive|auditor)$"),
    use_llm: bool = Query(False),
    db: AsyncSession = Depends(get_db),
):
    """
    Convenience endpoint to retrieve an AI explanation for an existing finding by UUID.
    """
    res = await db.execute(select(CryptoAsset).where(CryptoAsset.id == finding_id))
    asset = res.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Crypto asset finding not found")

    finding_dict = {
        "id": str(asset.id),
        "name": asset.name,
        "algorithm": asset.algorithm,
        "key_size": asset.key_size,
        "primitive": asset.primitive,
        "quantum_status": asset.quantum_status or asset.pqc_status,
        "sensitivity": asset.sensitivity,
        "source_type": asset.source_type,
        "file_path": asset.file_path,
        "usage": asset.usage,
    }

    return await agent.explain_finding(
        finding_dict,
        target_audience=audience,
        use_llm=use_llm,
    )


@router.get("/scan/{scan_id}/summary", response_model=AIScanSummaryResponse)
async def get_scan_ai_summary(
    scan_id: UUID,
    use_llm: bool = Query(False),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate an executive-ready post-quantum readiness report for an entire scan job.
    """
    scan_res = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = scan_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")

    assets_res = await db.execute(select(CryptoAsset).where(CryptoAsset.scan_id == scan_id))
    assets = assets_res.scalars().all()

    findings_list = [
        {
            "id": str(a.id),
            "name": a.name,
            "algorithm": a.algorithm,
            "key_size": a.key_size,
            "primitive": a.primitive,
            "quantum_status": a.quantum_status or a.pqc_status,
            "sensitivity": a.sensitivity,
            "source_type": a.source_type,
            "file_path": a.file_path,
        }
        for a in assets
    ]

    return await agent.explain_scan_summary(
        scan_id=str(scan_id),
        findings=findings_list,
        use_llm=use_llm,
    )


@router.post("/query", response_model=AIQueryResponse)
async def query_cryptographic_posture(
    request: AIQueryRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Ask natural language questions about Shor/Grover algorithms, Mosca's theorem,
    post-quantum migrations, and cryptographic findings.
    """
    scan_context = None
    if request.scan_id:
        try:
            sid = UUID(request.scan_id)
            scan_res = await db.execute(select(ScanJob).where(ScanJob.id == sid))
            scan = scan_res.scalar_one_or_none()
            if scan:
                scan_context = {"scan_id": str(sid), "target": scan.target, "status": scan.status}
        except ValueError:
            pass

    return await agent.answer_query(
        query=request.query,
        scan_context=scan_context,
        use_llm=request.use_llm,
    )
