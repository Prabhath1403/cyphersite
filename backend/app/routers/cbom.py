"""
CBOM router — handles CBOM document retrieval and export.
"""

import json
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.cbom import CBOMRecord
from app.core.cbom.exporter import export_csv
from app.core.cbom.pdf_report import generate_pdf_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/cbom", tags=["cbom"])


@router.get("/{scan_id}")
async def get_cbom(
    scan_id: UUID,
    format: str = Query(default="json", regex="^(json|csv|pdf)$"),
    db: AsyncSession = Depends(get_db),
):
    """
    Get CBOM document for a scan in the requested format.

    Supports JSON (CycloneDX), CSV (tabular), and PDF (report) formats.

    Args:
        scan_id: UUID of the scan.
        format: Output format — json, csv, or pdf.
        db: Database session.

    Returns:
        CBOM document in the requested format.
    """
    result = await db.execute(
        select(CBOMRecord).where(CBOMRecord.scan_id == scan_id)
    )
    cbom_record = result.scalar_one_or_none()

    if not cbom_record:
        raise HTTPException(status_code=404, detail="CBOM not found for this scan")

    cbom_data = json.loads(cbom_record.cyclonedx_json)

    if format == "json":
        return Response(
            content=json.dumps(cbom_data, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=cbom_{scan_id}.json"
            },
        )

    elif format == "csv":
        csv_content = export_csv(cbom_data)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=cbom_{scan_id}.csv"
            },
        )

    elif format == "pdf":
        pdf_bytes = generate_pdf_report(cbom_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=cbom_report_{scan_id}.pdf"
            },
        )
