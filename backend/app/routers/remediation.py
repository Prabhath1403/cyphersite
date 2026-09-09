"""
Developer Remediation and GitHub Issue Router.
"""

from uuid import UUID
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import ScanJob
from app.models.crypto_asset import CryptoAsset
from app.core.github import GitHubIssueCreator, GitHubIssuePayload

router = APIRouter(prefix="/api/remediation", tags=["remediation"])


class PublishIssueRequest(BaseModel):
    owner: str = Field(..., description="GitHub repository owner or organization")
    repo: str = Field(..., description="GitHub repository name")
    github_token: str = Field(..., description="GitHub Personal Access Token")
    title: str
    body: str
    labels: List[str] = Field(default_factory=list)


@router.get("/finding/{finding_id}/issue-preview")
async def preview_finding_issue(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a markdown GitHub Issue preview for a specific finding.
    """
    res = await db.execute(select(CryptoAsset).where(CryptoAsset.id == finding_id))
    asset = res.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Crypto asset finding not found")

    issue = GitHubIssueCreator.generate_issue_for_finding(asset)
    return issue.to_dict()


@router.post("/publish")
async def publish_github_issue(request: PublishIssueRequest):
    """
    Publish a cryptographic remediation issue to a remote GitHub repository.
    """
    payload = GitHubIssuePayload(
        title=request.title,
        body=request.body,
        labels=request.labels,
    )
    result = await GitHubIssueCreator.publish_issue_to_github(
        owner=request.owner,
        repo=request.repo,
        token=request.github_token,
        issue=payload,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=result.get("status_code", 500),
            detail=result.get("error", "Failed to publish issue to GitHub"),
        )
    return result


@router.get("/scan/{scan_id}/export-issues")
async def export_scan_issues(
    scan_id: UUID,
    min_priority: str = "P1_HIGH",
    db: AsyncSession = Depends(get_db),
):
    """
    Export all prioritized GitHub remediation issues for a scan.
    """
    res = await db.execute(select(CryptoAsset).where(CryptoAsset.scan_id == scan_id))
    findings = res.scalars().all()

    issues = []
    for f in findings:
        issue = GitHubIssueCreator.generate_issue_for_finding(f)
        issues.append(issue.to_dict())

    return {
        "scan_id": str(scan_id),
        "total_issues": len(issues),
        "issues": issues,
    }
