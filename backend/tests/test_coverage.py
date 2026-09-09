"""Tests for coverage and confidence reporting."""

from pathlib import Path
from uuid import uuid4

import pytest
from httpx import AsyncClient

from app.core.coverage.reporter import (
    analyze_directory_languages,
    build_coverage_report,
    CoverageReport,
)
from app.core.source_scanner import ScanTarget, CryptoFindingData
from app.core.source_scanner.python_scanner import PythonScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_FILE = FIXTURES_DIR / "sample_crypto_code.py"


def test_analyze_directory_languages():
    """Directory inspection identifies Python files."""
    lang_counts = analyze_directory_languages(FIXTURES_DIR)
    assert "python" in lang_counts
    assert lang_counts["python"] >= 1


def test_build_coverage_report():
    """Coverage report calculates accurate metrics."""
    scanner = PythonScanner()
    res = scanner.scan(ScanTarget(path=str(SAMPLE_FILE), scan_type="source"))

    report = build_coverage_report(
        scan_id=str(uuid4()),
        target=str(SAMPLE_FILE),
        scan_type="source",
        scan_result=res,
        target_path=str(SAMPLE_FILE),
    )

    assert report.files_scanned >= 1
    assert report.coverage_pct > 0.0
    assert report.coverage_tier in ("FULL", "HIGH")
    assert report.total_findings == res.total_findings

    # Check confidence breakdown
    conf = report.confidence
    assert "average_confidence" in conf
    assert conf["high_count"] > 0
    assert conf["average_confidence"] >= 0.8

    # Check breakdowns
    assert len(report.primitive_breakdown) > 0
    assert "hash" in report.primitive_breakdown or "symmetric" in report.primitive_breakdown
    assert len(report.library_breakdown) > 0


@pytest.mark.asyncio
async def test_scan_coverage_endpoint(client: AsyncClient):
    """GET /api/scan/{id}/coverage returns valid coverage statistics."""
    # 1. Trigger source scan
    post_res = await client.post(
        "/api/scan/source",
        json={
            "path": str(SAMPLE_FILE),
            "scan_depth": "standard",
        },
    )
    assert post_res.status_code == 200
    scan_id = post_res.json()["id"]

    # 2. Query coverage endpoint
    cov_res = await client.get(f"/api/scan/{scan_id}/coverage")
    assert cov_res.status_code == 200
    cov_data = cov_res.json()

    assert cov_data["scan_id"] == scan_id
    assert cov_data["files_scanned"] >= 1
    assert cov_data["coverage_tier"] in ("FULL", "HIGH")
    assert cov_data["confidence"]["high_count"] >= 1
    assert "python" in [l["language"] for l in cov_data["languages"]]
