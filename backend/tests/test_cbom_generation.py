"""Tests for CBOM generation and source code scanning API."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import AsyncClient

from app.core.cbom.builder import build_cbom, cbom_to_json_string
from app.core.cbom.exporter import export_csv, export_json, extract_summary_data
from app.core.source_scanner import ScanTarget, ScanResult, CryptoFindingData
from app.core.source_scanner.python_scanner import PythonScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_FILE = FIXTURES_DIR / "sample_crypto_code.py"


def test_build_cbom_network_asset():
    """CBOM builder correctly formats network assets."""
    assets = [
        {
            "id": str(uuid4()),
            "hostname": "api.example.com",
            "port": 443,
            "service_type": "api",
            "tls_versions": ["TLSv1.3", "TLSv1.2"],
            "cipher_suites": [
                {"name": "TLS_AES_256_GCM_SHA384", "encryption": "AES-256-GCM", "key_exchange": "ECDHE"}
            ],
            "certificate": {
                "public_key_algorithm": "RSA",
                "key_size": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
            },
            "pqc_status": "HYBRID_READY",
            "risk_score": 35.0,
            "vulnerabilities": ["Uses RSA certificate vulnerable to Shor's algorithm"],
            "recommendations": ["Migrate to ML-DSA certificate"],
        }
    ]

    cbom = build_cbom(scan_id=str(uuid4()), target="api.example.com", assets=assets)

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.5"
    assert len(cbom["components"]) == 1

    comp = cbom["components"][0]
    assert comp["type"] == "cryptographic-asset"
    assert comp["name"] == "api.example.com:443"
    assert comp["cryptoProperties"]["assetType"] == "protocol"
    assert "TLSv1.3" in comp["cryptoProperties"]["protocolProperties"]["version"]
    assert len(cbom["vulnerabilities"]) == 1
    assert cbom["vulnerabilities"][0]["ratings"][0]["severity"] == "low"


def test_build_cbom_source_code_findings():
    """CBOM builder correctly formats source-code crypto findings."""
    scanner = PythonScanner()
    res = scanner.scan(ScanTarget(path=str(SAMPLE_FILE), scan_type="source"))
    assert res.total_findings > 0

    scan_id = str(uuid4())
    cbom = build_cbom(scan_id=scan_id, target=str(SAMPLE_FILE), assets=res.findings)

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.5"
    assert len(cbom["components"]) == res.total_findings

    # Check component structure for source code finding
    rsa_comp = next((c for c in cbom["components"] if "RSA" in c["name"]), None)
    assert rsa_comp is not None
    assert rsa_comp["type"] == "cryptographic-asset"
    assert rsa_comp["cryptoProperties"]["assetType"] == "algorithm"
    assert rsa_comp["cryptoProperties"]["algorithmProperties"]["primitive"] in ("asymmetric", "signature")
    assert "evidence" in rsa_comp
    assert "occurrences" in rsa_comp["evidence"]
    assert len(rsa_comp["evidence"]["occurrences"]) > 0
    assert rsa_comp["evidence"]["occurrences"][0]["location"] == str(SAMPLE_FILE)

    # Check properties
    prop_dict = {p["name"]: p["value"] for p in rsa_comp["properties"]}
    assert prop_dict["ciphersight:source_type"] == "source_code"
    assert prop_dict["ciphersight:language"] == "python"
    assert prop_dict["ciphersight:pqc_status"] == "VULNERABLE"

    # Check vulnerabilities
    assert len(cbom["vulnerabilities"]) > 0


def test_cbom_exporter_and_summary():
    """Exporter handles source findings properly in CSV and summary data."""
    scanner = PythonScanner()
    res = scanner.scan(ScanTarget(path=str(SAMPLE_FILE), scan_type="source"))
    cbom = build_cbom(scan_id=str(uuid4()), target="test_project", assets=res.findings)

    csv_data = export_csv(cbom)
    assert "Component" in csv_data
    assert "Vulnerabilities" in csv_data
    assert "RSA" in csv_data
    assert "SHA-256" in csv_data

    summary = extract_summary_data(cbom)
    assert summary["total_components"] == res.total_findings
    assert summary["total_vulnerabilities"] > 0
    assert "RSA" in summary["unique_algorithms"]
    assert "SHA-256" in summary["unique_algorithms"]


@pytest.mark.asyncio
async def test_source_scan_endpoint_e2e(client: AsyncClient):
    """End-to-end test of POST /api/scan/source and GET /api/scan/{id}."""
    # 1. Submit source scan
    response = await client.post(
        "/api/scan/source",
        json={
            "path": str(SAMPLE_FILE),
            "repository": "ciphersight-fixture",
            "scan_depth": "standard",
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()

    scan_id = data["id"]
    assert data["status"] == "completed"
    assert data["scan_type"] == "source"
    assert data["total_assets"] >= 10
    assert data["vulnerable_count"] > 0
    assert len(data["findings"]) == data["total_assets"]

    first_finding = data["findings"][0]
    assert first_finding["scan_id"] == scan_id
    assert first_finding["source_type"] == "source_code"
    assert first_finding["file_path"] is not None

    # 2. Retrieve scan details
    detail_res = await client.get(f"/api/scan/{scan_id}")
    assert detail_res.status_code == 200
    detail_data = detail_res.json()
    assert detail_data["id"] == scan_id
    assert len(detail_data["findings"]) == data["total_assets"]

    # 3. Retrieve CBOM via /api/scan/{id}/cbom
    cbom_res = await client.get(f"/api/scan/{scan_id}/cbom")
    assert cbom_res.status_code == 200
    cbom_json = cbom_res.json()
    assert cbom_json["bomFormat"] == "CycloneDX"
    assert len(cbom_json["components"]) == data["total_assets"]

    # 4. Retrieve CBOM via /api/cbom/{id}?format=json
    legacy_cbom_res = await client.get(f"/api/cbom/{scan_id}?format=json")
    assert legacy_cbom_res.status_code == 200
    assert legacy_cbom_res.json()["bomFormat"] == "CycloneDX"

    # 5. Retrieve CSV via /api/cbom/{id}?format=csv
    csv_res = await client.get(f"/api/cbom/{scan_id}?format=csv")
    assert csv_res.status_code == 200
    assert "Component" in csv_res.text


@pytest.mark.asyncio
async def test_source_scan_invalid_path(client: AsyncClient):
    """Submitting non-existent path returns 400."""
    response = await client.post(
        "/api/scan/source",
        json={
            "path": "/non/existent/path/that/does/not/exist",
        },
    )
    assert response.status_code == 400
    assert "does not exist" in response.json()["detail"]
