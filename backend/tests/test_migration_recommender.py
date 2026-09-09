"""
Tests for the Cryptographic Migration Recommender and Migration API endpoints.
"""

import pytest
from app.core.source_scanner import CryptoFindingData
from app.core.migration import MigrationRecommender, MigrationAction


def test_recommend_for_rsa_signature():
    """Test recommendation for RSA digital signature finding."""
    finding = CryptoFindingData(
        name="RSA-2048 Signing Key",
        asset_type="source_code_usage",
        source_type="source_code",
        algorithm="RSA-2048",
        usage="digital_signature",
        sensitivity="CRITICAL",
        risk_score=90.0,
    )
    action = MigrationRecommender.recommend_for_finding(finding)

    assert action.target_algorithm == "ML-DSA-65"
    assert "FIPS 204" in action.target_standard
    assert action.priority == "P0_CRITICAL"
    assert "oqs.Signature" in action.code_remediation_snippet
    assert len(action.testing_checklist) >= 3


def test_recommend_for_dh_kex():
    """Test recommendation for Diffie-Hellman key exchange finding."""
    finding = CryptoFindingData(
        name="Diffie-Hellman Key Exchange",
        asset_type="network_endpoint",
        source_type="network",
        algorithm="Diffie-Hellman",
        usage="key_exchange",
        sensitivity="HIGH",
        risk_score=75.0,
    )
    action = MigrationRecommender.recommend_for_finding(finding)

    assert "ML-KEM-768" in action.target_algorithm
    assert "FIPS 203" in action.target_standard
    assert action.priority == "P1_HIGH"


def test_recommend_for_symmetric_aes128():
    """Test recommendation for AES-128 upgrade to AES-256."""
    finding = CryptoFindingData(
        name="AES-128-GCM Storage",
        asset_type="source_code_usage",
        source_type="source_code",
        algorithm="AES-128-GCM",
        usage="encryption",
        sensitivity="MEDIUM",
        risk_score=40.0,
    )
    action = MigrationRecommender.recommend_for_finding(finding)

    assert action.target_algorithm == "AES-256-GCM"
    assert action.priority == "P2_MEDIUM"
    assert "AESGCM.generate_key(bit_length=256)" in action.code_remediation_snippet


def test_generate_plan_priority_sorting():
    """Test that generated plan orders actions P0 -> P1 -> P2 -> P3."""
    findings = [
        CryptoFindingData(name="low", asset_type="source_code_usage", source_type="source_code", algorithm="AES-128", risk_score=40.0, sensitivity="LOW"),
        CryptoFindingData(name="crit", asset_type="source_code_usage", source_type="source_code", algorithm="RSA-2048", risk_score=90.0, sensitivity="CRITICAL"),
        CryptoFindingData(name="high", asset_type="source_code_usage", source_type="source_code", algorithm="ECDH", risk_score=70.0, sensitivity="HIGH"),
    ]
    actions = MigrationRecommender.generate_plan_for_findings(findings)

    assert len(actions) == 3
    assert actions[0].priority == "P0_CRITICAL"
    assert actions[1].priority == "P1_HIGH"
    assert actions[2].priority == "P2_MEDIUM"


@pytest.mark.asyncio
async def test_migration_api_endpoints(client, tmp_path):
    """Test POST /api/migration/recommend and GET /api/migration/plan/{scan_id} endpoints."""
    # 1. Ad-hoc recommendation
    rec_resp = await client.post(
        "/api/migration/recommend",
        json={
            "algorithm": "RSA-4096",
            "usage": "digital_signature",
            "sensitivity": "CRITICAL",
            "source_type": "source_code",
            "risk_score": 85.0,
        },
    )
    assert rec_resp.status_code == 200
    rec_data = rec_resp.json()
    assert rec_data["target_algorithm"] == "ML-DSA-65"
    assert rec_data["priority"] == "P0_CRITICAL"

    # 2. Run source scan to create records in DB
    py_file = tmp_path / "crypto_app.py"
    py_file.write_text("import hashlib\nh = hashlib.sha256(b'test').hexdigest()\n")

    scan_resp = await client.post(
        "/api/scan/source",
        json={"path": str(tmp_path), "scan_depth": "standard"},
    )
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["id"]

    # 3. Retrieve plan for this scan
    plan_resp = await client.get(f"/api/migration/plan/{scan_id}")
    assert plan_resp.status_code == 200
    plan_data = plan_resp.json()
    assert plan_data["scan_id"] == scan_id
    assert plan_data["total_actions"] >= 1
    assert "total_estimated_effort_hours" in plan_data
