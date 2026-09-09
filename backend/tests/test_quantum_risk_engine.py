"""
Tests for the Post-Quantum Risk Engine, Mosca's Theorem, and Risk API endpoints.
"""

import pytest
from app.core.risk import QuantumRiskEngine, MoscaEvaluation, RiskEvaluationResult


def test_mosca_theorem_violation():
    """Test Michele Mosca's Theorem detects retroactive vulnerability (X + Y > Z)."""
    # 10 years confidentiality + 3 years migration > 8 years to Q-Day
    eval_res = QuantumRiskEngine.evaluate_mosca(
        shelf_life_years=10.0,
        migration_years=3.0,
        q_day_years=8.0,
    )
    assert eval_res.is_violated is True
    assert eval_res.slack_years == -5.0
    assert eval_res.urgency_status == "CRITICAL_RETROACTIVE_EXPOSURE"
    assert "exceeding estimated time to Q-Day" in eval_res.description


def test_mosca_theorem_safe_window():
    """Test Mosca evaluation when sufficient time window exists."""
    eval_res = QuantumRiskEngine.evaluate_mosca(
        shelf_life_years=2.0,
        migration_years=1.0,
        q_day_years=8.0,
    )
    assert eval_res.is_violated is False
    assert eval_res.slack_years == 5.0
    assert eval_res.urgency_status == "SUFFICIENT_WINDOW"


def test_evaluate_asset_risk_rsa():
    """Test risk evaluation for quantum-vulnerable RSA."""
    res = QuantumRiskEngine.evaluate_asset_risk(
        algorithm="RSA-2048",
        sensitivity="CRITICAL",
        is_public=True,
    )
    assert res.pqc_status == "VULNERABLE"
    assert res.risk_level in ("CRITICAL", "HIGH")
    assert res.risk_score >= 85.0
    assert "Shor" in res.quantum_break_method
    assert "ML-DSA" in res.recommended_replacement or "ML-KEM" in res.recommended_replacement
    assert "CNSA_2_0" in res.regulatory_deadlines


def test_evaluate_asset_risk_ml_kem():
    """Test risk evaluation for standardized post-quantum ML-KEM."""
    res = QuantumRiskEngine.evaluate_asset_risk(
        algorithm="ML-KEM-768",
        sensitivity="HIGH",
    )
    assert res.pqc_status == "QUANTUM_SAFE"
    assert res.risk_level in ("INFO", "LOW")
    assert res.risk_score <= 15.0


@pytest.mark.asyncio
async def test_risk_api_endpoints(client, tmp_path):
    """Test POST /api/risk/evaluate and GET /api/risk/scan/{scan_id} endpoints."""
    # 1. Evaluate single algorithm
    resp = await client.post(
        "/api/risk/evaluate",
        json={
            "algorithm": "ECDSA-P256",
            "sensitivity": "HIGH",
            "is_public": True,
            "shelf_life_years": 7.0,
            "migration_years": 2.0,
            "q_day_years": 8.0,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["algorithm"] == "ECDSA-P256"
    assert data["pqc_status"] == "VULNERABLE"
    assert data["mosca"]["is_violated"] is True

    # 2. Run source scan to have a scan in DB
    py_file = tmp_path / "sign.py"
    py_file.write_text("import hashlib\nh = hashlib.sha256(b'test').hexdigest()\n")

    scan_resp = await client.post(
        "/api/scan/source",
        json={"path": str(tmp_path), "scan_depth": "standard"},
    )
    assert scan_resp.status_code == 200
    scan_id = scan_resp.json()["id"]

    # 3. Get scan risk profile
    profile_resp = await client.get(f"/api/risk/scan/{scan_id}")
    assert profile_resp.status_code == 200
    profile_data = profile_resp.json()
    assert profile_data["scan_id"] == scan_id
    assert profile_data["total_assets"] >= 1
    assert "portfolio_posture" in profile_data
