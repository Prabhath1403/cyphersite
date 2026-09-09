"""
Tests for AI Cryptographic Explanation Agent and Router.
"""

import pytest
import uuid
from httpx import AsyncClient

from app.core.ai.explainer import AIExplanationAgent
from app.models.scan import ScanJob
from app.models.crypto_asset import CryptoAsset


@pytest.mark.asyncio
async def test_ai_explainer_rsa_finding():
    """Verify AI explanation for RSA finding with Shor's algorithm and qubit metrics."""
    agent = AIExplanationAgent()
    finding = {
        "algorithm": "RSA",
        "key_size": 2048,
        "primitive": "asymmetric",
        "sensitivity": "financial",
        "source_type": "source_code",
        "usage": "signing",
    }
    res = await agent.explain_finding(finding)

    assert res["algorithm"] == "RSA"
    assert res["quantum_status"] == "vulnerable"
    assert "Shor" in res["theoretical_foundation"]["attack_algorithm"]
    assert "O((log N)^3)" in res["theoretical_foundation"]["quantum_complexity"]
    assert "4,098" in res["theoretical_foundation"]["qubits_required_estimate"]
    assert res["harvest_now_decrypt_later_risk"]["hndl_exposure"] == "CRITICAL"
    assert "ML-DSA-65" in res["tailored_remediation"]["recommended_replacement"]
    assert "FIPS 204" in res["tailored_remediation"]["target_standard"]
    assert "oqs.Signature" in res["tailored_remediation"]["code_snippet"]


@pytest.mark.asyncio
async def test_ai_explainer_aes128_finding():
    """Verify AI explanation for AES-128 finding with Grover's algorithm."""
    agent = AIExplanationAgent()
    finding = {
        "algorithm": "AES-128-GCM",
        "key_size": 128,
        "primitive": "symmetric",
        "sensitivity": "general",
        "source_type": "network",
    }
    res = await agent.explain_finding(finding)

    assert "AES-128" in res["algorithm"]
    assert res["quantum_status"] == "reduced_security_margin"
    assert "Grover" in res["theoretical_foundation"]["attack_algorithm"]
    assert "64-bit" in res["theoretical_foundation"]["quantum_complexity"]
    assert res["harvest_now_decrypt_later_risk"]["hndl_exposure"] == "MEDIUM"
    assert "AES-256-GCM" in res["tailored_remediation"]["recommended_replacement"]
    assert "AESGCM.generate_key(bit_length=256)" in res["tailored_remediation"]["code_snippet"]


@pytest.mark.asyncio
async def test_ai_explainer_pqc_safe_finding():
    """Verify AI explanation for quantum-safe ML-KEM finding."""
    agent = AIExplanationAgent()
    finding = {
        "algorithm": "ML-KEM-768",
        "primitive": "pqc",
        "sensitivity": "government_id",
        "source_type": "source_code",
    }
    res = await agent.explain_finding(finding)

    assert res["quantum_status"] == "safe"
    assert "Module Learning With Errors" in res["theoretical_foundation"]["mathematical_basis"]
    assert res["harvest_now_decrypt_later_risk"]["hndl_exposure"] == "NONE"


@pytest.mark.asyncio
async def test_ai_explainer_scan_summary():
    """Verify executive-level scan summary generation."""
    agent = AIExplanationAgent()
    findings = [
        {"algorithm": "RSA-2048", "quantum_status": "vulnerable"},
        {"algorithm": "ECDSA-P256", "quantum_status": "vulnerable"},
        {"algorithm": "AES-128-GCM", "quantum_status": "reduced_security_margin"},
        {"algorithm": "ML-KEM-768", "quantum_status": "safe"},
    ]
    summary = await agent.explain_scan_summary("scan-test-123", findings)

    assert summary["total_findings"] == 4
    assert summary["vulnerable_findings_count"] == 2
    assert summary["quantum_safe_count"] == 1
    assert summary["quantum_readiness_posture"] == "CRITICALLY_VULNERABLE"
    assert len(summary["recommended_priority_actions"]) > 0


@pytest.mark.asyncio
async def test_ai_explainer_qa_queries():
    """Verify query answers for Shor, Grover, and HNDL."""
    agent = AIExplanationAgent()

    res_shor = await agent.answer_query("Explain Shor's algorithm and its quantum threat")
    assert "Peter Shor" in res_shor["answer"] or "Quantum Fourier Transform" in res_shor["answer"]

    res_grover = await agent.answer_query("What is Grover's algorithm?")
    assert "Grover" in res_grover["answer"]
    assert "quadratic" in res_grover["answer"].lower()

    res_hndl = await agent.answer_query("What does HNDL mean in cryptography?")
    assert "Harvest Now" in res_hndl["answer"]


@pytest.mark.asyncio
async def test_ai_router_endpoints(client: AsyncClient, db_session):
    """Test API endpoints for /api/ai."""
    scan_id = uuid.uuid4()
    scan = ScanJob(
        id=scan_id,
        target="api.test.example.com",
        status="completed",
        scan_depth="deep",
    )
    db_session.add(scan)

    finding_id = uuid.uuid4()
    asset = CryptoAsset(
        id=finding_id,
        scan_id=scan_id,
        asset_type="algorithm",
        name="rsa_jwt_signer",
        algorithm="RSA",
        key_size=2048,
        primitive="asymmetric",
        usage="signing",
        sensitivity="authentication",
        source_type="source_code",
        file_path="/app/auth.py",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
    )
    db_session.add(asset)
    await db_session.commit()

    # 1. POST /api/ai/explain with in-memory finding_data
    resp1 = await client.post(
        "/api/ai/explain",
        json={
            "finding_data": {
                "algorithm": "ECDSA",
                "key_size": 256,
                "primitive": "asymmetric",
                "sensitivity": "financial",
            }
        },
    )
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["algorithm"] == "ECDSA"
    assert "Shor" in data1["theoretical_foundation"]["attack_algorithm"]

    # 2. POST /api/ai/explain with finding_id
    resp2 = await client.post(
        "/api/ai/explain",
        json={"finding_id": str(finding_id)},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["finding_id"] == str(finding_id)
    assert data2["algorithm"] == "RSA"

    # 3. GET /api/ai/finding/{id}
    resp3 = await client.get(f"/api/ai/finding/{finding_id}")
    assert resp3.status_code == 200
    assert resp3.json()["algorithm"] == "RSA"

    # 4. GET /api/ai/scan/{id}/summary
    resp4 = await client.get(f"/api/ai/scan/{scan_id}/summary")
    assert resp4.status_code == 200
    data4 = resp4.json()
    assert data4["scan_id"] == str(scan_id)
    assert data4["vulnerable_findings_count"] >= 1

    # 5. POST /api/ai/query
    resp5 = await client.post(
        "/api/ai/query",
        json={"query": "How does FIPS 203 protect against Shor's algorithm?"},
    )
    assert resp5.status_code == 200
    assert "FIPS 203" in resp5.json()["answer"]
