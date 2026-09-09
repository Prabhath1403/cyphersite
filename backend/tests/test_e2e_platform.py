"""
End-to-End Platform Integration Test Suite (Phase 18).

Validates the full lifecycle across all scanners, normalizers, risk engines,
graphs, CBOM generators, remediation issue exporters, and AI advisory endpoints.
"""

import os
import tempfile
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_complete_platform_e2e_workflow(client: AsyncClient):
    """
    Exercise the entire platform pipeline end-to-end:
    Source Code -> AST Scanner -> Pipeline Normalizer -> Sensitivity Engine
    -> CycloneDX CBOM -> Graph Engine -> Risk & Mosca -> Migration Plan
    -> GitHub Remediation Issues -> AI Explainer & Executive Summary.
    """
    # 1. Create a temporary source repository with realistic crypto usages
    with tempfile.TemporaryDirectory() as tmpdir:
        app_file = os.path.join(tmpdir, "payments.py")
        with open(app_file, "w") as f:
            f.write(
                "from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
                "from cryptography.hazmat.primitives import hashes\n"
                "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
                "import os\n\n"
                "# Incur RSA signing vulnerability for credit card tokenization\n"
                "def sign_credit_card_transaction(tx_data):\n"
                "    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
                "    signature = private_key.sign(tx_data, padding.PKCS1v15(), hashes.SHA256())\n"
                "    return signature\n\n"
                "# Incur AES-128 symmetric vulnerability with reduced quantum margin\n"
                "def encrypt_payment_vault(key_16_bytes, iv, plaintext):\n"
                "    cipher = Cipher(algorithms.AES(key_16_bytes), modes.CBC(iv))\n"
                "    encryptor = cipher.encryptor()\n"
                "    return encryptor.update(plaintext) + encryptor.finalize()\n"
            )

        # 2. Trigger source scan
        scan_resp = await client.post(
            "/api/scan/source",
            json={"path": tmpdir, "repository": "payments-service", "scan_depth": "deep"},
        )
        assert scan_resp.status_code == 200, scan_resp.text
        scan_data = scan_resp.json()
        scan_id = scan_data["id"]
        assert scan_id is not None
        assert scan_data["total_assets"] >= 2

        # 3. Retrieve scan details
        details_resp = await client.get(f"/api/scan/{scan_id}")
        assert details_resp.status_code == 200
        details = details_resp.json()
        assert details["status"] == "completed"

        # 4. Retrieve scan coverage
        coverage_resp = await client.get(f"/api/scan/{scan_id}/coverage")
        assert coverage_resp.status_code == 200
        cov = coverage_resp.json()
        assert cov["files_scanned"] >= 1
        assert cov["coverage_tier"] in ("FULL", "HIGH")
        assert cov["confidence"]["high_count"] >= 1

        # 5. Retrieve CycloneDX CBOM
        cbom_resp = await client.get(f"/api/cbom/{scan_id}?format=json")
        assert cbom_resp.status_code == 200
        cbom = cbom_resp.json()
        assert cbom["bomFormat"] == "CycloneDX"
        assert len(cbom["components"]) >= 2

        # 6. Retrieve Cryptographic Topology Graph
        graph_resp = await client.get(f"/api/graph/{scan_id}")
        assert graph_resp.status_code == 200
        graph = graph_resp.json()
        assert len(graph["nodes"]) >= 3
        assert len(graph["edges"]) >= 2

        # 7. Evaluate Post-Quantum Risk & Mosca Theorem
        risk_resp = await client.get(f"/api/risk/scan/{scan_id}")
        assert risk_resp.status_code == 200
        risk_data = risk_resp.json()
        assert "portfolio_posture" in risk_data
        assert risk_data["total_assets"] >= 2

        # 8. Retrieve Migration Plan
        plan_resp = await client.get(f"/api/migration/plan/{scan_id}")
        assert plan_resp.status_code == 200
        plan = plan_resp.json()
        assert plan["scan_id"] == scan_id
        assert len(plan["actions"]) >= 2
        assert any(a["priority"].startswith("P") for a in plan["actions"])

        # 9. Export GitHub Remediation Issues
        issues_resp = await client.get(f"/api/remediation/scan/{scan_id}/export-issues")
        assert issues_resp.status_code == 200
        issues = issues_resp.json()
        assert len(issues["issues"]) >= 2

        # 10. Generate AI Executive Summary & Explanations
        ai_resp = await client.get(f"/api/ai/scan/{scan_id}/summary")
        assert ai_resp.status_code == 200
        ai_summary = ai_resp.json()
        assert ai_summary["scan_id"] == scan_id
        assert ai_summary["vulnerable_findings_count"] >= 1
        assert "Shor" in str(ai_summary["primary_quantum_vectors"])
        assert len(ai_summary["recommended_priority_actions"]) > 0


@pytest.mark.asyncio
async def test_container_and_binary_scans_e2e(client: AsyncClient):
    """Verify container and binary scan endpoints integrate seamlessly into unified findings."""
    # 1. Container scan
    c_resp = await client.post(
        "/api/scan/container",
        json={"image": "alpine:3.19", "scan_depth": "standard"},
    )
    assert c_resp.status_code == 200, c_resp.text
    c_data = c_resp.json()
    assert c_data["scan_type"] == "container"

    # 2. Binary scan with mock binary
    with tempfile.NamedTemporaryFile(suffix=".bin") as tmp_bin:
        # Write minimal ELF header + RSA symbol
        tmp_bin.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 20 + b"RSA_generate_key_ex\x00AES_set_encrypt_key\x00")
        tmp_bin.flush()

        b_resp = await client.post(
            "/api/scan/binary",
            json={"path": tmp_bin.name, "repository": "crypto_daemon"},
        )
        assert b_resp.status_code == 200, b_resp.text
        b_data = b_resp.json()
        assert b_data["scan_type"] == "binary"
        assert b_data["total_assets"] >= 1


@pytest.mark.asyncio
async def test_ai_qa_and_finding_deep_dive_e2e(client: AsyncClient):
    """Verify AI Cryptographic Advisor Q&A and finding deep-dive."""
    # Free-form query
    query_resp = await client.post(
        "/api/ai/query",
        json={"query": "Explain how Grover's algorithm affects symmetric ciphers"},
    )
    assert query_resp.status_code == 200
    assert "quadratic" in query_resp.json()["answer"].lower()

    # Finding explanation
    explain_resp = await client.post(
        "/api/ai/explain",
        json={
            "finding_data": {
                "algorithm": "ECDH",
                "key_size": 256,
                "primitive": "asymmetric",
                "sensitivity": "financial",
            }
        },
    )
    assert explain_resp.status_code == 200
    expl = explain_resp.json()
    assert expl["algorithm"] == "ECDH"
    assert "Shor" in expl["theoretical_foundation"]["attack_algorithm"]
    assert "ML-KEM-768" in expl["tailored_remediation"]["recommended_replacement"]
