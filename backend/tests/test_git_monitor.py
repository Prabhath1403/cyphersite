"""
Tests for Git Monitor & Instant Single-File Incremental Scanner.
"""

import pytest
from app.core.git_monitor.incremental_scanner import IncrementalScanner
from app.core.git_monitor.engine import GitMonitorEngine
from app.models.scan import ScanJob
from app.models.crypto_asset import CryptoAsset
from app.models.git_monitor import GitMonitorEvent
from sqlalchemy import select


def test_incremental_scanner_detects_vulnerable_rsa():
    """Verify single-file AST scanner detects RSA vulnerability."""
    code = """
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
"""
    findings = IncrementalScanner.scan_source_code(
        code=code,
        file_path="services/auth.py",
        repository="test/repo",
    )
    assert len(findings) >= 1
    rsa_finding = next((f for f in findings if f.algorithm == "RSA"), None)
    assert rsa_finding is not None
    assert rsa_finding.pqc_status == "VULNERABLE"


def test_incremental_scanner_detects_quantum_safe_aesgcm():
    """Verify single-file AST scanner detects modern AES-GCM as safe/hybrid."""
    code = """
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
"""
    findings = IncrementalScanner.scan_source_code(
        code=code,
        file_path="services/auth.py",
        repository="test/repo",
    )
    assert len(findings) >= 1
    aes_finding = next((f for f in findings if "AES" in f.name or f.algorithm == "AES"), None)
    assert aes_finding is not None
    assert aes_finding.pqc_status == "QUANTUM_SAFE"


@pytest.mark.asyncio
async def test_engine_remediates_single_file(db_session):
    """
    Test that modifying a file from RSA to AESGCM:
    1. Removes old vulnerable findings
    2. Adds new quantum-safe findings
    3. Decreases vulnerable_count
    4. Records an audit GitMonitorEvent
    """
    repo = "test-org/payment-service"
    file_path = "crypto/payment.py"

    # Step 1: Initial vulnerable state
    vulnerable_code = """
from cryptography.hazmat.primitives.asymmetric import rsa

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""
    res1 = await GitMonitorEngine.process_file_change(
        db=db_session,
        repository=repo,
        file_path=file_path,
        content=vulnerable_code,
        commit_id="commit-001",
        commit_message="Initial commit with RSA",
    )

    assert res1["action"] in ("updated", "new_vulnerabilities")
    assert res1["stats"]["vulnerable_count"] >= 1

    # Verify ScanJob and CryptoAsset exist
    scan_res = await db_session.execute(select(ScanJob).where(ScanJob.target == repo))
    scan = scan_res.scalars().first()
    assert scan is not None
    assert scan.vulnerable_count >= 1

    # Step 2: Developer pushes fix: replaces RSA with AESGCM
    remediated_code = """
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
cipher = AESGCM(key)
"""
    res2 = await GitMonitorEngine.process_file_change(
        db=db_session,
        repository=repo,
        file_path=file_path,
        content=remediated_code,
        commit_id="commit-002",
        commit_message="fix(crypto): replace RSA with AES-256-GCM",
    )

    assert res2["action"] == "remediated"
    assert res2["vulnerabilities_fixed"] >= 1
    assert res2["stats"]["vulnerable_count"] == 0
    assert res2["stats"]["quantum_safe_count"] >= 1

    # Verify in DB
    asset_res = await db_session.execute(
        select(CryptoAsset).where(CryptoAsset.scan_id == scan.id)
    )
    remaining_assets = asset_res.scalars().all()
    assert all(a.pqc_status != "VULNERABLE" for a in remaining_assets)

    # Verify audit event
    events_res = await db_session.execute(
        select(GitMonitorEvent).where(GitMonitorEvent.repository == repo)
    )
    events = events_res.scalars().all()
    assert len(events) == 2
    assert events[-1].action == "remediated"
    assert events[-1].vulnerabilities_fixed >= 1


@pytest.mark.asyncio
async def test_git_monitor_api_endpoints(client):
    """Test /api/git-monitor HTTP endpoints."""
    # 1. Test status
    status_resp = await client.get("/api/git-monitor/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["monitor_active"] is True

    # 2. Test webhook-info
    info_resp = await client.get("/api/git-monitor/webhook-info")
    assert info_resp.status_code == 200
    assert info_resp.json()["webhook_url"] == "/api/git-monitor/webhook"

    # 3. Test presets listing
    presets_resp = await client.get("/api/git-monitor/presets")
    assert presets_resp.status_code == 200
    presets = presets_resp.json()
    assert len(presets) >= 3

    # 4. Test simulate-push
    push_data = {
        "repository": "test/sim-repo",
        "branch": "main",
        "file_path": "auth/token.py",
        "code_content": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nk = AESGCM.generate_key(256)\n",
        "commit_message": "test push",
        "author": "Dev",
    }
    push_resp = await client.post("/api/git-monitor/simulate-push", json=push_data)
    assert push_resp.status_code == 200
    data = push_resp.json()
    assert data["repository"] == "test/sim-repo"
    assert data["stats"]["quantum_safe_count"] >= 1

    # 5. Test trigger-preset
    trigger_resp = await client.post(
        "/api/git-monitor/trigger-preset",
        json={"preset_id": "fix_rsa_to_mlkem", "repository": "test/sim-repo"},
    )
    assert trigger_resp.status_code == 200
    trigger_data = trigger_resp.json()
    assert "preset" in trigger_data

    # 6. Test events listing
    events_resp = await client.get("/api/git-monitor/events")
    assert events_resp.status_code == 200
    events = events_resp.json()
    assert len(events) >= 1
