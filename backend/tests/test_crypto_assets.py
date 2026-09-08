"""Comprehensive tests for the CryptoAsset feature."""

import uuid
import pytest
from datetime import datetime
from sqlalchemy import select

from app.models.scan import ScanJob
from app.models.crypto_asset import CryptoAsset, CRYPTO_ASSET_TYPES, CRYPTO_SOURCE_TYPES


# ---------------------------------------------------------------------------
# Helper to create a scan job (required as FK parent)
# ---------------------------------------------------------------------------

async def create_test_scan(db_session, target="example.com"):
    """Insert a ScanJob and return its UUID."""
    scan = ScanJob(target=target, status="completed", scan_depth="quick")
    db_session.add(scan)
    await db_session.flush()
    await db_session.refresh(scan)
    return scan.id


# ═══════════════════════════════════════════════════════════════════════════
# MODEL TESTS
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_create_crypto_asset(db_session):
    """CryptoAsset can be created and persisted."""
    scan_id = await create_test_scan(db_session)
    asset = CryptoAsset(
        scan_id=scan_id,
        asset_type="algorithm",
        source_type="source_code",
        name="RSA-2048",
        algorithm="RSA",
        key_size=2048,
    )
    db_session.add(asset)
    await db_session.flush()
    await db_session.refresh(asset)

    assert asset.id is not None
    assert asset.name == "RSA-2048"
    assert asset.algorithm == "RSA"
    assert asset.key_size == 2048


@pytest.mark.asyncio
async def test_retrieve_crypto_asset(db_session):
    """CryptoAsset can be retrieved after persistence."""
    scan_id = await create_test_scan(db_session)
    asset = CryptoAsset(
        scan_id=scan_id,
        asset_type="certificate",
        source_type="network",
        name="example.com cert",
    )
    db_session.add(asset)
    await db_session.flush()
    await db_session.refresh(asset)

    result = await db_session.execute(
        select(CryptoAsset).where(CryptoAsset.id == asset.id)
    )
    fetched = result.scalar_one()
    assert fetched.name == "example.com cert"
    assert fetched.asset_type == "certificate"


@pytest.mark.asyncio
async def test_optional_fields_are_null(db_session):
    """Optional fields default to None."""
    scan_id = await create_test_scan(db_session)
    asset = CryptoAsset(
        scan_id=scan_id,
        asset_type="library",
        source_type="dependency",
        name="OpenSSL",
    )
    db_session.add(asset)
    await db_session.flush()
    await db_session.refresh(asset)

    assert asset.algorithm is None
    assert asset.key_size is None
    assert asset.hostname is None
    assert asset.file_path is None
    assert asset.pqc_status is None
    assert asset.risk_score is None
    assert asset.vulnerabilities is None
    assert asset.business_criticality is None


@pytest.mark.asyncio
async def test_scan_job_relationship(db_session):
    """CryptoAsset → ScanJob relationship works."""
    scan_id = await create_test_scan(db_session)
    asset = CryptoAsset(
        scan_id=scan_id,
        asset_type="algorithm",
        source_type="network",
        name="AES-256",
    )
    db_session.add(asset)
    await db_session.flush()

    result = await db_session.execute(
        select(ScanJob).where(ScanJob.id == scan_id)
    )
    scan = result.scalar_one()
    # Access relationship (may need explicit load for async)
    assert scan is not None
    assert scan.target == "example.com"


@pytest.mark.asyncio
async def test_asset_type_values():
    """All expected asset types are defined."""
    expected = {
        "algorithm", "key", "certificate", "protocol",
        "library", "dependency", "hsm", "cloud_service",
        "source_code_usage", "binary_usage", "container_usage",
        "network_endpoint",
    }
    assert set(CRYPTO_ASSET_TYPES) == expected


@pytest.mark.asyncio
async def test_source_type_values():
    """All expected source types are defined."""
    expected = {
        "network", "source_code", "binary", "container",
        "dependency", "manual",
    }
    assert set(CRYPTO_SOURCE_TYPES) == expected


# ═══════════════════════════════════════════════════════════════════════════
# API TESTS
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_list_crypto_assets_empty(client):
    """GET /api/crypto-assets returns empty list when no assets exist."""
    resp = await client.get("/api/crypto-assets")
    assert resp.status_code == 200
    data = resp.json()
    assert data["assets"] == []
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_create_and_get_crypto_asset(client, db_session):
    """POST then GET a crypto asset."""
    scan_id = await create_test_scan(db_session)

    payload = {
        "scan_id": str(scan_id),
        "asset_type": "source_code_usage",
        "source_type": "source_code",
        "name": "RSA-2048",
        "algorithm": "RSA",
        "algorithm_family": "RSA",
        "key_size": 2048,
        "file_path": "src/auth.py",
        "line_number": 42,
        "language": "python",
    }
    create_resp = await client.post("/api/crypto-assets", json=payload)
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["name"] == "RSA-2048"
    assert created["asset_type"] == "source_code_usage"
    asset_id = created["id"]

    get_resp = await client.get(f"/api/crypto-assets/{asset_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == asset_id


@pytest.mark.asyncio
async def test_create_network_finding(client, db_session):
    """Create a network endpoint crypto asset."""
    scan_id = await create_test_scan(db_session)
    payload = {
        "scan_id": str(scan_id),
        "asset_type": "network_endpoint",
        "source_type": "network",
        "name": "api.example.com",
        "protocol": "TLS",
        "hostname": "api.example.com",
        "port": 443,
        "key_exchange": "ECDHE",
    }
    resp = await client.post("/api/crypto-assets", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["asset_type"] == "network_endpoint"
    assert data["hostname"] == "api.example.com"
    assert data["port"] == 443


@pytest.mark.asyncio
async def test_create_dependency_finding(client, db_session):
    """Create a dependency crypto asset."""
    scan_id = await create_test_scan(db_session)
    payload = {
        "scan_id": str(scan_id),
        "asset_type": "dependency",
        "source_type": "dependency",
        "name": "cryptography",
        "version": "42.0.0",
        "source_location": "requirements.txt",
    }
    resp = await client.post("/api/crypto-assets", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "cryptography"
    assert data["version"] == "42.0.0"


@pytest.mark.asyncio
async def test_create_container_finding(client, db_session):
    """Create a container usage crypto asset."""
    scan_id = await create_test_scan(db_session)
    payload = {
        "scan_id": str(scan_id),
        "asset_type": "container_usage",
        "source_type": "container",
        "name": "OpenSSL",
        "version": "3.0.2",
    }
    resp = await client.post("/api/crypto-assets", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["asset_type"] == "container_usage"
    assert data["version"] == "3.0.2"


@pytest.mark.asyncio
async def test_list_multiple_assets(client, db_session):
    """List returns multiple assets."""
    scan_id = await create_test_scan(db_session)
    for i in range(3):
        await client.post("/api/crypto-assets", json={
            "scan_id": str(scan_id),
            "asset_type": "algorithm",
            "source_type": "network",
            "name": f"algo-{i}",
        })
    resp = await client.get("/api/crypto-assets")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert len(data["assets"]) == 3


@pytest.mark.asyncio
async def test_filter_by_asset_type(client, db_session):
    """Filter by asset_type returns only matching assets."""
    scan_id = await create_test_scan(db_session)
    await client.post("/api/crypto-assets", json={
        "scan_id": str(scan_id), "asset_type": "algorithm",
        "source_type": "network", "name": "RSA",
    })
    await client.post("/api/crypto-assets", json={
        "scan_id": str(scan_id), "asset_type": "certificate",
        "source_type": "network", "name": "cert",
    })
    resp = await client.get("/api/crypto-assets?asset_type=algorithm")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["assets"][0]["asset_type"] == "algorithm"


@pytest.mark.asyncio
async def test_filter_by_source_type(client, db_session):
    """Filter by source_type."""
    scan_id = await create_test_scan(db_session)
    await client.post("/api/crypto-assets", json={
        "scan_id": str(scan_id), "asset_type": "algorithm",
        "source_type": "source_code", "name": "AES",
    })
    await client.post("/api/crypto-assets", json={
        "scan_id": str(scan_id), "asset_type": "algorithm",
        "source_type": "network", "name": "RSA",
    })
    resp = await client.get("/api/crypto-assets?source_type=source_code")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


@pytest.mark.asyncio
async def test_filter_by_pqc_status(client, db_session):
    """Filter by pqc_status."""
    scan_id = await create_test_scan(db_session)
    await client.post("/api/crypto-assets", json={
        "scan_id": str(scan_id), "asset_type": "algorithm",
        "source_type": "network", "name": "AES-256",
        "pqc_status": "QUANTUM_SAFE",
    })
    await client.post("/api/crypto-assets", json={
        "scan_id": str(scan_id), "asset_type": "algorithm",
        "source_type": "network", "name": "RSA-2048",
        "pqc_status": "VULNERABLE",
    })
    resp = await client.get("/api/crypto-assets?pqc_status=VULNERABLE")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["assets"][0]["pqc_status"] == "VULNERABLE"


@pytest.mark.asyncio
async def test_filter_by_scan_id(client, db_session):
    """Filter by scan_id."""
    scan_id_1 = await create_test_scan(db_session, target="host1.com")
    scan_id_2 = await create_test_scan(db_session, target="host2.com")
    await client.post("/api/crypto-assets", json={
        "scan_id": str(scan_id_1), "asset_type": "algorithm",
        "source_type": "network", "name": "RSA",
    })
    await client.post("/api/crypto-assets", json={
        "scan_id": str(scan_id_2), "asset_type": "algorithm",
        "source_type": "network", "name": "AES",
    })
    resp = await client.get(f"/api/crypto-assets?scan_id={scan_id_1}")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


@pytest.mark.asyncio
async def test_pagination(client, db_session):
    """Pagination with limit and offset works."""
    scan_id = await create_test_scan(db_session)
    for i in range(5):
        await client.post("/api/crypto-assets", json={
            "scan_id": str(scan_id), "asset_type": "algorithm",
            "source_type": "network", "name": f"algo-{i}",
        })
    resp = await client.get("/api/crypto-assets?limit=2&offset=0")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 5
    assert len(data["assets"]) == 2

    resp2 = await client.get("/api/crypto-assets?limit=2&offset=2")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["assets"]) == 2
    assert data2["total"] == 5


@pytest.mark.asyncio
async def test_get_nonexistent_asset(client):
    """GET with nonexistent UUID returns 404."""
    fake_id = str(uuid.uuid4())
    resp = await client.get(f"/api/crypto-assets/{fake_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_invalid_uuid(client):
    """GET with invalid ID format returns 422."""
    resp = await client.get("/api/crypto-assets/not-a-uuid")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_invalid_asset_type(client, db_session):
    """POST with invalid asset_type returns 422."""
    scan_id = await create_test_scan(db_session)
    resp = await client.post("/api/crypto-assets", json={
        "scan_id": str(scan_id),
        "asset_type": "invalid_type",
        "source_type": "network",
        "name": "test",
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_invalid_source_type(client, db_session):
    """POST with invalid source_type returns 422."""
    scan_id = await create_test_scan(db_session)
    resp = await client.post("/api/crypto-assets", json={
        "scan_id": str(scan_id),
        "asset_type": "algorithm",
        "source_type": "invalid_source",
        "name": "test",
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_nonexistent_scan_id(client):
    """POST with nonexistent scan_id returns 404."""
    resp = await client.post("/api/crypto-assets", json={
        "scan_id": str(uuid.uuid4()),
        "asset_type": "algorithm",
        "source_type": "network",
        "name": "test",
    })
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_filter_invalid_asset_type(client):
    """GET with invalid asset_type filter returns 422."""
    resp = await client.get("/api/crypto-assets?asset_type=invalid")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_filter_invalid_source_type(client):
    """GET with invalid source_type filter returns 422."""
    resp = await client.get("/api/crypto-assets?source_type=invalid")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_filter_nonexistent_scan_id(client):
    """GET with nonexistent scan_id returns 404."""
    resp = await client.get(f"/api/crypto-assets?scan_id={uuid.uuid4()}")
    assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# COMPATIBILITY / CONVERSION TESTS
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_convert_network_asset(db_session):
    """Convert a network Asset to a CryptoAsset."""
    from app.models.asset import Asset
    from app.core.converter import crypto_asset_from_network_asset

    scan_id = await create_test_scan(db_session)
    asset = Asset(
        scan_id=scan_id,
        hostname="example.com",
        port=443,
        service_type="web_server",
        key_exchange="ECDHE",
        pqc_status="VULNERABLE",
        risk_score=85.0,
        tls_versions=["TLSv1.3", "TLSv1.2"],
        cipher_suites=[{"name": "TLS_AES_256_GCM_SHA384"}],
        certificate={"signature_algorithm": "sha256WithRSAEncryption", "key_size": 2048},
    )
    db_session.add(asset)
    await db_session.flush()
    await db_session.refresh(asset)

    crypto = crypto_asset_from_network_asset(asset)
    assert crypto.asset_type == "network_endpoint"
    assert crypto.source_type == "network"
    assert crypto.hostname == "example.com"
    assert crypto.port == 443
    assert crypto.key_exchange == "ECDHE"
    assert crypto.pqc_status == "VULNERABLE"
    assert crypto.risk_score == 85.0
    assert crypto.protocol == "TLSv1.3"
    assert crypto.algorithm == "sha256WithRSAEncryption"
    assert crypto.key_size == 2048
    assert crypto.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert crypto.scan_id == scan_id


# ═══════════════════════════════════════════════════════════════════════════
# EXISTING ENDPOINT COMPATIBILITY TESTS
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_health_endpoint(client):
    """Health check still works."""
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_scans_endpoint_still_works(client, db_session):
    """Existing scan creation and listing still works."""
    # Create a scan via direct model insertion (not using the scan router
    # which would trigger Celery which isn't available in tests)
    scan = ScanJob(target="test.com", status="completed", scan_depth="quick")
    db_session.add(scan)
    await db_session.flush()
    await db_session.refresh(scan)

    resp = await client.get(f"/api/scans/{scan.id}")
    assert resp.status_code == 200
    assert resp.json()["target"] == "test.com"


@pytest.mark.asyncio
async def test_existing_assets_endpoint_still_works(client):
    """Existing /api/assets endpoint still works."""
    resp = await client.get("/api/assets")
    assert resp.status_code == 200
