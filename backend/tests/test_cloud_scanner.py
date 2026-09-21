"""
Tests for the Cloud Infrastructure Scanner & Post-Quantum CSPM Engine.
"""

import pytest
from app.core.cloud import (
    CloudInfrastructureScanner,
    CloudFleetAuditReport,
    CLOUD_SILICON_MATRIX,
)


def test_cloud_silicon_matrix():
    """Verify matrix contains essential AWS, Azure, and GCP compute shapes."""
    assert "t2.micro" in CLOUD_SILICON_MATRIX
    assert "c6i.xlarge" in CLOUD_SILICON_MATRIX
    assert "c7g.xlarge" in CLOUD_SILICON_MATRIX
    assert "Standard_D4s_v5" in CLOUD_SILICON_MATRIX
    assert "n2-standard-4" in CLOUD_SILICON_MATRIX

    # Check that t2 has UPGRADE_REQUIRED due to lack of AVX-512 and burstable CPU
    assert CLOUD_SILICON_MATRIX["t2.micro"]["pqc_status"] == "UPGRADE_REQUIRED"
    assert CLOUD_SILICON_MATRIX["c6i.xlarge"]["pqc_status"] == "PQC_READY"


def test_audit_fleet_aws_simulation():
    """Test auditing of the demo AWS enterprise fleet."""
    report = CloudInfrastructureScanner.audit_fleet(
        provider="AWS",
        account_id="123456789012 (Prod)",
    )
    assert isinstance(report, CloudFleetAuditReport)
    assert report.total_assets >= 5
    assert report.pqc_ready_count >= 1
    assert report.upgrade_required_count >= 1
    assert report.potential_monthly_savings_usd > 0.0
    assert report.impact_on_mosca_years >= 1.5  # Legacy CloudHSM adds to Y
    assert "terraform" in report.remediation_terraform.lower() or "aws_instance" in report.remediation_terraform


def test_audit_custom_inventory():
    """Test auditing a custom user-provided inventory list."""
    custom_inv = [
        {"id": "vm-1", "name": "web-server", "service_type": "ComputeInstance", "instance_type": "c6i.xlarge", "monthly_cost": 100.0},
        {"id": "vm-2", "name": "legacy-db", "service_type": "ComputeInstance", "instance_type": "t2.medium", "monthly_cost": 50.0},
    ]
    report = CloudInfrastructureScanner.audit_fleet(
        provider="AWS",
        account_id="custom-acct",
        inventory=custom_inv,
    )
    assert report.total_assets == 2
    assert report.pqc_ready_count == 1
    assert report.upgrade_required_count == 1
    assert report.potential_monthly_savings_usd > 0.0


@pytest.mark.asyncio
async def test_cloud_api_endpoints(client):
    """Test API endpoints for AWS, Azure, GCP scans and catalog."""
    # 1. AWS scan
    resp = await client.post("/api/cloud/scan/aws", json={"provider": "AWS", "use_demo_fleet": True})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["report"]["provider"] == "AWS"
    assert len(data["report"]["assets"]) >= 5

    # 2. Azure scan
    azure_resp = await client.post("/api/cloud/scan/azure", json={"provider": "Azure", "use_demo_fleet": True})
    assert azure_resp.status_code == 200
    azure_data = azure_resp.json()
    assert azure_data["report"]["provider"] == "Azure"

    # 3. GCP scan
    gcp_resp = await client.post("/api/cloud/scan/gcp", json={"provider": "GCP", "use_demo_fleet": True})
    assert gcp_resp.status_code == 200
    gcp_data = gcp_resp.json()
    assert gcp_data["report"]["provider"] == "GCP"

    # 4. Upload custom inventory
    upload_resp = await client.post(
        "/api/cloud/evaluate-inventory",
        json={
            "provider": "AWS",
            "account_id": "terraform-export-test",
            "items": [
                {"id": "inst-1", "name": "auth-svc", "instance_type": "c7g.xlarge", "monthly_cost": 120.0},
            ],
        },
    )
    assert upload_resp.status_code == 200
    assert upload_resp.json()["report"]["total_assets"] == 1
    assert upload_resp.json()["report"]["pqc_ready_count"] == 1

    # 5. Catalog
    cat_resp = await client.get("/api/cloud/instance-types")
    assert cat_resp.status_code == 200
    assert cat_resp.json()["total_compute_shapes"] >= 10
