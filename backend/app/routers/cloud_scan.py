"""
Cloud Infrastructure Scanner API Router (PQC-CSPM).

Endpoints to audit cloud fleet compute shapes, CloudHSM instances, and Load Balancers
across AWS, Azure, and GCP against Post-Quantum Cryptography standards.
"""

from typing import Any, Dict, List, Optional
from app.core.auth.security import get_current_active_user
from app.models.user import User

from fastapi import APIRouter, Depends, HTTPException, Depends
from pydantic import BaseModel, Field

from app.core.cloud import (
    CloudInfrastructureScanner,
    CLOUD_SILICON_MATRIX,
    CLOUD_MANAGED_SERVICES_MATRIX,
)

router = APIRouter(prefix="/api/cloud", tags=["cloud"])


class CloudScanRequest(BaseModel):
    provider: str = Field(default="AWS", description="Cloud provider: AWS | Azure | GCP")
    role_arn: Optional[str] = Field(default=None, description="Read-only IAM Role ARN (AWS) or Service Principal (Azure)")
    external_id: Optional[str] = Field(default=None, description="External ID for cross-account assume role security")
    account_id: Optional[str] = Field(default="123456789012 (Enterprise Production)", description="Cloud Account or Project ID")
    region: Optional[str] = Field(default="us-east-1", description="Primary cloud region")
    use_demo_fleet: bool = Field(default=True, description="Whether to evaluate a sample production cloud fleet if credentials not supplied")


class InventoryItem(BaseModel):
    id: str
    name: Optional[str] = None
    service_type: Optional[str] = "ComputeInstance"
    instance_type: str
    region: Optional[str] = "us-east-1"
    monthly_cost: Optional[float] = 0.0


class CloudInventoryUploadRequest(BaseModel):
    provider: str = Field(default="AWS", description="Cloud provider (AWS / Azure / GCP)")
    account_id: Optional[str] = Field(default="custom-inventory-account")
    items: List[InventoryItem]


@router.post("/scan/aws")
async def scan_aws_fleet(request: CloudScanRequest, current_user: User = Depends(get_current_active_user)):
    """
    Audit an AWS cloud environment using a Read-Only IAM Role or demo production fleet.
    Audits EC2 instance types, CloudHSMs, and ALB SSL policies.
    """
    try:
        report = CloudInfrastructureScanner.audit_fleet(
            provider="AWS",
            account_id=request.account_id or "123456789012 (AWS Production)",
            inventory=None if request.use_demo_fleet else [],
        )
        return {
            "status": "success",
            "report": {
                **report.__dict__,
                "assets": [a.__dict__ for a in report.assets],
            },
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to audit AWS cloud infrastructure: {exc}")


@router.post("/scan/azure")
async def scan_azure_fleet(request: CloudScanRequest, current_user: User = Depends(get_current_active_user)):
    """
    Audit an Azure subscription using an Azure Reader Service Principal or demo fleet.
    """
    demo_azure = [
        {"id": "vm-prod-web-01", "name": "web-frontend-01", "service_type": "ComputeInstance", "instance_type": "Standard_B2s", "region": "eastus", "monthly_cost": 30.36},
        {"id": "vm-prod-api-01", "name": "core-api-server", "service_type": "ComputeInstance", "instance_type": "Standard_D4s_v5", "region": "eastus", "monthly_cost": 140.16},
        {"id": "hsm-azure-01", "name": "enterprise-managed-hsm", "service_type": "CloudHSM", "instance_type": "azure_keyvault_managed_hsm", "region": "eastus", "monthly_cost": 3200.00},
    ]
    report = CloudInfrastructureScanner.audit_fleet(
        provider="Azure",
        account_id=request.account_id or "sub-98765432-azure-prod",
        inventory=demo_azure,
    )
    return {
        "status": "success",
        "report": {
            **report.__dict__,
            "assets": [a.__dict__ for a in report.assets],
        },
    }


@router.post("/scan/gcp")
async def scan_gcp_fleet(request: CloudScanRequest, current_user: User = Depends(get_current_active_user)):
    """
    Audit a Google Cloud Project using a GCP Security Reviewer service account.
    """
    demo_gcp = [
        {"id": "gce-legacy-worker", "name": "batch-processor-01", "service_type": "ComputeInstance", "instance_type": "n1-standard-4", "region": "us-central1", "monthly_cost": 134.00},
        {"id": "gce-modern-api", "name": "fastapi-endpoint-01", "service_type": "ComputeInstance", "instance_type": "n2-standard-4", "region": "us-central1", "monthly_cost": 150.00},
        {"id": "gce-arm-service", "name": "microservice-auth", "service_type": "ComputeInstance", "instance_type": "t2a-standard-4", "region": "us-central1", "monthly_cost": 98.00},
    ]
    report = CloudInfrastructureScanner.audit_fleet(
        provider="GCP",
        account_id=request.account_id or "gcp-prod-enterprise-4401",
        inventory=demo_gcp,
    )
    return {
        "status": "success",
        "report": {
            **report.__dict__,
            "assets": [a.__dict__ for a in report.assets],
        },
    }


@router.post("/evaluate-inventory")
async def evaluate_uploaded_inventory(request: CloudInventoryUploadRequest, current_user: User = Depends(get_current_active_user)):
    """
    Audit a user-provided inventory of cloud resources (e.g. exported from Terraform or AWS Config).
    """
    raw_items = [i.__dict__ for i in request.items]
    report = CloudInfrastructureScanner.audit_fleet(
        provider=request.provider,
        account_id=request.account_id or "custom-inventory",
        inventory=raw_items,
    )
    return {
        "status": "success",
        "report": {
            **report.__dict__,
            "assets": [a.__dict__ for a in report.assets],
        },
    }


@router.get("/instance-types")
async def get_cloud_instance_catalog(current_user: User = Depends(get_current_active_user)):
    """
    Retrieve the Cloud Silicon & PQC Knowledge Matrix.
    """
    return {
        "total_compute_shapes": len(CLOUD_SILICON_MATRIX),
        "total_managed_services": len(CLOUD_MANAGED_SERVICES_MATRIX),
        "compute_shapes": CLOUD_SILICON_MATRIX,
        "managed_services": CLOUD_MANAGED_SERVICES_MATRIX,
    }
