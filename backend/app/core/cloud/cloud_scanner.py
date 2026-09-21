"""
Cloud Infrastructure Scanner & Post-Quantum CSPM Engine.

Audits cloud compute shapes (EC2, Azure VMs, GCP Compute), CloudHSM instances,
and Load Balancer TLS policies against Post-Quantum lattice requirements.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.core.cloud.knowledge_matrix import (
    CLOUD_SILICON_MATRIX,
    CLOUD_MANAGED_SERVICES_MATRIX,
)

logger = logging.getLogger(__name__)


@dataclass
class CloudAssetAuditItem:
    """Audited cloud infrastructure component."""
    id: str
    name: str
    provider: str                       # AWS | Azure | GCP
    service_type: str                   # ComputeInstance | CloudHSM | LoadBalancer | KeyVault
    instance_type_or_model: str
    region: str
    pqc_status: str                     # PQC_READY | UPGRADE_RECOMMENDED | UPGRADE_REQUIRED
    cpu_family: Optional[str] = None
    avx512_supported: bool = False
    neon_supported: bool = False
    performance_multiplier: float = 1.0
    finding: str = ""
    recommendation: str = ""
    upgrade_target: Optional[str] = None
    estimated_monthly_cost_usd: float = 0.0
    potential_savings_pct: float = 0.0


@dataclass
class CloudFleetAuditReport:
    """Consolidated PQC readiness report for a cloud organization or account."""
    provider: str
    account_or_project_id: str
    total_assets: int
    fleet_pqc_score: float              # 0.0 to 100.0
    fleet_status: str                   # FLEET_PQC_READY | MODERATE_RISK | CRITICAL_HARDWARE_DEFICIT
    pqc_ready_count: int
    upgrade_recommended_count: int
    upgrade_required_count: int
    potential_monthly_savings_usd: float
    impact_on_mosca_years: float        # Hardware-induced delay on migration time Y
    assets: List[CloudAssetAuditItem] = field(default_factory=list)
    remediation_terraform: str = ""
    remediation_cli: str = ""


# Default realistic enterprise cloud fleet for simulation / demo
DEMO_AWS_FLEET = [
    {
        "id": "i-0a817b2f91e42c01",
        "name": "payment-api-gateway-01",
        "service_type": "ComputeInstance",
        "instance_type": "t2.medium",
        "region": "us-east-1",
        "monthly_cost": 33.80,
    },
    {
        "id": "i-0c926a11e83f7b02",
        "name": "payment-api-gateway-02",
        "service_type": "ComputeInstance",
        "instance_type": "t2.medium",
        "region": "us-east-1",
        "monthly_cost": 33.80,
    },
    {
        "id": "i-0d481e9381c62f03",
        "name": "auth-jwt-signer-prod",
        "service_type": "ComputeInstance",
        "instance_type": "m4.xlarge",
        "region": "us-east-1",
        "monthly_cost": 146.00,
    },
    {
        "id": "i-0f738b1827a41e04",
        "name": "high-throughput-orders-worker",
        "service_type": "ComputeInstance",
        "instance_type": "c5.xlarge",
        "region": "us-east-1",
        "monthly_cost": 124.10,
    },
    {
        "id": "i-0e118c7721d94a05",
        "name": "ml-kem-tls-ingress-proxy",
        "service_type": "ComputeInstance",
        "instance_type": "c6i.xlarge",
        "region": "us-east-1",
        "monthly_cost": 124.10,
    },
    {
        "id": "i-09912b7721d94a06",
        "name": "modern-graviton-microservice",
        "service_type": "ComputeInstance",
        "instance_type": "c7g.xlarge",
        "region": "us-east-1",
        "monthly_cost": 105.80,
    },
    {
        "id": "cluster-hsm-0a9182bf",
        "name": "prod-master-root-ca-hsm",
        "service_type": "CloudHSM",
        "instance_type": "aws_cloudhsm_classic",
        "region": "us-east-1",
        "monthly_cost": 1200.00,
    },
    {
        "id": "alb-ingress-public",
        "name": "public-internet-alb-listener-443",
        "service_type": "LoadBalancer",
        "instance_type": "aws_alb_policy_2016_08",
        "region": "us-east-1",
        "monthly_cost": 28.00,
    },
]


class CloudInfrastructureScanner:
    """Audits cloud fleets and maps instance shapes to PQC vector capability."""

    @classmethod
    def audit_fleet(
        cls,
        provider: str = "AWS",
        account_id: str = "123456789012 (Enterprise Production)",
        inventory: Optional[List[Dict[str, Any]]] = None,
    ) -> CloudFleetAuditReport:
        """
        Runs comprehensive post-quantum evaluation across a cloud fleet.
        """
        raw_items = inventory if inventory is not None else DEMO_AWS_FLEET
        audited_assets: List[CloudAssetAuditItem] = []

        ready_count = 0
        rec_count = 0
        req_count = 0
        total_savings = 0.0
        has_critical_hsm_defect = False

        for item in raw_items:
            asset_id = item.get("id") or "cloud-res"
            name = item.get("name") or asset_id
            stype = item.get("service_type") or "ComputeInstance"
            shape = item.get("instance_type") or "unknown"
            region = item.get("region") or "us-east-1"
            cost = float(item.get("monthly_cost") or 0.0)

            # Check Compute Matrix
            if stype == "ComputeInstance":
                entry = CLOUD_SILICON_MATRIX.get(shape)
                if entry:
                    status = entry["pqc_status"]
                    cpu_family = entry["cpu_family"]
                    avx512 = entry["avx512"]
                    neon = entry["neon"]
                    penalty = entry["performance_penalty"]
                    finding = f"{cpu_family}. " + (
                        "Optimal AVX-512/NEON vectorization active."
                        if status == "PQC_READY"
                        else "Lacks AVX-512 vector acceleration. Slows down lattice polynomial operations."
                    )
                    rec = entry["recommendation"]
                    target = entry["upgrade_target"]
                    delta_pct = entry["cost_delta_pct"]

                    # Calculate potential savings if migrating to cheaper instance
                    if delta_pct < 0:
                        savings = cost * (abs(delta_pct) / 100.0)
                        total_savings += savings
                else:
                    status = "UPGRADE_RECOMMENDED"
                    cpu_family = "Generic Cloud Compute"
                    avx512 = False
                    neon = False
                    penalty = 2.0
                    finding = f"Unknown instance type '{shape}'. Review CPU architecture."
                    rec = "Upgrade to modern c6i or Graviton3 (c7g) for certified PQC acceleration."
                    target = "c6i.large"
                    delta_pct = 0.0

            # Check Managed Services (CloudHSM, Load Balancer)
            else:
                entry = CLOUD_MANAGED_SERVICES_MATRIX.get(shape)
                if entry:
                    status = entry["pqc_status"]
                    cpu_family = entry.get("fips_level") or "Hardware Security Module"
                    avx512 = False
                    neon = False
                    penalty = 1.0
                    finding = entry["finding"]
                    rec = entry["recommendation"]
                    target = "AWS CloudHSM v2" if stype == "CloudHSM" else "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"
                    delta_pct = 0.0
                    if status == "UPGRADE_REQUIRED" and stype == "CloudHSM":
                        has_critical_hsm_defect = True
                else:
                    status = "UPGRADE_RECOMMENDED"
                    cpu_family = "Managed Cloud Service"
                    avx512 = False
                    neon = False
                    penalty = 1.0
                    finding = f"Managed cloud service '{stype}' requires PQC review."
                    rec = "Verify vendor support for FIPS 203/204 algorithms."
                    target = None
                    delta_pct = 0.0

            if status == "PQC_READY":
                ready_count += 1
            elif status == "UPGRADE_RECOMMENDED":
                rec_count += 1
            else:
                req_count += 1

            audited_assets.append(
                CloudAssetAuditItem(
                    id=asset_id,
                    name=name,
                    provider=provider,
                    service_type=stype,
                    instance_type_or_model=shape,
                    region=region,
                    pqc_status=status,
                    cpu_family=cpu_family,
                    avx512_supported=avx512,
                    neon_supported=neon,
                    performance_multiplier=penalty,
                    finding=finding,
                    recommendation=rec,
                    upgrade_target=target,
                    estimated_monthly_cost_usd=cost,
                    potential_savings_pct=abs(delta_pct) if delta_pct < 0 else 0.0,
                )
            )

        total_assets = len(audited_assets)
        if total_assets > 0:
            fleet_score = round(((ready_count * 1.0) + (rec_count * 0.5)) / total_assets * 100.0, 1)
        else:
            fleet_score = 100.0

        if fleet_score >= 80.0:
            fleet_status = "FLEET_PQC_READY"
        elif fleet_score >= 50.0:
            fleet_status = "MODERATE_RISK"
        else:
            fleet_status = "CRITICAL_HARDWARE_DEFICIT"

        # Impact on Mosca's Theorem Y (Migration Time in years):
        # Cloud VM instance changes take 0.2 years, but replacing CloudHSMs adds 1.5 years
        impact_y = 0.3
        if has_critical_hsm_defect:
            impact_y += 1.5
        if req_count >= 3:
            impact_y += 0.5

        # Generate Terraform remediation snippet
        terraform_code = (
            "# --- CypherCite Automated Cloud Modernization Plan ---\n"
            "# 1. Migrate vulnerable burstable instances to Graviton2/3:\n"
            "resource \"aws_instance\" \"payment_api_gateway\" {\n"
            "  ami           = \"ami-0c7217cdde317cfec\" # Amazon Linux 2023 (ARM64)\n"
            "  instance_type = \"t4g.medium\"             # Upgraded from t2.medium (-20% cost, 4.2x PQC speedup)\n"
            "  # ...\n"
            "}\n\n"
            "# 2. Enforce Post-Quantum TLS 1.3 on Load Balancer:\n"
            "resource \"aws_lb_listener\" \"https_ingress\" {\n"
            "  load_balancer_arn = aws_lb.public_alb.arn\n"
            "  port              = \"443\"\n"
            "  protocol          = \"HTTPS\"\n"
            "  ssl_policy        = \"ELBSecurityPolicy-TLS13-1-2-Res-2021-06\"\n"
            "  # ...\n"
            "}\n"
        )

        cli_code = (
            "# AWS CLI commands to upgrade instances:\n"
            "aws ec2 modify-instance-attribute --instance-id i-0a817b2f91e42c01 --instance-type \"{\"Value\": \"t4g.medium\"}\"\n"
            "aws elbv2 modify-listener --listener-arn <listener-arn> --ssl-policy ELBSecurityPolicy-TLS13-1-2-Res-2021-06\n"
        )

        return CloudFleetAuditReport(
            provider=provider,
            account_or_project_id=account_id,
            total_assets=total_assets,
            fleet_pqc_score=fleet_score,
            fleet_status=fleet_status,
            pqc_ready_count=ready_count,
            upgrade_recommended_count=rec_count,
            upgrade_required_count=req_count,
            potential_monthly_savings_usd=round(total_savings, 2),
            impact_on_mosca_years=round(impact_y, 2),
            assets=audited_assets,
            remediation_terraform=terraform_code,
            remediation_cli=cli_code,
        )
