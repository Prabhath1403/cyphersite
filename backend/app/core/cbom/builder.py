"""
CycloneDX CBOM Builder — generates Cryptographic Bill of Materials.

Creates structured CBOM documents following the CycloneDX standard,
representing each asset's cryptographic posture.
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


def build_cbom(
    scan_id: str,
    target: str,
    assets: List[Dict[str, Any]],
    scan_timestamp: Optional[str] = None,
) -> dict:
    """
    Build a CycloneDX CBOM document from scan results.

    Creates a CycloneDX 1.5 compatible CBOM with each asset
    represented as a cryptographic-asset component.

    Args:
        scan_id: UUID of the scan job.
        target: Original scan target.
        assets: List of asset dictionaries with crypto details.
        scan_timestamp: ISO timestamp of the scan.

    Returns:
        CycloneDX CBOM dictionary.
    """
    if scan_timestamp is None:
        scan_timestamp = datetime.utcnow().isoformat() + "Z"

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": scan_timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "CipherSight",
                        "version": "1.0.0",
                        "description": "Quantum-Proof Cryptographic Scanner & CBOM Generator",
                        "manufacturer": {
                            "name": "CipherSight Security",
                        },
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": target,
                "bom-ref": f"scan-{scan_id}",
                "description": f"Cryptographic scan of {target}",
            },
            "properties": [
                {"name": "ciphersight:scan_id", "value": str(scan_id)},
                {"name": "ciphersight:target", "value": target},
            ],
        },
        "components": [],
        "compositions": [],
        "vulnerabilities": [],
    }

    for asset in assets:
        component = _build_component(asset)
        cbom["components"].append(component)

        # Add vulnerabilities for non-quantum-safe assets
        asset_vulns = asset.get("vulnerabilities", [])
        if asset_vulns:
            for vuln_desc in asset_vulns:
                vuln = _build_vulnerability(asset, vuln_desc)
                cbom["vulnerabilities"].append(vuln)

    # Add composition
    cbom["compositions"].append({
        "aggregate": "complete",
        "assemblies": [comp["bom-ref"] for comp in cbom["components"]],
    })

    return cbom


def _build_component(asset: Dict[str, Any]) -> dict:
    """
    Build a CycloneDX component from an asset.

    Args:
        asset: Asset dictionary with crypto details.

    Returns:
        CycloneDX component dictionary.
    """
    asset_id = str(asset.get("id", uuid4()))
    hostname = asset.get("hostname", "unknown")
    port = asset.get("port", 443)

    component = {
        "type": "cryptographic-asset",
        "bom-ref": f"asset-{asset_id}",
        "name": f"{hostname}:{port}",
        "description": f"Cryptographic endpoint at {hostname}:{port}",
        "properties": [],
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {
                "type": "tls",
                "version": "",
                "cipherSuites": [],
            },
        },
    }

    # Add TLS versions
    tls_versions = asset.get("tls_versions", [])
    if tls_versions:
        component["cryptoProperties"]["protocolProperties"]["version"] = ", ".join(tls_versions)
        component["properties"].append({
            "name": "ciphersight:tls_versions",
            "value": json.dumps(tls_versions),
        })

    # Add cipher suites
    cipher_suites = asset.get("cipher_suites", [])
    for suite in cipher_suites:
        cs_entry = {
            "name": suite.get("name", "unknown"),
            "algorithms": [],
            "identifiers": [],
        }
        if suite.get("key_exchange"):
            cs_entry["algorithms"].append(suite["key_exchange"])
        if suite.get("encryption"):
            cs_entry["algorithms"].append(suite["encryption"])
        component["cryptoProperties"]["protocolProperties"]["cipherSuites"].append(cs_entry)

    # Add certificate info
    cert = asset.get("certificate", {})
    if cert:
        component["properties"].append({
            "name": "ciphersight:certificate_algorithm",
            "value": cert.get("public_key_algorithm", "unknown"),
        })
        component["properties"].append({
            "name": "ciphersight:certificate_key_size",
            "value": str(cert.get("key_size", 0)),
        })
        component["properties"].append({
            "name": "ciphersight:certificate_signature",
            "value": cert.get("signature_algorithm", "unknown"),
        })

    # Add PQC assessment properties
    pqc_status = asset.get("pqc_status", "UNKNOWN")
    risk_score = asset.get("risk_score", 100)

    component["properties"].extend([
        {"name": "ciphersight:pqc_status", "value": pqc_status},
        {"name": "ciphersight:risk_score", "value": str(risk_score)},
        {"name": "ciphersight:service_type", "value": asset.get("service_type", "other")},
    ])

    # Key exchange
    if asset.get("key_exchange"):
        component["properties"].append({
            "name": "ciphersight:key_exchange",
            "value": asset["key_exchange"],
        })

    return component


def _build_vulnerability(asset: Dict[str, Any], description: str) -> dict:
    """
    Build a CycloneDX vulnerability entry.

    Args:
        asset: Asset dictionary.
        description: Vulnerability description.

    Returns:
        CycloneDX vulnerability dictionary.
    """
    risk_score = asset.get("risk_score", 50)
    severity = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 40 else "low"

    return {
        "id": f"CIPHERSIGHT-{uuid4().hex[:8].upper()}",
        "source": {"name": "CipherSight PQC Assessor"},
        "description": description,
        "ratings": [
            {
                "score": risk_score / 10,
                "severity": severity,
                "method": "other",
                "source": {"name": "CipherSight Risk Engine"},
            }
        ],
        "affects": [
            {
                "ref": f"asset-{asset.get('id', '')}",
            }
        ],
        "recommendation": "; ".join(asset.get("recommendations", [])[:3]),
        "properties": [
            {"name": "ciphersight:pqc_status", "value": asset.get("pqc_status", "VULNERABLE")},
        ],
    }


def cbom_to_json_string(cbom: dict, indent: int = 2) -> str:
    """Serialize CBOM to a JSON string."""
    return json.dumps(cbom, indent=indent, default=str)
