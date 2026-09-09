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
    assets: List[Any],
    scan_timestamp: Optional[str] = None,
) -> dict:
    """
    Build a CycloneDX CBOM document from scan results.

    Creates a CycloneDX 1.5 compatible CBOM with each asset or crypto finding
    represented as a cryptographic-asset component. Supports both network
    endpoints and source-code findings.

    Args:
        scan_id: UUID of the scan job.
        target: Original scan target (domain, IP, repo URL, or local path).
        assets: List of asset dictionaries or CryptoAsset/CryptoFindingData objects.
        scan_timestamp: ISO timestamp of the scan.

    Returns:
        CycloneDX CBOM dictionary.
    """
    if scan_timestamp is None:
        scan_timestamp = datetime.utcnow().isoformat() + "Z"

    # Normalize incoming assets to dicts
    normalized_assets = []
    for a in assets:
        if isinstance(a, dict):
            normalized_assets.append(a)
        elif hasattr(a, "to_orm_kwargs"):
            d = a.to_orm_kwargs()
            if not d.get("id") and hasattr(a, "id"):
                d["id"] = getattr(a, "id")
            normalized_assets.append(d)
        elif hasattr(a, "__dict__"):
            d = {k: v for k, v in a.__dict__.items() if not k.startswith("_")}
            normalized_assets.append(d)
        else:
            normalized_assets.append(dict(a))

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

    for asset in normalized_assets:
        component = _build_component(asset)
        cbom["components"].append(component)

        # Add vulnerabilities for non-quantum-safe assets
        asset_vulns = asset.get("vulnerabilities") or []
        pqc_status = asset.get("pqc_status")
        quantum_status = asset.get("quantum_status")

        if asset_vulns:
            for vuln_desc in asset_vulns:
                vuln = _build_vulnerability(asset, vuln_desc)
                cbom["vulnerabilities"].append(vuln)
        elif pqc_status == "VULNERABLE" or quantum_status == "vulnerable":
            name = asset.get("name") or asset.get("algorithm") or "Asset"
            vuln = _build_vulnerability(asset, f"{name} is vulnerable to quantum attacks")
            cbom["vulnerabilities"].append(vuln)

    # Add composition
    cbom["compositions"].append({
        "aggregate": "complete",
        "assemblies": [comp["bom-ref"] for comp in cbom["components"]],
    })

    return cbom


def _build_component(asset: Dict[str, Any]) -> dict:
    """
    Build a CycloneDX component from an asset or crypto finding.

    Handles both network endpoints and source-code / library findings.

    Args:
        asset: Asset dictionary with crypto details.

    Returns:
        CycloneDX component dictionary.
    """
    asset_id = str(asset.get("id", uuid4()))
    source_type = asset.get("source_type", "")
    file_path = asset.get("file_path")

    # Check if this is a source code / algorithm finding vs network endpoint
    is_source = (
        source_type == "source_code"
        or bool(file_path)
        or (asset.get("asset_type") in ("source_code_usage", "algorithm", "library", "dependency") and not asset.get("hostname"))
    )

    if is_source:
        name = asset.get("name") or asset.get("algorithm") or "Unknown-Crypto"
        line_number = asset.get("line_number")
        loc_str = f" in {file_path}:{line_number}" if file_path and line_number else (f" in {file_path}" if file_path else "")
        description = f"Cryptographic finding: {name}{loc_str}"

        # CycloneDX 1.5 cryptoProperties
        crypto_props = {
            "assetType": "algorithm" if asset.get("asset_type") in ("algorithm", "source_code_usage") else asset.get("asset_type", "algorithm"),
            "algorithmProperties": {
                "primitive": asset.get("primitive"),
                "parameterSetIdentifier": str(asset.get("key_size")) if asset.get("key_size") else None,
                "curve": None,
                "mode": asset.get("mode"),
                "padding": asset.get("padding"),
                "cryptoFunctions": [asset.get("usage")] if asset.get("usage") else [],
            },
        }
        if asset.get("algorithm"):
            crypto_props["algorithmProperties"]["name"] = asset.get("algorithm")

        component = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{asset_id}",
            "name": name,
            "description": description,
            "properties": [],
            "cryptoProperties": crypto_props,
        }

        if asset.get("version") or asset.get("library_version"):
            component["version"] = asset.get("version") or asset.get("library_version")

        # Evidence / Occurrences
        if file_path:
            occ: Dict[str, Any] = {"location": file_path}
            if line_number:
                occ["line"] = line_number
            component["evidence"] = {"occurrences": [occ]}
            if asset.get("evidence") and isinstance(asset["evidence"], dict):
                component["evidence"]["details"] = asset["evidence"]

        # CipherSight custom properties
        props_to_add = [
            ("ciphersight:source_type", asset.get("source_type", "source_code")),
            ("ciphersight:asset_type", asset.get("asset_type", "source_code_usage")),
            ("ciphersight:algorithm", asset.get("algorithm")),
            ("ciphersight:algorithm_family", asset.get("algorithm_family")),
            ("ciphersight:key_size", str(asset.get("key_size")) if asset.get("key_size") is not None else None),
            ("ciphersight:primitive", asset.get("primitive")),
            ("ciphersight:mode", asset.get("mode")),
            ("ciphersight:padding", asset.get("padding")),
            ("ciphersight:usage", asset.get("usage")),
            ("ciphersight:library", asset.get("library")),
            ("ciphersight:library_version", asset.get("library_version")),
            ("ciphersight:file_path", file_path),
            ("ciphersight:line_number", str(line_number) if line_number is not None else None),
            ("ciphersight:function_name", asset.get("function_name")),
            ("ciphersight:language", asset.get("language")),
            ("ciphersight:repository", asset.get("repository")),
            ("ciphersight:confidence", str(asset.get("confidence")) if asset.get("confidence") is not None else None),
            ("ciphersight:pqc_status", asset.get("pqc_status", "UNKNOWN")),
            ("ciphersight:quantum_status", asset.get("quantum_status")),
            ("ciphersight:risk_score", str(asset.get("risk_score", 50))),
            ("ciphersight:risk_level", asset.get("risk_level")),
            ("ciphersight:sensitivity", asset.get("sensitivity")),
        ]
        for prop_name, prop_val in props_to_add:
            if prop_val is not None:
                component["properties"].append({"name": prop_name, "value": prop_val})

        return component

    # Network endpoint component (backward-compatible)
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
    risk_score = float(asset.get("risk_score") or 50)
    risk_level = asset.get("risk_level")
    if risk_level:
        severity = risk_level.lower()
    else:
        severity = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 40 else "low"

    asset_id = str(asset.get("id", ""))
    is_source = (asset.get("source_type") == "source_code") or bool(asset.get("file_path"))
    bom_ref = f"crypto-asset-{asset_id}" if is_source else f"asset-{asset_id}"

    recs = asset.get("recommendations") or []
    recommendation = "; ".join(recs[:3]) if recs else "Upgrade to post-quantum cryptographic algorithms"

    return {
        "id": f"CIPHERSIGHT-{uuid4().hex[:8].upper()}",
        "source": {"name": "CipherSight PQC Assessor"},
        "description": description,
        "ratings": [
            {
                "score": round(risk_score / 10, 1),
                "severity": severity,
                "method": "other",
                "source": {"name": "CipherSight Risk Engine"},
            }
        ],
        "affects": [
            {
                "ref": bom_ref,
            }
        ],
        "recommendation": recommendation,
        "properties": [
            {"name": "ciphersight:pqc_status", "value": asset.get("pqc_status", "VULNERABLE")},
        ],
    }


def cbom_to_json_string(cbom: dict, indent: int = 2) -> str:
    """Serialize CBOM to a JSON string."""
    return json.dumps(cbom, indent=indent, default=str)
