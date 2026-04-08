"""
CBOM Exporter — exports CBOM data in JSON, CSV, and PDF formats.
"""

import csv
import io
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


def export_json(cbom: dict) -> str:
    """
    Export CBOM as formatted JSON string.

    Args:
        cbom: CycloneDX CBOM dictionary.

    Returns:
        Formatted JSON string.
    """
    return json.dumps(cbom, indent=2, default=str)


def export_csv(cbom: dict) -> str:
    """
    Export CBOM components as CSV.

    Flattens the component data into a tabular format suitable
    for spreadsheet analysis.

    Args:
        cbom: CycloneDX CBOM dictionary.

    Returns:
        CSV string.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "Component",
        "Type",
        "PQC Status",
        "Risk Score",
        "Service Type",
        "TLS Versions",
        "Key Exchange",
        "Certificate Algorithm",
        "Certificate Key Size",
        "Cipher Suites Count",
    ])

    for component in cbom.get("components", []):
        props = {p["name"]: p["value"] for p in component.get("properties", [])}

        # Count cipher suites
        crypto_props = component.get("cryptoProperties", {})
        protocol_props = crypto_props.get("protocolProperties", {})
        cipher_count = len(protocol_props.get("cipherSuites", []))

        writer.writerow([
            component.get("name", ""),
            component.get("type", ""),
            props.get("ciphersight:pqc_status", ""),
            props.get("ciphersight:risk_score", ""),
            props.get("ciphersight:service_type", ""),
            protocol_props.get("version", ""),
            props.get("ciphersight:key_exchange", ""),
            props.get("ciphersight:certificate_algorithm", ""),
            props.get("ciphersight:certificate_key_size", ""),
            cipher_count,
        ])

    # Add vulnerabilities section
    writer.writerow([])
    writer.writerow(["--- Vulnerabilities ---"])
    writer.writerow(["ID", "Description", "Severity", "Affected Component", "Recommendation"])

    for vuln in cbom.get("vulnerabilities", []):
        ratings = vuln.get("ratings", [{}])
        severity = ratings[0].get("severity", "") if ratings else ""
        affects = vuln.get("affects", [{}])
        affected = affects[0].get("ref", "") if affects else ""

        writer.writerow([
            vuln.get("id", ""),
            vuln.get("description", ""),
            severity,
            affected,
            vuln.get("recommendation", ""),
        ])

    return output.getvalue()


def extract_summary_data(cbom: dict) -> Dict[str, Any]:
    """
    Extract summary statistics from CBOM for reports.

    Args:
        cbom: CycloneDX CBOM dictionary.

    Returns:
        Summary statistics dictionary.
    """
    components = cbom.get("components", [])
    vulnerabilities = cbom.get("vulnerabilities", [])

    status_counts = {"QUANTUM_SAFE": 0, "HYBRID_READY": 0, "VULNERABLE": 0}
    total_risk = 0
    algorithms_seen = set()

    for comp in components:
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        status = props.get("ciphersight:pqc_status", "VULNERABLE")
        risk = float(props.get("ciphersight:risk_score", 100))

        status_counts[status] = status_counts.get(status, 0) + 1
        total_risk += risk

        # Collect algorithms
        crypto_props = comp.get("cryptoProperties", {})
        for suite in crypto_props.get("protocolProperties", {}).get("cipherSuites", []):
            for algo in suite.get("algorithms", []):
                algorithms_seen.add(algo)

    avg_risk = total_risk / max(len(components), 1)

    return {
        "total_components": len(components),
        "total_vulnerabilities": len(vulnerabilities),
        "status_counts": status_counts,
        "avg_risk_score": round(avg_risk, 1),
        "unique_algorithms": sorted(list(algorithms_seen)),
        "scan_timestamp": cbom.get("metadata", {}).get("timestamp", ""),
        "target": cbom.get("metadata", {}).get("component", {}).get("name", ""),
    }
