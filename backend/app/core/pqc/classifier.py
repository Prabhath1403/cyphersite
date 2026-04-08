"""
Asset classifier — categorizes assets by PQC readiness.

Provides utility functions to classify and summarize asset
security postures across a scan.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ClassificationSummary:
    """Summary of classification results across assets."""
    total: int = 0
    quantum_safe: int = 0
    hybrid_ready: int = 0
    vulnerable: int = 0
    quantum_safe_pct: float = 0.0
    hybrid_ready_pct: float = 0.0
    vulnerable_pct: float = 0.0
    avg_risk_score: float = 0.0
    highest_risk_asset: Optional[str] = None
    highest_risk_score: float = 0.0

    def to_dict(self):
        return asdict(self)


def classify_asset(pqc_status: str, risk_score: float) -> str:
    """
    Classify an asset into a security tier.

    Args:
        pqc_status: PQC status from assessor.
        risk_score: Risk score from assessor.

    Returns:
        Classification label with emoji indicator.
    """
    if pqc_status == "QUANTUM_SAFE":
        return "🟢 Quantum Safe"
    elif pqc_status == "HYBRID_READY":
        return "🟡 Hybrid Ready"
    else:
        if risk_score >= 80:
            return "🔴 Critical"
        elif risk_score >= 60:
            return "🟠 High Risk"
        else:
            return "🔴 Vulnerable"


def get_severity_level(risk_score: float) -> str:
    """
    Get severity level from risk score.

    Args:
        risk_score: 0-100 risk score.

    Returns:
        Severity string: CRITICAL, HIGH, MEDIUM, LOW, INFO
    """
    if risk_score >= 80:
        return "CRITICAL"
    elif risk_score >= 60:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    elif risk_score >= 20:
        return "LOW"
    else:
        return "INFO"


def summarize_classifications(assets: List[Dict[str, Any]]) -> ClassificationSummary:
    """
    Produce a summary of all asset classifications.

    Args:
        assets: List of asset dictionaries with pqc_status and risk_score.

    Returns:
        ClassificationSummary with aggregated statistics.
    """
    summary = ClassificationSummary(total=len(assets))

    if not assets:
        return summary

    total_risk = 0.0

    for asset in assets:
        status = asset.get("pqc_status", "VULNERABLE")
        risk = asset.get("risk_score", 100.0)
        hostname = asset.get("hostname", "unknown")

        if status == "QUANTUM_SAFE":
            summary.quantum_safe += 1
        elif status == "HYBRID_READY":
            summary.hybrid_ready += 1
        else:
            summary.vulnerable += 1

        total_risk += risk

        if risk > summary.highest_risk_score:
            summary.highest_risk_score = risk
            summary.highest_risk_asset = hostname

    # Calculate percentages
    if summary.total > 0:
        summary.quantum_safe_pct = round(summary.quantum_safe / summary.total * 100, 1)
        summary.hybrid_ready_pct = round(summary.hybrid_ready / summary.total * 100, 1)
        summary.vulnerable_pct = round(summary.vulnerable / summary.total * 100, 1)
        summary.avg_risk_score = round(total_risk / summary.total, 1)

    return summary
