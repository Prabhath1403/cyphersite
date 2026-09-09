"""
Quantum Risk Engine — calculates multi-factor post-quantum risk,
evaluates Mosca's Theorem of Quantum Risk, and checks regulatory compliance.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

KB_PATH = Path(__file__).parent / "knowledge_base" / "algorithms.yaml"


@dataclass
class MoscaEvaluation:
    """Result of evaluating Michele Mosca's Theorem of Quantum Risk."""
    x_shelf_life_years: float
    y_migration_years: float
    z_q_day_years: float
    total_timeline: float               # X + Y
    slack_years: float                  # Z - (X + Y)
    is_violated: bool                   # True if X + Y > Z
    urgency_status: str                 # CRITICAL_RETROACTIVE_EXPOSURE | APPROACHING_DEADLINE | SUFFICIENT_WINDOW
    description: str


@dataclass
class RiskEvaluationResult:
    """Comprehensive risk evaluation for a cryptographic asset."""
    algorithm: str
    risk_score: float                   # 0.0 - 100.0
    risk_level: str                     # CRITICAL | HIGH | MEDIUM | LOW | INFO
    pqc_status: str                     # QUANTUM_SAFE | HYBRID_READY | VULNERABLE | REDUCED_SECURITY_MARGIN
    quantum_break_method: str
    quantum_complexity: str
    recommended_replacement: str
    mosca: Optional[MoscaEvaluation] = None
    regulatory_deadlines: Dict[str, str] = field(default_factory=dict)
    risk_factors: Dict[str, float] = field(default_factory=dict)


class QuantumRiskEngine:
    """
    Evaluates quantum cryptographic risk using authoritative knowledge-base signatures,
    Mosca's inequality ($X + Y > Z$), and CNSA/NIST regulatory timetables.
    """

    _kb_cache: Optional[Dict[str, Any]] = None

    @classmethod
    def load_kb(cls) -> Dict[str, Any]:
        if cls._kb_cache is None:
            if KB_PATH.exists():
                try:
                    with open(KB_PATH, "r") as f:
                        cls._kb_cache = yaml.safe_load(f).get("algorithms", {})
                except Exception as exc:
                    logger.warning("Failed to parse algorithms.yaml: %s", exc)
                    cls._kb_cache = {}
            else:
                cls._kb_cache = {}
        return cls._kb_cache

    @classmethod
    def evaluate_mosca(
        cls,
        shelf_life_years: float = 10.0,
        migration_years: float = 3.0,
        q_day_years: float = 8.0,       # Default ~2034
    ) -> MoscaEvaluation:
        """
        Evaluate Mosca's Theorem: If (X + Y > Z), then retroactive decryption is inevitable.
        """
        total = shelf_life_years + migration_years
        slack = round(q_day_years - total, 2)
        is_violated = total > q_day_years

        if is_violated:
            status = "CRITICAL_RETROACTIVE_EXPOSURE"
            desc = (
                f"Mosca Violation: Data lifetime ({shelf_life_years}y) + migration time ({migration_years}y) = "
                f"{total}y, exceeding estimated time to Q-Day ({q_day_years}y) by {abs(slack)}y. "
                "Data is already vulnerable to retroactive decryption (HNDL)."
            )
        elif slack <= 2.0:
            status = "APPROACHING_DEADLINE"
            desc = (
                f"Approaching Mosca Threshold: Only {slack} years of safety margin remain before "
                "data protection is compromised by quantum cryptanalysis."
            )
        else:
            status = "SUFFICIENT_WINDOW"
            desc = f"Safety margin of {slack} years remains before estimated Q-Day."

        return MoscaEvaluation(
            x_shelf_life_years=shelf_life_years,
            y_migration_years=migration_years,
            z_q_day_years=q_day_years,
            total_timeline=total,
            slack_years=slack,
            is_violated=is_violated,
            urgency_status=status,
            description=desc,
        )

    @classmethod
    def evaluate_asset_risk(
        cls,
        algorithm: str,
        sensitivity: str = "MEDIUM",
        is_public: bool = False,
        shelf_life_years: float = 5.0,
        migration_years: float = 2.0,
        q_day_years: float = 8.0,
    ) -> RiskEvaluationResult:
        """
        Compute multi-factor quantum risk score for an algorithm.
        """
        kb = cls.load_kb()
        clean_algo = algorithm.strip()

        # Find matching KB entry
        entry = None
        for k, v in kb.items():
            if k.lower() in clean_algo.lower() or clean_algo.lower() in k.lower():
                entry = v
                break

        # Fallback entry
        if not entry:
            is_pqc = any(p in clean_algo.upper() for p in ("ML-KEM", "ML-DSA", "SLH-DSA", "FALCON", "KYBER", "DILITHIUM"))
            is_asym = any(a in clean_algo.upper() for a in ("RSA", "DSA", "DH", "ECDSA", "ECDH"))
            entry = {
                "quantum_status": "safe" if is_pqc else ("vulnerable" if is_asym else "unknown"),
                "quantum_break_method": "None known" if is_pqc else ("Shor's Algorithm" if is_asym else "Grover's Algorithm"),
                "quantum_complexity": "NIST PQC" if is_pqc else ("Polynomial Time" if is_asym else "O(2^{k/2})"),
                "recommended_replacement": "Maintain" if is_pqc else "NIST FIPS 203/204 Standard",
                "regulatory_deadlines": {"NIST": "Migrate to PQC"},
            }

        q_status = entry.get("quantum_status", "unknown")

        # 1. Base Algorithm Factor (0 - 40)
        if q_status == "vulnerable":
            base_algo_score = 40.0
        elif q_status == "reduced_security_margin":
            base_algo_score = 20.0
        elif q_status == "safe":
            base_algo_score = 0.0
        else:
            base_algo_score = 15.0

        # 2. Sensitivity Factor (0 - 30) & Exposure Factor (0 - 10)
        # Only amplifies quantum risk if algorithm is vulnerable or reduced security margin
        if q_status == "safe":
            sens_score = 0.0
            exposure_score = 0.0
            eff_shelf_life = shelf_life_years
        else:
            sens_upper = sensitivity.upper()
            if sens_upper == "CRITICAL":
                sens_score = 30.0
                eff_shelf_life = max(shelf_life_years, 10.0)
            elif sens_upper == "HIGH":
                sens_score = 20.0
                eff_shelf_life = max(shelf_life_years, 7.0)
            elif sens_upper == "MEDIUM":
                sens_score = 10.0
                eff_shelf_life = shelf_life_years
            else:
                sens_score = 0.0
                eff_shelf_life = shelf_life_years
            exposure_score = 10.0 if is_public else 4.0

        # 3. Mosca Urgency Factor (0 - 20)
        mosca_eval = None
        if q_status == "vulnerable":
            mosca_eval = cls.evaluate_mosca(
                shelf_life_years=eff_shelf_life,
                migration_years=migration_years,
                q_day_years=q_day_years,
            )
            if mosca_eval.is_violated:
                mosca_score = 20.0
            elif mosca_eval.urgency_status == "APPROACHING_DEADLINE":
                mosca_score = 12.0
            else:
                mosca_score = 5.0
        else:
            mosca_score = 0.0

        total_score = min(100.0, round(base_algo_score + sens_score + mosca_score + exposure_score, 1))

        if total_score >= 85.0:
            level = "CRITICAL"
        elif total_score >= 65.0:
            level = "HIGH"
        elif total_score >= 40.0:
            level = "MEDIUM"
        elif total_score > 10.0:
            level = "LOW"
        else:
            level = "INFO"

        pqc_status_map = {
            "safe": "QUANTUM_SAFE",
            "vulnerable": "VULNERABLE",
            "reduced_security_margin": "REDUCED_SECURITY_MARGIN",
        }

        return RiskEvaluationResult(
            algorithm=clean_algo,
            risk_score=total_score,
            risk_level=level,
            pqc_status=pqc_status_map.get(q_status, "UNKNOWN"),
            quantum_break_method=entry.get("quantum_break_method", "Unknown"),
            quantum_complexity=entry.get("quantum_complexity", "Unknown"),
            recommended_replacement=entry.get("recommended_replacement", "NIST PQC Standard"),
            mosca=mosca_eval,
            regulatory_deadlines=entry.get("regulatory_deadlines", {}),
            risk_factors={
                "algorithm_vulnerability": base_algo_score,
                "data_sensitivity": sens_score,
                "mosca_timeline": mosca_score,
                "exposure": exposure_score,
            },
        )
