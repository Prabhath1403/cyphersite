"""
Unified Scan Pipeline — orchestrates multiple scanners, normalizes outputs,
and generates canonical CBOMs and inventory graphs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from app.core.source_scanner import (
    BaseScanner,
    CryptoFindingData,
    ScanResult,
    ScanTarget,
)
from app.core.pipeline.normalizer import CryptoNormalizer
from app.core.sensitivity import SensitivityInferenceEngine
from app.core.cbom.builder import build_cbom, cbom_to_json_string

logger = logging.getLogger(__name__)


@dataclass
class UnifiedScanExecutionResult:
    """Aggregate result from the unified pipeline."""
    target: str
    scan_type: str
    findings: List[CryptoFindingData] = field(default_factory=list)
    total_assets: int = 0
    quantum_safe_count: int = 0
    hybrid_count: int = 0
    vulnerable_count: int = 0
    average_risk_score: float = 0.0
    cbom_json: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class UnifiedScanPipeline:
    """
    Central pipeline orchestrating discovery, normalization, CBOM creation,
    and PQC readiness evaluation across all target modalities.
    """

    def __init__(self):
        self._scanners: Dict[str, BaseScanner] = {}
        self._register_default_scanners()

    def _register_default_scanners(self) -> None:
        """Register built-in scanners for source, container, and binary targets."""
        try:
            from app.core.source_scanner.python_scanner import PythonScanner
            self.register_scanner(PythonScanner())
        except Exception as exc:
            logger.debug("PythonScanner registration skipped: %s", exc)

        try:
            from app.core.container_scanner import ContainerScanner
            self.register_scanner(ContainerScanner())
        except Exception as exc:
            logger.debug("ContainerScanner registration skipped: %s", exc)

        try:
            from app.core.binary_scanner import BinaryScanner
            self.register_scanner(BinaryScanner())
        except Exception as exc:
            logger.debug("BinaryScanner registration skipped: %s", exc)

    def register_scanner(self, scanner: BaseScanner) -> None:
        """Register a scanner for its supported target types."""
        for t in scanner.supported_types:
            self._scanners[t] = scanner
            logger.info("Registered scanner '%s' for type '%s'", scanner.name, t)

    def execute(self, target: ScanTarget, scan_id: str = "pipeline-scan") -> UnifiedScanExecutionResult:
        """
        Execute scan for the given target, normalize findings, and generate CBOM.
        """
        scan_type = target.scan_type.lower()
        scanner = self._scanners.get(scan_type)

        if not scanner:
            return UnifiedScanExecutionResult(
                target=target.path,
                scan_type=scan_type,
                errors=[f"No scanner registered for scan type: '{scan_type}'"],
            )

        # 1. Execute Scanner
        scan_result: ScanResult = scanner.scan(target)

        # 2. Normalize Findings through CryptoNormalizer & Data Sensitivity Engine
        normalized_findings = CryptoNormalizer.batch_normalize(scan_result.findings)
        normalized_findings = SensitivityInferenceEngine.batch_enrich(normalized_findings)

        # 3. Compute Metrics
        qs = 0
        hybrid = 0
        vuln = 0
        total_risk = 0.0

        for f in normalized_findings:
            status = (f.pqc_status or "").upper()
            if status == "QUANTUM_SAFE":
                qs += 1
            elif status == "HYBRID_READY":
                hybrid += 1
            else:
                vuln += 1
            total_risk += float(f.risk_score or 0.0)

        total = len(normalized_findings)
        avg_risk = round(total_risk / total, 2) if total > 0 else 0.0

        # 4. Build CBOM
        cbom = build_cbom(
            scan_id=scan_id,
            target=target.path,
            assets=normalized_findings,
        )
        cbom_json = cbom_to_json_string(cbom)

        return UnifiedScanExecutionResult(
            target=target.path,
            scan_type=scan_type,
            findings=normalized_findings,
            total_assets=total,
            quantum_safe_count=qs,
            hybrid_count=hybrid,
            vulnerable_count=vuln,
            average_risk_score=avg_risk,
            cbom_json=cbom_json,
            errors=list(scan_result.errors),
            warnings=list(scan_result.warnings),
        )
