"""
Data Sensitivity Inference Engine.

Infers the sensitivity classification of cryptographic operations (CRITICAL, HIGH,
MEDIUM, LOW, PUBLIC) based on contextual cues:
- Function and variable identifiers
- File paths and package namespaces
- Surrounding code AST contexts
- Cryptographic usage and primitives
- Harvest Now, Decrypt Later (HNDL) exposure risk
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from app.core.source_scanner import CryptoFindingData


class SensitivityLevel(str, Enum):
    CRITICAL = "CRITICAL"    # Passwords, master keys, credit cards (PCI), SSN, health data (HIPAA)
    HIGH = "HIGH"            # PII, session tokens, authentication credentials, emails, personal data
    MEDIUM = "MEDIUM"        # Internal API tokens, tenant identifiers, audit logs, system configs
    LOW = "LOW"              # Telemetry, cache keys, non-sensitive operational identifiers
    PUBLIC = "PUBLIC"        # Static integrity digests, public assets, etags
    UNKNOWN = "UNKNOWN"


@dataclass
class SensitivityResult:
    """Outcome of sensitivity inference."""
    level: str
    confidence: float
    rationale: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    hndl_exposure: str = "NEGLIGIBLE"  # EXTREME | HIGH | MODERATE | LOW | NEGLIGIBLE
    regulatory_impact: List[str] = field(default_factory=list)  # PCI-DSS, HIPAA, GDPR, etc.


# Pattern taxonomies with weights
CRITICAL_PATTERNS = [
    (r"\b(password|passwd|pwd)\b", "User password credential", ["GDPR", "NIST-800-63"]),
    (r"\b(master key|master_key|private key|private_key|root key|root_key|signing key|signing_key)\b", "Cryptographic key material", ["FIPS-140-3"]),
    (r"\b(credit card|credit_card|creditcard|card num|card_num|pan|cvv|cvc)\b", "Payment card information (PCI-DSS)", ["PCI-DSS"]),
    (r"\b(ssn|social security|social_security|national id|national_id|passport)\b", "National identity numbers", ["GDPR", "Privacy-Act"]),
    (r"\b(medical|health|patient|diagnosis|hipaa|phi)\b", "Protected Health Information (PHI)", ["HIPAA"]),
    (r"\b(bank account|bank_account|routing num|routing_num|iban)\b", "Banking financial details", ["GLBA", "PCI-DSS"]),
]

HIGH_PATTERNS = [
    (r"\b(auth|authenticate|authorization)\b", "Authentication mechanism", ["NIST-800-63"]),
    (r"\b(token|jwt|bearer|session|session id|session_id)\b", "Session authorization token", ["OAuth2"]),
    (r"\b(email|phone|mobile|address|birthdate|dob)\b", "Personally Identifiable Information (PII)", ["GDPR", "CCPA"]),
    (r"\b(user id|user_id|account id|account_id|customer id|customer_id)\b", "Customer account identifier", ["GDPR"]),
    (r"\b(credential|secret|api secret|api_secret)\b", "Application secret credential", ["SOC2"]),
]

MEDIUM_PATTERNS = [
    (r"\b(api key|api_key|client id|client_id|tenant id|tenant_id|org id|org_id)\b", "Tenant / organization identifier", ["SOC2"]),
    (r"\b(config|settings|internal secret|internal_secret)\b", "Internal system configuration", []),
    (r"\b(audit|telemetry secret|telemetry_secret|event log|event_log)\b", "Audit log integrity", []),
]

LOW_OR_PUBLIC_PATTERNS = [
    (r"\b(etag|content hash|content_hash|file hash|file_hash|checksum|sha256 checksum|sha256_checksum)\b", "Public content integrity digest", []),
    (r"\b(cache key|cache_key|lookup key|lookup_key|cache id|cache_id)\b", "Ephemeral cache lookup key", []),
    (r"\b(public key|public_key|cert|certificate)\b", "Public certificate material", []),
    (r"\b(git commit|git_commit|version hash|version_hash|build id|build_id)\b", "Build artifact digest", []),
]

# High-sensitivity path keywords
SENSITIVE_PATH_PATTERNS = [
    (r"/(auth|identity|login|sso|oauth)/", SensitivityLevel.HIGH, "Authentication directory", ["NIST-800-63"]),
    (r"/(payments?|billing|checkout|cards?)/", SensitivityLevel.CRITICAL, "Payment processing directory", ["PCI-DSS"]),
    (r"/(keys?|vault|secrets?|certificates?)/", SensitivityLevel.HIGH, "Key management directory", ["FIPS-140-3"]),
    (r"/(health|patients?|medical)/", SensitivityLevel.CRITICAL, "Healthcare data directory", ["HIPAA"]),
    (r"/(user|profile|account)/", SensitivityLevel.HIGH, "User profile directory", ["GDPR"]),
]


class SensitivityInferenceEngine:
    """
    Infers data sensitivity level for cryptographic findings and computes
    Harvest Now, Decrypt Later (HNDL) exposure risk.
    """

    @classmethod
    def infer(
        cls,
        finding: CryptoFindingData,
        surrounding_code: Optional[str] = None,
    ) -> SensitivityResult:
        """
        Analyze finding attributes and code context to classify data sensitivity.
        """
        matched_rationales: List[str] = []
        matched_patterns: List[str] = []
        regulatory: Set[str] = set()

        score_critical = 0
        score_high = 0
        score_medium = 0
        score_low = 0

        # Build search text from all available context fields
        context_parts = []
        if finding.function_name:
            context_parts.append(finding.function_name)
        if finding.file_path:
            context_parts.append(finding.file_path)
        if finding.name:
            context_parts.append(finding.name)
        if finding.usage:
            context_parts.append(finding.usage)
        if finding.evidence and isinstance(finding.evidence, dict):
            for k, v in finding.evidence.items():
                if isinstance(v, str):
                    context_parts.append(v)
        if surrounding_code:
            context_parts.append(surrounding_code)

        raw_search_text = " ".join(context_parts)
        # Decompose camelCase and snake_case into normalized token space
        tokens_text = re.sub(r"([a-z])([A-Z])", r"\1 \2", raw_search_text)
        tokens_text = re.sub(r"[_\-/\\]+", " ", tokens_text).lower()
        search_text = f"{raw_search_text.lower()} {tokens_text}"

        # 1. Path-based inference
        file_path = finding.file_path or ""
        for path_pat, level, desc, reg in SENSITIVE_PATH_PATTERNS:
            if re.search(path_pat, file_path, re.IGNORECASE):
                matched_rationales.append(f"Located in {desc} ({path_pat})")
                regulatory.update(reg)
                if level == SensitivityLevel.CRITICAL:
                    score_critical += 3
                elif level == SensitivityLevel.HIGH:
                    score_high += 2

        # 2. Pattern matching
        for pattern, desc, reg in CRITICAL_PATTERNS:
            if re.search(pattern, search_text, re.IGNORECASE):
                score_critical += 3
                matched_patterns.append(pattern)
                matched_rationales.append(f"Matched critical pattern '{desc}'")
                regulatory.update(reg)

        for pattern, desc, reg in HIGH_PATTERNS:
            if re.search(pattern, search_text, re.IGNORECASE):
                score_high += 2
                matched_patterns.append(pattern)
                matched_rationales.append(f"Matched high sensitivity pattern '{desc}'")
                regulatory.update(reg)

        for pattern, desc, reg in MEDIUM_PATTERNS:
            if re.search(pattern, search_text, re.IGNORECASE):
                score_medium += 1
                matched_patterns.append(pattern)
                matched_rationales.append(f"Matched medium sensitivity pattern '{desc}'")
                regulatory.update(reg)

        for pattern, desc, reg in LOW_OR_PUBLIC_PATTERNS:
            if re.search(pattern, search_text, re.IGNORECASE):
                score_low += 1
                matched_patterns.append(pattern)
                matched_rationales.append(f"Matched low/public pattern '{desc}'")

        # 3. Determine sensitivity level
        if score_critical > 0:
            level = SensitivityLevel.CRITICAL
            confidence = min(0.95, 0.70 + 0.08 * score_critical)
        elif score_high > 0:
            level = SensitivityLevel.HIGH
            confidence = min(0.90, 0.65 + 0.07 * score_high)
        elif score_medium > 0:
            level = SensitivityLevel.MEDIUM
            confidence = 0.75
        elif score_low > 0:
            level = SensitivityLevel.LOW
            confidence = 0.70
        else:
            # Fallback based on usage
            usage = (finding.usage or "").lower()
            if "password" in usage or "signing" in usage:
                level = SensitivityLevel.HIGH
                confidence = 0.60
                matched_rationales.append(f"Inferred high sensitivity from usage: '{usage}'")
            elif "encryption" in usage:
                level = SensitivityLevel.MEDIUM
                confidence = 0.50
                matched_rationales.append("General encryption usage without explicit data classifier")
            else:
                level = SensitivityLevel.LOW
                confidence = 0.40
                matched_rationales.append("No sensitive identifiers detected in surrounding context")

        # 4. Evaluate HNDL (Harvest Now, Decrypt Later) exposure
        # Asymmetric or classical key exchange protecting sensitive data is prime target for HNDL
        q_status = (finding.quantum_status or "").lower()
        is_vulnerable_kex = (
            q_status == "vulnerable"
            and finding.usage in ("key_exchange", "encryption", "general_crypto")
        )

        if is_vulnerable_kex:
            if level == SensitivityLevel.CRITICAL:
                hndl = "EXTREME"
            elif level == SensitivityLevel.HIGH:
                hndl = "HIGH"
            elif level == SensitivityLevel.MEDIUM:
                hndl = "MODERATE"
            else:
                hndl = "LOW"
        else:
            hndl = "NEGLIGIBLE"

        return SensitivityResult(
            level=level.value,
            confidence=round(confidence, 2),
            rationale=matched_rationales,
            matched_patterns=matched_patterns,
            hndl_exposure=hndl,
            regulatory_impact=sorted(list(regulatory)),
        )

    @classmethod
    def enrich_finding(cls, finding: CryptoFindingData, surrounding_code: Optional[str] = None) -> CryptoFindingData:
        """
        Enrich a CryptoFindingData with sensitivity metrics and HNDL alerts.
        """
        res = cls.infer(finding, surrounding_code)
        finding.sensitivity = res.level
        finding.sensitivity_confidence = res.confidence

        if res.hndl_exposure in ("EXTREME", "HIGH"):
            hndl_warning = (
                f"🚨 High HNDL Exposure: {res.level} sensitivity data encrypted with quantum-vulnerable "
                f"algorithm '{finding.algorithm}'. Adversaries recording traffic now can decrypt upon CRQC arrival."
            )
            if finding.vulnerabilities is None:
                finding.vulnerabilities = []
            if hndl_warning not in finding.vulnerabilities:
                finding.vulnerabilities.insert(0, hndl_warning)

        return finding

    @classmethod
    def batch_enrich(cls, findings: List[CryptoFindingData]) -> List[CryptoFindingData]:
        """Batch enrich a list of findings."""
        return [cls.enrich_finding(f) for f in findings]
