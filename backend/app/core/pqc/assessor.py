"""
PQC Readiness Assessor — rule engine for post-quantum security assessment.

Evaluates TLS fingerprints against NIST PQC standards and produces
risk scores, vulnerability lists, and remediation recommendations.
"""

import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

from app.core.pqc.nist_rules import (
    VULNERABLE_KEY_EXCHANGES,
    VULNERABLE_CURVES,
    DEPRECATED_HASHES,
    DEPRECATED_TLS_VERSIONS,
    HYBRID_READY_KEY_EXCHANGES,
    MODERN_TLS_VERSIONS,
    RSA_MIN_HYBRID,
    is_pqc_algorithm,
    is_deprecated_hash,
    is_deprecated_tls,
)

logger = logging.getLogger(__name__)


@dataclass
class PQCAssessmentResult:
    """Result of a PQC readiness assessment."""
    pqc_status: str = "VULNERABLE"  # QUANTUM_SAFE, HYBRID_READY, VULNERABLE
    risk_score: float = 100.0  # 0-100 (100 = most vulnerable)
    vulnerabilities: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def _check_tls_versions(tls_versions: List[str]) -> tuple:
    """
    Check TLS version support for vulnerabilities.

    Returns:
        Tuple of (vulnerabilities, recommendations, risk_delta, has_modern)
    """
    vulns = []
    recs = []
    risk_delta = 0
    has_modern = False

    for version in tls_versions:
        if is_deprecated_tls(version):
            vulns.append(f"Deprecated TLS version supported: {version}")
            risk_delta += 15
            recs.append(f"Disable {version} — it is cryptographically broken")

    for version in tls_versions:
        if version in MODERN_TLS_VERSIONS or "1.3" in version:
            has_modern = True
            risk_delta -= 5  # TLS 1.3 is a positive signal
            break

    if not has_modern and tls_versions:
        vulns.append("TLS 1.3 not supported")
        risk_delta += 10
        recs.append("Enable TLS 1.3 for improved security and PQC readiness")

    return vulns, recs, risk_delta, has_modern


def _check_cipher_suites(cipher_suites: List[Dict[str, Any]]) -> tuple:
    """
    Check cipher suites for quantum vulnerabilities.

    Returns:
        Tuple of (vulnerabilities, recommendations, risk_delta, has_pqc,
                  has_hybrid, has_ephemeral_kex)
    """
    vulns = []
    recs = []
    risk_delta = 0
    has_pqc = False
    has_hybrid = False
    has_ephemeral_kex = False
    seen_vulns = set()

    for suite in cipher_suites:
        name = suite.get("name", "")
        kex = suite.get("key_exchange", "")
        enc = suite.get("encryption", "")
        mac = suite.get("mac", "")
        key_size = suite.get("key_size", 0)

        # Check for PQC algorithms
        if is_pqc_algorithm(name) or is_pqc_algorithm(kex):
            has_pqc = True
            continue

        # Check for hybrid PQC+classical algorithms
        name_lower = name.lower()
        kex_lower = kex.lower()
        if ("kyber" in name_lower or "mlkem" in name_lower or
            "kyber" in kex_lower or "mlkem" in kex_lower):
            has_hybrid = True
            has_pqc = True
            continue

        # Track if any cipher uses ephemeral key exchange
        if kex in HYBRID_READY_KEY_EXCHANGES:
            has_ephemeral_kex = True

        # Check key exchange vulnerabilities — only flag truly vulnerable ones
        if kex in VULNERABLE_KEY_EXCHANGES:
            vuln_key = f"kex_{kex}"
            if vuln_key not in seen_vulns:
                seen_vulns.add(vuln_key)
                vulns.append(f"Quantum-vulnerable key exchange: {kex}")
                risk_delta += 10

        # Check for weak key sizes
        if kex == "RSA" and key_size > 0 and key_size < RSA_MIN_HYBRID:
            vuln_key = f"rsa_weak_{key_size}"
            if vuln_key not in seen_vulns:
                seen_vulns.add(vuln_key)
                vulns.append(f"RSA key size too small: {key_size} bits (minimum {RSA_MIN_HYBRID})")
                risk_delta += 15

        # Check for weak MACs
        if mac and mac.upper() in ("MD5", "SHA1"):
            vuln_key = f"mac_{mac}"
            if vuln_key not in seen_vulns:
                seen_vulns.add(vuln_key)
                vulns.append(f"Weak MAC algorithm: {mac}")
                risk_delta += 5

        # Check for weak encryption
        if "3DES" in enc or "DES" in enc or "RC4" in enc:
            vuln_key = f"enc_{enc}"
            if vuln_key not in seen_vulns:
                seen_vulns.add(vuln_key)
                vulns.append(f"Weak encryption algorithm: {enc}")
                risk_delta += 10

    if not has_pqc:
        recs.append("Deploy PQC key encapsulation (ML-KEM/Kyber) per NIST FIPS 203")
        recs.append("Consider hybrid key exchange (X25519Kyber768) for gradual migration")

    return vulns, recs, risk_delta, has_pqc, has_hybrid, has_ephemeral_kex


def _check_certificate(certificate: Dict[str, Any]) -> tuple:
    """
    Check certificate for quantum vulnerabilities.

    Note: Certificate signature algorithm vulnerabilities are informational
    for hybrid-ready status. The key exchange is what protects confidentiality;
    certificate signatures protect authenticity. Both matter but key exchange
    is more urgent for quantum safety.

    Returns:
        Tuple of (vulnerabilities, recommendations, risk_delta)
    """
    vulns = []
    recs = []
    risk_delta = 0

    if not certificate:
        return vulns, recs, risk_delta

    pub_algo = certificate.get("public_key_algorithm", "")
    key_size = certificate.get("key_size", 0)
    sig_algo = certificate.get("signature_algorithm", "")

    # Check public key algorithm — these are informational for PQC assessment
    # since classical cert signatures are a long-term concern, not immediate
    if "RSA" in pub_algo.upper():
        if key_size < RSA_MIN_HYBRID:
            vulns.append(f"Certificate RSA key size: {key_size} bits (long-term quantum risk)")
            risk_delta += 5  # Reduced from 20; cert signing is less urgent than kex
            recs.append(f"Upgrade certificate to RSA >= {RSA_MIN_HYBRID} bits or switch to PQC signatures")

    if "EC" in pub_algo.upper() and pub_algo != "":
        # EC certificates are standard and not an immediate quantum threat
        # for authentication; the key exchange protects confidentiality
        recs.append("Future: Migrate to PQC signature algorithm (ML-DSA per NIST FIPS 204)")
        risk_delta += 3  # Minor risk; EC certs are standard practice

    # Check signature algorithm for deprecated hashes
    if is_deprecated_hash(sig_algo):
        vulns.append(f"Certificate uses deprecated hash in signature: {sig_algo}")
        risk_delta += 15
        recs.append("Re-issue certificate with SHA-256 or stronger hash algorithm")

    # Check for PQC signatures (big positive signal)
    if is_pqc_algorithm(pub_algo) or is_pqc_algorithm(sig_algo):
        risk_delta -= 30  # Significant risk reduction for PQC certs

    return vulns, recs, risk_delta


def assess_pqc_readiness(
    tls_versions: List[str],
    cipher_suites: List[Dict[str, Any]],
    certificate: Dict[str, Any],
    key_exchange: str = "",
) -> PQCAssessmentResult:
    """
    Assess the PQC readiness of an asset based on its TLS fingerprint.

    Applies NIST PQC rules to determine quantum safety classification,
    generates a risk score, and provides remediation recommendations.

    Classification logic:
    - QUANTUM_SAFE: Uses PQC algorithms (ML-KEM, ML-DSA, SLH-DSA, or hybrids)
    - HYBRID_READY: TLS 1.3 with ephemeral key exchange + modern ciphers
    - VULNERABLE: Legacy protocols, weak key exchange, deprecated algorithms

    Args:
        tls_versions: List of supported TLS versions.
        cipher_suites: List of cipher suite dictionaries.
        certificate: Certificate information dictionary.
        key_exchange: Primary key exchange algorithm.

    Returns:
        PQCAssessmentResult with status, risk score, and recommendations.
    """
    result = PQCAssessmentResult()
    total_risk = 0.0

    # Step 0: Check for empty data (handshake/connection failure)
    if not tls_versions and not cipher_suites and not certificate:
        result.pqc_status = "VULNERABLE"
        result.risk_score = 100.0
        result.vulnerabilities.append("TLS handshake failed or connection timed out during inspection")
        result.recommendations.append("Ensure the server is configured correctly for TLS")
        result.recommendations.append("Check if a firewall or WAF is blocking scan traffic")
        return result

    # Step 1: Check TLS versions
    tls_vulns, tls_recs, tls_risk, has_modern_tls = _check_tls_versions(tls_versions or [])
    result.vulnerabilities.extend(tls_vulns)
    result.recommendations.extend(tls_recs)
    total_risk += tls_risk

    # Step 2: Check cipher suites
    cs_vulns, cs_recs, cs_risk, has_pqc, has_hybrid, has_ephemeral_kex = _check_cipher_suites(cipher_suites or [])
    result.vulnerabilities.extend(cs_vulns)
    result.recommendations.extend(cs_recs)
    total_risk += cs_risk

    # Step 3: Check certificate
    cert_vulns, cert_recs, cert_risk = _check_certificate(certificate or {})
    result.vulnerabilities.extend(cert_vulns)
    result.recommendations.extend(cert_recs)
    total_risk += cert_risk

    # Step 4: Check primary key exchange
    if key_exchange:
        if key_exchange in VULNERABLE_KEY_EXCHANGES:
            total_risk += 10
        elif key_exchange in HYBRID_READY_KEY_EXCHANGES:
            total_risk -= 5

    # Step 5: Determine PQC status
    # Key insight: TLS 1.3 mandates ephemeral key exchange (PFS),
    # making it inherently more quantum-resistant than TLS 1.2 with RSA kex.
    # Combined with modern cipher suites, TLS 1.3 qualifies as HYBRID_READY.

    if has_pqc:
        result.pqc_status = "QUANTUM_SAFE"
    elif (has_hybrid or
          has_modern_tls and (
              key_exchange in HYBRID_READY_KEY_EXCHANGES or
              has_ephemeral_kex
          )):
        # TLS 1.3 + ECDHE/X25519 = HYBRID_READY
        # This correctly catches google.com-style configurations
        result.pqc_status = "HYBRID_READY"
        if not any("PQC" in r for r in result.recommendations):
            result.recommendations.append(
                "Upgrade to full PQC with ML-KEM key exchange (NIST FIPS 203)"
            )
    elif has_modern_tls:
        # Has TLS 1.3 but key exchange couldn't be determined — still better
        # than no TLS 1.3. TLS 1.3 mandates PFS, so classify as HYBRID_READY.
        result.pqc_status = "HYBRID_READY"
        result.recommendations.append(
            "Upgrade to full PQC with ML-KEM key exchange (NIST FIPS 203)"
        )
    else:
        result.pqc_status = "VULNERABLE"
        if not result.vulnerabilities:
            result.vulnerabilities.append("No post-quantum cryptographic algorithms detected")
        result.recommendations.insert(0, "CRITICAL: Begin PQC migration immediately")

    # Step 6: Calculate final risk score (0-100)
    base_risk = {
        "QUANTUM_SAFE": 5,
        "HYBRID_READY": 30,
        "VULNERABLE": 65,
    }
    result.risk_score = min(100.0, max(0.0, base_risk.get(result.pqc_status, 65) + total_risk))

    # Step 7: Add universal recommendations
    if result.pqc_status != "QUANTUM_SAFE":
        result.recommendations.append("Review NIST SP 800-208 for hash-based signature guidance")
        result.recommendations.append("Plan cryptographic agility to enable rapid algorithm transitions")

    # Store assessment details
    result.details = {
        "has_pqc": has_pqc,
        "has_hybrid": has_hybrid,
        "has_modern_tls": has_modern_tls,
        "has_ephemeral_kex": has_ephemeral_kex,
        "vulnerability_count": len(result.vulnerabilities),
    }

    logger.info(f"PQC assessment: status={result.pqc_status}, risk={result.risk_score}")
    return result
