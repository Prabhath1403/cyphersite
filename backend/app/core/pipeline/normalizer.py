"""
Unified Cryptographic Finding Normalizer.

Ensures every finding emitted by any scanner (source code, network, container, binary)
adheres to canonical nomenclature, standardized algorithm taxonomies, deterministic
risk scoring, and NIST PQC status classifications.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from app.core.source_scanner import CryptoFindingData


# Canonical algorithm aliases
ALGORITHM_CANONICAL_MAP: Dict[str, Tuple[str, str, str]] = {
    # alias_lower -> (canonical_name, algorithm_family, primitive)
    # ── Post-Quantum Cryptography (NIST FIPS 203/204/205) ───────────────────
    "ml-kem-512": ("ML-KEM-512", "Lattice-based KEM", "pqc"),
    "mlkem512": ("ML-KEM-512", "Lattice-based KEM", "pqc"),
    "kyber512": ("ML-KEM-512", "Lattice-based KEM", "pqc"),
    "ml-kem-768": ("ML-KEM-768", "Lattice-based KEM", "pqc"),
    "mlkem768": ("ML-KEM-768", "Lattice-based KEM", "pqc"),
    "kyber768": ("ML-KEM-768", "Lattice-based KEM", "pqc"),
    "kyber": ("ML-KEM-768", "Lattice-based KEM", "pqc"),
    "ml-kem-1024": ("ML-KEM-1024", "Lattice-based KEM", "pqc"),
    "mlkem1024": ("ML-KEM-1024", "Lattice-based KEM", "pqc"),
    "kyber1024": ("ML-KEM-1024", "Lattice-based KEM", "pqc"),
    "ml-dsa-44": ("ML-DSA-44", "Lattice-based Signature", "pqc"),
    "mldsa44": ("ML-DSA-44", "Lattice-based Signature", "pqc"),
    "dilithium2": ("ML-DSA-44", "Lattice-based Signature", "pqc"),
    "ml-dsa-65": ("ML-DSA-65", "Lattice-based Signature", "pqc"),
    "mldsa65": ("ML-DSA-65", "Lattice-based Signature", "pqc"),
    "dilithium3": ("ML-DSA-65", "Lattice-based Signature", "pqc"),
    "dilithium": ("ML-DSA-65", "Lattice-based Signature", "pqc"),
    "ml-dsa-87": ("ML-DSA-87", "Lattice-based Signature", "pqc"),
    "mldsa87": ("ML-DSA-87", "Lattice-based Signature", "pqc"),
    "dilithium5": ("ML-DSA-87", "Lattice-based Signature", "pqc"),
    "falcon-512": ("Falcon-512", "Lattice-based Signature", "pqc"),
    "falcon512": ("Falcon-512", "Lattice-based Signature", "pqc"),
    "falcon-1024": ("Falcon-1024", "Lattice-based Signature", "pqc"),
    "falcon1024": ("Falcon-1024", "Lattice-based Signature", "pqc"),
    "slh-dsa": ("SLH-DSA", "Stateless Hash-based Signature", "pqc"),
    "sphincs+": ("SLH-DSA", "Stateless Hash-based Signature", "pqc"),
    "sphincs": ("SLH-DSA", "Stateless Hash-based Signature", "pqc"),

    # ── Classical Asymmetric (Quantum Vulnerable) ───────────────────────────
    "rsa": ("RSA", "Public Key Cryptography", "asymmetric"),
    "rsa-2048": ("RSA-2048", "Public Key Cryptography", "asymmetric"),
    "rsa-3072": ("RSA-3072", "Public Key Cryptography", "asymmetric"),
    "rsa-4096": ("RSA-4096", "Public Key Cryptography", "asymmetric"),
    "dsa": ("DSA", "Discrete Logarithm", "asymmetric"),
    "dh": ("Diffie-Hellman", "Discrete Logarithm", "asymmetric"),
    "diffie-hellman": ("Diffie-Hellman", "Discrete Logarithm", "asymmetric"),
    "ecdsa": ("ECDSA", "Elliptic Curve Cryptography", "asymmetric"),
    "ecdh": ("ECDH", "Elliptic Curve Cryptography", "asymmetric"),
    "secp256r1": ("ECDSA-P256", "Elliptic Curve Cryptography", "asymmetric"),
    "prime256v1": ("ECDSA-P256", "Elliptic Curve Cryptography", "asymmetric"),
    "p-256": ("ECDSA-P256", "Elliptic Curve Cryptography", "asymmetric"),
    "secp384r1": ("ECDSA-P384", "Elliptic Curve Cryptography", "asymmetric"),
    "p-384": ("ECDSA-P384", "Elliptic Curve Cryptography", "asymmetric"),
    "secp521r1": ("ECDSA-P521", "Elliptic Curve Cryptography", "asymmetric"),
    "ed25519": ("Ed25519", "Edwards Curve", "asymmetric"),
    "x25519": ("X25519", "Montgomery Curve", "asymmetric"),
    "curve25519": ("Curve25519", "Montgomery Curve", "asymmetric"),

    # ── Symmetric Ciphers ───────────────────────────────────────────────────
    "aes-256-gcm": ("AES-256-GCM", "AES", "symmetric"),
    "aes-256-cbc": ("AES-256-CBC", "AES", "symmetric"),
    "aes-256-ctr": ("AES-256-CTR", "AES", "symmetric"),
    "aes-256": ("AES-256", "AES", "symmetric"),
    "aes-192-gcm": ("AES-192-GCM", "AES", "symmetric"),
    "aes-192": ("AES-192", "AES", "symmetric"),
    "aes-128-gcm": ("AES-128-GCM", "AES", "symmetric"),
    "aes-128-cbc": ("AES-128-CBC", "AES", "symmetric"),
    "aes-128": ("AES-128", "AES", "symmetric"),
    "aes": ("AES", "AES", "symmetric"),
    "chacha20-poly1305": ("ChaCha20-Poly1305", "Stream Cipher", "symmetric"),
    "chacha20": ("ChaCha20", "Stream Cipher", "symmetric"),
    "des": ("DES", "Legacy Symmetric", "symmetric"),
    "3des": ("3DES", "Legacy Symmetric", "symmetric"),
    "triple-des": ("3DES", "Legacy Symmetric", "symmetric"),
    "rc4": ("RC4", "Legacy Stream Cipher", "symmetric"),

    # ── Hash Functions ───────────────────────────────────────────────────────
    "sha-256": ("SHA-256", "SHA-2", "hash"),
    "sha256": ("SHA-256", "SHA-2", "hash"),
    "sha-384": ("SHA-384", "SHA-2", "hash"),
    "sha384": ("SHA-384", "SHA-2", "hash"),
    "sha-512": ("SHA-512", "SHA-2", "hash"),
    "sha512": ("SHA-512", "SHA-2", "hash"),
    "sha3-256": ("SHA3-256", "SHA-3", "hash"),
    "sha3-512": ("SHA3-512", "SHA-3", "hash"),
    "blake2b": ("BLAKE2b", "BLAKE", "hash"),
    "sha-1": ("SHA-1", "Legacy Hash", "hash"),
    "sha1": ("SHA-1", "Legacy Hash", "hash"),
    "md5": ("MD5", "Legacy Hash", "hash"),
}


class CryptoNormalizer:
    """Normalizes cryptographic findings to canonical structure."""

    @classmethod
    def canonicalize_algorithm(cls, raw_algo: Optional[str]) -> Tuple[str, str, str]:
        """
        Normalize algorithm name into (canonical_name, family, primitive).
        """
        if not raw_algo:
            return ("Unknown", "Unknown", "unknown")

        cleaned = raw_algo.strip().lower().replace("_", "-")
        if cleaned in ALGORITHM_CANONICAL_MAP:
            return ALGORITHM_CANONICAL_MAP[cleaned]

        # Check partial prefix matches
        for alias, (c_name, family, prim) in ALGORITHM_CANONICAL_MAP.items():
            if alias in cleaned:
                return (c_name, family, prim)

        # Fallback
        return (raw_algo.strip(), "General", "unknown")

    @classmethod
    def evaluate_pqc_status(
        cls,
        primitive: str,
        algorithm: str,
        key_size: Optional[int] = None,
    ) -> Tuple[str, str, float, str]:
        """
        Derive (pqc_status, quantum_status, risk_score, risk_level).
        """
        p_lower = (primitive or "").lower()
        algo_upper = (algorithm or "").upper()

        if p_lower == "pqc" or any(p in algo_upper for p in ("ML-KEM", "ML-DSA", "SLH-DSA", "FALCON", "KYBER", "DILITHIUM")):
            return ("QUANTUM_SAFE", "safe", 0.0, "INFO")

        if p_lower == "hybrid" or "HYBRID" in algo_upper:
            return ("HYBRID_READY", "safe", 15.0, "LOW")

        if p_lower == "asymmetric" or any(a in algo_upper for a in ("RSA", "DSA", "DH", "ECDSA", "ECDH", "CURVE25519", "ED25519", "P-256", "P-384")):
            score = 90.0 if "DSA" in algo_upper or "DH" in algo_upper else 85.0
            return ("VULNERABLE", "vulnerable", score, "CRITICAL" if score >= 90 else "HIGH")

        if p_lower == "symmetric":
            if any(l in algo_upper for l in ("DES", "3DES", "RC4")):
                return ("VULNERABLE", "vulnerable", 95.0, "CRITICAL")
            if "128" in algo_upper or (key_size and key_size < 256):
                return ("REDUCED_SECURITY_MARGIN", "reduced_security_margin", 40.0, "MEDIUM")
            return ("QUANTUM_SAFE", "safe", 10.0, "LOW")

        if p_lower == "hash":
            if any(b in algo_upper for b in ("MD5", "SHA-1", "SHA1")):
                return ("VULNERABLE", "vulnerable", 90.0, "CRITICAL")
            return ("QUANTUM_SAFE", "safe", 5.0, "LOW")

        return ("UNKNOWN", "unknown", 30.0, "LOW")

    @classmethod
    def normalize_finding(cls, finding: CryptoFindingData) -> CryptoFindingData:
        """
        Pass a finding through full canonical normalization.
        """
        c_algo, c_family, c_prim = cls.canonicalize_algorithm(finding.algorithm)

        # Retain finding's primitive if already specific and canonical was generic
        primitive = finding.primitive or c_prim
        if primitive == "unknown":
            primitive = c_prim

        pqc_status, quantum_status, risk_score, risk_level = cls.evaluate_pqc_status(
            primitive=primitive,
            algorithm=c_algo,
            key_size=finding.key_size,
        )

        finding.algorithm = c_algo
        if not finding.algorithm_family or finding.algorithm_family == "General":
            finding.algorithm_family = c_family
        finding.primitive = primitive
        finding.pqc_status = pqc_status
        finding.quantum_status = quantum_status
        if finding.risk_score is None:
            finding.risk_score = risk_score
        if finding.risk_level is None:
            finding.risk_level = risk_level

        # Clamp confidence
        finding.confidence = max(0.0, min(1.0, float(finding.confidence or 1.0)))

        return finding

    @classmethod
    def batch_normalize(cls, findings: List[CryptoFindingData]) -> List[CryptoFindingData]:
        """Normalize a collection of findings."""
        return [cls.normalize_finding(f) for f in findings]
