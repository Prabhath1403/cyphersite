"""
NIST PQC algorithm mappings and rules.

Defines algorithm classifications according to NIST FIPS 203/204/205
standards for Post-Quantum Cryptography.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set


@dataclass
class AlgorithmInfo:
    """Information about a cryptographic algorithm."""
    name: str
    category: str  # key_exchange, signature, encryption, hash
    pqc_safe: bool
    nist_standard: str = ""
    description: str = ""
    minimum_security_level: int = 0  # NIST security level 1-5


# === QUANTUM-SAFE ALGORITHMS (NIST PQC Standards) ===

PQC_KEY_ENCAPSULATION = {
    "ML-KEM-512": AlgorithmInfo(
        name="ML-KEM-512", category="key_exchange", pqc_safe=True,
        nist_standard="FIPS 203", description="Module-Lattice Key Encapsulation (Kyber-512)",
        minimum_security_level=1,
    ),
    "ML-KEM-768": AlgorithmInfo(
        name="ML-KEM-768", category="key_exchange", pqc_safe=True,
        nist_standard="FIPS 203", description="Module-Lattice Key Encapsulation (Kyber-768)",
        minimum_security_level=3,
    ),
    "ML-KEM-1024": AlgorithmInfo(
        name="ML-KEM-1024", category="key_exchange", pqc_safe=True,
        nist_standard="FIPS 203", description="Module-Lattice Key Encapsulation (Kyber-1024)",
        minimum_security_level=5,
    ),
    "KYBER512": AlgorithmInfo(
        name="Kyber-512", category="key_exchange", pqc_safe=True,
        nist_standard="FIPS 203", description="Kyber key encapsulation (legacy name)",
        minimum_security_level=1,
    ),
    "KYBER768": AlgorithmInfo(
        name="Kyber-768", category="key_exchange", pqc_safe=True,
        nist_standard="FIPS 203", description="Kyber key encapsulation (legacy name)",
        minimum_security_level=3,
    ),
    "KYBER1024": AlgorithmInfo(
        name="Kyber-1024", category="key_exchange", pqc_safe=True,
        nist_standard="FIPS 203", description="Kyber key encapsulation (legacy name)",
        minimum_security_level=5,
    ),
}

PQC_SIGNATURES = {
    "ML-DSA-44": AlgorithmInfo(
        name="ML-DSA-44", category="signature", pqc_safe=True,
        nist_standard="FIPS 204", description="Module-Lattice Digital Signature (Dilithium2)",
        minimum_security_level=2,
    ),
    "ML-DSA-65": AlgorithmInfo(
        name="ML-DSA-65", category="signature", pqc_safe=True,
        nist_standard="FIPS 204", description="Module-Lattice Digital Signature (Dilithium3)",
        minimum_security_level=3,
    ),
    "ML-DSA-87": AlgorithmInfo(
        name="ML-DSA-87", category="signature", pqc_safe=True,
        nist_standard="FIPS 204", description="Module-Lattice Digital Signature (Dilithium5)",
        minimum_security_level=5,
    ),
    "SLH-DSA-SHA2-128s": AlgorithmInfo(
        name="SLH-DSA-SHA2-128s", category="signature", pqc_safe=True,
        nist_standard="FIPS 205", description="Stateless Hash-Based Signature (SPHINCS+-SHA2-128s)",
        minimum_security_level=1,
    ),
    "SLH-DSA-SHA2-128f": AlgorithmInfo(
        name="SLH-DSA-SHA2-128f", category="signature", pqc_safe=True,
        nist_standard="FIPS 205", description="Stateless Hash-Based Signature (SPHINCS+-SHA2-128f)",
        minimum_security_level=1,
    ),
    "SLH-DSA-SHA2-192s": AlgorithmInfo(
        name="SLH-DSA-SHA2-192s", category="signature", pqc_safe=True,
        nist_standard="FIPS 205", description="Stateless Hash-Based Signature (SPHINCS+-SHA2-192s)",
        minimum_security_level=3,
    ),
    "SLH-DSA-SHA2-256s": AlgorithmInfo(
        name="SLH-DSA-SHA2-256s", category="signature", pqc_safe=True,
        nist_standard="FIPS 205", description="Stateless Hash-Based Signature (SPHINCS+-SHA2-256s)",
        minimum_security_level=5,
    ),
    "SLH-DSA-SHAKE-128s": AlgorithmInfo(
        name="SLH-DSA-SHAKE-128s", category="signature", pqc_safe=True,
        nist_standard="FIPS 205", description="SPHINCS+ with SHAKE-128s",
        minimum_security_level=1,
    ),
    "SLH-DSA-SHAKE-256s": AlgorithmInfo(
        name="SLH-DSA-SHAKE-256s", category="signature", pqc_safe=True,
        nist_standard="FIPS 205", description="SPHINCS+ with SHAKE-256s",
        minimum_security_level=5,
    ),
}

# === HYBRID PQC+CLASSICAL COMBINATIONS ===

HYBRID_ALGORITHMS = {
    "X25519Kyber768": AlgorithmInfo(
        name="X25519Kyber768", category="key_exchange", pqc_safe=True,
        description="Hybrid X25519 + Kyber768 key exchange",
    ),
    "X25519MLKEM768": AlgorithmInfo(
        name="X25519MLKEM768", category="key_exchange", pqc_safe=True,
        description="Hybrid X25519 + ML-KEM-768 key exchange",
    ),
    "SecP256r1MLKEM768": AlgorithmInfo(
        name="SecP256r1MLKEM768", category="key_exchange", pqc_safe=True,
        description="Hybrid P-256 + ML-KEM-768 key exchange",
    ),
}

# === VULNERABLE ALGORITHMS ===

VULNERABLE_KEY_EXCHANGES: Set[str] = {
    "RSA", "DH", "DHE", "ECDH",
}

VULNERABLE_CURVES: Set[str] = {
    "P-256", "P-384", "secp256k1", "secp256r1", "secp384r1",
    "prime256v1",
}

DEPRECATED_HASHES: Set[str] = {
    "MD5", "SHA1", "SHA-1", "md5WithRSAEncryption", "sha1WithRSAEncryption",
}

DEPRECATED_TLS_VERSIONS: Set[str] = {
    "SSLv2", "SSLv3", "SSL 2.0", "SSL 3.0",
    "TLS 1.0", "TLSv1", "TLSv1.0",
    "TLS 1.1", "TLSv1.1",
}

# === HYBRID-READY INDICATORS ===

HYBRID_READY_KEY_EXCHANGES: Set[str] = {
    "ECDHE", "X25519", "X448",
}

MODERN_TLS_VERSIONS: Set[str] = {
    "TLS 1.3", "TLSv1.3",
}

# Minimum RSA key sizes for different classifications
RSA_MIN_HYBRID = 3072
RSA_MIN_SAFE = 4096

# All PQC algorithm names for quick lookup
ALL_PQC_ALGORITHMS: Set[str] = (
    set(PQC_KEY_ENCAPSULATION.keys()) |
    set(PQC_SIGNATURES.keys()) |
    set(HYBRID_ALGORITHMS.keys()) |
    {"KYBER", "DILITHIUM", "SPHINCS+", "ML-KEM", "ML-DSA", "SLH-DSA"}
)


def is_pqc_algorithm(name: str) -> bool:
    """Check if an algorithm name is a PQC algorithm."""
    upper = name.upper().replace("-", "").replace("_", "")
    for pqc_name in ALL_PQC_ALGORITHMS:
        if pqc_name.upper().replace("-", "").replace("_", "") in upper:
            return True
    return False


def is_deprecated_hash(name: str) -> bool:
    """Check if a hash algorithm is deprecated."""
    upper = name.upper()
    return any(dep.upper() in upper for dep in DEPRECATED_HASHES)


def is_deprecated_tls(version: str) -> bool:
    """Check if a TLS version is deprecated."""
    return version in DEPRECATED_TLS_VERSIONS
