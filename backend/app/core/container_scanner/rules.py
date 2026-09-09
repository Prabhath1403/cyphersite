"""
Detection rules and signatures for container image cryptographic scanning.

Covers:
- Linux OS packages (Debian dpkg, Alpine apk, RedHat RPM)
- Shared cryptographic binary libraries (.so)
- Language runtime crypto dependencies (Python site-packages, Java jars)
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Optional, List


@dataclass(frozen=True)
class ContainerCryptoSignature:
    name: str
    category: str              # os_package | shared_library | python_package | java_package
    algorithm_family: str
    primitive: str             # library | protocol | symmetric | asymmetric | hybrid | pqc
    pqc_status: str            # QUANTUM_SAFE | HYBRID_READY | VULNERABLE | UNKNOWN
    quantum_status: str        # safe | reduced_security_margin | vulnerable | unknown
    base_risk_score: float     # 0 - 100
    risk_level: str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    vulnerability_template: str
    recommendation_template: str


# OS package signatures matched by name (exact or prefix)
OS_PACKAGE_SIGNATURES: Dict[str, ContainerCryptoSignature] = {
    "openssl": ContainerCryptoSignature(
        name="OpenSSL",
        category="os_package",
        algorithm_family="General Crypto & TLS",
        primitive="library",
        pqc_status="VULNERABLE",  # adjusted by version dynamically
        quantum_status="vulnerable",
        base_risk_score=75.0,
        risk_level="HIGH",
        vulnerability_template="OpenSSL {version} relies on classical public key cryptography (RSA/ECC)",
        recommendation_template="Deploy OpenSSL 3.x with oqs-provider for NIST PQC algorithm support",
    ),
    "libssl": ContainerCryptoSignature(
        name="libssl",
        category="os_package",
        algorithm_family="TLS Protocol",
        primitive="protocol",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=75.0,
        risk_level="HIGH",
        vulnerability_template="libssl {version} handles TLS handshakes without native PQC key exchange",
        recommendation_template="Upgrade to libssl3 and enable hybrid post-quantum key encapsulation",
    ),
    "libcrypto": ContainerCryptoSignature(
        name="libcrypto",
        category="os_package",
        algorithm_family="General Crypto",
        primitive="library",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=75.0,
        risk_level="HIGH",
        vulnerability_template="libcrypto {version} provides classical primitives vulnerable to Shor's algorithm",
        recommendation_template="Audit and migrate asymmetric keys to ML-KEM/ML-DSA",
    ),
    "gnutls": ContainerCryptoSignature(
        name="GnuTLS",
        category="os_package",
        algorithm_family="TLS Protocol",
        primitive="library",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=80.0,
        risk_level="HIGH",
        vulnerability_template="GnuTLS {version} does not implement standard NIST PQC key encapsulation",
        recommendation_template="Plan migration to PQC-ready TLS libraries or OpenSSL 3 with oqs-provider",
    ),
    "libnss3": ContainerCryptoSignature(
        name="Network Security Services (NSS)",
        category="os_package",
        algorithm_family="General Crypto",
        primitive="library",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=80.0,
        risk_level="HIGH",
        vulnerability_template="Mozilla NSS {version} relies on classical asymmetric primitives",
        recommendation_template="Monitor NSS post-quantum roadmap and plan hybrid algorithm deployment",
    ),
    "libsodium": ContainerCryptoSignature(
        name="libsodium",
        category="os_package",
        algorithm_family="ECC / Curve25519",
        primitive="asymmetric",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=75.0,
        risk_level="HIGH",
        vulnerability_template="libsodium {version} uses X25519/Ed25519 which are broken by Shor's algorithm",
        recommendation_template="Implement hybrid KEM/signature schemes alongside libsodium",
    ),
    "liboqs": ContainerCryptoSignature(
        name="liboqs",
        category="os_package",
        algorithm_family="NIST PQC Standards",
        primitive="pqc",
        pqc_status="QUANTUM_SAFE",
        quantum_status="safe",
        base_risk_score=10.0,
        risk_level="LOW",
        vulnerability_template="",
        recommendation_template="Ensure active use of ML-KEM and ML-DSA within application configurations",
    ),
    "oqs-provider": ContainerCryptoSignature(
        name="oqs-provider",
        category="os_package",
        algorithm_family="OpenSSL PQC Provider",
        primitive="pqc",
        pqc_status="QUANTUM_SAFE",
        quantum_status="safe",
        base_risk_score=10.0,
        risk_level="LOW",
        vulnerability_template="",
        recommendation_template="OpenSSL 3.x PQC provider is installed; verify PQC cipher suites are negotiated",
    ),
}

# Shared library binary filenames (.so) mapped to signatures
SHARED_LIBRARY_SIGNATURES: Dict[str, ContainerCryptoSignature] = {
    "libcrypto.so": ContainerCryptoSignature(
        name="libcrypto",
        category="shared_library",
        algorithm_family="OpenSSL Core",
        primitive="library",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=70.0,
        risk_level="HIGH",
        vulnerability_template="Shared library {filename} provides classical cryptographic functions",
        recommendation_template="Upgrade host image to OpenSSL 3.x+ and inspect algorithm usage",
    ),
    "libssl.so": ContainerCryptoSignature(
        name="libssl",
        category="shared_library",
        algorithm_family="OpenSSL TLS",
        primitive="protocol",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=70.0,
        risk_level="HIGH",
        vulnerability_template="Shared library {filename} implements TLS transport",
        recommendation_template="Ensure TLS 1.3 is enforced with hybrid key exchange enabled",
    ),
    "libgnutls.so": ContainerCryptoSignature(
        name="libgnutls",
        category="shared_library",
        algorithm_family="GnuTLS",
        primitive="library",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=75.0,
        risk_level="HIGH",
        vulnerability_template="Shared library {filename} lacks NIST PQC standards",
        recommendation_template="Upgrade or replace with quantum-resistant crypto engine",
    ),
    "libsodium.so": ContainerCryptoSignature(
        name="libsodium",
        category="shared_library",
        algorithm_family="Curve25519",
        primitive="asymmetric",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=75.0,
        risk_level="HIGH",
        vulnerability_template="Shared library {filename} uses discrete logarithm over elliptic curves",
        recommendation_template="Plan transition to lattice-based cryptography (ML-KEM / ML-DSA)",
    ),
    "liboqs.so": ContainerCryptoSignature(
        name="liboqs",
        category="shared_library",
        algorithm_family="NIST PQC",
        primitive="pqc",
        pqc_status="QUANTUM_SAFE",
        quantum_status="safe",
        base_risk_score=10.0,
        risk_level="LOW",
        vulnerability_template="",
        recommendation_template="Post-quantum cryptographic library detected; verify integration",
    ),
}

# Python package names installed in container site-packages
PYTHON_CONTAINER_PACKAGES: Dict[str, ContainerCryptoSignature] = {
    "cryptography": ContainerCryptoSignature(
        name="pyca/cryptography",
        category="python_package",
        algorithm_family="Multi-primitive",
        primitive="library",
        pqc_status="HYBRID_READY",
        quantum_status="reduced_security_margin",
        base_risk_score=45.0,
        risk_level="MEDIUM",
        vulnerability_template="Python cryptography {version} handles classical asymmetric and symmetric crypto",
        recommendation_template="Ensure symmetric ciphers use 256-bit keys and monitor pyca PQC progress",
    ),
    "pycryptodome": ContainerCryptoSignature(
        name="pycryptodome",
        category="python_package",
        algorithm_family="Multi-primitive",
        primitive="library",
        pqc_status="HYBRID_READY",
        quantum_status="reduced_security_margin",
        base_risk_score=50.0,
        risk_level="MEDIUM",
        vulnerability_template="PyCryptodome {version} implements classical algorithms",
        recommendation_template="Review algorithms for Shor's algorithm vulnerabilities",
    ),
    "rsa": ContainerCryptoSignature(
        name="python-rsa",
        category="python_package",
        algorithm_family="RSA",
        primitive="asymmetric",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=90.0,
        risk_level="CRITICAL",
        vulnerability_template="Pure-Python RSA {version} is completely vulnerable to Shor's quantum algorithm",
        recommendation_template="Replace RSA key generation and signatures with NIST PQC standards (ML-DSA)",
    ),
    "ecdsa": ContainerCryptoSignature(
        name="python-ecdsa",
        category="python_package",
        algorithm_family="ECC",
        primitive="asymmetric",
        pqc_status="VULNERABLE",
        quantum_status="vulnerable",
        base_risk_score=90.0,
        risk_level="CRITICAL",
        vulnerability_template="ECDSA {version} is broken by quantum computers (Shor's algorithm)",
        recommendation_template="Replace ECDSA signatures with ML-DSA (NIST FIPS 204)",
    ),
}


def evaluate_openssl_version(version_str: str) -> tuple[str, str, float, str]:
    """
    Evaluate OpenSSL version for Post-Quantum Readiness.

    Returns:
        (pqc_status, quantum_status, risk_score, risk_level)
    """
    v = version_str.strip().lower()
    if v.startswith("3."):
        # OpenSSL 3.x supports providers and modern TLS 1.3
        return "HYBRID_READY", "reduced_security_margin", 35.0, "MEDIUM"
    elif v.startswith("1.1.1"):
        # Deprecated EOL, classical only
        return "VULNERABLE", "vulnerable", 80.0, "HIGH"
    elif v.startswith("1.0") or v.startswith("0.9"):
        # Severely outdated and vulnerable
        return "VULNERABLE", "vulnerable", 95.0, "CRITICAL"
    return "VULNERABLE", "vulnerable", 75.0, "HIGH"
