"""
Parsers for container image package databases, libraries, and certificates.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

logger = logging.getLogger(__name__)


@dataclass
class InstalledPackage:
    name: str
    version: str
    manager: str  # dpkg | apk | rpm | python | java
    description: Optional[str] = None
    origin_path: Optional[str] = None


def parse_dpkg_status(content: str, origin_path: str = "/var/lib/dpkg/status") -> List[InstalledPackage]:
    """
    Parse a Debian/Ubuntu dpkg status file into a list of packages.
    """
    packages: List[InstalledPackage] = []
    blocks = content.strip().split("\n\n")

    for block in blocks:
        lines = block.splitlines()
        pkg_data: Dict[str, str] = {}
        for line in lines:
            if ":" in line and not line.startswith(" "):
                k, _, v = line.partition(":")
                pkg_data[k.strip()] = v.strip()

        # Only count installed packages
        status = pkg_data.get("Status", "")
        if "installed" in status and "Package" in pkg_data:
            packages.append(InstalledPackage(
                name=pkg_data["Package"],
                version=pkg_data.get("Version", "unknown"),
                manager="dpkg",
                description=pkg_data.get("Description"),
                origin_path=origin_path,
            ))

    return packages


def parse_apk_installed(content: str, origin_path: str = "/lib/apk/db/installed") -> List[InstalledPackage]:
    """
    Parse an Alpine Linux apk installed packages database.
    """
    packages: List[InstalledPackage] = []
    blocks = content.strip().split("\n\n")

    for block in blocks:
        lines = block.splitlines()
        name = None
        version = None
        desc = None

        for line in lines:
            if line.startswith("P:"):
                name = line[2:].strip()
            elif line.startswith("V:"):
                version = line[2:].strip()
            elif line.startswith("T:"):
                desc = line[2:].strip()

        if name and version:
            packages.append(InstalledPackage(
                name=name,
                version=version,
                manager="apk",
                description=desc,
                origin_path=origin_path,
            ))

    return packages


def parse_python_metadata(content: str, origin_path: Optional[str] = None) -> Optional[InstalledPackage]:
    """
    Parse a Python *.dist-info/METADATA or PKG-INFO file.
    """
    name = None
    version = None
    summary = None

    for line in content.splitlines():
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("Summary:"):
            summary = line.split(":", 1)[1].strip()

    if name and version:
        return InstalledPackage(
            name=name,
            version=version,
            manager="python",
            description=summary,
            origin_path=origin_path,
        )
    return None


def parse_x509_certificate(cert_bytes: bytes, file_path: str = "") -> Optional[Dict[str, Any]]:
    """
    Extract public key algorithm, key size, and signature algorithm from an x509 cert.
    """
    try:
        if b"-----BEGIN CERTIFICATE-----" in cert_bytes:
            cert = x509.load_pem_x509_certificate(cert_bytes)
        else:
            cert = x509.load_der_x509_certificate(cert_bytes)

        pub_key = cert.public_key()
        algo = "Unknown"
        key_size = None

        if isinstance(pub_key, rsa.RSAPublicKey):
            algo = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            algo = "ECDSA"
            key_size = pub_key.curve.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            algo = "DSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            algo = "Ed25519"
            key_size = 256
        elif isinstance(pub_key, ed448.Ed448PublicKey):
            algo = "Ed448"
            key_size = 448

        sig_algo = cert.signature_algorithm_oid._name if hasattr(cert, "signature_algorithm_oid") else "unknown"

        return {
            "algorithm": algo,
            "key_size": key_size,
            "signature_algorithm": sig_algo,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "file_path": file_path,
        }
    except Exception as exc:
        logger.debug("Failed to parse certificate at %s: %s", file_path, exc)
        return None
