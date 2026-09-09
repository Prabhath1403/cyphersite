"""
Container Image Scanner — discovers cryptographic packages, shared libraries,
and certificates in Docker / OCI container images and filesystems.
"""

from __future__ import annotations

import io
import logging
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

from app.core.source_scanner import (
    BaseScanner,
    CryptoFindingData,
    ScanResult,
    ScanTarget,
)
from app.core.container_scanner.rules import (
    OS_PACKAGE_SIGNATURES,
    SHARED_LIBRARY_SIGNATURES,
    PYTHON_CONTAINER_PACKAGES,
    evaluate_openssl_version,
)
from app.core.container_scanner.package_parser import (
    parse_dpkg_status,
    parse_apk_installed,
    parse_python_metadata,
    parse_x509_certificate,
    InstalledPackage,
)

logger = logging.getLogger(__name__)

LIB_SEARCH_PREFIXES = ("lib/", "usr/lib/", "usr/local/lib/")


class ContainerScanner(BaseScanner):
    """
    Scans container images (tar archives, rootfs directories, or Docker tags)
    for cryptographic libraries, installed packages, and TLS certificates.
    """

    @property
    def name(self) -> str:
        return "Container Image Scanner"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_types(self) -> List[str]:
        return ["container"]

    def scan(self, target: ScanTarget) -> ScanResult:
        """
        Scan a container image target.

        Target path can be:
        - A tarball file (.tar, .tar.gz) of a Docker/OCI image
        - A rootfs directory
        - A container image reference (e.g. 'ubuntu:22.04') if docker is running
        """
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            languages_detected=["container", "c", "python"],
        )

        target_path_str = target.path.strip()
        target_path = Path(target_path_str)

        temp_dir = None
        try:
            if target_path.is_file() and any(target_path_str.endswith(ext) for ext in (".tar", ".tar.gz", ".tgz")):
                # Target is an image tar archive
                self._scan_tar_archive(target_path, result)

            elif target_path.is_dir():
                # Target is an extracted rootfs or container directory
                self._scan_rootfs_directory(target_path, result)

            else:
                # Attempt to export image via docker CLI if available
                temp_dir = tempfile.mkdtemp(prefix="ciphersight_docker_")
                archive_path = Path(temp_dir) / "image.tar"

                try:
                    logger.info("Attempting docker save for image: %s", target_path_str)
                    subprocess.run(
                        ["docker", "save", "-o", str(archive_path), target_path_str],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=180,
                    )
                    self._scan_tar_archive(archive_path, result)
                except (subprocess.SubprocessError, FileNotFoundError) as exc:
                    result.errors.append(
                        f"Target '{target_path_str}' is neither an existing file/directory nor a readable Docker image. "
                        f"(Docker export error: {exc})"
                    )

        except Exception as exc:
            logger.exception("Error during container scan: %s", exc)
            result.errors.append(f"Container scan failed: {exc}")

        finally:
            if temp_dir and Path(temp_dir).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

        return result

    def _scan_tar_archive(self, tar_path: Path, result: ScanResult) -> None:
        """
        Walk through an OCI / Docker tarball archive, inspecting layer tars.
        """
        seen_packages: Set[str] = set()

        try:
            with tarfile.open(tar_path, "r:*") as outer_tar:
                for member in outer_tar.getmembers():
                    result.files_scanned += 1
                    # Inspect inner layer tar files
                    if member.name.endswith(".tar") or member.name.endswith("/layer.tar"):
                        f = outer_tar.extractfile(member)
                        if f:
                            try:
                                with tarfile.open(fileobj=f, mode="r:*") as layer_tar:
                                    self._inspect_layer_tar(layer_tar, result, seen_packages)
                            except Exception as layer_err:
                                logger.debug("Could not read layer %s: %s", member.name, layer_err)

                    # Also check direct files in single-layer / rootfs tarballs
                    self._check_tar_member(member, outer_tar, result, seen_packages)

        except Exception as exc:
            result.errors.append(f"Failed to read tar archive {tar_path}: {exc}")

    def _inspect_layer_tar(
        self,
        layer_tar: tarfile.TarFile,
        result: ScanResult,
        seen_packages: Set[str],
    ) -> None:
        """Inspect members inside a single container layer."""
        for member in layer_tar.getmembers():
            result.files_scanned += 1
            self._check_tar_member(member, layer_tar, result, seen_packages)

    def _check_tar_member(
        self,
        member: tarfile.TarInfo,
        tar_obj: tarfile.TarFile,
        result: ScanResult,
        seen_packages: Set[str],
    ) -> None:
        """Inspect a single tar entry for package DBs or crypto libraries."""
        norm_name = member.name.lstrip("./")

        # 1. Debian/Ubuntu dpkg status
        if norm_name.endswith("var/lib/dpkg/status"):
            f = tar_obj.extractfile(member)
            if f:
                content = f.read().decode("utf-8", errors="replace")
                pkgs = parse_dpkg_status(content, norm_name)
                self._process_installed_packages(pkgs, result, seen_packages)

        # 2. Alpine apk installed
        elif norm_name.endswith("lib/apk/db/installed"):
            f = tar_obj.extractfile(member)
            if f:
                content = f.read().decode("utf-8", errors="replace")
                pkgs = parse_apk_installed(content, norm_name)
                self._process_installed_packages(pkgs, result, seen_packages)

        # 3. Python package METADATA in site-packages
        elif norm_name.endswith(".dist-info/METADATA") or norm_name.endswith(".egg-info/PKG-INFO"):
            f = tar_obj.extractfile(member)
            if f:
                content = f.read().decode("utf-8", errors="replace")
                pkg = parse_python_metadata(content, norm_name)
                if pkg:
                    self._process_installed_packages([pkg], result, seen_packages)

        # 4. Shared library binaries
        elif any(norm_name.startswith(p) for p in LIB_SEARCH_PREFIXES) and ".so" in member.name:
            self._check_shared_library(norm_name, result, seen_packages)

        # 5. Certificates in /etc/ssl/certs
        elif norm_name.startswith("etc/ssl/certs/") and (norm_name.endswith(".pem") or norm_name.endswith(".crt")):
            f = tar_obj.extractfile(member)
            if f:
                cert_bytes = f.read()
                self._check_certificate(norm_name, cert_bytes, result)

    def _scan_rootfs_directory(self, root_dir: Path, result: ScanResult) -> None:
        """
        Scan an unpacked rootfs directory.
        """
        seen_packages: Set[str] = set()

        # 1. Check dpkg status
        dpkg_file = root_dir / "var" / "lib" / "dpkg" / "status"
        if dpkg_file.exists():
            result.files_scanned += 1
            content = dpkg_file.read_text(encoding="utf-8", errors="replace")
            pkgs = parse_dpkg_status(content, str(dpkg_file))
            self._process_installed_packages(pkgs, result, seen_packages)

        # 2. Check apk installed
        apk_file = root_dir / "lib" / "apk" / "db" / "installed"
        if apk_file.exists():
            result.files_scanned += 1
            content = apk_file.read_text(encoding="utf-8", errors="replace")
            pkgs = parse_apk_installed(content, str(apk_file))
            self._process_installed_packages(pkgs, result, seen_packages)

        # 3. Search for shared libraries and python packages
        for entry in root_dir.rglob("*"):
            if not entry.is_file():
                continue
            result.files_scanned += 1
            rel_str = str(entry.relative_to(root_dir))

            if ".dist-info/METADATA" in rel_str or ".egg-info/PKG-INFO" in rel_str:
                content = entry.read_text(encoding="utf-8", errors="replace")
                pkg = parse_python_metadata(content, rel_str)
                if pkg:
                    self._process_installed_packages([pkg], result, seen_packages)

            elif any(rel_str.startswith(p) for p in LIB_SEARCH_PREFIXES) and ".so" in entry.name:
                self._check_shared_library(rel_str, result, seen_packages)

            elif "etc/ssl/certs" in rel_str and (rel_str.endswith(".pem") or rel_str.endswith(".crt")):
                cert_bytes = entry.read_bytes()
                self._check_certificate(rel_str, cert_bytes, result)

    def _process_installed_packages(
        self,
        packages: List[InstalledPackage],
        result: ScanResult,
        seen_packages: Set[str],
    ) -> None:
        """Match installed packages against crypto signatures and record findings."""
        for pkg in packages:
            pkg_key = f"{pkg.name}:{pkg.version}"
            if pkg_key in seen_packages:
                continue

            # Check OS package signatures
            matched_sig = None
            matched_name = pkg.name.lower()

            for sig_key, sig in OS_PACKAGE_SIGNATURES.items():
                if sig_key in matched_name:
                    matched_sig = sig
                    break

            # Check Python package signatures
            if not matched_sig and pkg.manager == "python":
                matched_sig = PYTHON_CONTAINER_PACKAGES.get(pkg.name.lower())

            if matched_sig:
                seen_packages.add(pkg_key)

                # Special version evaluation for OpenSSL
                if "openssl" in matched_name or "libssl" in matched_name:
                    pqc_status, quantum_status, risk_score, risk_level = evaluate_openssl_version(pkg.version)
                else:
                    pqc_status = matched_sig.pqc_status
                    quantum_status = matched_sig.quantum_status
                    risk_score = matched_sig.base_risk_score
                    risk_level = matched_sig.risk_level

                vuln_msg = matched_sig.vulnerability_template.format(version=pkg.version) if matched_sig.vulnerability_template else ""
                vulns = [vuln_msg] if vuln_msg else []
                recs = [matched_sig.recommendation_template] if matched_sig.recommendation_template else []

                finding = CryptoFindingData(
                    name=f"{matched_sig.name} ({pkg.version})",
                    asset_type="container_usage",
                    source_type="container",
                    algorithm=matched_sig.algorithm_family,
                    algorithm_family=matched_sig.algorithm_family,
                    primitive=matched_sig.primitive,
                    usage="cryptographic_service",
                    library=matched_sig.name,
                    library_version=pkg.version,
                    version=pkg.version,
                    file_path=pkg.origin_path,
                    language="c" if pkg.manager in ("dpkg", "apk") else "python",
                    confidence=1.0,
                    pqc_status=pqc_status,
                    quantum_status=quantum_status,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    vulnerabilities=vulns,
                    recommendations=recs,
                    evidence={
                        "type": "package_manager_entry",
                        "package_name": pkg.name,
                        "version": pkg.version,
                        "package_manager": pkg.manager,
                        "origin_path": pkg.origin_path,
                    },
                    details={
                        "manager": pkg.manager,
                        "quantum_status": quantum_status,
                        "description": pkg.description,
                    },
                )
                result.findings.append(finding)

    def _check_shared_library(
        self,
        rel_path: str,
        result: ScanResult,
        seen_packages: Set[str],
    ) -> None:
        """Inspect a discovered shared library binary file."""
        filename = Path(rel_path).name
        for lib_key, sig in SHARED_LIBRARY_SIGNATURES.items():
            if filename.startswith(lib_key):
                key = f"so:{filename}"
                if key in seen_packages:
                    return
                seen_packages.add(key)

                vuln_msg = sig.vulnerability_template.format(filename=filename) if sig.vulnerability_template else ""
                vulns = [vuln_msg] if vuln_msg else []
                recs = [sig.recommendation_template] if sig.recommendation_template else []

                finding = CryptoFindingData(
                    name=filename,
                    asset_type="binary_usage",
                    source_type="container",
                    algorithm=sig.algorithm_family,
                    algorithm_family=sig.algorithm_family,
                    primitive=sig.primitive,
                    usage="shared_library",
                    library=sig.name,
                    file_path=rel_path,
                    confidence=0.85,
                    pqc_status=sig.pqc_status,
                    quantum_status=sig.quantum_status,
                    risk_score=sig.base_risk_score,
                    risk_level=sig.risk_level,
                    vulnerabilities=vulns,
                    recommendations=recs,
                    evidence={
                        "type": "shared_library_binary",
                        "filename": filename,
                        "path": rel_path,
                    },
                    details={
                        "quantum_status": sig.quantum_status,
                    },
                )
                result.findings.append(finding)
                break

    def _check_certificate(self, rel_path: str, cert_bytes: bytes, result: ScanResult) -> None:
        """Inspect an x509 certificate found inside the container filesystem."""
        parsed = parse_x509_certificate(cert_bytes, rel_path)
        if not parsed:
            return

        algo = parsed["algorithm"]
        key_size = parsed["key_size"]

        # PQC assessment for certificate
        is_vuln = algo in ("RSA", "DSA", "ECDSA", "Ed25519")
        pqc_status = "VULNERABLE" if is_vuln else "UNKNOWN"
        quantum_status = "vulnerable" if is_vuln else "unknown"
        risk_score = 80.0 if is_vuln else 50.0
        risk_level = "HIGH" if is_vuln else "MEDIUM"

        vulns = [f"Certificate uses {algo}-{key_size} vulnerable to Shor's algorithm"] if is_vuln else []
        recs = ["Transition certificate authority and certs to NIST ML-DSA (FIPS 204)"] if is_vuln else []

        finding = CryptoFindingData(
            name=f"Cert: {Path(rel_path).name}",
            asset_type="certificate",
            source_type="container",
            algorithm=algo,
            algorithm_family=algo,
            key_size=key_size,
            primitive="asymmetric",
            usage="signing",
            file_path=rel_path,
            confidence=1.0,
            pqc_status=pqc_status,
            quantum_status=quantum_status,
            risk_score=risk_score,
            risk_level=risk_level,
            vulnerabilities=vulns,
            recommendations=recs,
            evidence={
                "type": "x509_certificate",
                "subject": parsed["subject"],
                "issuer": parsed["issuer"],
                "signature_algorithm": parsed["signature_algorithm"],
            },
            details=parsed,
        )
        result.findings.append(finding)
