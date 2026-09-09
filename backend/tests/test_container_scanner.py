"""Tests for Container Image Scanner."""

import io
import tarfile
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import AsyncClient

from app.core.container_scanner import ContainerScanner
from app.core.container_scanner.package_parser import (
    parse_dpkg_status,
    parse_apk_installed,
    parse_python_metadata,
)
from app.core.container_scanner.rules import evaluate_openssl_version
from app.core.source_scanner import ScanTarget

SAMPLE_DPKG_STATUS = """
Package: openssl
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 1540
Maintainer: Ubuntu Developers
Architecture: amd64
Version: 3.0.2-0ubuntu1.15
Description: Secure Sockets Layer toolkit - cryptographic utility

Package: gnutls-bin
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 1120
Architecture: amd64
Version: 3.7.3-4ubuntu1.4
Description: GNU TLS library - commandline utilities

Package: curl
Status: install ok installed
Priority: optional
Section: web
Architecture: amd64
Version: 7.81.0-1ubuntu1.16
Description: command line tool for transferring data with URL syntax
"""

SAMPLE_APK_INSTALLED = """
P:openssl
V:3.1.2-r0
T:SSL toolkit
S:180000

P:musl
V:1.2.4-r1
T:the musl c-library
S:600000
"""

SAMPLE_PYTHON_METADATA = """
Metadata-Version: 2.1
Name: cryptography
Version: 42.0.5
Summary: cryptography is a package which provides cryptographic recipes and primitives
"""


def test_evaluate_openssl_version():
    """OpenSSL version evaluation correctly maps PQC readiness."""
    status3, q_status3, risk3, level3 = evaluate_openssl_version("3.0.2")
    assert status3 == "HYBRID_READY"
    assert q_status3 == "reduced_security_margin"
    assert risk3 < 50.0

    status1, q_status1, risk1, level1 = evaluate_openssl_version("1.1.1u")
    assert status1 == "VULNERABLE"
    assert risk1 >= 75.0

    status0, q_status0, risk0, level0 = evaluate_openssl_version("1.0.2g")
    assert status0 == "VULNERABLE"
    assert risk0 >= 90.0


def test_parse_dpkg_status():
    """Dpkg status parser extracts installed packages."""
    pkgs = parse_dpkg_status(SAMPLE_DPKG_STATUS)
    pkg_map = {p.name: p for p in pkgs}
    assert "openssl" in pkg_map
    assert pkg_map["openssl"].version == "3.0.2-0ubuntu1.15"
    assert "gnutls-bin" in pkg_map
    assert "curl" in pkg_map


def test_parse_apk_installed():
    """Apk installed parser extracts Alpine packages."""
    pkgs = parse_apk_installed(SAMPLE_APK_INSTALLED)
    pkg_map = {p.name: p for p in pkgs}
    assert "openssl" in pkg_map
    assert pkg_map["openssl"].version == "3.1.2-r0"


def test_parse_python_metadata():
    """Python dist-info parser extracts package name and version."""
    pkg = parse_python_metadata(SAMPLE_PYTHON_METADATA)
    assert pkg is not None
    assert pkg.name == "cryptography"
    assert pkg.version == "42.0.5"


def test_container_scanner_rootfs(tmp_path: Path):
    """Scanner detects crypto packages and libraries in rootfs directory."""
    # Setup mock rootfs
    dpkg_dir = tmp_path / "var" / "lib" / "dpkg"
    dpkg_dir.mkdir(parents=True)
    (dpkg_dir / "status").write_text(SAMPLE_DPKG_STATUS)

    lib_dir = tmp_path / "usr" / "lib" / "x86_64-linux-gnu"
    lib_dir.mkdir(parents=True)
    (lib_dir / "libcrypto.so.3").write_text("dummy binary content")

    py_dir = tmp_path / "usr" / "local" / "lib" / "python3.11" / "site-packages" / "cryptography-42.0.5.dist-info"
    py_dir.mkdir(parents=True)
    (py_dir / "METADATA").write_text(SAMPLE_PYTHON_METADATA)

    scanner = ContainerScanner()
    result = scanner.scan(ScanTarget(path=str(tmp_path), scan_type="container"))

    assert result.files_scanned > 0
    assert result.total_findings >= 3

    names = [f.name for f in result.findings]
    assert any("OpenSSL" in n for n in names)
    assert any("libcrypto" in n for n in names)
    assert any("cryptography" in n for n in names)

    # Verify OpenSSL finding posture
    openssl_f = next(f for f in result.findings if "OpenSSL" in f.name)
    assert openssl_f.source_type == "container"
    assert openssl_f.pqc_status == "HYBRID_READY"


def test_container_scanner_tar_archive(tmp_path: Path):
    """Scanner unpacks and detects crypto in a container image tar archive."""
    tar_path = tmp_path / "sample_image.tar"

    with tarfile.open(tar_path, "w") as tar:
        # Add dpkg status
        data = SAMPLE_DPKG_STATUS.encode("utf-8")
        ti = tarfile.TarInfo(name="var/lib/dpkg/status")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))

        # Add shared lib
        lib_data = b"ELF dummy shared library"
        ti_lib = tarfile.TarInfo(name="usr/lib/libcrypto.so.3")
        ti_lib.size = len(lib_data)
        tar.addfile(ti_lib, io.BytesIO(lib_data))

    scanner = ContainerScanner()
    result = scanner.scan(ScanTarget(path=str(tar_path), scan_type="container"))

    assert result.total_findings >= 2
    names = [f.name for f in result.findings]
    assert any("OpenSSL" in n for n in names)
    assert any("libcrypto" in n for n in names)


@pytest.mark.asyncio
async def test_container_scan_api_endpoint(client: AsyncClient, tmp_path: Path):
    """E2E test of POST /api/scan/container and CBOM generation."""
    # 1. Create a sample container image tarball
    tar_path = tmp_path / "mock_container.tar"
    with tarfile.open(tar_path, "w") as tar:
        data = SAMPLE_DPKG_STATUS.encode("utf-8")
        ti = tarfile.TarInfo(name="var/lib/dpkg/status")
        ti.size = len(data)
        tar.addfile(ti, io.BytesIO(data))

    # 2. Trigger container scan
    response = await client.post(
        "/api/scan/container",
        json={
            "image": str(tar_path),
            "repository": "mock-ubuntu-image:latest",
            "scan_depth": "standard",
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()

    scan_id = data["id"]
    assert data["status"] == "completed"
    assert data["scan_type"] == "container"
    assert data["total_assets"] >= 2
    assert len(data["findings"]) == data["total_assets"]

    # 3. Retrieve CBOM
    cbom_res = await client.get(f"/api/scan/{scan_id}/cbom")
    assert cbom_res.status_code == 200
    cbom_data = cbom_res.json()
    assert cbom_data["bomFormat"] == "CycloneDX"
    assert len(cbom_data["components"]) == data["total_assets"]
