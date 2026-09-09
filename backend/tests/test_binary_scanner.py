"""
Tests for the Compiled Binary Scanner, format parsers, and API endpoints.
"""

import os
import struct
import tempfile
from pathlib import Path
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.source_scanner import ScanTarget
from app.core.binary_scanner.scanner import BinaryScanner
from app.core.binary_scanner.format_parser import parse_binary, extract_strings
from app.core.binary_scanner.signatures import SYMBOL_SIGNATURES, STRING_PATTERNS


def create_minimal_elf_with_symbols(file_path: Path, symbols: list[str], embedded_strings: list[str] = None):
    """
    Construct a synthetic, valid minimal 64-bit Little-Endian ELF binary with
    .shstrtab, .dynsym, and .dynstr sections containing specified symbols.
    """
    if embedded_strings is None:
        embedded_strings = []

    # 1. Build string tables
    # Section names (.shstrtab)
    shstrtab = b"\x00.shstrtab\x00.dynsym\x00.dynstr\x00.rodata\x00"
    shstr_shstrtab = 1
    shstr_dynsym = shstrtab.find(b".dynsym")
    shstr_dynstr = shstrtab.find(b".dynstr")
    shstr_rodata = shstrtab.find(b".rodata")

    # Symbol names (.dynstr)
    dynstr = b"\x00"
    sym_indices = []
    for s in symbols:
        idx = len(dynstr)
        dynstr += s.encode("ascii") + b"\x00"
        sym_indices.append(idx)

    # Embedded strings (.rodata)
    rodata = b"\x00"
    for st in embedded_strings:
        rodata += st.encode("ascii") + b"\x00"

    # 2. Build Symbol Table (.dynsym)
    # Entry 0: STN_UNDEF (24 bytes of 0)
    dynsym = bytearray(24)
    for s_idx in sym_indices:
        # Elf64_Sym: st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
        dynsym.extend(struct.pack("<IBBHQQ", s_idx, 0x12, 0, 1, 0x1000, 32))

    # Calculate offsets
    ehdr_size = 64
    shent_size = 64
    num_sections = 5  # null, .shstrtab, .dynsym, .dynstr, .rodata

    offset = ehdr_size
    off_shstrtab = offset
    offset += len(shstrtab)

    off_dynsym = offset
    offset += len(dynsym)

    off_dynstr = offset
    offset += len(dynstr)

    off_rodata = offset
    offset += len(rodata)

    # Pad offset to 8 bytes for section header table
    while offset % 8 != 0:
        offset += 1
    shoff = offset

    # Build ELF Header (64 bytes)
    # e_ident: 16 bytes
    # e_type: ET_EXEC (2), e_machine: EM_X86_64 (0x3E), e_version: 1 (4)
    # e_entry: 0x400000 (8), e_phoff: 0 (8), e_shoff: shoff (8), e_flags: 0 (4)
    # e_ehsize: 64 (2), e_phentsize: 0 (2), e_phnum: 0 (2)
    # e_shentsize: 64 (2), e_shnum: num_sections (2), e_shstrndx: 1 (2)
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2,       # ET_EXEC
        0x3E,    # EM_X86_64
        1,       # EV_CURRENT
        0x400000,
        0,
        shoff,
        0,
        64,
        0,
        0,
        64,
        num_sections,
        1,       # shstrndx (.shstrtab is section 1)
    )

    # Build Section Headers
    # Null section
    sh_null = bytearray(64)

    # .shstrtab section (type 3 = SHT_STRTAB)
    sh_shstrtab = struct.pack("<IIQQQQIIQQ", shstr_shstrtab, 3, 0, 0, off_shstrtab, len(shstrtab), 0, 0, 1, 0)

    # .dynsym section (type 11 = SHT_DYNSYM, link=3 points to .dynstr, entsize=24)
    sh_dynsym = struct.pack("<IIQQQQIIQQ", shstr_dynsym, 11, 2, 0, off_dynsym, len(dynsym), 3, 1, 8, 24)

    # .dynstr section (type 3 = SHT_STRTAB)
    sh_dynstr = struct.pack("<IIQQQQIIQQ", shstr_dynstr, 3, 2, 0, off_dynstr, len(dynstr), 0, 0, 1, 0)

    # .rodata section (type 1 = SHT_PROGBITS)
    sh_rodata = struct.pack("<IIQQQQIIQQ", shstr_rodata, 1, 2, 0, off_rodata, len(rodata), 0, 0, 4, 0)

    with open(file_path, "wb") as f:
        f.write(ehdr)
        f.write(shstrtab)
        f.write(dynsym)
        f.write(dynstr)
        f.write(rodata)
        # padding
        f.write(b"\x00" * (shoff - (off_rodata + len(rodata))))
        # section headers
        f.write(sh_null)
        f.write(sh_shstrtab)
        f.write(sh_dynsym)
        f.write(sh_dynstr)
        f.write(sh_rodata)


def test_signatures_catalog():
    """Verify built-in signature dictionaries and patterns."""
    assert "RSA_generate_key" in SYMBOL_SIGNATURES
    rsa_sig = SYMBOL_SIGNATURES["RSA_generate_key"]
    assert rsa_sig.pqc_status == "VULNERABLE"
    assert rsa_sig.quantum_status == "vulnerable"
    assert rsa_sig.risk_level == "HIGH"

    assert "OQS_KEM_ml_kem_768_new" in SYMBOL_SIGNATURES
    kem_sig = SYMBOL_SIGNATURES["OQS_KEM_ml_kem_768_new"]
    assert kem_sig.pqc_status == "QUANTUM_SAFE"
    assert kem_sig.quantum_status == "safe"
    assert kem_sig.base_risk_score == 0.0

    assert "EVP_aes_256_gcm" in SYMBOL_SIGNATURES
    aes_sig = SYMBOL_SIGNATURES["EVP_aes_256_gcm"]
    assert aes_sig.pqc_status == "QUANTUM_SAFE"


def test_extract_strings(tmp_path):
    """Test extracting printable ASCII and UTF-16LE strings."""
    bin_file = tmp_path / "test_strings.bin"
    content = b"random\x00\xff\xfeOpenSSL 3.0.13\x00\x01\x02ML-KEM-768\x00\xaa\xbb"
    bin_file.write_bytes(content)

    strings = extract_strings(bin_file)
    assert any("OpenSSL 3.0.13" in s for s in strings)
    assert any("ML-KEM-768" in s for s in strings)


def test_elf_parser_with_synthetic_binary(tmp_path):
    """Test ELF parser parsing symbols and architecture."""
    elf_file = tmp_path / "libcrypto_test.so"
    symbols = ["RSA_generate_key", "OQS_KEM_ml_kem_768_new", "EVP_aes_256_gcm"]
    embedded = ["OpenSSL 3.3.0", "ML-KEM-768"]
    create_minimal_elf_with_symbols(elf_file, symbols, embedded)

    parsed = parse_binary(elf_file)
    assert parsed.format == "ELF"
    assert parsed.is_64bit is True
    assert parsed.architecture == "x86_64"
    assert "RSA_generate_key" in parsed.symbols
    assert "OQS_KEM_ml_kem_768_new" in parsed.symbols
    assert "EVP_aes_256_gcm" in parsed.symbols


def test_binary_scanner_end_to_end(tmp_path):
    """Test BinaryScanner discovers symbols, classifies PQC readiness, and returns CryptoFindingData."""
    elf_file = tmp_path / "app_binary"
    symbols = [
        "RSA_generate_key",
        "OQS_KEM_ml_kem_768_new",
        "EVP_aes_256_gcm",
        "MD5_Init",
        "crypto_box_curve25519xsalsa20poly1305",
    ]
    embedded = ["OpenSSL 3.2.0"]
    create_minimal_elf_with_symbols(elf_file, symbols, embedded)

    scanner = BinaryScanner()
    target = ScanTarget(path=str(elf_file), scan_type="binary", depth="deep")
    result = scanner.scan(target)

    assert result.files_scanned == 1
    assert len(result.findings) >= 5

    algorithms = {f.algorithm for f in result.findings}
    assert "RSA" in algorithms
    assert "ML-KEM-768" in algorithms
    assert "AES-256-GCM" in algorithms
    assert "MD5" in algorithms

    # Check PQC status classifications
    rsa_f = next(f for f in result.findings if f.algorithm == "RSA")
    assert rsa_f.pqc_status == "VULNERABLE"
    assert rsa_f.quantum_status == "vulnerable"
    assert rsa_f.source_type == "binary"
    assert rsa_f.asset_type == "binary_usage"

    kem_f = next(f for f in result.findings if f.algorithm == "ML-KEM-768")
    assert kem_f.pqc_status == "QUANTUM_SAFE"
    assert kem_f.quantum_status == "safe"
    assert kem_f.risk_level == "INFO"


@pytest.mark.asyncio
async def test_binary_scan_api_endpoint(client, tmp_path):
    """Test POST /api/scan/binary endpoint executes scan, builds CBOM, and persists records."""
    elf_file = tmp_path / "microservice_crypto"
    symbols = ["RSA_generate_key", "OQS_KEM_ml_kem_768_new", "EVP_aes_128_gcm"]
    create_minimal_elf_with_symbols(elf_file, symbols)

    resp = await client.post(
        "/api/scan/binary",
        json={
            "path": str(elf_file),
            "scan_depth": "standard",
            "repository": "test-binary-repo",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["scan_type"] == "binary"
    assert data["status"] == "completed"
    assert data["total_assets"] >= 3
    assert data["quantum_safe_count"] >= 1
    assert data["vulnerable_count"] >= 1

    scan_id = data["id"]

    # Verify CBOM endpoint returns valid CycloneDX 1.5 CBOM
    cbom_resp = await client.get(f"/api/scan/{scan_id}/cbom")
    assert cbom_resp.status_code == 200
    cbom_data = cbom_resp.json()
    assert cbom_data["bomFormat"] == "CycloneDX"
    assert len(cbom_data["components"]) >= 3
