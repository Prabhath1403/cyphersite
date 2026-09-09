"""Tests for the Python source scanner.

Validates that the AST-based scanner correctly detects crypto API
calls from various Python libraries and produces accurate findings
with proper evidence, confidence, and metadata.
"""

import os
import pytest
from pathlib import Path

from app.core.source_scanner import ScanTarget, ScanResult, CryptoFindingData
from app.core.source_scanner.python_scanner import (
    PythonScanner,
    ImportTracker,
    CryptoCallVisitor,
)


# ── Path to test fixture ─────────────────────────────────────────────────
FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_FILE = FIXTURES_DIR / "sample_crypto_code.py"


# ═══════════════════════════════════════════════════════════════════════════
# SCANNER INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestPythonScanner:
    """Integration tests scanning the full sample fixture file."""

    @pytest.fixture
    def scanner(self):
        return PythonScanner()

    @pytest.fixture
    def scan_result(self, scanner) -> ScanResult:
        target = ScanTarget(
            path=str(SAMPLE_FILE),
            scan_type="source",
            language="python",
            repository="test-repo",
        )
        return scanner.scan(target)

    def test_scanner_metadata(self, scanner):
        """Scanner has correct metadata."""
        assert scanner.name == "Python Source Scanner"
        assert scanner.version == "0.1.0"
        assert "source" in scanner.supported_types

    def test_can_handle(self, scanner):
        """Scanner correctly identifies what it can handle."""
        assert scanner.can_handle(ScanTarget(path="/tmp", scan_type="source"))
        assert not scanner.can_handle(ScanTarget(path="/tmp", scan_type="network"))

    def test_scan_completes(self, scan_result):
        """Scanner runs without errors on the fixture file."""
        assert scan_result.files_scanned == 1
        assert scan_result.files_skipped == 0
        assert len(scan_result.errors) == 0

    def test_finds_multiple_crypto_calls(self, scan_result):
        """Scanner discovers multiple crypto findings."""
        assert scan_result.total_findings >= 10, (
            f"Expected ≥10 findings, got {scan_result.total_findings}"
        )

    def test_detects_hashlib_sha256(self, scan_result):
        """Detects hashlib.sha256 call."""
        sha256_findings = [
            f for f in scan_result.findings
            if f.algorithm == "SHA-256" and f.library == "hashlib"
        ]
        assert len(sha256_findings) >= 1
        finding = sha256_findings[0]
        assert finding.primitive == "hash"
        assert finding.usage == "hashing"
        assert finding.confidence == 1.0

    def test_detects_hashlib_md5(self, scan_result):
        """Detects hashlib.md5 — known insecure."""
        md5_findings = [
            f for f in scan_result.findings
            if f.algorithm == "MD5" and f.library == "hashlib"
        ]
        assert len(md5_findings) >= 1
        finding = md5_findings[0]
        assert finding.details["quantum_status"] == "vulnerable"

    def test_detects_sha3(self, scan_result):
        """Detects hashlib.sha3_256 — quantum safe."""
        sha3_findings = [
            f for f in scan_result.findings
            if f.algorithm == "SHA3-256"
        ]
        assert len(sha3_findings) >= 1
        assert sha3_findings[0].details["quantum_status"] == "safe"

    def test_detects_hmac(self, scan_result):
        """Detects hmac.new call."""
        hmac_findings = [
            f for f in scan_result.findings
            if f.algorithm == "HMAC" and f.library == "hmac"
        ]
        assert len(hmac_findings) >= 1
        assert hmac_findings[0].primitive == "mac"
        assert hmac_findings[0].usage == "authentication"

    def test_detects_rsa_key_generation(self, scan_result):
        """Detects rsa.generate_private_key with key size."""
        rsa_findings = [
            f for f in scan_result.findings
            if f.algorithm == "RSA" and f.library == "cryptography"
        ]
        assert len(rsa_findings) >= 1
        # Check that key sizes are extracted
        key_sizes = [f.key_size for f in rsa_findings if f.key_size]
        assert 2048 in key_sizes or 4096 in key_sizes

    def test_detects_aes(self, scan_result):
        """Detects AES cipher usage."""
        aes_findings = [
            f for f in scan_result.findings
            if f.algorithm == "AES" and f.library == "cryptography"
        ]
        assert len(aes_findings) >= 1

    def test_detects_gcm_mode(self, scan_result):
        """Detects GCM cipher mode."""
        gcm_findings = [
            f for f in scan_result.findings
            if f.mode == "GCM"
        ]
        assert len(gcm_findings) >= 1

    def test_detects_ecb_mode(self, scan_result):
        """Detects insecure ECB mode."""
        ecb_findings = [
            f for f in scan_result.findings
            if f.mode == "ECB"
        ]
        assert len(ecb_findings) >= 1
        assert ecb_findings[0].details["quantum_status"] == "vulnerable"

    def test_detects_pbkdf2(self, scan_result):
        """Detects PBKDF2 key derivation."""
        kdf_findings = [
            f for f in scan_result.findings
            if f.algorithm == "PBKDF2"
        ]
        assert len(kdf_findings) >= 1
        assert kdf_findings[0].primitive == "kdf"
        assert kdf_findings[0].usage == "key_derivation"

    def test_detects_fernet(self, scan_result):
        """Detects Fernet high-level encryption."""
        fernet_findings = [
            f for f in scan_result.findings
            if "Fernet" in (f.algorithm or "") or "AES-128-CBC" in (f.algorithm or "")
        ]
        assert len(fernet_findings) >= 1

    def test_detects_ecdsa(self, scan_result):
        """Detects ECDSA key generation."""
        ec_findings = [
            f for f in scan_result.findings
            if f.algorithm == "ECDSA" and f.library == "cryptography"
        ]
        assert len(ec_findings) >= 1
        assert ec_findings[0].primitive == "asymmetric"

    def test_detects_ssl_context(self, scan_result):
        """Detects ssl.create_default_context."""
        ssl_findings = [
            f for f in scan_result.findings
            if f.library == "ssl" and f.algorithm == "TLS"
        ]
        assert len(ssl_findings) >= 1
        assert ssl_findings[0].primitive == "protocol"

    def test_detects_3des(self, scan_result):
        """Detects insecure TripleDES usage."""
        des3_findings = [
            f for f in scan_result.findings
            if f.algorithm == "3DES"
        ]
        assert len(des3_findings) >= 1
        assert des3_findings[0].details["quantum_status"] == "vulnerable"

    def test_detects_pss_padding(self, scan_result):
        """Detects RSA-PSS padding."""
        pss_findings = [
            f for f in scan_result.findings
            if f.padding == "PSS"
        ]
        assert len(pss_findings) >= 1

    def test_all_findings_have_evidence(self, scan_result):
        """Every finding includes structured evidence."""
        for finding in scan_result.findings:
            assert finding.evidence is not None, f"Missing evidence: {finding.name}"
            assert "code_line" in finding.evidence
            assert "line_number" in finding.evidence
            assert finding.evidence["type"] == "ast_match"

    def test_all_findings_have_file_path(self, scan_result):
        """Every finding has a file path."""
        for finding in scan_result.findings:
            assert finding.file_path is not None
            assert finding.file_path.endswith(".py")

    def test_all_findings_have_language(self, scan_result):
        """Every finding is tagged as Python."""
        for finding in scan_result.findings:
            assert finding.language == "python"

    def test_all_findings_are_source_code_type(self, scan_result):
        """Every finding has correct asset and source types."""
        for finding in scan_result.findings:
            assert finding.asset_type == "source_code_usage"
            assert finding.source_type == "source_code"

    def test_repository_propagated(self, scan_result):
        """Repository identifier is propagated to findings."""
        for finding in scan_result.findings:
            assert finding.repository == "test-repo"

    def test_function_context_captured(self, scan_result):
        """Findings inside functions capture the function name."""
        func_findings = [
            f for f in scan_result.findings
            if f.function_name is not None
        ]
        assert len(func_findings) > 0
        func_names = [f.function_name for f in func_findings]
        assert any("hash_password" in fn for fn in func_names)

    def test_class_context_captured(self, scan_result):
        """Findings inside classes capture the class.method context."""
        class_findings = [
            f for f in scan_result.findings
            if f.function_name and "CryptoService" in f.function_name
        ]
        assert len(class_findings) >= 1

    def test_to_orm_kwargs(self, scan_result):
        """CryptoFindingData.to_orm_kwargs produces valid dict."""
        for finding in scan_result.findings:
            kwargs = finding.to_orm_kwargs()
            assert "name" in kwargs
            assert "asset_type" in kwargs
            assert "source_type" in kwargs
            # None values should be excluded
            for v in kwargs.values():
                assert v is not None


# ═══════════════════════════════════════════════════════════════════════════
# EDGE CASE TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestPythonScannerEdgeCases:
    """Edge cases and error handling."""

    @pytest.fixture
    def scanner(self):
        return PythonScanner()

    def test_nonexistent_path(self, scanner):
        """Scanner handles nonexistent path gracefully."""
        target = ScanTarget(path="/nonexistent/path", scan_type="source")
        result = scanner.scan(target)
        assert len(result.errors) > 0
        assert result.files_scanned == 0

    def test_empty_file(self, scanner, tmp_path):
        """Scanner handles empty Python file."""
        empty = tmp_path / "empty.py"
        empty.write_text("")
        target = ScanTarget(path=str(empty), scan_type="source")
        result = scanner.scan(target)
        assert result.files_scanned == 1
        assert result.total_findings == 0

    def test_syntax_error_file(self, scanner, tmp_path):
        """Scanner handles Python file with syntax errors."""
        bad = tmp_path / "bad.py"
        bad.write_text("def broken(\n")
        target = ScanTarget(path=str(bad), scan_type="source")
        result = scanner.scan(target)
        assert result.files_skipped == 1

    def test_no_crypto_file(self, scanner, tmp_path):
        """Scanner produces no findings for non-crypto code."""
        clean = tmp_path / "clean.py"
        clean.write_text(
            "import os\nimport json\n\ndef hello():\n    print('hello')\n"
        )
        target = ScanTarget(path=str(clean), scan_type="source")
        result = scanner.scan(target)
        assert result.files_scanned == 1
        assert result.total_findings == 0

    def test_directory_scan(self, scanner, tmp_path):
        """Scanner can scan an entire directory."""
        (tmp_path / "a.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
        (tmp_path / "b.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
        (tmp_path / "not_py.txt").write_text("not python")

        target = ScanTarget(path=str(tmp_path), scan_type="source")
        result = scanner.scan(target)
        assert result.files_scanned == 2
        assert result.total_findings == 2

    def test_skips_venv_directory(self, scanner, tmp_path):
        """Scanner skips venv directories."""
        venv = tmp_path / "venv"
        venv.mkdir()
        (venv / "crypto.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
        (tmp_path / "main.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")

        target = ScanTarget(path=str(tmp_path), scan_type="source")
        result = scanner.scan(target)
        assert result.files_scanned == 1  # Only main.py
        assert result.total_findings == 1


# ═══════════════════════════════════════════════════════════════════════════
# IMPORT TRACKER UNIT TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestImportTracker:
    """Unit tests for the import resolution logic."""

    def _track(self, source: str) -> ImportTracker:
        import ast
        tree = ast.parse(source)
        tracker = ImportTracker()
        tracker.visit(tree)
        return tracker

    def test_plain_import(self):
        tracker = self._track("import hashlib")
        assert tracker.imports["hashlib"] == "hashlib"

    def test_aliased_import(self):
        tracker = self._track("import hashlib as hl")
        assert tracker.imports["hl"] == "hashlib"

    def test_from_import(self):
        tracker = self._track("from hashlib import sha256")
        assert tracker.from_imports["sha256"] == "hashlib.sha256"

    def test_from_import_deep(self):
        tracker = self._track(
            "from cryptography.hazmat.primitives.ciphers import algorithms"
        )
        assert tracker.from_imports["algorithms"] == (
            "cryptography.hazmat.primitives.ciphers.algorithms"
        )

    def test_from_import_with_alias(self):
        tracker = self._track("from hashlib import sha256 as s")
        assert tracker.from_imports["s"] == "hashlib.sha256"

    def test_from_import_specific(self):
        tracker = self._track(
            "from cryptography.hazmat.primitives.ciphers.algorithms import AES"
        )
        assert tracker.from_imports["AES"] == (
            "cryptography.hazmat.primitives.ciphers.algorithms.AES"
        )
