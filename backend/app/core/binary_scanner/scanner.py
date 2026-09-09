"""
Compiled Binary Scanner — discovers cryptographic symbols, embedded algorithms,
and post-quantum readiness across compiled ELF, PE, Mach-O executables and libraries.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from app.core.source_scanner import (
    BaseScanner,
    CryptoFindingData,
    ScanResult,
    ScanTarget,
)
from app.core.binary_scanner.signatures import (
    SYMBOL_SIGNATURES,
    SYMBOL_PREFIX_RULES,
    STRING_PATTERNS,
    BinaryCryptoSignature,
)
from app.core.binary_scanner.format_parser import (
    parse_binary,
    ParsedBinaryInfo,
)

logger = logging.getLogger(__name__)

BINARY_EXTENSIONS = {
    ".so", ".dylib", ".dll", ".exe", ".bin", ".elf", ".o", ".a",
    ".node", ".oct", ".axf", ".ko",
}

NON_BINARY_EXTENSIONS = {
    ".py", ".pyc", ".js", ".jsx", ".ts", ".tsx", ".html", ".css",
    ".json", ".yaml", ".yml", ".md", ".txt", ".csv", ".xml", ".sql",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
}


class BinaryScanner(BaseScanner):
    """
    Scanner for compiled ELF, PE, and Mach-O binaries and shared libraries.
    Discovers embedded crypto symbols, imported dynamic libraries, algorithm identifiers,
    and classifies quantum vulnerability vs post-quantum readiness.
    """

    @property
    def name(self) -> str:
        return "Compiled Binary Scanner"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_types(self) -> List[str]:
        return ["binary"]

    def scan(self, target: ScanTarget) -> ScanResult:
        """
        Scan a binary target.
        Target path can be:
        - A single binary file (.so, .dll, .dylib, executable, etc.)
        - A directory of binaries
        - An archive (.tar, .tar.gz, .zip) containing binaries
        """
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            languages_detected=["c", "cpp", "binary"],
        )

        target_path_str = target.path.strip()
        target_path = Path(target_path_str)

        temp_dir = None
        try:
            if not target_path.exists():
                result.errors.append(f"Target binary path does not exist: {target_path_str}")
                return result

            # Handle archive files (.tar, .zip)
            scan_root = target_path
            if target_path.is_file():
                if tarfile.is_tarfile(str(target_path)):
                    temp_dir = tempfile.mkdtemp(prefix="cyphercite_binary_tar_")
                    with tarfile.open(str(target_path), "r:*") as tar:
                        tar.extractall(path=temp_dir)
                    scan_root = Path(temp_dir)
                elif zipfile.is_zipfile(str(target_path)):
                    temp_dir = tempfile.mkdtemp(prefix="cyphercite_binary_zip_")
                    with zipfile.ZipFile(str(target_path), "r") as z:
                        z.extractall(path=temp_dir)
                    scan_root = Path(temp_dir)

            # Discover binary files to inspect
            binary_files: List[Path] = []
            if scan_root.is_file():
                binary_files.append(scan_root)
            else:
                for root, dirs, files in os.walk(scan_root):
                    dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "vendor")]
                    for fname in files:
                        p = Path(root) / fname
                        ext = p.suffix.lower()
                        if ext in NON_BINARY_EXTENSIONS:
                            continue
                        if ext in BINARY_EXTENSIONS or self._is_binary_file(p):
                            binary_files.append(p)

            logger.info("BinaryScanner discovered %d binary candidate files in %s", len(binary_files), target_path)

            for binary_path in binary_files:
                try:
                    findings_for_file = self._scan_single_binary(binary_path, target.repository)
                    result.findings.extend(findings_for_file)
                    result.files_scanned += 1
                except Exception as exc:
                    logger.debug("Error scanning binary %s: %s", binary_path, exc)
                    result.errors.append(f"Error scanning {binary_path.name}: {exc}")

        finally:
            if temp_dir and Path(temp_dir).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

        return result

    def _is_binary_file(self, file_path: Path) -> bool:
        """Check if file starts with common binary executable magic bytes."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(4)
            if header.startswith(b"\x7fELF") or header.startswith(b"MZ"):
                return True
            if header in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
                return True
        except Exception:
            pass
        return False

    def _scan_single_binary(self, file_path: Path, repository: Optional[str]) -> List[CryptoFindingData]:
        """Parse and match crypto signatures for a single binary."""
        parsed: ParsedBinaryInfo = parse_binary(file_path)
        findings: List[CryptoFindingData] = []
        seen_keys: Set[str] = set()

        # 1. Match Exact Symbol Signatures
        for sym in parsed.symbols:
            if sym in SYMBOL_SIGNATURES:
                sig = SYMBOL_SIGNATURES[sym]
                key = f"{sig.library}:{sig.algorithm}:{sig.usage}:{sym}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(
                        CryptoFindingData(
                            name=f"{sig.name} ({sym})",
                            asset_type="binary_usage",
                            source_type="binary",
                            algorithm=sig.algorithm,
                            algorithm_family=sig.algorithm_family,
                            primitive=sig.primitive,
                            usage=sig.usage,
                            library=sig.library,
                            file_path=str(file_path),
                            source_location=f"{file_path.name}:{sym}",
                            repository=repository,
                            confidence=sig.min_confidence,
                            pqc_status=sig.pqc_status,
                            quantum_status=sig.quantum_status,
                            risk_score=sig.base_risk_score,
                            risk_level=sig.risk_level,
                            evidence={
                                "symbol": sym,
                                "binary_format": parsed.format,
                                "architecture": parsed.architecture,
                                "match_type": "exact_symbol",
                            },
                            vulnerabilities=list(sig.vulnerabilities),
                            recommendations=list(sig.recommendations),
                        )
                    )

        # 2. Match Symbol Prefix Rules
        for sym in parsed.symbols:
            for prefix, name_prefix, algo, family, primitive, pqc, q_status, score, level in SYMBOL_PREFIX_RULES:
                if sym.startswith(prefix):
                    key = f"{algo}:{sym}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        vulns = []
                        recs = []
                        if pqc == "VULNERABLE":
                            vulns = [f"Cryptographic function {sym} is vulnerable to quantum cryptanalysis."]
                            recs = ["Migrate to NIST PQC standardized algorithms (ML-KEM / ML-DSA)."]
                        elif pqc == "QUANTUM_SAFE":
                            recs = ["Quantum safe algorithm. Continue standard cryptographic maintenance."]

                        findings.append(
                            CryptoFindingData(
                                name=f"{name_prefix} ({sym})",
                                asset_type="binary_usage",
                                source_type="binary",
                                algorithm=algo,
                                algorithm_family=family,
                                primitive=primitive,
                                usage="cryptographic_operation",
                                library=name_prefix.split()[0],
                                file_path=str(file_path),
                                source_location=f"{file_path.name}:{sym}",
                                repository=repository,
                                confidence=0.88,
                                pqc_status=pqc,
                                quantum_status=q_status,
                                risk_score=score,
                                risk_level=level,
                                evidence={
                                    "symbol": sym,
                                    "binary_format": parsed.format,
                                    "architecture": parsed.architecture,
                                    "match_type": "symbol_prefix",
                                },
                                vulnerabilities=vulns,
                                recommendations=recs,
                            )
                        )
                    break

        # 3. Match Imported Shared Libraries
        for lib in parsed.imported_libraries:
            lib_lower = lib.lower()
            if "liboqs" in lib_lower:
                key = f"lib:{lib}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(
                        CryptoFindingData(
                            name=f"liboqs Shared Library ({lib})",
                            asset_type="library",
                            source_type="binary",
                            algorithm="Post-Quantum Cryptography",
                            algorithm_family="PQC Library",
                            primitive="pqc",
                            usage="pqc_library",
                            library="liboqs",
                            file_path=str(file_path),
                            source_location=f"{file_path.name}->{lib}",
                            repository=repository,
                            confidence=0.95,
                            pqc_status="QUANTUM_SAFE",
                            quantum_status="safe",
                            risk_score=0.0,
                            risk_level="INFO",
                            evidence={"imported_library": lib, "binary_format": parsed.format},
                            recommendations=["Application dynamically links Open Quantum Safe library (liboqs)."],
                        )
                    )
            elif "crypto" in lib_lower or "ssl" in lib_lower:
                key = f"lib:{lib}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    is_openssl3 = "3" in lib_lower
                    findings.append(
                        CryptoFindingData(
                            name=f"Cryptographic Shared Library ({lib})",
                            asset_type="library",
                            source_type="binary",
                            algorithm="TLS/Crypto Suite",
                            algorithm_family="Cryptographic Library",
                            primitive="library",
                            usage="general_crypto",
                            library="OpenSSL" if "ssl" in lib_lower or "crypto" in lib_lower else lib,
                            file_path=str(file_path),
                            source_location=f"{file_path.name}->{lib}",
                            repository=repository,
                            confidence=0.90,
                            pqc_status="HYBRID_READY" if is_openssl3 else "VULNERABLE",
                            quantum_status="reduced_security_margin" if is_openssl3 else "vulnerable",
                            risk_score=40.0 if is_openssl3 else 75.0,
                            risk_level="MEDIUM" if is_openssl3 else "HIGH",
                            evidence={"imported_library": lib, "binary_format": parsed.format},
                            vulnerabilities=[] if is_openssl3 else ["Legacy crypto library linking classical RSA/ECC primitives."],
                            recommendations=["Ensure OpenSSL 3.x with oqs-provider is used for quantum resistance."],
                        )
                    )

        # 4. Match Embedded Strings and Algorithm Identifiers
        for string_item in parsed.strings:
            for pattern, name, library, primitive in STRING_PATTERNS:
                match = re.search(pattern, string_item, re.IGNORECASE)
                if match:
                    matched_text = match.group(0)
                    key = f"str:{matched_text.lower()}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        pqc_status = "QUANTUM_SAFE" if primitive == "pqc" else ("VULNERABLE" if primitive == "asymmetric" else "UNKNOWN")
                        q_status = "safe" if primitive == "pqc" else ("vulnerable" if primitive == "asymmetric" else "unknown")
                        score = 0.0 if primitive == "pqc" else (75.0 if primitive == "asymmetric" else 30.0)
                        level = "INFO" if primitive == "pqc" else ("HIGH" if primitive == "asymmetric" else "LOW")

                        findings.append(
                            CryptoFindingData(
                                name=f"{name} ({matched_text})",
                                asset_type="binary_usage",
                                source_type="binary",
                                algorithm=matched_text,
                                algorithm_family=library,
                                primitive=primitive,
                                usage="embedded_identifier",
                                library=library,
                                file_path=str(file_path),
                                source_location=f"{file_path.name}:{matched_text}",
                                repository=repository,
                                confidence=0.82,
                                pqc_status=pqc_status,
                                quantum_status=q_status,
                                risk_score=score,
                                risk_level=level,
                                evidence={
                                    "matched_string": matched_text,
                                    "binary_format": parsed.format,
                                    "match_type": "embedded_string",
                                },
                                recommendations=[f"Verified embedded cryptographic identifier: {matched_text}."],
                            )
                        )

        return findings
