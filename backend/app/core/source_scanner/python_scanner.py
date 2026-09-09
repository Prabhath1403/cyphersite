"""Python source-code scanner — AST-based cryptographic API detection.

Walks Python source files using the ``ast`` module, tracks imports,
and matches function / constructor calls against the detection rules
defined in ``rules/python_rules.py``.

Design:
  - Deterministic: no ML, no heuristics beyond what the rules encode.
  - Evidence-rich: captures the exact code line, import chain, and
    function context for every finding.
  - Confidence-scored: each rule carries a confidence value (0.0–1.0).

Usage::

    scanner = PythonScanner()
    result = scanner.scan(ScanTarget(path="/path/to/repo", scan_type="source"))
"""

from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from app.core.source_scanner import (
    BaseScanner,
    CryptoFindingData,
    ScanResult,
    ScanTarget,
)
from app.core.source_scanner.rules.python_rules import (
    ALL_RULES,
    CryptoRule,
    RULE_INDEX,
)

logger = logging.getLogger(__name__)

# Maximum file size to parse (5 MB) — skip huge generated files
MAX_FILE_SIZE = 5 * 1024 * 1024

# Directories to skip during file discovery
SKIP_DIRS = {
    "__pycache__", ".git", ".hg", ".svn", "node_modules",
    ".tox", ".venv", "venv", "env", ".env", ".eggs",
    "dist", "build", "*.egg-info", ".mypy_cache", ".pytest_cache",
}


class ImportTracker(ast.NodeVisitor):
    """First pass: collect all imports in a file.

    Builds a mapping from local names to fully-qualified module paths
    so we can resolve call targets in the second pass.

    Examples::

        import hashlib                → {"hashlib": "hashlib"}
        from hashlib import sha256    → {"sha256": "hashlib.sha256"}
        from cryptography.hazmat.primitives.ciphers import algorithms
            → {"algorithms": "cryptography.hazmat.primitives.ciphers.algorithms"}
        from cryptography.hazmat.primitives.ciphers.algorithms import AES
            → {"AES": "cryptography.hazmat.primitives.ciphers.algorithms.AES"}
    """

    def __init__(self) -> None:
        self.imports: Dict[str, str] = {}     # local_name → full_module_path
        self.from_imports: Dict[str, str] = {}  # local_name → module.qualname

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name
            self.imports[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            if module:
                self.from_imports[local] = f"{module}.{alias.name}"
            else:
                self.from_imports[local] = alias.name
        self.generic_visit(node)


class CryptoCallVisitor(ast.NodeVisitor):
    """Second pass: find crypto API calls and match them against rules."""

    def __init__(
        self,
        imports: Dict[str, str],
        from_imports: Dict[str, str],
        source_lines: List[str],
        file_path: str,
        repository: Optional[str],
    ) -> None:
        self.imports = imports
        self.from_imports = from_imports
        self.source_lines = source_lines
        self.file_path = file_path
        self.repository = repository
        self.findings: List[CryptoFindingData] = []
        self._current_function: Optional[str] = None
        self._current_class: Optional[str] = None

        # Build a fast lookup: resolved_qualname → rule
        self._rule_lookup: Dict[str, CryptoRule] = {}
        for rule in ALL_RULES:
            key = f"{rule.module}.{rule.qualname}"
            self._rule_lookup[key] = rule
            # Also allow matching just module.qualname for from-imports
            self._rule_lookup[rule.qualname] = rule

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old_func = self._current_function
        self._current_function = node.name
        self.generic_visit(node)
        self._current_function = old_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        old_func = self._current_function
        self._current_function = node.name
        self.generic_visit(node)
        self._current_function = old_func

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class

    def visit_Call(self, node: ast.Call) -> None:
        """Match a function call against crypto detection rules."""
        resolved = self._resolve_call(node)
        if resolved:
            rule = self._match_rule(resolved)
            if rule:
                self._record_finding(node, rule, resolved)

        self.generic_visit(node)

    def _resolve_call(self, node: ast.Call) -> Optional[str]:
        """Resolve a Call node to a fully-qualified name using import data."""
        func = node.func

        if isinstance(func, ast.Name):
            # Direct call: e.g. sha256(...)  or  AES(...)
            name = func.id
            if name in self.from_imports:
                return self.from_imports[name]
            if name in self.imports:
                return self.imports[name]
            return None

        if isinstance(func, ast.Attribute):
            # Attribute call: e.g. hashlib.sha256(...) or algorithms.AES(...)
            parts = self._unpack_attribute(func)
            if not parts:
                return None

            root = parts[0]
            rest = ".".join(parts[1:])

            # Case 1: `import hashlib` → hashlib.sha256
            if root in self.imports:
                return f"{self.imports[root]}.{rest}"

            # Case 2: `from ... import algorithms` → algorithms.AES
            if root in self.from_imports:
                return f"{self.from_imports[root]}.{rest}"

            return None

        return None

    def _unpack_attribute(self, node: ast.Attribute) -> Optional[List[str]]:
        """Unpack chained attribute access into a list of names."""
        parts: List[str] = [node.attr]
        current = node.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            parts.reverse()
            return parts
        return None

    def _match_rule(self, resolved: str) -> Optional[CryptoRule]:
        """Try to find a matching rule for the resolved call name."""
        # Exact match: "cryptography.hazmat.primitives.ciphers.algorithms.AES"
        if resolved in self._rule_lookup:
            return self._rule_lookup[resolved]

        # Try matching module + qualname combinations
        # e.g. resolved = "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key"
        for rule in ALL_RULES:
            full_key = f"{rule.module}.{rule.qualname}"
            if resolved == full_key:
                return rule
            # Handle class method patterns: e.g. Ed25519PrivateKey.generate
            if "." in rule.qualname:
                cls_name, method = rule.qualname.rsplit(".", 1)
                if resolved.endswith(f".{cls_name}.{method}"):
                    return rule

        return None

    def _record_finding(
        self, node: ast.Call, rule: CryptoRule, resolved: str
    ) -> None:
        """Create a CryptoFindingData from a matched call node."""
        line_no = node.lineno
        code_line = ""
        if 0 < line_no <= len(self.source_lines):
            code_line = self.source_lines[line_no - 1].rstrip()

        # Try to extract key_size from arguments (e.g. rsa.generate_private_key(65537, 2048))
        key_size = rule.key_size
        if key_size is None:
            key_size = self._extract_key_size(node, rule)

        func_context = self._current_function
        if self._current_class and self._current_function:
            func_context = f"{self._current_class}.{self._current_function}"
        elif self._current_class:
            func_context = self._current_class

        finding = CryptoFindingData(
            name=rule.algorithm,
            asset_type="source_code_usage",
            source_type="source_code",
            algorithm=rule.algorithm,
            algorithm_family=rule.family or None,
            key_size=key_size,
            primitive=rule.primitive,
            mode=rule.mode,
            padding=rule.padding,
            usage=rule.usage,
            library=rule.library or None,
            file_path=self.file_path,
            line_number=line_no,
            function_name=func_context,
            language="python",
            repository=self.repository,
            confidence=rule.confidence,
            evidence={
                "type": "ast_match",
                "resolved_call": resolved,
                "rule_module": rule.module,
                "rule_qualname": rule.qualname,
                "code_line": code_line,
                "line_number": line_no,
            },
            details={
                "quantum_status": rule.quantum,
                "notes": rule.notes or None,
            },
        )
        self.findings.append(finding)

    def _extract_key_size(
        self, node: ast.Call, rule: CryptoRule
    ) -> Optional[int]:
        """Attempt to extract key size from call arguments."""
        # RSA: generate_private_key(public_exponent=65537, key_size=2048)
        if rule.family == "RSA" and "generate" in rule.qualname:
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, int):
                        return kw.value.value
            # Positional: second argument
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                if isinstance(node.args[1].value, int):
                    return node.args[1].value

        # AES: algorithms.AES(key)  → key_size = len(key) * 8, not always determinable
        # For AES, we rely on the byte length of the key which isn't always a literal

        # DSA/DH: generate_private_key(key_size=...)
        if rule.family in ("DSA", "DH"):
            for kw in node.keywords:
                if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                    if isinstance(kw.value.value, int):
                        return kw.value.value
            if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant):
                if isinstance(node.args[0].value, int) and node.args[0].value > 100:
                    return node.args[0].value

        return None


class PythonScanner(BaseScanner):
    """AST-based Python source-code scanner for cryptographic API detection."""

    @property
    def name(self) -> str:
        return "Python Source Scanner"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def supported_types(self) -> List[str]:
        return ["source"]

    def scan(self, target: ScanTarget) -> ScanResult:
        """Scan a directory of Python files for crypto API usage.

        Args:
            target: ScanTarget with path pointing to a directory.

        Returns:
            ScanResult with all crypto findings.
        """
        result = ScanResult(
            scanner_name=self.name,
            scanner_version=self.version,
            languages_detected=["python"],
        )

        root_path = Path(target.path)
        if not root_path.exists():
            result.errors.append(f"Target path does not exist: {target.path}")
            return result

        if root_path.is_file():
            py_files = [root_path] if root_path.suffix == ".py" else []
        else:
            py_files = self._discover_python_files(root_path)

        logger.info(
            "Python scanner: found %d .py files in %s",
            len(py_files), target.path,
        )

        for py_file in py_files:
            try:
                findings = self._scan_file(
                    py_file, repository=target.repository
                )
                result.findings.extend(findings)
                result.files_scanned += 1
            except Exception as e:
                result.files_skipped += 1
                result.errors.append(f"{py_file}: {e}")
                logger.warning("Failed to scan %s: %s", py_file, e)

        logger.info(
            "Python scanner complete: %d files scanned, %d skipped, %d findings",
            result.files_scanned,
            result.files_skipped,
            result.total_findings,
        )
        return result

    def _discover_python_files(self, root: Path) -> List[Path]:
        """Recursively discover .py files, skipping excluded directories."""
        py_files: List[Path] = []

        for dirpath, dirnames, filenames in os.walk(root):
            # Prune excluded directories in-place
            dirnames[:] = [
                d for d in dirnames
                if d not in SKIP_DIRS and not d.endswith(".egg-info")
            ]

            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fpath = Path(dirpath) / fname
                try:
                    if fpath.stat().st_size > MAX_FILE_SIZE:
                        logger.debug("Skipping large file: %s", fpath)
                        continue
                except OSError:
                    continue
                py_files.append(fpath)

        return sorted(py_files)

    def _scan_file(
        self, file_path: Path, repository: Optional[str] = None
    ) -> List[CryptoFindingData]:
        """Parse and scan a single Python file.

        Args:
            file_path: Path to the .py file.
            repository: Optional repo identifier.

        Returns:
            List of crypto findings from this file.
        """
        source = file_path.read_text(encoding="utf-8", errors="replace")
        source_lines = source.splitlines()

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as e:
            logger.debug("Syntax error in %s: %s", file_path, e)
            raise

        # Pass 1: collect imports
        tracker = ImportTracker()
        tracker.visit(tree)

        # Pass 2: find crypto calls
        visitor = CryptoCallVisitor(
            imports=tracker.imports,
            from_imports=tracker.from_imports,
            source_lines=source_lines,
            file_path=str(file_path),
            repository=repository,
        )
        visitor.visit(tree)

        return visitor.findings
