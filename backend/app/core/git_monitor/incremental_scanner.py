"""
Incremental Single-File Scanner.
Executes sub-second AST cryptographic analysis on single modified files.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import List, Optional

from app.core.source_scanner import CryptoFindingData
from app.core.source_scanner.python_scanner import (
    ImportTracker,
    CryptoCallVisitor,
)

logger = logging.getLogger(__name__)


class IncrementalScanner:
    """Performs lightning-fast AST cryptographic inspection on a single file."""

    @classmethod
    def scan_source_code(
        cls,
        code: str,
        file_path: str,
        repository: Optional[str] = None,
    ) -> List[CryptoFindingData]:
        """Scan a Python source code string for cryptographic APIs."""
        if not code or not code.strip():
            return []

        source_lines = code.splitlines()
        try:
            tree = ast.parse(code, filename=file_path)
        except SyntaxError as e:
            logger.warning("Syntax error in %s: %s", file_path, e)
            return []
        except Exception as e:
            logger.error("Failed to parse AST for %s: %s", file_path, e)
            return []

        # Pass 1: collect imports
        tracker = ImportTracker()
        tracker.visit(tree)

        # Pass 2: find crypto calls
        visitor = CryptoCallVisitor(
            imports=tracker.imports,
            from_imports=tracker.from_imports,
            source_lines=source_lines,
            file_path=file_path,
            repository=repository,
        )
        visitor.visit(tree)

        return visitor.findings

    @classmethod
    def scan_single_file(
        cls,
        file_path: str | Path,
        repository: Optional[str] = None,
    ) -> List[CryptoFindingData]:
        """Scan a local file from disk."""
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            logger.warning("File does not exist: %s", file_path)
            return []
        try:
            code = p.read_text(encoding="utf-8", errors="replace")
            return cls.scan_source_code(code, str(p), repository=repository)
        except Exception as e:
            logger.error("Error reading file %s: %s", file_path, e)
            return []
