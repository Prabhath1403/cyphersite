"""
Coverage & Confidence Reporter — tracks scan coverage, language support,
and finding confidence metrics.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from app.core.source_scanner import ScanResult, CryptoFindingData

logger = logging.getLogger(__name__)

# File extension mappings to programming languages
LANGUAGE_EXTENSIONS: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".kt": "kotlin",
    ".swift": "swift",
}

# Currently supported languages by source scanners
SUPPORTED_LANGUAGES = {"python"}

SKIP_DIRS = {
    "__pycache__", ".git", ".hg", ".svn", "node_modules",
    ".tox", ".venv", "venv", "env", ".env", ".eggs",
    "dist", "build", ".mypy_cache", ".pytest_cache",
}


@dataclass
class ConfidenceMetrics:
    """Confidence distribution metrics across findings."""
    average_confidence: float = 1.0
    high_count: int = 0      # confidence >= 0.8
    medium_count: int = 0    # 0.5 <= confidence < 0.8
    low_count: int = 0       # confidence < 0.5


@dataclass
class LanguageStats:
    """Language discovery and support statistics."""
    language: str
    files_count: int
    supported: bool
    scanner: Optional[str] = None


@dataclass
class CoverageReport:
    """Comprehensive coverage and confidence report for a scan."""
    scan_id: Optional[str] = None
    target: str = ""
    scan_type: str = "source"
    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    coverage_pct: float = 100.0
    coverage_tier: str = "FULL"  # FULL (100%), HIGH (>=80%), PARTIAL (>=50%), LOW (<50%)
    languages: List[Dict[str, Any]] = field(default_factory=list)
    confidence: Dict[str, Any] = field(default_factory=dict)
    primitive_breakdown: Dict[str, int] = field(default_factory=dict)
    library_breakdown: Dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def analyze_directory_languages(path: Union[str, Path]) -> Dict[str, int]:
    """
    Inspect a directory and count files by programming language.

    Args:
        path: Root directory or file path.

    Returns:
        Dict mapping language name to file count.
    """
    p = Path(path)
    if not p.exists():
        return {}

    if p.is_file():
        lang = LANGUAGE_EXTENSIONS.get(p.suffix.lower())
        return {lang: 1} if lang else {"unknown": 1}

    counts: Dict[str, int] = {}
    try:
        for entry in p.rglob("*"):
            if not entry.is_file():
                continue
            # Skip excluded paths
            if any(part in SKIP_DIRS for part in entry.parts):
                continue
            ext = entry.suffix.lower()
            lang = LANGUAGE_EXTENSIONS.get(ext)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    except Exception as exc:
        logger.warning("Error inspecting languages in %s: %exc", p, exc)

    return counts


def build_coverage_report(
    scan_id: Optional[str],
    target: str,
    scan_type: str = "source",
    findings: Optional[List[Any]] = None,
    scan_result: Optional[ScanResult] = None,
    target_path: Optional[str] = None,
) -> CoverageReport:
    """
    Build a comprehensive coverage report from scan findings or ScanResult.

    Args:
        scan_id: UUID string of the scan job.
        target: Target identifier or path.
        scan_type: "source", "network", etc.
        findings: List of CryptoAsset or CryptoFindingData or dicts.
        scan_result: Optional ScanResult from source scanner.
        target_path: Optional filesystem path for file language analysis.

    Returns:
        CoverageReport instance.
    """
    findings = findings or []
    if scan_result and not findings:
        findings = scan_result.findings

    files_scanned = scan_result.files_scanned if scan_result else 0
    files_skipped = scan_result.files_skipped if scan_result else 0
    errors = list(scan_result.errors) if scan_result else []
    warnings = list(scan_result.warnings) if scan_result else []

    # File and language analysis if path is provided
    inspect_path = target_path or target
    lang_counts = {}
    try:
        inspect_p = Path(inspect_path)
        if inspect_p.exists():
            lang_counts = analyze_directory_languages(inspect_p)
    except Exception:
        pass

    total_code_files = sum(lang_counts.values()) if lang_counts else (files_scanned + files_skipped)
    files_discovered = max(total_code_files, files_scanned + files_skipped, 1 if files_scanned > 0 else 0)

    if files_scanned == 0 and findings:
        # Infer scanned file count from unique file paths in findings
        unique_files = set()
        for f in findings:
            fp = f.file_path if hasattr(f, "file_path") else (f.get("file_path") if isinstance(f, dict) else None)
            if fp:
                unique_files.add(fp)
        files_scanned = max(len(unique_files), 1)

    # Coverage percentage
    if files_discovered > 0:
        coverage_pct = round((files_scanned / files_discovered) * 100.0, 1)
    else:
        coverage_pct = 100.0 if files_scanned > 0 else 0.0

    if coverage_pct >= 100.0:
        tier = "FULL"
    elif coverage_pct >= 80.0:
        tier = "HIGH"
    elif coverage_pct >= 50.0:
        tier = "PARTIAL"
    else:
        tier = "LOW"

    # Language stats list
    languages_list: List[Dict[str, Any]] = []
    if lang_counts:
        for lang, count in sorted(lang_counts.items(), key=lambda x: -x[1]):
            is_supported = lang in SUPPORTED_LANGUAGES
            languages_list.append({
                "language": lang,
                "files_count": count,
                "supported": is_supported,
                "scanner": "Python Source Scanner" if lang == "python" else None,
            })
    elif scan_result and scan_result.languages_detected:
        for lang in scan_result.languages_detected:
            languages_list.append({
                "language": lang,
                "files_count": files_scanned,
                "supported": lang in SUPPORTED_LANGUAGES,
                "scanner": "Python Source Scanner" if lang == "python" else None,
            })

    # Confidence metrics
    confidences: List[float] = []
    primitive_breakdown: Dict[str, int] = {}
    library_breakdown: Dict[str, int] = {}

    for item in findings:
        conf = 1.0
        prim = None
        lib = None

        if isinstance(item, dict):
            conf = float(item.get("confidence") or 1.0)
            prim = item.get("primitive")
            lib = item.get("library")
        elif hasattr(item, "confidence"):
            conf = float(item.confidence if item.confidence is not None else 1.0)
            prim = getattr(item, "primitive", None)
            lib = getattr(item, "library", None)

        confidences.append(conf)

        if prim:
            primitive_breakdown[prim] = primitive_breakdown.get(prim, 0) + 1
        if lib:
            library_breakdown[lib] = library_breakdown.get(lib, 0) + 1

    high_c = sum(1 for c in confidences if c >= 0.8)
    med_c = sum(1 for c in confidences if 0.5 <= c < 0.8)
    low_c = sum(1 for c in confidences if c < 0.5)
    avg_c = round(sum(confidences) / max(len(confidences), 1), 3) if confidences else 1.0

    confidence_dict = {
        "average_confidence": avg_c,
        "high_count": high_c,
        "medium_count": med_c,
        "low_count": low_c,
    }

    return CoverageReport(
        scan_id=str(scan_id) if scan_id else None,
        target=target,
        scan_type=scan_type,
        files_discovered=files_discovered,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        coverage_pct=coverage_pct,
        coverage_tier=tier,
        languages=languages_list,
        confidence=confidence_dict,
        primitive_breakdown=primitive_breakdown,
        library_breakdown=library_breakdown,
        total_findings=len(findings),
        errors=errors,
        warnings=warnings,
    )
