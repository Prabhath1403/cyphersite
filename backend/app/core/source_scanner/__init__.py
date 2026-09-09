"""Base scanner interface for all cryptographic discovery scanners.

All scanners (source code, network, container, binary) must implement
this interface so the platform can orchestrate them uniformly.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class ScanTarget:
    """Describes a target to scan.

    The meaning of ``path`` depends on the scanner type:
    - Source scanner: local directory or Git URL
    - Network scanner: hostname / IP / CIDR
    - Container scanner: image reference
    - Binary scanner: file path
    """
    path: str
    scan_type: str  # "source" | "network" | "container" | "binary"
    language: Optional[str] = None    # hint for source scanners
    depth: str = "standard"           # "quick" | "standard" | "deep"
    repository: Optional[str] = None  # repo identifier / URL


@dataclass
class CryptoFindingData:
    """Intermediate finding produced by scanners before ORM persistence.

    Scanners return a list of these; the pipeline converts them into
    ``CryptoAsset`` ORM instances for database persistence.
    """
    # ── Identity ──────────────────────────────────────────────────────────
    name: str
    asset_type: str         # matches CRYPTO_ASSET_TYPES
    source_type: str        # matches CRYPTO_SOURCE_TYPES

    # ── Cryptographic properties ──────────────────────────────────────────
    algorithm: Optional[str] = None
    algorithm_family: Optional[str] = None
    key_size: Optional[int] = None
    key_type: Optional[str] = None
    hash_algorithm: Optional[str] = None
    key_exchange: Optional[str] = None
    cipher_suite: Optional[str] = None
    protocol: Optional[str] = None
    primitive: Optional[str] = None      # symmetric | asymmetric | hash | ...
    mode: Optional[str] = None           # GCM | CBC | CTR | ...
    padding: Optional[str] = None        # PKCS7 | OAEP | ...
    usage: Optional[str] = None          # encryption | signing | ...

    # ── Library ───────────────────────────────────────────────────────────
    library: Optional[str] = None
    library_version: Optional[str] = None
    version: Optional[str] = None

    # ── Provenance ────────────────────────────────────────────────────────
    repository: Optional[str] = None
    source_location: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    language: Optional[str] = None

    # ── Network ───────────────────────────────────────────────────────────
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None

    # ── Detection quality ─────────────────────────────────────────────────
    confidence: float = 1.0
    evidence: Optional[dict] = None    # code snippet, matched pattern, etc.

    # ── Extra ─────────────────────────────────────────────────────────────
    details: Optional[dict] = None

    def to_orm_kwargs(self) -> dict:
        """Return a dict suitable for ``CryptoAsset(**kwargs)``."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class ScanResult:
    """Aggregate result of a scanner run."""
    findings: List[CryptoFindingData] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    languages_detected: List[str] = field(default_factory=list)
    scanner_name: str = ""
    scanner_version: str = "0.1.0"

    @property
    def total_findings(self) -> int:
        return len(self.findings)


class BaseScanner(ABC):
    """Abstract base class for all cryptographic discovery scanners.

    Subclasses must implement ``scan()`` which takes a ``ScanTarget``
    and returns a ``ScanResult`` containing zero or more ``CryptoFindingData``.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scanner name (e.g. 'Python Source Scanner')."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Scanner version string."""
        ...

    @property
    @abstractmethod
    def supported_types(self) -> List[str]:
        """List of scan_type values this scanner handles."""
        ...

    @abstractmethod
    def scan(self, target: ScanTarget) -> ScanResult:
        """Execute a scan on the given target.

        Args:
            target: Describes what to scan.

        Returns:
            ScanResult with all discovered cryptographic findings.
        """
        ...

    def can_handle(self, target: ScanTarget) -> bool:
        """Check if this scanner can handle the given target."""
        return target.scan_type in self.supported_types
