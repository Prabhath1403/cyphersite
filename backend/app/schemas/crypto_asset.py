"""Pydantic schemas for CryptoAsset data."""

from datetime import datetime
from typing import Optional, List, Any
from uuid import UUID
from enum import Enum

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enum types for API validation
# ---------------------------------------------------------------------------

class CryptoAssetType(str, Enum):
    """Types of cryptographic assets that can be discovered."""
    ALGORITHM = "algorithm"
    KEY = "key"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    LIBRARY = "library"
    DEPENDENCY = "dependency"
    HSM = "hsm"
    CLOUD_SERVICE = "cloud_service"
    SOURCE_CODE_USAGE = "source_code_usage"
    BINARY_USAGE = "binary_usage"
    CONTAINER_USAGE = "container_usage"
    NETWORK_ENDPOINT = "network_endpoint"


class CryptoSourceType(str, Enum):
    """Source/provenance of the cryptographic discovery."""
    NETWORK = "network"
    SOURCE_CODE = "source_code"
    BINARY = "binary"
    CONTAINER = "container"
    DEPENDENCY = "dependency"
    MANUAL = "manual"


class CryptoPrimitive(str, Enum):
    """Cryptographic primitive classification."""
    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    PROTOCOL = "protocol"
    SIGNATURE = "signature"
    RNG = "rng"


class CryptoUsage(str, Enum):
    """How the cryptographic asset is being used."""
    ENCRYPTION = "encryption"
    SIGNING = "signing"
    KEY_EXCHANGE = "key_exchange"
    HASHING = "hashing"
    AUTHENTICATION = "authentication"
    TLS = "tls"
    JWT = "jwt"
    KEY_DERIVATION = "key_derivation"
    RANDOM = "random"
    CERTIFICATE = "certificate"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk severity level."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class QuantumStatus(str, Enum):
    """Direct quantum vulnerability classification."""
    VULNERABLE = "vulnerable"
    REDUCED_SECURITY_MARGIN = "reduced_security_margin"
    SAFE = "safe"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class CryptoAssetCreate(BaseModel):
    """Schema for creating a new CryptoAsset."""
    scan_id: UUID
    asset_type: CryptoAssetType
    source_type: CryptoSourceType
    name: str = Field(..., min_length=1, max_length=500)
    version: Optional[str] = Field(default=None, max_length=100)

    # Cryptographic properties
    algorithm: Optional[str] = Field(default=None, max_length=100)
    algorithm_family: Optional[str] = Field(default=None, max_length=50)
    key_size: Optional[int] = Field(default=None, ge=0)
    key_type: Optional[str] = Field(default=None, max_length=50)
    hash_algorithm: Optional[str] = Field(default=None, max_length=50)
    key_exchange: Optional[str] = Field(default=None, max_length=100)
    cipher_suite: Optional[str] = Field(default=None, max_length=200)
    protocol: Optional[str] = Field(default=None, max_length=50)

    # Extended crypto properties
    primitive: Optional[str] = Field(default=None, max_length=30)
    mode: Optional[str] = Field(default=None, max_length=30)
    padding: Optional[str] = Field(default=None, max_length=30)
    usage: Optional[str] = Field(default=None, max_length=50)

    # Library properties
    library: Optional[str] = Field(default=None, max_length=200)
    library_version: Optional[str] = Field(default=None, max_length=100)

    # Source-code provenance
    repository: Optional[str] = Field(default=None, max_length=500)
    source_location: Optional[str] = Field(default=None, max_length=500)
    file_path: Optional[str] = Field(default=None, max_length=500)
    line_number: Optional[int] = Field(default=None, ge=0)
    function_name: Optional[str] = Field(default=None, max_length=200)
    language: Optional[str] = Field(default=None, max_length=50)

    # Network information
    hostname: Optional[str] = Field(default=None, max_length=500)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    port: Optional[int] = Field(default=None, ge=1, le=65535)

    # Detection confidence
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    evidence: Optional[Any] = None

    # Security
    pqc_status: Optional[str] = Field(default=None, max_length=20)
    quantum_status: Optional[str] = Field(default=None, max_length=30)
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    risk_level: Optional[str] = Field(default=None, max_length=10)
    vulnerabilities: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None

    # Sensitivity inference
    sensitivity: Optional[str] = Field(default=None, max_length=30)
    sensitivity_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    # Business-risk
    business_criticality: Optional[str] = Field(default=None, max_length=20)
    data_sensitivity: Optional[str] = Field(default=None, max_length=20)
    data_lifetime_years: Optional[int] = Field(default=None, ge=0)
    migration_time_months: Optional[int] = Field(default=None, ge=0)

    # Extra data
    details: Optional[Any] = None


class CryptoAssetUpdate(BaseModel):
    """Schema for updating an existing CryptoAsset. All fields optional."""
    asset_type: Optional[CryptoAssetType] = None
    source_type: Optional[CryptoSourceType] = None
    name: Optional[str] = Field(default=None, min_length=1, max_length=500)
    version: Optional[str] = Field(default=None, max_length=100)

    algorithm: Optional[str] = Field(default=None, max_length=100)
    algorithm_family: Optional[str] = Field(default=None, max_length=50)
    key_size: Optional[int] = Field(default=None, ge=0)
    key_type: Optional[str] = Field(default=None, max_length=50)
    hash_algorithm: Optional[str] = Field(default=None, max_length=50)
    key_exchange: Optional[str] = Field(default=None, max_length=100)
    cipher_suite: Optional[str] = Field(default=None, max_length=200)
    protocol: Optional[str] = Field(default=None, max_length=50)

    primitive: Optional[str] = Field(default=None, max_length=30)
    mode: Optional[str] = Field(default=None, max_length=30)
    padding: Optional[str] = Field(default=None, max_length=30)
    usage: Optional[str] = Field(default=None, max_length=50)

    library: Optional[str] = Field(default=None, max_length=200)
    library_version: Optional[str] = Field(default=None, max_length=100)

    repository: Optional[str] = Field(default=None, max_length=500)
    source_location: Optional[str] = Field(default=None, max_length=500)
    file_path: Optional[str] = Field(default=None, max_length=500)
    line_number: Optional[int] = Field(default=None, ge=0)
    function_name: Optional[str] = Field(default=None, max_length=200)
    language: Optional[str] = Field(default=None, max_length=50)

    hostname: Optional[str] = Field(default=None, max_length=500)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    port: Optional[int] = Field(default=None, ge=1, le=65535)

    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    evidence: Optional[Any] = None

    pqc_status: Optional[str] = Field(default=None, max_length=20)
    quantum_status: Optional[str] = Field(default=None, max_length=30)
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    risk_level: Optional[str] = Field(default=None, max_length=10)
    vulnerabilities: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None

    sensitivity: Optional[str] = Field(default=None, max_length=30)
    sensitivity_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    business_criticality: Optional[str] = Field(default=None, max_length=20)
    data_sensitivity: Optional[str] = Field(default=None, max_length=20)
    data_lifetime_years: Optional[int] = Field(default=None, ge=0)
    migration_time_months: Optional[int] = Field(default=None, ge=0)

    details: Optional[Any] = None


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class CryptoAssetResponse(BaseModel):
    """Full response for a single CryptoAsset."""
    id: UUID
    scan_id: UUID
    asset_type: str
    source_type: str
    name: str
    version: Optional[str] = None

    algorithm: Optional[str] = None
    algorithm_family: Optional[str] = None
    key_size: Optional[int] = None
    key_type: Optional[str] = None
    hash_algorithm: Optional[str] = None
    key_exchange: Optional[str] = None
    cipher_suite: Optional[str] = None
    protocol: Optional[str] = None

    primitive: Optional[str] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    usage: Optional[str] = None

    library: Optional[str] = None
    library_version: Optional[str] = None

    repository: Optional[str] = None
    source_location: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    language: Optional[str] = None

    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None

    confidence: Optional[float] = None
    evidence: Optional[Any] = None

    pqc_status: Optional[str] = None
    quantum_status: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    vulnerabilities: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None

    sensitivity: Optional[str] = None
    sensitivity_confidence: Optional[float] = None

    business_criticality: Optional[str] = None
    data_sensitivity: Optional[str] = None
    data_lifetime_years: Optional[int] = None
    migration_time_months: Optional[int] = None

    details: Optional[Any] = None
    created_at: datetime

    class Config:
        from_attributes = True


# Alias for new platform code
CryptoFindingResponse = CryptoAssetResponse


class CryptoAssetListResponse(BaseModel):
    """Paginated list response for CryptoAssets."""
    assets: List[CryptoAssetResponse]
    total: int
