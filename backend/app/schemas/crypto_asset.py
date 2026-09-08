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

    # Library properties
    library: Optional[str] = Field(default=None, max_length=200)
    library_version: Optional[str] = Field(default=None, max_length=100)

    # Source-code provenance
    source_location: Optional[str] = Field(default=None, max_length=500)
    file_path: Optional[str] = Field(default=None, max_length=500)
    line_number: Optional[int] = Field(default=None, ge=0)
    function_name: Optional[str] = Field(default=None, max_length=200)
    language: Optional[str] = Field(default=None, max_length=50)

    # Network information
    hostname: Optional[str] = Field(default=None, max_length=500)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    port: Optional[int] = Field(default=None, ge=1, le=65535)

    # Security
    pqc_status: Optional[str] = Field(default=None, max_length=20)
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    vulnerabilities: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None

    # Business-risk (future use)
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

    library: Optional[str] = Field(default=None, max_length=200)
    library_version: Optional[str] = Field(default=None, max_length=100)

    source_location: Optional[str] = Field(default=None, max_length=500)
    file_path: Optional[str] = Field(default=None, max_length=500)
    line_number: Optional[int] = Field(default=None, ge=0)
    function_name: Optional[str] = Field(default=None, max_length=200)
    language: Optional[str] = Field(default=None, max_length=50)

    hostname: Optional[str] = Field(default=None, max_length=500)
    ip_address: Optional[str] = Field(default=None, max_length=45)
    port: Optional[int] = Field(default=None, ge=1, le=65535)

    pqc_status: Optional[str] = Field(default=None, max_length=20)
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    vulnerabilities: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None

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

    library: Optional[str] = None
    library_version: Optional[str] = None

    source_location: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    language: Optional[str] = None

    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None

    pqc_status: Optional[str] = None
    risk_score: Optional[float] = None
    vulnerabilities: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None

    business_criticality: Optional[str] = None
    data_sensitivity: Optional[str] = None
    data_lifetime_years: Optional[int] = None
    migration_time_months: Optional[int] = None

    details: Optional[Any] = None
    created_at: datetime

    class Config:
        from_attributes = True


class CryptoAssetListResponse(BaseModel):
    """Paginated list response for CryptoAssets."""
    assets: List[CryptoAssetResponse]
    total: int
