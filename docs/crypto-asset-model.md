# CryptoAsset — Unified Cryptographic Asset Model

## Overview

The `CryptoAsset` model is the canonical representation of any cryptographic
finding discovered by CipherSight scanners. It provides a single, unified
schema that all scanners (current and future) must produce, enabling downstream
consumers to work against one consistent data structure.

> **Every future scanner must convert its cryptographic findings into the
> canonical CryptoAsset representation.**

## Architecture

```
Scanner (network / source-code / binary / container / dependency)
    ↓
CryptoAsset  ← canonical model
    ↓
CBOM Generator / Risk Engine / Mosca Analysis / PQC Recommender / Migration Planner
```

## Why CryptoAsset Exists

Before CryptoAsset, each scanner type had its own bespoke model:

| Scanner | Old Model | Problem |
|---------|-----------|----------|
| Network | `Asset` | Network-specific fields (TLS versions, cipher suites) |
| Source code | — | No model existed |
| Binary | — | No model existed |
| Container | — | No model existed |
| Dependency | — | No model existed |

CryptoAsset solves this by providing a flexible schema with nullable fields
that accommodates all scanner types.

## Supported Asset Types

| Value | Description |
|-------|-------------|
| `algorithm` | A cryptographic algorithm (e.g., RSA, AES, SHA-256) |
| `key` | A cryptographic key |
| `certificate` | A digital certificate |
| `protocol` | A cryptographic protocol (e.g., TLS 1.3) |
| `library` | A cryptographic library (e.g., OpenSSL) |
| `dependency` | A software dependency containing crypto |
| `hsm` | A Hardware Security Module |
| `cloud_service` | A cloud-based cryptographic service (e.g., AWS KMS) |
| `source_code_usage` | Cryptographic usage found in source code |
| `binary_usage` | Cryptographic usage found in a compiled binary |
| `container_usage` | Cryptographic usage found in a container image |
| `network_endpoint` | A network endpoint with cryptographic properties |

## Supported Source Types

| Value | Description |
|-------|-------------|
| `network` | Discovered via network scanning (TLS inspection) |
| `source_code` | Discovered via source code analysis |
| `binary` | Discovered via binary analysis |
| `container` | Discovered via container image scanning |
| `dependency` | Discovered via dependency analysis |
| `manual` | Manually entered by a user |

## Field Reference

### Identity Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | Auto | Primary key |
| `scan_id` | UUID | Yes | Foreign key to the parent scan job |
| `asset_type` | string | Yes | One of the supported asset types |
| `source_type` | string | Yes | One of the supported source types |
| `name` | string | Yes | Human-readable name for the finding |
| `version` | string | No | Version if applicable |

### Cryptographic Properties

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `algorithm` | string | No | Algorithm name (e.g., RSA, AES-256) |
| `algorithm_family` | string | No | Algorithm family (e.g., RSA, ECC) |
| `key_size` | int | No | Key size in bits |
| `key_type` | string | No | Key type (e.g., public, private, symmetric) |
| `hash_algorithm` | string | No | Hash algorithm used |
| `key_exchange` | string | No | Key exchange mechanism |
| `cipher_suite` | string | No | Full cipher suite name |
| `protocol` | string | No | Protocol name (e.g., TLS 1.3) |

### Library Properties

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `library` | string | No | Library name |
| `library_version` | string | No | Library version |

### Source-Code Provenance

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_location` | string | No | General source location |
| `file_path` | string | No | File path where finding was discovered |
| `line_number` | int | No | Line number in the file |
| `function_name` | string | No | Function containing the finding |
| `language` | string | No | Programming language |

### Network Information

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | No | Hostname or domain |
| `ip_address` | string | No | IP address |
| `port` | int | No | Port number |

### Security / PQC Assessment

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pqc_status` | string | No | QUANTUM_SAFE, HYBRID_READY, VULNERABLE, UNKNOWN |
| `risk_score` | float | No | Risk score 0.0–100.0 |
| `vulnerabilities` | JSON | No | List of vulnerability descriptions |
| `recommendations` | JSON | No | List of remediation recommendations |

### Business-Risk Fields (Future Use)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `business_criticality` | string | No | critical, high, medium, low |
| `data_sensitivity` | string | No | top_secret, secret, confidential, public |
| `data_lifetime_years` | int | No | Expected data lifetime in years |
| `migration_time_months` | int | No | Estimated migration time in months |

### Metadata

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `details` | JSON | No | Scanner-specific extra data |
| `created_at` | datetime | Auto | Creation timestamp |

## API Usage

### List Crypto Assets

```http
GET /api/crypto-assets
GET /api/crypto-assets?scan_id={uuid}
GET /api/crypto-assets?asset_type=algorithm
GET /api/crypto-assets?source_type=source_code
GET /api/crypto-assets?pqc_status=VULNERABLE
GET /api/crypto-assets?limit=20&offset=0
```

Response:
```json
{
  "assets": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "scan_id": "...",
      "asset_type": "algorithm",
      "source_type": "source_code",
      "name": "RSA-2048",
      "algorithm": "RSA",
      "key_size": 2048,
      "pqc_status": "VULNERABLE",
      "created_at": "2025-09-08T10:30:00"
    }
  ],
  "total": 1
}
```

### Get Single Crypto Asset

```http
GET /api/crypto-assets/{asset_id}
```

### Create Crypto Asset

```http
POST /api/crypto-assets
Content-Type: application/json

{
  "scan_id": "...",
  "asset_type": "source_code_usage",
  "source_type": "source_code",
  "name": "RSA-2048",
  "algorithm": "RSA",
  "algorithm_family": "RSA",
  "key_size": 2048,
  "file_path": "src/auth.py",
  "line_number": 42,
  "language": "python"
}
```

## Example JSON by Scanner Type

### Source-Code Finding
```json
{
  "asset_type": "source_code_usage",
  "source_type": "source_code",
  "name": "RSA-2048",
  "algorithm": "RSA",
  "algorithm_family": "RSA",
  "key_size": 2048,
  "file_path": "src/auth.py",
  "line_number": 42,
  "language": "python"
}
```

### Network Finding
```json
{
  "asset_type": "network_endpoint",
  "source_type": "network",
  "name": "api.example.com",
  "protocol": "TLS",
  "hostname": "api.example.com",
  "port": 443,
  "key_exchange": "ECDHE"
}
```

### Dependency Finding
```json
{
  "asset_type": "dependency",
  "source_type": "dependency",
  "name": "cryptography",
  "version": "42.0.0",
  "source_location": "requirements.txt"
}
```

### Container Finding
```json
{
  "asset_type": "container_usage",
  "source_type": "container",
  "name": "OpenSSL",
  "version": "3.0.2"
}
```

## How Future Scanners Should Create CryptoAssets

1. Perform the scan to discover cryptographic findings.
2. Map each finding to the appropriate `asset_type` and `source_type`.
3. Populate the relevant fields (leave others as `null`).
4. Create the CryptoAsset via the `POST /api/crypto-assets` endpoint or by
   directly inserting into the database using the SQLAlchemy model.

For existing network scanner results, use the compatibility converter:

```python
from app.core.converter import crypto_asset_from_network_asset

crypto_asset = crypto_asset_from_network_asset(existing_asset)
db.add(crypto_asset)
await db.flush()
```

## Relationship with Existing Asset Model

The existing `Asset` model continues to work for the network scanner.
CryptoAsset is the new canonical model. Over time, all scanners will
produce CryptoAssets directly. The `crypto_asset_from_network_asset()`
converter function bridges the two models during the transition.

```
Existing Asset (network only)
       ↓
crypto_asset_from_network_asset()
       ↓
CryptoAsset (canonical)
```
