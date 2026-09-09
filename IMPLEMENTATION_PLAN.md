# Unified Cryptographic Discovery, CBOM & Post-Quantum Migration Intelligence Platform

## Phase 1: Repository Audit — CipherSight Assessment

---

### 1. Current Directory Structure

```
cyphercite/
├── .env / .env.example           # Environment config
├── docker-compose.yml            # 6 services: db, redis, backend, worker, frontend, nginx
├── README.md
├── docs/
│   └── crypto-asset-model.md     # CryptoAsset architecture doc (well-written)
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt          # 20+ Python deps
│   ├── alembic/ + alembic.ini    # DB migrations (setup exists)
│   ├── pytest.ini
│   ├── tests/
│   │   ├── conftest.py           # Async test fixtures
│   │   └── test_crypto_assets.py # 510 lines, 25+ tests
│   └── app/
│       ├── main.py               # FastAPI entry point
│       ├── config.py             # pydantic-settings based config
│       ├── database.py           # Async SQLAlchemy + PostgreSQL
│       ├── models/               # 5 ORM models
│       ├── schemas/              # Pydantic v2 schemas
│       ├── routers/              # 6 API routers
│       ├── tasks/                # Celery tasks
│       └── core/
│           ├── converter.py      # Asset → CryptoAsset bridge
│           ├── scanner/          # Discovery + TLS + VPN + API probe
│           ├── pqc/              # PQC assessor + NIST rules + classifier
│           ├── cbom/             # CycloneDX builder + CSV/PDF export
│           └── certificate/      # PQC badge + QR generation
├── frontend/
│   ├── Dockerfile
│   ├── package.json              # React 18 + Vite + Tailwind
│   ├── src/
│   │   ├── App.jsx               # React Router setup
│   │   ├── main.jsx              # Entry + QueryClient
│   │   ├── index.css             # Tailwind + glassmorphism theme
│   │   ├── api/client.js         # Axios API client
│   │   ├── hooks/                # useScanSocket, useScanResults
│   │   ├── pages/                # Dashboard, NewScan, ScanDetail, AssetDetail, CBOMReport
│   │   └── components/           # AssetTable, CipherChart, RiskHeatmap, PQCBadge, etc.
└── nginx/
    └── nginx.conf                # Reverse proxy config
```

---

### 2. Frontend Stack

| Aspect | Current |
|--------|---------|
| Framework | React 18 (JSX, not TypeScript) |
| Build Tool | Vite 6 |
| Styling | Tailwind CSS 3.4 + custom glassmorphism |
| State Mgmt | TanStack React Query v5 |
| Routing | React Router v6 |
| HTTP Client | Axios |
| Charting | Recharts |
| Real-time | WebSocket via custom hooks |
| Notifications | react-hot-toast |
| Code Display | react-syntax-highlighter |
| Icons | Lucide-React (per README, not in package.json) |

> [!NOTE]
> Frontend is in **JSX** (not TypeScript). The new platform spec requires **TypeScript**. We should migrate incrementally as we add new pages/components.

---

### 3. Backend Stack

| Aspect | Current |
|--------|---------|
| Framework | FastAPI 0.115 + Pydantic v2 |
| ORM | SQLAlchemy 2.0 (async) |
| Database | PostgreSQL 15 (via asyncpg) |
| Migrations | Alembic (initialized) |
| Task Queue | Celery 5.4 + Redis 7 |
| TLS/Crypto | cryptography 44.0, dnspython, Python ssl |
| Reports | ReportLab (PDF), Pandas (CSV) |
| Auth | python-jose + passlib (JWT, configured but not fully wired) |
| HTTP Client | aiohttp + httpx |
| Badges | qrcode + Pillow |

---

### 4. Existing Database Models

| Model | Table | Fields | Purpose |
|-------|-------|--------|---------|
| [ScanJob](file:///home/prabhath/projects/cyphercite/backend/app/models/scan.py) | `scan_jobs` | id, target, status, scan_depth, created_at, completed_at, total_assets, quantum_safe_count, vulnerable_count, hybrid_count, error_message | Top-level scan job |
| [Asset](file:///home/prabhath/projects/cyphercite/backend/app/models/asset.py) | `assets` | id, scan_id, hostname, ip_address, port, service_type, tls_versions (JSONB), cipher_suites (JSONB), certificate (JSONB), key_exchange, pqc_status, risk_score, vulnerabilities (JSONB), recommendations (JSONB) | Network TLS endpoint |
| [CryptoAsset](file:///home/prabhath/projects/cyphercite/backend/app/models/crypto_asset.py) | `crypto_assets` | 30+ fields covering identity, crypto props, library, source-code provenance, network info, PQC status, business-risk, metadata (JSONB) | **Unified canonical finding** |
| [CBOMRecord](file:///home/prabhath/projects/cyphercite/backend/app/models/cbom.py) | `cbom_records` | id, scan_id, cyclonedx_json (Text) | Stores generated CycloneDX CBOM |
| [PQCCertificate](file:///home/prabhath/projects/cyphercite/backend/app/models/certificate.py) | `pqc_certificates` | id, asset_id, cert_id, status, algorithms_verified, fingerprint, badge paths | PQC readiness badge |

> [!IMPORTANT]
> The **CryptoAsset model already exists** and was explicitly designed as the unified canonical finding representation. Its docstring states: *"Every scanner must convert its findings into CryptoAsset records."* This is **exactly** what the new platform's `CryptoFinding` schema requires. We should **extend** CryptoAsset rather than creating a new model from scratch.

---

### 5. Existing API Endpoints

| Method | Path | Router | Purpose |
|--------|------|--------|---------|
| POST | `/api/scans` | [scans.py](file:///home/prabhath/projects/cyphercite/backend/app/routers/scans.py) | Create scan job → Celery |
| GET | `/api/scans` | scans.py | List scans (paginated) |
| GET | `/api/scans/{id}` | scans.py | Get scan details |
| GET | `/api/scans/dashboard` | scans.py | Dashboard stats |
| GET | `/api/assets` | [assets.py](file:///home/prabhath/projects/cyphercite/backend/app/routers/assets.py) | List network assets |
| GET | `/api/cbom/{scan_id}` | [cbom.py](file:///home/prabhath/projects/cyphercite/backend/app/routers/cbom.py) | Get CBOM (JSON/CSV/PDF) |
| GET/POST | `/api/crypto-assets` | [crypto_assets.py](file:///home/prabhath/projects/cyphercite/backend/app/routers/crypto_assets.py) | CRUD for unified crypto findings |
| GET | `/api/crypto-assets/{id}` | crypto_assets.py | Get single crypto asset |
| GET | `/api/certificates/{id}` | certificates.py | Get PQC certificate |
| WS | `/api/ws/scan/{id}` | [ws.py](file:///home/prabhath/projects/cyphercite/backend/app/routers/ws.py) | Real-time scan progress |
| GET | `/api/health` | main.py | Health check |

---

### 6. Existing Scanner Functionality

| Module | LOC | Reusable? | Notes |
|--------|-----|-----------|-------|
| [discovery.py](file:///home/prabhath/projects/cyphercite/backend/app/core/scanner/discovery.py) | 628 | ✅ **Excellent** | DNS resolution, subdomain enumeration (passive: crt.sh, HackerTarget, CertSpotter, AlienVault + active brute-force), port scanning, CIDR expansion |
| [tls_inspector.py](file:///home/prabhath/projects/cyphercite/backend/app/core/scanner/tls_inspector.py) | 346 | ✅ **Excellent** | Deep TLS fingerprinting, cipher suite parsing (TLS 1.2/1.3 aware), certificate DER parsing via cryptography lib |
| [vpn_detector.py](file:///home/prabhath/projects/cyphercite/backend/app/core/scanner/vpn_detector.py) | 136 | ✅ Good | VPN detection by port + TLS cert analysis |
| [api_prober.py](file:///home/prabhath/projects/cyphercite/backend/app/core/scanner/api_prober.py) | 133 | ✅ Good | HTTP/HTTPS API detection + security header collection |
| [scan_tasks.py](file:///home/prabhath/projects/cyphercite/backend/app/tasks/scan_tasks.py) | 609 | ✅ **Reuse pipeline** | Full scan orchestration: Discovery → TLS → PQC → CBOM → Cert. Has both async and sync TLS inspection |

---

### 7. Existing CBOM Implementation

| Module | LOC | Status |
|--------|-----|--------|
| [builder.py](file:///home/prabhath/projects/cyphercite/backend/app/core/cbom/builder.py) | 227 | ✅ CycloneDX 1.5 compliant. Generates components, vulnerabilities, compositions. **Currently network-only** — needs extension for source/binary/container findings |
| [exporter.py](file:///home/prabhath/projects/cyphercite/backend/app/core/cbom/exporter.py) | ~100 | ✅ CSV export working |
| [pdf_report.py](file:///home/prabhath/projects/cyphercite/backend/app/core/cbom/pdf_report.py) | ~200 | ✅ PDF report via ReportLab |

---

### 8. Existing PQC Assessment

| Module | LOC | Status |
|--------|-----|--------|
| [nist_rules.py](file:///home/prabhath/projects/cyphercite/backend/app/core/pqc/nist_rules.py) | 185 | ✅ **Comprehensive** — NIST FIPS 203/204/205 algorithm mappings, hybrid PQC combos, vulnerable/deprecated sets |
| [assessor.py](file:///home/prabhath/projects/cyphercite/backend/app/core/pqc/assessor.py) | 324 | ✅ **Solid** — Deterministic rule-based risk scoring (0-100), status classification (QUANTUM_SAFE/HYBRID_READY/VULNERABLE/INCONCLUSIVE) |
| [classifier.py](file:///home/prabhath/projects/cyphercite/backend/app/core/pqc/classifier.py) | 122 | ✅ Classification summary + severity levels |

---

### 9. Existing Converter (Asset → CryptoAsset Bridge)

[converter.py](file:///home/prabhath/projects/cyphercite/backend/app/core/converter.py) — 89 lines. Maps network Asset fields to CryptoAsset. This proves the "all scanners → one model" architecture was already planned.

---

### 10. Code Reuse Assessment

#### ✅ Reuse Directly
- **All scanner modules** (discovery, TLS inspector, VPN detector, API prober)
- **PQC assessor + NIST rules** (extend for source-code context)
- **CryptoAsset model** (extend with new fields: `confidence`, `evidence`, `sensitivity`, `primitive`, `mode`, `padding`, `usage`)
- **Database infrastructure** (async SQLAlchemy, migrations, session management)
- **Celery/Redis** task queue infrastructure
- **Docker Compose** architecture (extend with Neo4j)
- **CBOM builder** (extend `_build_component` for non-network findings)
- **Frontend structure** (pages, components, hooks architecture)
- **WebSocket progress** system
- **Test infrastructure** (conftest, async test patterns)

#### 🔧 Refactor / Extend
- **CryptoAsset model** → Add `confidence`, `evidence`, `sensitivity`, `primitive`, `mode`, `padding`, `usage` fields
- **CBOM builder** → Generalize beyond network-only components
- **Scan pipeline** → Add scanner type routing (source/container/binary alongside network)
- **Frontend** → Migrate to TypeScript, add new pages for source scans
- **Risk engine** → Extract from network-only PQC assessor into configurable knowledge-base-driven engine

#### ❌ Missing (Must Build New)
- Python source-code scanner (AST + tree-sitter)
- Container image scanner
- Binary scanner
- Sensitivity inference engine
- Neo4j dependency graph
- Graph visualization (React Flow)
- Quantum risk knowledge base (YAML/JSON)
- Migration recommendation engine
- GitHub Issue integration
- AI explanation agent
- Coverage/confidence reporting system

---

### 11. Proposed Directory Structure

```
cyphercite/
├── docker-compose.yml                    # Add Neo4j service
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py                     # Add Neo4j, GitHub config
│   │   ├── database.py
│   │   ├── models/
│   │   │   ├── scan.py                   # Extend with scan_type field
│   │   │   ├── asset.py                  # Keep for backward compat
│   │   │   ├── crypto_asset.py           # Extend (= CryptoFinding)
│   │   │   ├── cbom.py
│   │   │   └── certificate.py
│   │   ├── schemas/
│   │   │   ├── crypto_asset.py           # Extend
│   │   │   ├── scan.py
│   │   │   ├── coverage.py              # [NEW] Coverage reporting
│   │   │   └── migration.py             # [NEW] Migration schemas
│   │   ├── routers/
│   │   │   ├── scans.py                  # Extend for source/container scans
│   │   │   ├── source_scan.py           # [NEW] Source scan endpoints
│   │   │   ├── crypto_assets.py
│   │   │   ├── cbom.py
│   │   │   ├── coverage.py             # [NEW]
│   │   │   ├── risk.py                  # [NEW] Risk/migration endpoints
│   │   │   └── ws.py
│   │   ├── core/
│   │   │   ├── converter.py
│   │   │   ├── scanner/                  # Existing network scanners
│   │   │   │   ├── discovery.py          # Reuse
│   │   │   │   ├── tls_inspector.py      # Reuse
│   │   │   │   ├── vpn_detector.py       # Reuse
│   │   │   │   └── api_prober.py         # Reuse
│   │   │   ├── source_scanner/          # [NEW] Source code analysis
│   │   │   │   ├── __init__.py
│   │   │   │   ├── python_scanner.py     # Python AST scanner
│   │   │   │   ├── rules/               # Detection rule configs
│   │   │   │   │   └── python_rules.py
│   │   │   │   └── base.py              # Scanner interface
│   │   │   ├── container_scanner/       # [NEW] Phase 7
│   │   │   ├── binary_scanner/          # [NEW] Phase 8
│   │   │   ├── pqc/                      # Existing — extend
│   │   │   │   ├── assessor.py
│   │   │   │   ├── nist_rules.py
│   │   │   │   └── classifier.py
│   │   │   ├── cbom/                     # Existing — extend
│   │   │   │   ├── builder.py            # Generalize
│   │   │   │   ├── exporter.py
│   │   │   │   └── pdf_report.py
│   │   │   ├── risk/                    # [NEW] Phase 13
│   │   │   │   ├── quantum_risk.py
│   │   │   │   └── knowledge_base/
│   │   │   │       └── algorithms.yaml
│   │   │   ├── sensitivity/             # [NEW] Phase 10
│   │   │   │   └── inference.py
│   │   │   ├── migration/              # [NEW] Phase 15
│   │   │   │   └── recommender.py
│   │   │   ├── coverage/               # [NEW] Phase 5
│   │   │   │   └── reporter.py
│   │   │   ├── graph/                   # [NEW] Phase 11
│   │   │   │   └── neo4j_client.py
│   │   │   ├── github/                  # [NEW] Phase 16
│   │   │   │   └── issue_creator.py
│   │   │   └── ai/                      # [NEW] Phase 17
│   │   │       └── explainer.py
│   │   └── tasks/
│   │       ├── celery_app.py
│   │       ├── scan_tasks.py             # Existing network scan
│   │       └── source_scan_tasks.py     # [NEW]
│   └── tests/
│       ├── test_crypto_assets.py         # Existing — keep
│       ├── test_python_scanner.py       # [NEW]
│       ├── test_cbom_generation.py      # [NEW]
│       └── test_coverage.py             # [NEW]
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.tsx            # Migrate JSX → TSX
│       │   ├── SourceScan.tsx          # [NEW]
│       │   ├── CryptoInventory.tsx     # [NEW]
│       │   └── DependencyGraph.tsx     # [NEW] React Flow
│       └── components/
│           ├── ... existing ...
│           └── GraphView.tsx           # [NEW] React Flow
└── nginx/nginx.conf
```

---

## Phase-by-Phase Implementation Plan

> [!IMPORTANT]
> Each phase produces a **working, testable milestone** before proceeding to the next.

---

### Phase 2: CryptoFinding Schema Enhancement

#### [MODIFY] [crypto_asset.py](file:///home/prabhath/projects/cyphercite/backend/app/models/crypto_asset.py)

Extend the existing `CryptoAsset` model (which already serves as the canonical finding) with fields needed by the new platform:

- `confidence: Float` — detection confidence (0.0–1.0)
- `evidence: JSONB` — structured evidence (code snippet, matched pattern, etc.)
- `usage: String` — usage context (encryption, signing, key_exchange, hashing, etc.)
- `primitive: String` — crypto primitive (symmetric, asymmetric, hash, mac, kdf, protocol)
- `mode: String` — cipher mode (GCM, CBC, CTR, etc.)
- `padding: String` — padding scheme (PKCS7, OAEP, etc.)
- `sensitivity: String` — inferred sensitivity level
- `sensitivity_confidence: Float` — sensitivity inference confidence
- `quantum_status: String` — direct quantum status (vulnerable, reduced_margin, safe, unknown)
- `risk_level: String` — CRITICAL/HIGH/MEDIUM/LOW/INFO
- `repository: String` — source repository identifier

#### [MODIFY] [crypto_asset.py](file:///home/prabhath/projects/cyphercite/backend/app/schemas/crypto_asset.py)

Update Pydantic schemas to match new model fields.

---

### Phase 3: Python Source Scanner

#### [NEW] `backend/app/core/source_scanner/base.py`
Abstract `BaseScanner` interface that all scanners implement:
```python
class BaseScanner(ABC):
    def scan(self, target) -> List[CryptoFinding]: ...
```

#### [NEW] `backend/app/core/source_scanner/python_scanner.py`
AST-based Python source scanner detecting crypto APIs from: `cryptography`, `PyCryptodome`, `hashlib`, `hmac`, `ssl`. Captures algorithm, key size, mode, padding, library, file, line, usage, evidence, confidence.

#### [NEW] `backend/app/core/source_scanner/rules/python_rules.py`
Detection rules as structured data (importable function signatures → crypto primitives).

#### [NEW] `backend/tests/test_python_scanner.py`
Test with sample Python files containing known crypto patterns.

---

### Phase 4: CBOM Generation

#### [MODIFY] [builder.py](file:///home/prabhath/projects/cyphercite/backend/app/core/cbom/builder.py)
Generalize `_build_component()` to handle source-code findings (file paths, line numbers, algorithm details) in addition to network endpoints.

#### [NEW] `backend/app/routers/source_scan.py`
New endpoints:
- `POST /api/scan/source` — submit source code scan
- `GET /api/scan/{id}` — get scan results
- `GET /api/scan/{id}/cbom` — get CBOM for scan

**First E2E milestone**: Python repo → Python Scanner → CryptoFinding → CycloneDX CBOM → `cbom.json`

---

### Phase 5: Coverage & Confidence

#### [NEW] `backend/app/core/coverage/reporter.py`
Coverage reporter that tracks: files discovered, scanned, skipped; languages detected/supported; confidence per finding.

---

### Phase 6: Network Scanner Integration

#### [MODIFY] [scan_tasks.py](file:///home/prabhath/projects/cyphercite/backend/app/tasks/scan_tasks.py)
Refactor to produce `CryptoAsset` records directly (currently produces `Asset` records; the converter bridge already exists). Add network scanner to the unified pipeline.

---

### Phase 7–8: Container + Binary Scanners

Build as separate scanner modules following the `BaseScanner` interface, producing `CryptoAsset` output.

---

### Phase 9: Unified Pipeline

All scanners confirmed producing `CryptoAsset[]`. Single normalizer feeds risk/CBOM/graph.

---

### Phase 10–19: (Later phases as specified in the requirements)

Sensitivity inference → Neo4j graph → Quantum risk engine → Migration priority → Migration recommendations → GitHub issues → AI explanation → Dashboard → E2E testing → Docker deployment.

---

## Verification Plan

### Automated Tests
- `pytest backend/tests/` — all existing tests must pass
- New tests for each phase: scanner, CBOM, coverage
- E2E pipeline test: sample Python project → CryptoFinding → CBOM

### Manual Verification
- Docker Compose `up --build` — all services healthy
- API docs at `/api/docs` — new endpoints visible
- Submit a Python source scan and retrieve CBOM JSON

---

## Open Questions

> [!IMPORTANT]
> **1. CryptoAsset vs. CryptoFinding naming**: The existing codebase uses `CryptoAsset` as the unified model. Your spec calls it `CryptoFinding`. Should we rename the model or keep `CryptoAsset` for backward compatibility and alias `CryptoFinding` in code?

> [!IMPORTANT]
> **2. Frontend TypeScript migration strategy**: Current frontend is JSX. Should we migrate existing pages to TSX now, or only write new pages in TypeScript and migrate existing ones later?

> [!IMPORTANT]
> **3. Git repository scanning**: Should the source scanner accept Git repository URLs (clone + scan), local directory paths, or both? This affects the `POST /api/scan/source` input format.

> [!IMPORTANT]
> **4. Neo4j hosting**: Neo4j will be added to Docker Compose. Should it use Neo4j Community (free, single DB) or do you have an Enterprise license? This affects graph features available.
