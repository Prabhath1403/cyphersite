# 🛡️ CipherSight — Unified Cryptographic Discovery, CBOM & Post-Quantum Migration Intelligence Platform

<p align="center">
  <img src="https://img.shields.io/badge/Status-Post--Quantum%20Ready-00E676?style=for-the-badge&logo=shield" alt="Status">
  <img src="https://img.shields.io/badge/Standards-NIST%20FIPS%20203%20%7C%20204%20%7C%20205-00E5FF?style=for-the-badge" alt="Standards">
  <img src="https://img.shields.io/badge/Mandates-NSA%20CNSA%202.0-8A2BE2?style=for-the-badge" alt="CNSA 2.0">
  <img src="https://img.shields.io/badge/CBOM-CycloneDX%201.5-FFD600?style=for-the-badge" alt="CycloneDX">
  <img src="https://img.shields.io/badge/Tests-122%20Passed-00E676?style=for-the-badge&logo=pytest" alt="Tests">
</p>

<p align="center">
  <strong>The Enterprise-Grade Discovery, Assessment, and Migration Platform for the Post-Quantum Transition</strong><br>
  <em>Unifying network infrastructure, source code, container images, and compiled binaries into a single canonical Cryptographic Bill of Materials (CBOM) with AI-powered remediation and topology graph analysis.</em><br>
  Built for the <strong>PNB Cybersecurity Hackathon 2025-26</strong>
</p>

---

## 📑 Table of Contents

- [🌟 Platform Overview](#-platform-overview)
- [🧬 Core Architecture & Engines](#-core-architecture--engines)
- [🔍 Multi-Modal Cryptographic Scanners](#-multi-modal-cryptographic-scanners)
- [📊 Post-Quantum Risk & Mosca Theorem Engine](#-post-quantum-risk--mosca-theorem-engine)
- [🕸️ Cryptographic Topology Graph (Neo4j)](#️-cryptographic-topology-graph-neo4j)
- [🚀 Prioritized Migration & Developer Remediation](#-prioritized-migration--developer-remediation)
- [🧠 AI Cryptographic Explanation & Advisory Agent](#-ai-cryptographic-explanation--advisory-agent)
- [📜 CycloneDX 1.5 CBOM Generation](#-cyclonedx-15-cbom-generation)
- [🖥️ Cyber-Control Center (Frontend)](#️-cyber-control-center-frontend)
- [🛠️ Technology Stack](#️-technology-stack)
- [🚀 Quick Start & Docker Deployment](#-quick-start--docker-deployment)
- [📡 API Reference](#-api-reference)
- [🧪 Testing & Verification](#-testing--verification)

---

## 🌟 Platform Overview

As Cryptographically Relevant Quantum Computers (CRQCs) approach reality, legacy public-key algorithms (**RSA, ECC, Diffie-Hellman, ECDSA**) face total mathematical collapse under **Shor's Algorithm** ($O((\log N)^3)$), while symmetric ciphers (**AES-128, 3DES**) suffer quadratic key-space reduction under **Grover's Algorithm** ($O(\sqrt{N})$). Furthermore, state-sponsored adversaries actively engage in **Harvest Now, Decrypt Later (HNDL)** attacks—recording encrypted enterprise and financial traffic today to decrypt retroactively.

**CipherSight** provides an end-to-end, multi-modal discovery and post-quantum migration platform that continuously scans, catalogs, assesses, and remediates cryptographic assets across an organization's digital attack surface.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Multi-Modal Discovery Scanners                      │
│   [ Network / TLS ]   [ Python Source ]   [ Containers ]   [ Binaries ]│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Raw Findings
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              Unified Scan Pipeline & Cryptographic Normalizer          │
│   • Canonical Algorithm Dictionary    • Primitive & Mode Resolution    │
│   • Key-Size Normalization            • Unified CryptoAsset Schema     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Canonical CryptoAssets
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Data Sensitivity & HNDL Risk Inference Engine            │
│   • Contextual Tokenizer (Code/Data)  • Sensitivity Class Hierarchy    │
│   • HNDL Retrospective Risk Rating    • Automated Finding Enrichment   │
└───────────────────┬───────────────────────────────┬────────────────────┘
                    │                               │
       ┌────────────┴────────────┐     ┌────────────┴────────────┐
       ▼                         ▼     ▼                         ▼
┌──────────────┐         ┌──────────────┐     ┌──────────────┐  ┌──────────────┐
│  CycloneDX   │         │  Topology    │     │ Quantum Risk │  │  Prioritized │
│  1.5 CBOM    │         │  Graph Engine│     │  & Mosca     │  │  Migration   │
│  (JSON/PDF)  │         │   (Neo4j)    │     │  Theorem     │  │  Recommender │
└──────────────┘         └──────────────┘     └──────────────┘  └───────┬──────┘
                                                                        │
                                   ┌────────────────────────────────────┴──────┐
                                   ▼                                           ▼
                    ┌──────────────────────────────┐            ┌──────────────────────────────┐
                    │ GitHub Developer Remediation │            │ AI Cryptographic Explainer   │
                    │ • Markdown Issue Generator   │            │ • Shor / Grover Mathematics  │
                    │ • 1-Click Remote Publishing  │            │ • Qubit & Hardware Estimates │
                    │ • Batch JSON / Markdown Export│           │ • Interactive Q&A Console    │
                    └──────────────────────────────┘            └──────────────────────────────┘
```

---

## 🧬 Core Architecture & Engines

1. **Unified Scan Pipeline**: Ingests disparate outputs from all scanner types and normalizes them into the canonical [`CryptoAsset`](backend/app/models/crypto_asset.py) data model.
2. **Data Sensitivity Inference**: Automatically classifies data sensitivity (`financial`, `authentication`, `government_id`, `medical`, `pii`, `general`) using contextual tokenization of variable names, parameter types, database fields, and function identifiers.
3. **Cryptographic Topology Graph**: Constructs dependency graphs linking Applications $\rightarrow$ Source Files / Hosts $\rightarrow$ Algorithms $\rightarrow$ Sensitive Data Assets, with Neo4j Cypher query support.
4. **Quantum Risk & Mosca Theorem Engine**: Evaluates migration urgency via Mosca's Equation ($X + Y > Z$), multi-factor risk scoring (0–100), and a structured `algorithms.yaml` post-quantum knowledge base.
5. **Prioritized Migration Recommender**: Sorts remediation actions into P0 (Critical HNDL), P1 (High Signatures/Auth), P2 (Medium Symmetric), and P3 (Low Hash/Agility) tiers, complete with copy-paste Python (liboqs) code snippets.
6. **Developer Remediation & GitHub Integration**: Formats findings into production-ready GitHub Issues and allows direct remote publishing via the GitHub REST API.
7. **AI Cryptographic Explainer & Advisor**: Deterministic scientific reasoning agent with optional LLM augmentation that calculates exact qubit requirements, explains Shor/Grover mechanics, and answers queries.
8. **CBOM Generator**: Produces standard CycloneDX 1.5 Cryptographic Bill of Materials in JSON, CSV, and PDF formats.

---

## 🔍 Multi-Modal Cryptographic Scanners

### 1. Network & TLS Scanner
- **Active & Passive Discovery**: Parallel DNS resolution, passive subdomain reconnaissance (crt.sh, HackerTarget, CertSpotter, AlienVault), and CIDR expansion.
- **Deep Handshake Inspection**: Raw TLS packet inspection, cipher suite negotiation (TLS 1.2 and 1.3 aware), certificate DER decoding, and VPN endpoint detection.

### 2. Python Source Code Scanner (AST)
- **Zero False-Positive AST Parsing**: Traverses Python Abstract Syntax Trees without executing untrusted code.
- **Library Signatures**: Detects APIs from `cryptography`, `PyCryptodome`, `hashlib`, `hmac`, and `ssl`.
- **Granular Provenance**: Captures file paths, line numbers, function names, cipher modes (GCM, CBC, CTR), padding schemes (PKCS7, OAEP, PSS), and evidence snippets.

### 3. Container Image Scanner (Daemonless)
- **No Docker Daemon Required**: Inspects OCI tarballs, layered archives, or exported filesystems purely in Python.
- **OS Package Auditing**: Parses package databases (`dpkg/status`, `rpm/Packages`, `apk/installed`) to detect crypto libraries (`libssl`, `libcrypto`, `gnutls`, `nss`, `openssl`).
- **Binary & Script References**: Scans binaries and scripts inside the image for cryptographic primitives and PQC symbols.

### 4. Compiled Binary Scanner (Daemonless)
- **Pure-Python Executable Parsers**: Inspects **ELF** (Linux), **PE** (Windows), and **Mach-O** (macOS) executables without external reverse-engineering tools (no Ghidra/radare2 dependencies).
- **Symbol & Function Signatures**: Extracts dynamic imports, static symbol tables, and PQC signatures (FIPS 203/204/205 symbols: `ML-KEM`, `Kyber`, `ML-DSA`, `Dilithium`, `SLH-DSA`, `SPHINCS+`).

---

## 📊 Post-Quantum Risk & Mosca Theorem Engine

The platform evaluates cryptographic findings using **Mosca's Theorem**:

$$\text{If } X + Y > Z \implies \text{CRITICAL HNDL EXPOSURE}$$

- **$X$ (Shelf-Life / Retention Time)**: How long the encrypted data must remain confidential (e.g., 25 years for medical records, 10 years for banking).
- **$Y$ (Migration Time)**: Time required to migrate the systems and infrastructure to post-quantum standards (typically 3–7 years).
- **$Z$ (Quantum Horizon)**: Estimated time until a Cryptographically Relevant Quantum Computer (CRQC) emerges (estimated 2029–2035).

### Multi-Factor Risk Formula:
$$R = (\text{Algorithm Vulnerability} \times 0.40) + (\text{Data Sensitivity} \times 0.30) + (\text{Internet Exposure} \times 0.20) + (\text{Mosca Urgency} \times 0.10)$$

Algorithm classifications and regulatory timelines are driven by a hot-reloadable knowledge base in [`backend/app/core/risk/knowledge_base/algorithms.yaml`](backend/app/core/risk/knowledge_base/algorithms.yaml).

---

## 🕸️ Cryptographic Topology Graph (Neo4j)

CipherSight automatically models cryptographic relationships as a graph:

- **Nodes**: `Application`, `File`, `Host`, `Algorithm`, `Data`
- **Edges**:
  - `(:Application)-[:CONTAINS]->(:File)`
  - `(:File)-[:IMPLEMENTS]->(:Algorithm)`
  - `(:File)-[:CONTAINS]->(:Data)`
  - `(:Algorithm)-[:ENCRYPTS]->(:Data)`
  - `(:Host)-[:EXPOSES]->(:Algorithm)`
- **Attack Path Discovery**: Identifies critical chains where quantum-vulnerable algorithms protect high-sensitivity data exposed to external network traffic.
- **Neo4j Integration**: Built-in Cypher query generation for synchronization with Neo4j 5 Community.

---

## 🚀 Prioritized Migration & Developer Remediation

CipherSight eliminates guesswork by generating concrete, copy-paste code remediation snippets and prioritized engineering roadmaps:

| Priority | Focus Area | Target NIST Standard | Example Action |
|:---:|:---|:---|:---|
| **P0 • Critical** | Key Encapsulation & Ephemeral Exchange (HNDL Threat) | **NIST FIPS 203 (ML-KEM-768)** | Replace RSA / ECDH key exchange with ML-KEM-768 or hybrid X25519+ML-KEM. |
| **P1 • High** | Digital Signatures & Identity Authentication | **NIST FIPS 204 (ML-DSA-65)** | Replace RSA-2048 / ECDSA certificate signing with ML-DSA-65 or SLH-DSA (FIPS 205). |
| **P2 • Medium** | Symmetric Encryption (Grover Reduction) | **NIST SP 800-38D (AES-256-GCM)** | Upgrade AES-128 (effective 64-bit quantum margin) to AES-256-GCM (128-bit quantum security). |
| **P3 • Low** | Hash Functions & General Agility | **SHA-384 / Cryptographic Agility** | Transition legacy SHA-1/MD5 to SHA-384/SHA-512 and modularize crypto APIs. |

### 1-Click GitHub Issue Publisher
- Generates formatted Markdown issue templates with vulnerability details, file/line locations, attack mechanics, and remediation code.
- Publishes directly to user repositories via `POST /api/remediation/publish` or exports as a JSON bundle via `GET /api/remediation/scan/{id}/export-issues`.

---

## 🧠 AI Cryptographic Explanation & Advisory Agent

The AI Cryptographic Explanation Agent provides mathematically grounded reasoning:

- **Exact Theoretical Foundations**: Detailed algorithmic breakdowns of Shor's integer factorization, discrete logarithms on elliptic curves (ECDLP), and Grover's amplitude amplification.
- **Qubit Requirements Estimation**:
  - **RSA-2048**: $\sim 4,098$ logical qubits ($\sim 20$ million physical qubits with surface code error correction).
  - **ECC P-256**: $\sim 2,330$ logical qubits.
- **Interactive Q&A Console**: Answers natural language questions on Shor, Grover, Mosca, FIPS 203/204/205, and NSA CNSA 2.0.
- **Custom Primitive Analyzer**: Instantly evaluates user-specified algorithms, key sizes, and sensitivities.
- **Executive Board Summarizer**: Synthesizes CISO/board-ready reports on enterprise quantum readiness.

---

## 📜 CycloneDX 1.5 CBOM Generation

Generates verified Cryptographic Bill of Materials following the **CycloneDX 1.5** specification:
- **Components**: Algorithms, protocols, certificates, keys, libraries, and source usages.
- **Cryptographic Properties**: Primitive, algorithm family, key size, cipher mode, padding, and PQC status.
- **Vulnerabilities**: Quantum exposure tags, Shor/Grover vulnerability identifiers, and recommendations.
- **Multi-Format Export**: Available via `GET /api/cbom/{scan_id}` in **JSON**, **CSV**, and **PDF** report formats.

---

## 🖥️ Cyber-Control Center (Frontend)

The frontend is built with React 18, Vite, and a custom Tailwind CSS Glassmorphism theme:

- **📊 Dashboard (`/`)**: Executive statistics, quantum readiness ratios, recent scans, and risk heatmaps.
- **🔍 New Scan (`/scan/new`)**: 4-Way multi-modal scanner supporting Network targets, Source directories/repos, Container images, and Compiled binaries.
- **📦 Crypto Inventory (`/inventory`)**: Canonical searchable catalog of all findings with filtering by source, primitive, sensitivity, and status, with inline AI explanation and GitHub issue modals.
- **🕸️ Topology Graph (`/graph`)**: Interactive SVG visualization of the cryptographic dependency graph with zoom, pan, and inspector drawer.
- **🚀 Migration Roadmap (`/roadmap`)**: Prioritized P0–P3 roadmap cards with code snippet viewers, effort estimates, and issue export.
- **🧠 AI Advisor (`/ai`)**: Interactive Q&A chat console, custom primitive analyzer, and executive summary generator.
- **📋 Scan Detail (`/scan/:scanId`)**: Per-scan breakdown, coverage metrics, and findings table.
- **📜 CBOM Report (`/cbom/:scanId`)**: CycloneDX viewer and 1-click JSON, CSV, and PDF downloads.

---

## 🛠️ The Technology Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18, Vite 6, Tailwind CSS 3.4 (Glassmorphism), TanStack React Query v5, Recharts, React Router v6, Axios, react-hot-toast |
| **Backend API** | Python 3.11+, FastAPI 0.115, Pydantic v2, Uvicorn |
| **Database & ORM** | PostgreSQL 15, SQLAlchemy 2.0 (Async), Asyncpg, Alembic |
| **Graph Database** | Neo4j 5 Community, Cypher Query Language, APOC |
| **Task Queue & Cache**| Celery 5.4, Redis 7 |
| **Cryptographic Analysis** | Python `ast`, `cryptography` 44.0, pure-Python ELF/PE/Mach-O parsers, `reportlab` (PDF), `pandas` (CSV) |
| **Reverse Proxy** | Nginx Alpine (API, WebSocket, Artifacts, and Frontend routing) |
| **Containerization** | Docker, Docker Compose |

---

## 🚀 Quick Start & Docker Deployment

### Prerequisites
- Docker Engine 24.0+ and Docker Compose v2.20+
- (Optional for local dev) Python 3.11+ and Node.js 20+

### Launching with Docker Compose

```bash
# 1. Clone the repository
git clone https://github.com/Prabhath1403/cyphersite.git
cd cyphersite

# 2. Configure environment variables
cp .env.example .env

# 3. Build and launch all 7 services
docker compose up --build -d
```

### Deployed Services & Endpoints

| Service | Container Name | Port | Description |
|---|---|---|---|
| **Frontend UI** | `ciphersight-frontend` | `http://localhost:3000` | Cyber-Control Center Web UI |
| **Backend API** | `ciphersight-backend` | `http://localhost:8000` | FastAPI REST & WebSocket API |
| **API Docs (Swagger)**| `ciphersight-backend` | `http://localhost:8000/api/docs`| Interactive OpenAPI documentation |
| **Nginx Proxy** | `ciphersight-nginx` | `http://localhost:80` | Unified gateway for Web, API, and WS |
| **Neo4j Graph UI** | `ciphersight-neo4j` | `http://localhost:7474` | Neo4j Browser (`neo4j/cyphercite123`) |
| **PostgreSQL** | `ciphersight-db` | `localhost:5433` | Primary relational store |
| **Redis** | `ciphersight-redis` | `localhost:6379` | Task broker and result backend |
| **Celery Worker** | `ciphersight-worker` | Internal | Background scan execution worker |

---

## 📡 API Reference

### Scans & Discovery
- `POST /api/scans` — Submit asynchronous network TLS scan
- `POST /api/scan/source` — Submit source code repository scan
- `POST /api/scan/container` — Submit container image scan
- `POST /api/scan/binary` — Submit compiled binary executable scan
- `GET /api/scan/{id}` — Get scan job status and findings
- `GET /api/scan/{id}/coverage` — Get scanner coverage and confidence metrics

### Canonical Findings & CBOM
- `GET /api/crypto-assets` — Query canonical findings across all scanners
- `GET /api/cbom/{scan_id}?format=json|csv|pdf` — Generate and download CycloneDX CBOM

### Graph & Risk
- `GET /api/graph/{scan_id}` — Get cryptographic topology graph for a scan
- `GET /api/graph` — Get global cross-scan dependency graph
- `GET /api/risk/scan/{scan_id}` — Evaluate post-quantum risk & Mosca theorem
- `POST /api/risk/evaluate` — Ad-hoc risk evaluation for arbitrary finding

### Migration & Remediation
- `GET /api/migration/plan/{scan_id}` — Get prioritized P0–P3 migration roadmap
- `POST /api/migration/recommend` — Generate ad-hoc migration recommendation
- `GET /api/remediation/finding/{id}/issue-preview` — Generate GitHub issue markdown
- `GET /api/remediation/scan/{id}/export-issues` — Export all scan issues as JSON
- `POST /api/remediation/publish` — Publish issue directly to remote GitHub repo

### AI Cryptographic Advisory
- `POST /api/ai/explain` — Deep-dive explanation for a finding
- `GET /api/ai/finding/{id}` — Retrieve explanation by finding UUID
- `GET /api/ai/scan/{id}/summary` — Generate board-level executive post-quantum summary
- `POST /api/ai/query` — Natural language cryptographic Q&A

---

## 🧪 Testing & Verification

The platform is covered by an automated test suite verifying every layer of the pipeline:

```bash
# Run backend test suite (122 tests)
cd backend
source venv/bin/activate
pytest tests/ -v

# Run frontend production build verification
cd ../frontend
npm run build
```

**Test Coverage Highlights**:
- Source code AST scanner and detection rules (`test_python_scanner.py`)
- Container image package & binary parsers (`test_container_scanner.py`)
- Compiled binary ELF/PE/Mach-O parsers (`test_binary_scanner.py`)
- Unified pipeline & canonical normalizer (`test_unified_pipeline.py`)
- Sensitivity inference & tokenization (`test_sensitivity_engine.py`)
- Cryptographic topology graph engine (`test_graph_engine.py`)
- Quantum risk & Mosca theorem calculations (`test_quantum_risk_engine.py`)
- Migration recommender & code templates (`test_migration_recommender.py`)
- GitHub issue creator & REST publishing (`test_github_issue_creator.py`)
- AI explanation agent & Q&A router (`test_ai_explainer.py`)
- CycloneDX CBOM builder & exports (`test_cbom_generation.py`)
- End-to-end full platform integration (`test_e2e_platform.py`)

---

## 📜 License

Distributed under the Apache 2.0 License. See `LICENSE` for more information.

<p align="center">
  <strong>Built with 🛡️ for a Quantum-Safe Future.</strong>
</p>
