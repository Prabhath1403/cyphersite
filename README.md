# 🛡️ CipherSight — Quantum-Proof Cryptographic Scanner & CBOM Generator

<p align="center">
  <strong>Identify and secure your infrastructure against the threat of Shor's Algorithm</strong><br>
  <em>The first light-weight, enterprise-grade Post-Quantum Cryptography (PQC) auditor.</em><br>
  Built for the <strong>PNB Cybersecurity Hackathon 2025-26</strong>
</p>

---

## 🌟 Modern Security Features

- **🌐 Dynamic Discovery Agent**: Automated parallel DNS enumeration + multi-port scanning to find every "hidden" TLS endpoint.
- **🔐 Deep Handshake Inspection**: Goes beyond standard tools by performing raw TLS packet analysis to extract exact cipher suites and key exchange types.
- **⚛️ NIST-Compliant Assessment**: Uses a high-fidelity rule engine based on **NIST FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, and **FIPS 205 (SLH-DSA)**.
- **📜 Verified CBOM Generation**: Automatically creates a **Cryptographic Bill of Materials** in **CycloneDX 1.5** format, ready for supply-chain audits.
- **🛡️ PQC-Ready Badges**: For assets that reach "Hybrid Ready" or "Quantum Safe" status, we generate verifiable digital badges with QR codes.

---

## 🛠️ The Technology Stack

### 🚀 Frontend (The Cyber-Control Center)
Built for speed, aesthetics, and real-time observability:
- **React 18**: Utilizing functional hooks and a modular component architecture for a snappy, fluid UI.
- **Vite**: A next-generation build tool that provides nearly instant Hot Module Replacement (HMR).
- **Tailwind CSS**: A utility-first CSS framework customized with a **Glassmorphism** theme to create a premium, futuristic look.
- **TanStack React Query**: Manages server state, caching, and auto-refetching for scan results.
- **Framer Motion**: Powering smooth micro-animations and page transitions to enhance the user experience.
- **Lucide-React**: A beautiful, consistent icon set specifically chosen for security and networking contexts.

### ⚙️ Backend (The Cryptographic Engine)
High-performance, asynchronous, and mathematically accurate:
- **Python 3.11 & FastAPI**: Leveraging Pydantic v2 for lightning-fast data validation and automatic OpenAPI documentation.
- **Celery & Redis**: An industrial-strength distributed task queue that allows for scanning hundreds of assets in parallel without blocking the UI.
- **SQLAlchemy (Async)**: Modern ORM for clean, scalable database interactions with **PostgreSQL**.
- **Cryptography.io**: The underlying engine used to parse binary (DER) certificate data and extract complex public key properties.
- **Nginx**: A high-performance reverse proxy that unifies the frontend and backend into a single application flow.

---

## 🧬 Architectural Overview (4 Core Engines)

CipherSight is split into four distinct sub-engines:

1.  **Discovery Engine**: Parallel DNS lookups + active TCP probing on 10+ common cryptographic ports.
2.  **TLS Inspector**: Performs a full synchronous handshake fallback to extract protocols (TLS 1.2/1.3) and ciphers when standard libraries fail.
3.  **Readiness Assessor**: Evaluates fingerprints against 15+ NIST-derived rules, calculating a Risk Score (0-100) and PQC Status (Level 1, 2, or 3).
4.  **CBOM Builder**: Synthesizes all scan data into a compliant CycloneDX 1.5 document for CSV, JSON, or PDF export.

---

## 🚀 Deployment Guide

### 📦 Quick Start (Docker Compose)
The easiest way to get CipherSight running is using our unified Docker environment:

```bash
# 1. Clone the repository
git clone https://github.com/Prabhath1403/cyphercite.git && cd cyphercite

# 2. Setup environment
cp .env.example .env

# 3. Launch all services (Backend, Worker, DB, Redis, Frontend, Nginx)
docker compose up --build
```

**Access URLs:**
- **App**: [http://localhost:3000](http://localhost:3000)
- **API Docs**: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
- **Database**: Port 5432 (PostgreSQL 15)

---

## 📊 PQC Status Guide

| Level | Status | Quantum Resistance |
|:---:|---|---|
| 🟢 | **QUANTUM_SAFE** | Full PQC protection (Lattice-based Key Exchange + Cert Signatures). |
| 🟡 | **HYBRID_READY** | Uses TLS 1.3 + modern ephemeral KEX (Kyber-compatible foundations). |
| 🔴 | **VULNERABLE** | Uses legacy RSA, old TLS (1.1/1.2), or weak/deprecated ciphers. |

---

## 🗂️ Project Map

```text
├── backend/
│   ├── app/core/ scanner/, pqc/, cbom/ (The Intelligence)
│   ├── app/routers/ (The Communication)
│   └── app/tasks/ (The Distributed Execution)
├── frontend/
│   ├── src/pages/ & components/ (The Interface)
│   └── src/hooks/ (The Real-time Logic)
├── nginx/ (The Unified Portal)
└── docker-compose.yml (The Orchestration)
```

**Built with 🛡️ by the Prabhath1403 for a Quantum-Safe Future.**
