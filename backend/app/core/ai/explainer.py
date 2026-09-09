"""
AI Cryptographic Explanation Agent.

Generates mathematically and architecturally rigorous explanations of quantum
vulnerabilities, Shor/Grover algorithmic mechanics, Harvest Now Decrypt Later (HNDL)
risks, regulatory compliance timelines, and actionable remediation steps.
Provides deterministic expert-rules output with optional LLM augmentation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import httpx

from app.config import settings
from app.core.migration.recommender import CODE_TEMPLATES

logger = logging.getLogger(__name__)


class AIExplanationAgent:
    """Intelligent Cryptographic Explanation and Post-Quantum Advisory Agent."""

    def __init__(self, api_key: Optional[str] = None, provider: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or settings.AI_API_KEY
        self.provider = provider or settings.AI_PROVIDER
        self.model = model or settings.AI_MODEL
        self.api_base = settings.AI_API_BASE

    async def explain_finding(
        self,
        finding: Dict[str, Any],
        target_audience: str = "developer",
        use_llm: bool = False,
    ) -> Dict[str, Any]:
        """Generate a complete post-quantum vulnerability and remediation explanation."""
        algorithm = (finding.get("algorithm") or finding.get("name") or "UNKNOWN").upper()
        key_size = finding.get("key_size")
        primitive = (finding.get("primitive") or "").lower()
        quantum_status = (finding.get("quantum_status") or finding.get("pqc_status") or "unknown").lower()
        sensitivity = (finding.get("sensitivity") or "general").lower()
        source_type = finding.get("source_type") or "unknown"
        file_path = finding.get("file_path") or finding.get("source_location") or ""
        finding_id = str(finding.get("id")) if finding.get("id") else None

        # 1. Theoretical foundation & attack mechanics
        theory = self._analyze_theoretical_foundation(algorithm, key_size, primitive)

        # 2. HNDL risk evaluation
        hndl = self._evaluate_hndl_risk(algorithm, sensitivity, quantum_status, source_type)

        # 3. Regulatory mandates
        regulations = self._get_regulatory_implications(algorithm)

        # 4. Tailored code & architectural remediation
        remediation = self._generate_remediation(finding, algorithm, key_size)

        # 5. Synthesis of summary explanation
        summary = self._synthesize_summary(algorithm, key_size, quantum_status, theory, target_audience)

        explanation = {
            "finding_id": finding_id,
            "algorithm": algorithm,
            "primitive": primitive or theory.get("inferred_primitive", "asymmetric"),
            "key_size": key_size,
            "quantum_status": quantum_status if quantum_status in ["vulnerable", "reduced_security_margin", "safe"] else theory.get("default_status", "vulnerable"),
            "quantum_vulnerability_summary": summary,
            "theoretical_foundation": {
                "attack_algorithm": theory["attack_algorithm"],
                "mathematical_basis": theory["mathematical_basis"],
                "quantum_complexity": theory["quantum_complexity"],
                "qubits_required_estimate": theory["qubits_required_estimate"],
            },
            "harvest_now_decrypt_later_risk": hndl,
            "regulatory_implications": regulations,
            "tailored_remediation": remediation,
            "confidence_score": 0.95,
            "engine": "deterministic_expert_system",
        }

        # LLM augmentation if enabled and available
        if use_llm and self.api_key:
            llm_summary = await self._augment_with_llm(explanation, target_audience)
            if llm_summary:
                explanation["quantum_vulnerability_summary"] = llm_summary
                explanation["engine"] = f"llm_augmented ({self.model})"

        return explanation

    async def explain_scan_summary(
        self,
        scan_id: str,
        findings: List[Dict[str, Any]],
        aggregate_risk: Optional[Dict[str, Any]] = None,
        use_llm: bool = False,
    ) -> Dict[str, Any]:
        """Synthesize an executive-ready post-quantum readiness report for an entire scan."""
        total = len(findings)
        vulnerable_count = 0
        reduced_count = 0
        safe_count = 0
        critical_vectors = set()

        for f in findings:
            q_status = (f.get("quantum_status") or f.get("pqc_status") or "").lower()
            algo = (f.get("algorithm") or f.get("name") or "").upper()

            if any(k in algo for k in ["ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "FALCON", "SPHINCS"]):
                safe_count += 1
            elif any(k in algo for k in ["AES-256", "SHA-384", "SHA-512", "CHACHA20"]):
                safe_count += 1
            elif any(k in algo for k in ["AES-128", "SHA-256"]):
                reduced_count += 1
                critical_vectors.add(f"{algo} (Grover key/preimage reduction)")
            elif any(k in algo for k in ["RSA", "ECC", "ECDSA", "ECDH", "DH", "DSA", "ED25519", "SECP"]):
                vulnerable_count += 1
                critical_vectors.add(f"{algo} (Shor polynomial factorization/DLP)")
            else:
                if q_status == "safe":
                    safe_count += 1
                elif q_status == "reduced_security_margin":
                    reduced_count += 1
                else:
                    vulnerable_count += 1

        if vulnerable_count == 0 and reduced_count == 0:
            readiness = "POST_QUANTUM_READY"
            exec_summary = (
                f"Scan {scan_id} evaluated {total} cryptographic assets with 0 critical quantum vulnerabilities. "
                "The target architecture adheres to NIST FIPS 203/204 post-quantum standards and CNSA 2.0 specifications."
            )
        elif vulnerable_count > 0:
            readiness = "CRITICALLY_VULNERABLE"
            exec_summary = (
                f"Scan {scan_id} identified {vulnerable_count} critical quantum-vulnerable algorithms across {total} inspected assets. "
                f"Adversaries utilizing Shor's Algorithm can compromise current public-key infrastructure once Cryptographically Relevant "
                f"Quantum Computers (CRQC) reach ~4,000 logical qubits. Active Harvest Now, Decrypt Later (HNDL) vectors threaten long-term confidentiality."
            )
        else:
            readiness = "NEEDS_UPGRADE"
            exec_summary = (
                f"Scan {scan_id} identified {reduced_count} symmetric assets operating with reduced quantum security margins under Grover's Algorithm. "
                "Upgrade to 256-bit symmetric primitives (AES-256-GCM) is recommended to maintain post-quantum resilience."
            )

        priority_actions = []
        if any("RSA" in v for v in critical_vectors) or any("DH" in v for v in critical_vectors):
            priority_actions.append("P0: Transition key exchange protocols to ML-KEM-768 (FIPS 203) or hybrid X25519+ML-KEM.")
        if any("ECDSA" in v for v in critical_vectors) or any("RSA" in v for v in critical_vectors):
            priority_actions.append("P1: Replace public-key authentication with ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).")
        if any("AES-128" in v for v in critical_vectors):
            priority_actions.append("P2: Upgrade symmetric encryption from AES-128 to AES-256-GCM to preserve >= 128-bit quantum security.")
        if not priority_actions:
            priority_actions.append("Maintain cryptographic agility and monitor annual NIST PQC standard updates.")

        result = {
            "scan_id": scan_id,
            "total_findings": total,
            "vulnerable_findings_count": vulnerable_count,
            "quantum_safe_count": safe_count,
            "executive_summary": exec_summary,
            "quantum_readiness_posture": readiness,
            "primary_quantum_vectors": sorted(list(critical_vectors)),
            "recommended_priority_actions": priority_actions,
            "engine": "deterministic_expert_system",
        }

        if use_llm and self.api_key:
            llm_text = await self._augment_scan_summary_with_llm(result)
            if llm_text:
                result["executive_summary"] = llm_text
                result["engine"] = f"llm_augmented ({self.model})"

        return result

    async def answer_query(
        self,
        query: str,
        scan_context: Optional[Dict[str, Any]] = None,
        use_llm: bool = False,
    ) -> Dict[str, Any]:
        """Answer natural language queries regarding cryptography, quantum attacks, and PQC migration."""
        query_lower = query.lower()

        # Deterministic domain matching (specific standards take priority)
        if "fips 203" in query_lower or "ml-kem" in query_lower or "kyber" in query_lower:
            ans = (
                "NIST FIPS 203 specifies ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism), derived from CRYSTALS-Kyber. "
                "Finalized in August 2024, it is NIST's primary standard for general encryption and key establishment. "
                "Parameter sets include ML-KEM-512 (Category 1), ML-KEM-768 (Category 3, recommended for most applications), "
                "and ML-KEM-1024 (Category 5). It relies on the hardness of the Module Learning With Errors (M-LWE) problem, "
                "which is mathematically resistant to Shor's algorithm."
            )
            refs = ["NIST FIPS 203 (August 2024)", "CRYSTALS-Kyber Specification"]
        elif "fips 204" in query_lower or "ml-dsa" in query_lower or "dilithium" in query_lower:
            ans = (
                "NIST FIPS 204 specifies ML-DSA (Module-Lattice-Based Digital Signature Algorithm), derived from CRYSTALS-Dilithium. "
                "Finalized in August 2024, it is the primary post-quantum digital signature standard. "
                "Parameter sets include ML-DSA-44 (Category 2), ML-DSA-65 (Category 3, standard replacement for RSA/ECDSA), "
                "and ML-DSA-87 (Category 5). It is built on Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS)."
            )
            refs = ["NIST FIPS 204 (August 2024)", "CRYSTALS-Dilithium Specification"]
        elif "cnsa" in query_lower:
            ans = (
                "Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) was issued by the NSA in September 2022. "
                "It mandates post-quantum cryptography for National Security Systems: transition starts in 2025, "
                "exclusive PQC use for software and firmware updates by 2030, and full deprecation of legacy algorithms by 2033. "
                "CNSA 2.0 designates ML-KEM and ML-DSA alongside AES-256 and SHA-384."
            )
            refs = ["NSA CNSA 2.0 Advisory (2022)", "CISA / NSA / NIST Joint Factsheet"]
        elif "hndl" in query_lower or "harvest" in query_lower:
            ans = (
                "Harvest Now, Decrypt Later (HNDL) is an active intelligence strategy where adversaries capture and store "
                "encrypted network traffic and sensitive data today. Even though the data cannot be decrypted classically, "
                "adversaries retain it until a Cryptographically Relevant Quantum Computer (CRQC) is built, at which point "
                "all captured sessions are decrypted retroactively. This makes migrating long-retention data (>= 5-10 years) "
                "an immediate priority today under Mosca's Theorem (X + Y > Z)."
            )
            refs = ["White House NSM-10", "Mosca, M. (2015) Cybersecurity in an Quantum World", "CISA PQC Roadmap"]
        elif "shor" in query_lower:
            ans = (
                "Shor's Algorithm (published by Peter Shor in 1994) is a quantum algorithm that solves the discrete "
                "logarithm problem and integer factorization in polynomial time O((log N)^3). Classically, factoring "
                "relies on sub-exponential algorithms like General Number Field Sieve (GNFS). Shor's algorithm uses "
                "Quantum Fourier Transform (QFT) to find the period r of a function f(x) = a^x mod N. "
                "A CRQC with ~4,098 logical qubits can factor RSA-2048 in hours, completely compromising RSA, ECC, and Diffie-Hellman."
            )
            refs = ["Shor, P.W. (1994) Algorithms for quantum computation: discrete logarithms and factoring", "NIST IR 8413", "CNSA 2.0"]
        elif "grover" in query_lower:
            ans = (
                "Grover's Algorithm (Lov Grover, 1996) provides a quadratic quantum speedup for unstructured database "
                "search from O(N) to O(sqrt(N)). For symmetric ciphers like AES, it effectively cuts the brute-force security "
                "bitlength in half: AES-128 offers only 2^64 quantum operations (vulnerable), whereas AES-256 maintains "
                "2^128 operations (quantum-safe). For hash functions, Grover reduces preimage resistance from 2^n to 2^(n/2)."
            )
            refs = ["Grover, L.K. (1996) A fast quantum mechanical algorithm for database search", "NIST FIPS 197", "NSA CNSA 2.0"]
        else:
            ans = (
                f"Query regarding '{query}': To safeguard modern cryptographic systems against quantum threats, "
                "organizations must identify asymmetric algorithms (RSA, ECC, Diffie-Hellman) vulnerable to Shor's polynomial "
                "factoring and discrete logarithms, and symmetric ciphers with < 256 bits vulnerable to Grover's search. "
                "NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) provide standardized post-quantum replacements."
            )
            refs = ["NIST Post-Quantum Cryptography Standardization", "RFC 9180 HPKE with PQC", "FIPS 203 / 204 / 205"]

        response = {
            "query": query,
            "answer": ans,
            "references": refs,
            "engine": "deterministic_expert_system",
        }

        if use_llm and self.api_key:
            llm_ans = await self._augment_query_with_llm(query, ans)
            if llm_ans:
                response["answer"] = llm_ans
                response["engine"] = f"llm_augmented ({self.model})"

        return response

    # ──────────────────────────────────────────────────────────────────────────
    # Internal Theoretical & Cryptographic Foundations
    # ──────────────────────────────────────────────────────────────────────────

    def _analyze_theoretical_foundation(
        self, algorithm: str, key_size: Optional[int], primitive: str
    ) -> Dict[str, str]:
        """Evaluate mathematical attack basis and qubit requirements."""
        algo = algorithm.upper()

        if any(k in algo for k in ["RSA"]):
            k_size = key_size or 2048
            qubits = 2 * k_size + 2
            return {
                "inferred_primitive": "asymmetric",
                "default_status": "vulnerable",
                "attack_algorithm": "Shor's Order-Finding Algorithm",
                "mathematical_basis": (
                    f"Order finding in the multiplicative group (Z/{k_size}Z)*. Classically, factoring composite N "
                    f"requires General Number Field Sieve (GNFS) in sub-exponential time O(exp((64/9)^(1/3) * (ln N)^(1/3) * (ln ln N)^(2/3))). "
                    f"Shor's quantum algorithm solves period-finding in polynomial time O((log N)^3) via the Quantum Fourier Transform (QFT)."
                ),
                "quantum_complexity": f"Polynomial time O((log N)^3) — broken in hours on CRQC",
                "qubits_required_estimate": f"~{qubits:,} logical qubits (~20 million physical qubits with surface code error correction)",
            }

        elif any(k in algo for k in ["ECDSA", "ECDH", "ED25519", "ECC", "SECP", "CURVE25519", "PRIME256V1"]):
            k_size = key_size or 256
            qubits = 9 * k_size  # ~2,330 logical qubits for 256-bit ECC
            return {
                "inferred_primitive": "asymmetric",
                "default_status": "vulnerable",
                "attack_algorithm": "Shor's Discrete Logarithm Algorithm on Elliptic Curves",
                "mathematical_basis": (
                    "Elliptic Curve Discrete Logarithm Problem (ECDLP) in E(F_p). While ECDLP has no sub-exponential "
                    "classical algorithms (Pollard's rho requires O(sqrt(p))), Shor's algorithm maps the discrete log "
                    "to a two-dimensional period-finding problem over Z_r x Z_r, collapsing security to polynomial time O(n^3)."
                ),
                "quantum_complexity": "Polynomial time O(n^3) — faster to break than RSA for equivalent security levels",
                "qubits_required_estimate": f"~2,330 logical qubits for {k_size}-bit curve (Roetteler et al. 2017)",
            }

        elif any(k in algo for k in ["DH", "DIFFIE", "DSA"]):
            k_size = key_size or 2048
            return {
                "inferred_primitive": "asymmetric",
                "default_status": "vulnerable",
                "attack_algorithm": "Shor's Discrete Logarithm Algorithm",
                "mathematical_basis": (
                    "Finite field discrete logarithm problem (DLP) in F_p*. Shor's algorithm determines secret exponents "
                    "x in g^x = h (mod p) in polynomial time O((log p)^3), allowing full passive decryption of recorded sessions."
                ),
                "quantum_complexity": "Polynomial time O((log p)^3)",
                "qubits_required_estimate": f"~{2 * k_size + 2:,} logical qubits",
            }

        elif "AES-128" in algo:
            return {
                "inferred_primitive": "symmetric",
                "default_status": "reduced_security_margin",
                "attack_algorithm": "Grover's Quantum Key Search Algorithm",
                "mathematical_basis": (
                    "Quantum amplitude amplification over 2^128 key space. Grover's algorithm evaluates oracle iterations "
                    "in O(sqrt(N)) time, reducing the brute-force complexity from 2^128 classical operations to 2^64 quantum operations. "
                    "2^64 operations is within the computational horizon of well-funded adversaries."
                ),
                "quantum_complexity": "O(2^64) — effective 64-bit security margin",
                "qubits_required_estimate": "~3,000 to ~6,000 logical qubits for quantum oracle circuit evaluation",
            }

        elif "AES-256" in algo:
            return {
                "inferred_primitive": "symmetric",
                "default_status": "safe",
                "attack_algorithm": "Grover's Quantum Search (Mitigated)",
                "mathematical_basis": (
                    "Grover's quadratic speedup reduces the 2^256 key search space to O(sqrt(2^256)) = 2^128 operations. "
                    "2^128 operations remains computationally intractable under the laws of physics, maintaining 128-bit post-quantum security."
                ),
                "quantum_complexity": "O(2^128) — full post-quantum security margin preserved",
                "qubits_required_estimate": "N/A — brute force computationally infeasible",
            }

        elif any(k in algo for k in ["ML-KEM", "KYBER"]):
            return {
                "inferred_primitive": "pqc",
                "default_status": "safe",
                "attack_algorithm": "None known (Resistant to Shor and Grover)",
                "mathematical_basis": (
                    "Hardness of the Module Learning With Errors (M-LWE) problem over polynomial rings R_q = Z_q[X]/(X^256 + 1). "
                    "M-LWE reduces to the worst-case Shortest Vector Problem (SVP) in module lattices, for which no polynomial-time "
                    "quantum or classical algorithm is known."
                ),
                "quantum_complexity": "NIST Security Category 3 (>= 128 bits post-quantum security)",
                "qubits_required_estimate": "Quantum resistant — no polynomial speedup exists",
            }

        elif any(k in algo for k in ["ML-DSA", "DILITHIUM"]):
            return {
                "inferred_primitive": "pqc",
                "default_status": "safe",
                "attack_algorithm": "None known (Resistant to Shor and Grover)",
                "mathematical_basis": (
                    "Hardness of Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS). "
                    "Uses Fiat-Shamir with Aborts over lattice structures. Immune to hidden subgroup quantum attacks."
                ),
                "quantum_complexity": "NIST Security Category 3 (>= 128 bits post-quantum security)",
                "qubits_required_estimate": "Quantum resistant",
            }

        elif any(k in algo for k in ["SLH-DSA", "SPHINCS"]):
            return {
                "inferred_primitive": "pqc",
                "default_status": "safe",
                "attack_algorithm": "None known (Conservative Hash-Based)",
                "mathematical_basis": (
                    "Stateless hash-based signature scheme using Few-Time Signatures (FORS) and hypertree structures (XMSS/WOTS+). "
                    "Relies solely on standard collision and preimage resistance of underlying cryptographic hashes."
                ),
                "quantum_complexity": "NIST Category 1-5 security depending on parameter choice",
                "qubits_required_estimate": "Quantum resistant",
            }

        elif any(k in algo for k in ["SHA-1", "MD5", "DES", "3DES", "RC4"]):
            return {
                "inferred_primitive": "legacy",
                "default_status": "vulnerable",
                "attack_algorithm": "Classical Collision / Linear Cryptanalysis + Quantum Amplification",
                "mathematical_basis": (
                    "Algorithm is already broken classically due to mathematical weaknesses (differential/linear attacks, small blocks, MD collisions). "
                    "Quantum search renders remaining security completely negligible."
                ),
                "quantum_complexity": "Trivially breakable classically and quantumly",
                "qubits_required_estimate": "< 500 qubits",
            }

        else:
            return {
                "inferred_primitive": primitive or "cryptographic_primitive",
                "default_status": "vulnerable" if primitive in ["asymmetric", "protocol"] else "unknown",
                "attack_algorithm": "Heuristic Shor / Grover Analysis",
                "mathematical_basis": "Algorithm evaluated against NIST Post-Quantum Cryptographic standard categories.",
                "quantum_complexity": "Depends on underlying group or key size",
                "qubits_required_estimate": "Estimated > 2,000 logical qubits",
            }

    def _evaluate_hndl_risk(
        self, algorithm: str, sensitivity: str, quantum_status: str, source_type: str
    ) -> Dict[str, str]:
        """Evaluate Harvest Now, Decrypt Later risk exposure."""
        algo = algorithm.upper()
        high_sensitivity = sensitivity in ["financial", "medical", "government_id", "authentication", "pii"]
        is_asymmetric_vulnerable = any(k in algo for k in ["RSA", "ECC", "ECDSA", "ECDH", "DH", "DSA", "ED25519"])

        if is_asymmetric_vulnerable and high_sensitivity:
            exposure = "CRITICAL"
            threat = (
                f"Adversaries actively collect ciphertext transmitted or encrypted with {algorithm}. "
                f"Because this data has high business/regulatory longevity ({sensitivity}), adversaries will decrypt "
                "stored records once CRQC hardware comes online, exposing historical secrets."
            )
            impact = "Complete loss of confidentiality for historical archives and past network sessions."
        elif is_asymmetric_vulnerable:
            exposure = "HIGH"
            threat = (
                f"{algorithm} provides zero forward secrecy against future quantum computers. "
                "Recorded sessions can be decrypted in batch mode retrospectively."
            )
            impact = "Past encrypted transmissions subject to retrospective decryption."
        elif "AES-128" in algo:
            exposure = "MEDIUM"
            threat = (
                "Encrypted data stored today may become vulnerable to Grover key searches if quantum computers with "
                "sufficient gate-depth and error correction scale within the next 10-15 years."
            )
            impact = "Reduced security margin (64-bit effective quantum strength)."
        elif quantum_status == "safe" or any(k in algo for k in ["ML-KEM", "ML-DSA", "SLH-DSA", "AES-256"]):
            exposure = "NONE"
            threat = "Algorithm resists known quantum attack algorithms (Shor and Grover). Ciphertext cannot be retroactively broken."
            impact = "Long-term data confidentiality guaranteed against quantum adversaries."
        else:
            exposure = "LOW"
            threat = "Standard cryptographic risk; no immediate high-priority HNDL interception vector detected."
            impact = "Limited exposure based on observed asset context."

        return {
            "hndl_exposure": exposure,
            "threat_description": threat,
            "confidentiality_impact": impact,
        }

    def _get_regulatory_implications(self, algorithm: str) -> Dict[str, str]:
        """Map algorithm to NIST, NSA CNSA 2.0, and international regulatory mandates."""
        algo = algorithm.upper()

        if any(k in algo for k in ["RSA", "ECC", "ECDSA", "ECDH", "DH", "DSA", "ED25519"]):
            return {
                "cnsa_deadline": "NSA CNSA 2.0 mandates transition start in 2025; exclusive PQC use by 2030; legacy disallowed by 2033.",
                "nist_standard": "NIST SP 800-131A Rev 2 deprecates after 2030. Replaced by FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA).",
                "compliance_summary": "Non-compliant for high-assurance or government workloads after 2030. Immediate migration planning required.",
            }
        elif "AES-128" in algo:
            return {
                "cnsa_deadline": "CNSA 2.0 exclusively authorizes AES-256 for national security systems; AES-128 is not permitted.",
                "nist_standard": "NIST SP 800-131A currently allows 128-bit classical security, but recommends 256-bit for quantum resilience.",
                "compliance_summary": "Fails CNSA 2.0 requirements. Upgrade to AES-256-GCM is required for defense and critical infrastructure.",
            }
        elif any(k in algo for k in ["ML-KEM", "KYBER"]):
            return {
                "cnsa_deadline": "Approved and designated as the primary post-quantum KEM standard under CNSA 2.0.",
                "nist_standard": "Standardized under NIST FIPS 203 (August 2024).",
                "compliance_summary": "Fully compliant with federal and international post-quantum mandates.",
            }
        elif any(k in algo for k in ["ML-DSA", "DILITHIUM"]):
            return {
                "cnsa_deadline": "Approved and designated as primary post-quantum signature algorithm under CNSA 2.0.",
                "nist_standard": "Standardized under NIST FIPS 204 (August 2024).",
                "compliance_summary": "Fully compliant with post-quantum digital signature standards.",
            }
        else:
            return {
                "cnsa_deadline": "Subject to CNSA 2.0 symmetric/asymmetric algorithm transition guidelines.",
                "nist_standard": "Evaluate against NIST Post-Quantum Cryptography transition standards.",
                "compliance_summary": "Review against organizational cryptographic policy.",
            }

    def _generate_remediation(
        self, finding: Dict[str, Any], algorithm: str, key_size: Optional[int]
    ) -> Dict[str, str]:
        """Produce concrete code snippet and migration configuration."""
        algo = algorithm.upper()

        if any(k in algo for k in ["RSA", "DSA", "ECDSA"]) and ("SIGN" in str(finding.get("usage", "")).upper() or "AUTHENTICATION" in str(finding.get("usage", "")).upper()):
            snippet = CODE_TEMPLATES.get("RSA_SIGN", {}).get("python", "")
            config = CODE_TEMPLATES.get("RSA_SIGN", {}).get("tls", "")
            target_algo = "ML-DSA-65"
            std = "NIST FIPS 204"
            urgency = "HIGH (P1)"
        elif any(k in algo for k in ["RSA", "DH", "ECDH", "ECC", "CURVE25519", "X25519"]):
            snippet = CODE_TEMPLATES.get("RSA_KEX", {}).get("python", "")
            config = CODE_TEMPLATES.get("RSA_KEX", {}).get("tls", "")
            target_algo = "ML-KEM-768 (or Hybrid X25519+ML-KEM-768)"
            std = "NIST FIPS 203"
            urgency = "CRITICAL (P0 — HNDL Threat)"
        elif "AES-128" in algo or "AES" in algo:
            snippet = CODE_TEMPLATES.get("SYMMETRIC_UPGRADE", {}).get("python", "")
            config = CODE_TEMPLATES.get("SYMMETRIC_UPGRADE", {}).get("tls", "")
            target_algo = "AES-256-GCM"
            std = "NIST SP 800-38D / CNSA 2.0"
            urgency = "MEDIUM (P2)"
        else:
            snippet = "# Upgrade to approved NIST Post-Quantum Algorithm (FIPS 203 / 204)"
            config = "# Configure TLS 1.3 with post-quantum hybrid key exchange (e.g. X25519MLKEM768)"
            target_algo = "ML-KEM-768 / ML-DSA-65"
            std = "NIST FIPS 203 / 204"
            urgency = "LOW (P3)"

        return {
            "recommended_replacement": target_algo,
            "target_standard": std,
            "migration_urgency": urgency,
            "code_snippet": snippet,
            "configuration_changes": config,
        }

    def _synthesize_summary(
        self, algorithm: str, key_size: Optional[int], quantum_status: str, theory: Dict[str, str], target_audience: str
    ) -> str:
        """Synthesize human-readable executive or engineering summary."""
        key_str = f"-{key_size}" if key_size else ""
        algo_name = f"{algorithm}{key_str}"

        if quantum_status == "safe":
            return (
                f"{algo_name} is mathematically resistant to known quantum cryptanalytic attacks. "
                "It fulfills NIST post-quantum security requirements and provides strong forward secrecy against future quantum computers."
            )
        elif quantum_status == "reduced_security_margin":
            return (
                f"{algo_name} experiences a quadratic security reduction under Grover's Algorithm, "
                f"reducing its effective security to {theory.get('quantum_complexity', 'reduced levels')}. "
                "Migrating to AES-256 restores a full 128-bit quantum security margin."
            )
        else:
            return (
                f"{algo_name} is fully vulnerable to {theory.get('attack_algorithm', 'Shor\'s Algorithm')}. "
                f"A quantum computer with approximately {theory.get('qubits_required_estimate', 'several thousand logical qubits')} "
                "can factor the modulus or solve the discrete logarithm in polynomial time O((log N)^3), completely breaking encryption and signatures."
            )

    # ──────────────────────────────────────────────────────────────────────────
    # LLM Augmentation Integration
    # ──────────────────────────────────────────────────────────────────────────

    async def _augment_with_llm(self, explanation: Dict[str, Any], target_audience: str) -> Optional[str]:
        """Optional refinement using an OpenAI-compatible / Gemini endpoint."""
        prompt = (
            f"As a principal post-quantum cryptographer, review this cryptographic vulnerability finding:\n"
            f"Algorithm: {explanation.get('algorithm')}\n"
            f"Primitive: {explanation.get('primitive')}\n"
            f"Quantum Status: {explanation.get('quantum_status')}\n"
            f"Theoretical Basis: {explanation.get('theoretical_foundation', {}).get('mathematical_basis')}\n"
            f"HNDL Exposure: {explanation.get('harvest_now_decrypt_later_risk', {}).get('hndl_exposure')}\n\n"
            f"Write a concise, 2-3 paragraph technical explanation tailored for a {target_audience}. "
            "Explain exactly why quantum computers break this primitive, the danger of Harvest Now Decrypt Later, "
            "and why the recommended FIPS replacement provides mathematical safety."
        )
        return await self._call_llm(prompt, "You are an elite post-quantum cryptographic security assistant.")

    async def _augment_scan_summary_with_llm(self, scan_summary: Dict[str, Any]) -> Optional[str]:
        """Optional refinement for executive scan summary."""
        prompt = (
            f"Summarize this organization's post-quantum readiness for an executive board:\n"
            f"Total Assets: {scan_summary.get('total_findings')}\n"
            f"Vulnerable Findings: {scan_summary.get('vulnerable_findings_count')}\n"
            f"Quantum Safe Findings: {scan_summary.get('quantum_safe_count')}\n"
            f"Primary Vectors: {', '.join(scan_summary.get('primary_quantum_vectors', []))}\n"
            "Highlight the regulatory and business risk (CNSA 2.0, HNDL), and summarize the priority action plan."
        )
        return await self._call_llm(prompt, "You are a Chief Information Security Officer post-quantum advisor.")

    async def _augment_query_with_llm(self, query: str, base_answer: str) -> Optional[str]:
        """Refine Q&A query using LLM."""
        prompt = (
            f"User Query: {query}\n\n"
            f"Base Cryptographic Answer:\n{base_answer}\n\n"
            "Provide an expanded, authoritative, mathematically precise answer with references."
        )
        return await self._call_llm(prompt, "You are a world-class cryptographer explaining post-quantum concepts.")

    async def _call_llm(self, prompt: str, system_prompt: str) -> Optional[str]:
        """Execute async HTTP request to LLM provider with graceful exception handling."""
        if not self.api_key:
            return None

        try:
            url = f"{self.api_base.rstrip('/')}/chat/completions"
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 500,
            }

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, headers=headers, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    choices = data.get("choices", [])
                    if choices:
                        return choices[0].get("message", {}).get("content", "").strip()
                else:
                    logger.warning(f"LLM API returned status {response.status_code}: {response.text}")
        except Exception as e:
            logger.warning(f"Failed to communicate with LLM provider: {e}")

        return None
