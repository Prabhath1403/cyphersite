"""
Cryptographic Migration Recommender — generates actionable, code-level
remediation plans, library upgrade paths, and prioritized roadmaps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MigrationAction:
    """Actionable migration recommendation for a single cryptographic finding."""
    finding_id: Optional[str]
    asset_name: str
    current_algorithm: str
    target_algorithm: str
    target_standard: str                 # NIST FIPS 203, FIPS 204, FIPS 205, etc.
    priority: str                        # P0_CRITICAL | P1_HIGH | P2_MEDIUM | P3_LOW
    urgency_reason: str
    estimated_effort_hours: int
    code_remediation_snippet: str
    configuration_changes: str
    testing_checklist: List[str] = field(default_factory=list)


CODE_TEMPLATES: Dict[str, Dict[str, str]] = {
    "RSA_SIGN": {
        "python": (
            "# --- Post-Quantum Remediation: Replace RSA with ML-DSA-65 (FIPS 204) ---\n"
            "# Using liboqs-python or pure Python FIPS 204 implementation:\n"
            "import oqs\n\n"
            "# Sign with ML-DSA-65:\n"
            "with oqs.Signature('ML-DSA-65') as signer:\n"
            "    public_key = signer.generate_keypair()\n"
            "    signature = signer.sign(message_bytes)\n"
            "    # Verification:\n"
            "    is_valid = signer.verify(message_bytes, signature, public_key)\n"
        ),
        "tls": (
            "# Configure TLS server with post-quantum digital signature support:\n"
            "ssl_protocols TLSv1.3;\n"
            "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\n"
            "ssl_certificate /etc/ssl/certs/mldsa65_cert.pem;\n"
        ),
    },
    "RSA_KEX": {
        "python": (
            "# --- Post-Quantum Remediation: Replace RSA/DH KEX with ML-KEM-768 (FIPS 203) ---\n"
            "import oqs\n\n"
            "# Client generates keypair:\n"
            "with oqs.KeyEncapsulation('ML-KEM-768') as client_kem:\n"
            "    client_public_key = client_kem.generate_keypair()\n"
            "    # Server encapsulates shared secret:\n"
            "    with oqs.KeyEncapsulation('ML-KEM-768') as server_kem:\n"
            "        ciphertext, server_shared_secret = server_kem.encap_secret(client_public_key)\n"
            "    # Client decapsulates shared secret:\n"
            "    client_shared_secret = client_kem.decap_secret(ciphertext)\n"
            "    assert client_shared_secret == server_shared_secret\n"
        ),
        "tls": (
            "# NGINX with OpenSSL 3.x + oqs-provider:\n"
            "ssl_protocols TLSv1.3;\n"
            "ssl_conf_command Curves X25519MLKEM768:X25519Kyber768Draft00:X25519;\n"
        ),
    },
    "SYMMETRIC_UPGRADE": {
        "python": (
            "# --- Upgrade Symmetric Cipher to AES-256-GCM for 128-bit quantum margin ---\n"
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "import os\n\n"
            "key = AESGCM.generate_key(bit_length=256)  # 256-bit key for post-quantum safety\n"
            "aesgcm = AESGCM(key)\n"
            "nonce = os.urandom(12)\n"
            "ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)\n"
        ),
        "tls": (
            "# Enforce AES-256-GCM in TLS 1.3:\n"
            "ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;\n"
            "ssl_prefer_server_ciphers on;\n"
        ),
    },
    "HASH_UPGRADE": {
        "python": (
            "# --- Replace broken MD5/SHA-1 with SHA-256 / SHA-3 ---\n"
            "import hashlib\n\n"
            "digest = hashlib.sha256(data_bytes).hexdigest()\n"
        ),
        "tls": "",
    },
}


class MigrationRecommender:
    """
    Generates actionable migration recommendations and priorities for
    cryptographic findings.
    """

    @classmethod
    def recommend_for_finding(cls, finding: Any) -> MigrationAction:
        f = finding.__dict__ if hasattr(finding, "__dict__") else finding

        finding_id = str(f.get("id")) if f.get("id") else None
        name = f.get("name") or "Cryptographic Asset"
        algorithm = (f.get("algorithm") or "Unknown").strip()
        algo_upper = algorithm.upper()
        usage = (f.get("usage") or "").lower()
        primitive = (f.get("primitive") or "").lower()
        sensitivity = (f.get("sensitivity") or "MEDIUM").upper()
        risk_score = float(f.get("risk_score") or 0.0)
        source_type = f.get("source_type") or "source_code"

        # 1. Determine Target Algorithm & Templates
        if any(a in algo_upper for a in ("RSA", "DSA", "ECDSA", "SIGN")):
            if "key_exchange" in usage or "encryption" in usage:
                target_algo = "ML-KEM-768"
                target_std = "NIST FIPS 203 (Module Lattice KEM)"
                template_key = "RSA_KEX"
            else:
                target_algo = "ML-DSA-65"
                target_std = "NIST FIPS 204 (Module Lattice Digital Signature)"
                template_key = "RSA_SIGN"
        elif any(a in algo_upper for a in ("DIFFIE", "DH", "ECDH", "CURVE25519", "X25519")):
            target_algo = "ML-KEM-768 (or Hybrid X25519+ML-KEM)"
            target_std = "NIST FIPS 203"
            template_key = "RSA_KEX"
        elif any(a in algo_upper for a in ("128", "DES", "3DES", "RC4")):
            target_algo = "AES-256-GCM"
            target_std = "NIST SP 800-38D (256-bit AEAD)"
            template_key = "SYMMETRIC_UPGRADE"
        elif any(a in algo_upper for a in ("MD5", "SHA1", "SHA-1")):
            target_algo = "SHA-256 or SHA3-256"
            target_std = "FIPS 180-4 / FIPS 202"
            template_key = "HASH_UPGRADE"
        else:
            target_algo = "ML-KEM-768 / ML-DSA-65"
            target_std = "NIST PQC Standards"
            template_key = "RSA_KEX"

        # 2. Priority Classification
        if risk_score >= 80.0 or (sensitivity == "CRITICAL" and "safe" not in (f.get("quantum_status") or "")):
            priority = "P0_CRITICAL"
            urgency = "Immediate HNDL exposure or classical vulnerability. Migration must be prioritized."
            effort = 16
        elif risk_score >= 60.0 or sensitivity == "HIGH":
            priority = "P1_HIGH"
            urgency = "High quantum vulnerability protecting sensitive application data. Schedule for upcoming sprint."
            effort = 8
        elif risk_score >= 35.0:
            priority = "P2_MEDIUM"
            urgency = "Reduced post-quantum security margin. Upgrade symmetric key sizes during normal refactoring."
            effort = 4
        else:
            priority = "P3_LOW"
            urgency = "Cryptographic hygiene or already post-quantum resilient."
            effort = 2

        # 3. Select Snippet
        code_type = "tls" if source_type == "network" else "python"
        snippet = CODE_TEMPLATES.get(template_key, {}).get(code_type, CODE_TEMPLATES.get(template_key, {}).get("python", ""))

        checklist = [
            f"Verify dependency support for {target_algo} (e.g. liboqs, cryptography 44+, OpenSSL 3.x)",
            "Deploy hybrid fallback for legacy client compatibility",
            "Perform regression benchmark on signature/ciphertext serialization overhead",
            "Validate compliance against CNSA 2.0 and NIST guidelines",
        ]

        return MigrationAction(
            finding_id=finding_id,
            asset_name=name,
            current_algorithm=algorithm,
            target_algorithm=target_algo,
            target_standard=target_std,
            priority=priority,
            urgency_reason=urgency,
            estimated_effort_hours=effort,
            code_remediation_snippet=snippet,
            configuration_changes=f"Update protocol configurations to mandate {target_algo}.",
            testing_checklist=checklist,
        )

    @classmethod
    def generate_plan_for_findings(cls, findings: List[Any]) -> List[MigrationAction]:
        """
        Generate and prioritize migration actions sorted by urgency (P0 -> P1 -> P2 -> P3).
        """
        priority_weights = {"P0_CRITICAL": 0, "P1_HIGH": 1, "P2_MEDIUM": 2, "P3_LOW": 3}
        actions = [cls.recommend_for_finding(f) for f in findings]
        actions.sort(key=lambda a: priority_weights.get(a.priority, 99))
        return actions
