"""
Tests for the Unified Scan Pipeline and CryptoNormalizer.
"""

import json
from pathlib import Path
import pytest

from app.core.source_scanner import CryptoFindingData, ScanTarget
from app.core.pipeline import CryptoNormalizer, UnifiedScanPipeline


def test_crypto_normalizer_canonicalize_algorithm():
    """Test algorithm name resolution and canonicalization."""
    c_algo, family, prim = CryptoNormalizer.canonicalize_algorithm("kyber768")
    assert c_algo == "ML-KEM-768"
    assert prim == "pqc"

    c_algo, family, prim = CryptoNormalizer.canonicalize_algorithm("dilithium3")
    assert c_algo == "ML-DSA-65"
    assert prim == "pqc"

    c_algo, family, prim = CryptoNormalizer.canonicalize_algorithm("secp256r1")
    assert c_algo == "ECDSA-P256"
    assert prim == "asymmetric"

    c_algo, family, prim = CryptoNormalizer.canonicalize_algorithm("aes_256_gcm")
    assert c_algo == "AES-256-GCM"
    assert prim == "symmetric"

    c_algo, family, prim = CryptoNormalizer.canonicalize_algorithm("sha256")
    assert c_algo == "SHA-256"
    assert prim == "hash"


def test_crypto_normalizer_evaluate_pqc_status():
    """Test deterministic PQC risk and status derivation."""
    pqc, q_stat, score, level = CryptoNormalizer.evaluate_pqc_status("pqc", "ML-KEM-768")
    assert pqc == "QUANTUM_SAFE"
    assert q_stat == "safe"
    assert score == 0.0
    assert level == "INFO"

    pqc, q_stat, score, level = CryptoNormalizer.evaluate_pqc_status("asymmetric", "RSA-2048")
    assert pqc == "VULNERABLE"
    assert q_stat == "vulnerable"
    assert score >= 85.0
    assert level in ("HIGH", "CRITICAL")

    pqc, q_stat, score, level = CryptoNormalizer.evaluate_pqc_status("symmetric", "AES-128-GCM")
    assert pqc == "REDUCED_SECURITY_MARGIN"
    assert q_stat == "reduced_security_margin"
    assert score == 40.0
    assert level == "MEDIUM"

    pqc, q_stat, score, level = CryptoNormalizer.evaluate_pqc_status("symmetric", "DES")
    assert pqc == "VULNERABLE"
    assert level == "CRITICAL"


def test_normalize_finding_in_place():
    """Test finding object normalization."""
    finding = CryptoFindingData(
        name="raw finding",
        asset_type="binary_usage",
        source_type="binary",
        algorithm="kyber512",
        confidence=1.5,  # Needs clamping
    )
    normalized = CryptoNormalizer.normalize_finding(finding)

    assert normalized.algorithm == "ML-KEM-512"
    assert normalized.primitive == "pqc"
    assert normalized.pqc_status == "QUANTUM_SAFE"
    assert normalized.quantum_status == "safe"
    assert normalized.risk_score == 0.0
    assert normalized.confidence == 1.0


def test_unified_scan_pipeline_execution(tmp_path):
    """Test UnifiedScanPipeline end-to-end execution on a sample target."""
    pipeline = UnifiedScanPipeline()

    # Create a dummy Python file with crypto usage
    sample_file = tmp_path / "crypto_service.py"
    sample_file.write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "h = hashlib.sha256(b'test').hexdigest()\n"
    )

    target = ScanTarget(
        path=str(tmp_path),
        scan_type="source",
        depth="standard",
    )

    exec_result = pipeline.execute(target, scan_id="test-pipeline-run")

    assert exec_result.scan_type == "source"
    assert exec_result.total_assets >= 2
    assert exec_result.vulnerable_count >= 1  # RSA
    assert exec_result.cbom_json != ""

    cbom_dict = json.loads(exec_result.cbom_json)
    assert cbom_dict["bomFormat"] == "CycloneDX"
    assert len(cbom_dict["components"]) == exec_result.total_assets


def test_unified_scan_pipeline_unsupported_type():
    """Test pipeline error handling when an unknown scanner type is requested."""
    pipeline = UnifiedScanPipeline()
    target = ScanTarget(path="/dev/null", scan_type="quantum_teleportation")
    result = pipeline.execute(target)
    assert len(result.errors) == 1
    assert "No scanner registered" in result.errors[0]
