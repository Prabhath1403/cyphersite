"""
Tests for the Data Sensitivity Inference Engine and HNDL Risk Estimator.
"""

import pytest

from app.core.source_scanner import CryptoFindingData
from app.core.sensitivity import SensitivityInferenceEngine, SensitivityLevel


def test_infer_critical_passwords():
    """Test inference of critical password hashing."""
    finding = CryptoFindingData(
        name="bcrypt password hash",
        asset_type="source_code_usage",
        source_type="source_code",
        algorithm="bcrypt",
        function_name="hash_user_password",
        file_path="/app/auth/security.py",
        usage="password_hashing",
    )
    result = SensitivityInferenceEngine.infer(finding)
    assert result.level == SensitivityLevel.CRITICAL
    assert result.confidence >= 0.70
    assert any("password" in r.lower() for r in result.rationale)


def test_infer_critical_pci_dss():
    """Test inference of credit card payment processing."""
    finding = CryptoFindingData(
        name="AES payment encryption",
        asset_type="source_code_usage",
        source_type="source_code",
        algorithm="AES-256-GCM",
        function_name="encrypt_credit_card_payload",
        file_path="/src/payments/gateway.py",
        usage="encryption",
    )
    result = SensitivityInferenceEngine.infer(finding)
    assert result.level == SensitivityLevel.CRITICAL
    assert "PCI-DSS" in result.regulatory_impact


def test_infer_high_session_jwt():
    """Test inference of session token signing."""
    finding = CryptoFindingData(
        name="RS256 JWT Signer",
        asset_type="source_code_usage",
        source_type="source_code",
        algorithm="RSA",
        function_name="sign_session_token",
        file_path="/src/identity/jwt.py",
        usage="digital_signature",
    )
    result = SensitivityInferenceEngine.infer(finding)
    assert result.level == SensitivityLevel.HIGH
    assert result.confidence >= 0.65


def test_infer_low_file_checksum():
    """Test inference of public file integrity check."""
    finding = CryptoFindingData(
        name="SHA-256 Asset Digest",
        asset_type="source_code_usage",
        source_type="source_code",
        algorithm="SHA-256",
        function_name="calculate_file_checksum",
        file_path="/src/static/cache.py",
        usage="hashing",
    )
    result = SensitivityInferenceEngine.infer(finding)
    assert result.level in (SensitivityLevel.LOW, SensitivityLevel.PUBLIC)


def test_hndl_exposure_rating_vulnerable_vs_pqc():
    """Test that quantum-vulnerable encryption with sensitive data flags EXTREME HNDL."""
    # 1. Vulnerable RSA key exchange with Critical payment data
    vuln_finding = CryptoFindingData(
        name="RSA Key Exchange",
        asset_type="network_endpoint",
        source_type="network",
        algorithm="RSA",
        quantum_status="vulnerable",
        pqc_status="VULNERABLE",
        usage="key_exchange",
        file_path="/payments/checkout.py",
        function_name="exchange_card_key",
    )
    vuln_result = SensitivityInferenceEngine.infer(vuln_finding)
    assert vuln_result.level == SensitivityLevel.CRITICAL
    assert vuln_result.hndl_exposure == "EXTREME"

    # Enriching adds HNDL warning to vulnerabilities list
    enriched = SensitivityInferenceEngine.enrich_finding(vuln_finding)
    assert enriched.sensitivity == "CRITICAL"
    assert any("HNDL" in v for v in enriched.vulnerabilities)

    # 2. Quantum Safe ML-KEM with Critical payment data
    pqc_finding = CryptoFindingData(
        name="ML-KEM Key Exchange",
        asset_type="network_endpoint",
        source_type="network",
        algorithm="ML-KEM-768",
        quantum_status="safe",
        pqc_status="QUANTUM_SAFE",
        usage="key_exchange",
        file_path="/payments/checkout.py",
        function_name="exchange_card_key",
    )
    pqc_result = SensitivityInferenceEngine.infer(pqc_finding)
    assert pqc_result.level == SensitivityLevel.CRITICAL
    assert pqc_result.hndl_exposure == "NEGLIGIBLE"


def test_batch_enrich():
    """Test batch enrichment of finding collections."""
    findings = [
        CryptoFindingData(
            name="f1",
            asset_type="source_code_usage",
            source_type="source_code",
            algorithm="RSA",
            function_name="hash_password",
        ),
        CryptoFindingData(
            name="f2",
            asset_type="source_code_usage",
            source_type="source_code",
            algorithm="SHA-256",
            function_name="compute_etag",
        ),
    ]
    enriched = SensitivityInferenceEngine.batch_enrich(findings)
    assert len(enriched) == 2
    assert enriched[0].sensitivity == "CRITICAL"
    assert enriched[1].sensitivity in ("LOW", "PUBLIC")
