"""Converter — bridge between existing network Asset and canonical CryptoAsset.

Allows existing network scanner results to be normalized into the
unified CryptoAsset representation without rewriting the scanner itself.
Future scanners should create CryptoAsset records directly.
"""

from __future__ import annotations

from typing import List

from app.models.asset import Asset
from app.models.crypto_asset import CryptoAsset


def crypto_asset_from_network_asset(asset: Asset) -> CryptoAsset:
    """Convert a network-scanner Asset to a canonical CryptoAsset.

    Maps the network-specific fields onto the unified schema.
    The original Asset is **not** modified or deleted.

    Args:
        asset: An existing network-scanner Asset ORM instance.

    Returns:
        A new (unsaved) CryptoAsset ORM instance.
    """
    # Derive protocol from tls_versions if available
    protocol = None
    if asset.tls_versions and isinstance(asset.tls_versions, list):
        protocol = asset.tls_versions[0] if asset.tls_versions else None

    # Derive algorithm + key_size from certificate data
    algorithm = None
    key_size = None
    if asset.certificate and isinstance(asset.certificate, dict):
        algorithm = asset.certificate.get("signature_algorithm")
        key_size = asset.certificate.get("key_size")

    # Derive primary cipher suite name
    cipher_suite = None
    if asset.cipher_suites and isinstance(asset.cipher_suites, list):
        first = asset.cipher_suites[0]
        if isinstance(first, dict):
            cipher_suite = first.get("name") or first.get("cipher")
        elif isinstance(first, str):
            cipher_suite = first

    return CryptoAsset(
        scan_id=asset.scan_id,
        asset_type="network_endpoint",
        source_type="network",
        name=f"{asset.hostname}:{asset.port}",
        protocol=protocol,
        algorithm=algorithm,
        key_size=key_size,
        key_exchange=asset.key_exchange,
        cipher_suite=cipher_suite,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
        port=asset.port,
        pqc_status=asset.pqc_status,
        risk_score=asset.risk_score,
        vulnerabilities=asset.vulnerabilities,
        recommendations=asset.recommendations,
        details={
            "service_type": asset.service_type,
            "tls_versions": asset.tls_versions,
            "cipher_suites": asset.cipher_suites,
            "certificate": asset.certificate,
            "cert_chain_length": asset.cert_chain_length,
            "hsts_enabled": asset.hsts_enabled,
            "ocsp_stapling": asset.ocsp_stapling,
            "original_asset_id": str(asset.id),
        },
    )


def crypto_assets_from_network_assets(assets: List[Asset]) -> List[CryptoAsset]:
    """Batch convert a list of network Assets to CryptoAssets.

    Args:
        assets: A list of network-scanner Asset ORM instances.

    Returns:
        A list of new (unsaved) CryptoAsset ORM instances.
    """
    return [crypto_asset_from_network_asset(a) for a in assets]
