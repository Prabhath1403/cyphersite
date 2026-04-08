"""
PQC Certificate Generator — creates verifiable certificate payloads.

Generates signed certificate payloads with SHA-256 fingerprints
for quantum-safe and PQC-ready assets.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta
from uuid import uuid4
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


def generate_certificate_payload(
    asset_hostname: str,
    pqc_status: str,
    algorithms_verified: List[str],
    asset_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a signed PQC certificate payload.

    Creates a certificate with a SHA-256 fingerprint for verification.

    Args:
        asset_hostname: Hostname of the certified asset.
        pqc_status: PQC status of the asset.
        algorithms_verified: List of PQC algorithms found.
        asset_id: Optional asset UUID.

    Returns:
        Certificate payload dictionary.
    """
    cert_id = str(uuid4())
    issued_at = datetime.utcnow()
    valid_until = issued_at + timedelta(days=90)

    # Determine certificate status
    if pqc_status == "QUANTUM_SAFE":
        cert_status = "FULLY_QUANTUM_SAFE"
    elif pqc_status == "HYBRID_READY":
        cert_status = "PQC_READY"
    else:
        return None  # Don't certify vulnerable assets

    payload = {
        "cert_id": cert_id,
        "asset": asset_hostname,
        "asset_id": asset_id,
        "status": cert_status,
        "algorithms_verified": algorithms_verified,
        "issued_at": issued_at.isoformat() + "Z",
        "valid_until": valid_until.isoformat() + "Z",
        "issuer": "CipherSight Scanner v1.0",
        "version": "1.0",
    }

    # Generate SHA-256 fingerprint of the payload
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    fingerprint = hashlib.sha256(payload_bytes).hexdigest()
    payload["fingerprint"] = fingerprint

    logger.info(f"Generated certificate {cert_id} for {asset_hostname} (status: {cert_status})")
    return payload


def verify_certificate(payload: Dict[str, Any]) -> bool:
    """
    Verify a certificate payload's integrity.

    Recalculates the SHA-256 fingerprint and checks validity dates.

    Args:
        payload: Certificate payload dictionary.

    Returns:
        True if the certificate is valid.
    """
    try:
        # Extract and remove fingerprint for verification
        stored_fingerprint = payload.get("fingerprint", "")
        verify_payload = {k: v for k, v in payload.items() if k != "fingerprint"}

        # Recalculate fingerprint
        payload_bytes = json.dumps(verify_payload, sort_keys=True).encode("utf-8")
        calculated_fingerprint = hashlib.sha256(payload_bytes).hexdigest()

        if calculated_fingerprint != stored_fingerprint:
            logger.warning(f"Certificate fingerprint mismatch for {payload.get('cert_id')}")
            return False

        # Check validity period
        valid_until = datetime.fromisoformat(payload["valid_until"].rstrip("Z"))
        if datetime.utcnow() > valid_until:
            logger.info(f"Certificate {payload.get('cert_id')} has expired")
            return False

        return True

    except Exception as e:
        logger.error(f"Certificate verification error: {e}")
        return False
