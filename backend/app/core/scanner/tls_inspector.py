"""
TLS Inspector — deep TLS/SSL fingerprinting.

Extracts TLS versions, cipher suites, certificate details,
key exchange algorithms, and security features for each endpoint.
"""

import asyncio
import logging
import ssl
import socket
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    """Parsed certificate information."""
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    san: List[str] = field(default_factory=list)
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    public_key_algorithm: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    version: int = 0

    def to_dict(self):
        return asdict(self)


@dataclass
class TLSFingerprint:
    """Complete TLS fingerprint for an endpoint."""
    host: str = ""
    port: int = 443
    tls_versions: List[str] = field(default_factory=list)
    cipher_suites: List[Dict[str, Any]] = field(default_factory=list)
    certificate: Dict[str, Any] = field(default_factory=dict)
    key_exchange: str = ""
    cert_chain_length: int = 0
    hsts_enabled: str = "unknown"
    ocsp_stapling: str = "unknown"
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _parse_dn(dn_tuple) -> Dict[str, str]:
    """Parse a distinguished name tuple into a dictionary."""
    result = {}
    if dn_tuple:
        for entry in dn_tuple:
            for key, value in entry:
                result[key] = value
    return result


def _parse_san(cert_dict: dict) -> List[str]:
    """Parse Subject Alternative Names from certificate."""
    san_list = []
    san = cert_dict.get("subjectAltName", ())
    for san_type, san_value in san:
        san_list.append(f"{san_type}:{san_value}")
    return san_list


def _parse_cipher_name(cipher_name: str) -> Dict[str, str]:
    """
    Parse a cipher suite name into its components.

    Handles both TLS 1.2 style (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
    and TLS 1.3 style (TLS_AES_256_GCM_SHA384) cipher names.

    TLS 1.3 ciphers don't include key exchange in the name — it's
    negotiated separately. We mark them as 'TLS13_EPHEMERAL' instead
    of 'unknown' since TLS 1.3 mandates ephemeral key exchange.
    """
    parts = {
        "key_exchange": "unknown",
        "authentication": "unknown",
        "encryption": "unknown",
        "mac": "unknown",
    }

    name = cipher_name.upper()

    # Check if this is a TLS 1.3 cipher (no key exchange in name)
    is_tls13_cipher = (
        name.startswith("TLS_AES_") or
        name.startswith("TLS_CHACHA20_") or
        ("_GCM_" in name and "WITH" not in name and "ECDHE" not in name and "RSA" not in name)
    )

    if is_tls13_cipher:
        # TLS 1.3 mandates ephemeral key exchange (ECDHE or X25519).
        # The specific group is negotiated via supported_groups extension.
        parts["key_exchange"] = "ECDHE"  # TLS 1.3 always uses ephemeral
        parts["authentication"] = "TLS13"
    else:
        # Standard TLS 1.2 key exchange detection
        if "ECDHE" in name:
            parts["key_exchange"] = "ECDHE"
        elif "ECDH" in name:
            parts["key_exchange"] = "ECDH"
        elif "DHE" in name or "EDH" in name:
            parts["key_exchange"] = "DHE"
        elif "RSA" in name and "WITH" in name:
            parts["key_exchange"] = "RSA"
        elif "X25519" in name:
            parts["key_exchange"] = "X25519"

        # Authentication detection
        if "ECDSA" in name:
            parts["authentication"] = "ECDSA"
        elif "RSA" in name:
            parts["authentication"] = "RSA"
        elif "PSK" in name:
            parts["authentication"] = "PSK"

    # Detect encryption
    if "AES_256_GCM" in name or "AES256GCM" in name:
        parts["encryption"] = "AES_256_GCM"
    elif "AES_128_GCM" in name or "AES128GCM" in name:
        parts["encryption"] = "AES_128_GCM"
    elif "AES_256_CBC" in name:
        parts["encryption"] = "AES_256_CBC"
    elif "AES_128_CBC" in name:
        parts["encryption"] = "AES_128_CBC"
    elif "CHACHA20" in name:
        parts["encryption"] = "CHACHA20_POLY1305"
    elif "3DES" in name or "DES_CBC3" in name:
        parts["encryption"] = "3DES_EDE_CBC"

    # Detect MAC
    if "SHA384" in name:
        parts["mac"] = "SHA384"
    elif "SHA256" in name:
        parts["mac"] = "SHA256"
    elif "SHA" in name and "SHAKE" not in name:
        parts["mac"] = "SHA1"
    elif "MD5" in name:
        parts["mac"] = "MD5"

    return parts


async def inspect_tls(host: str, port: int = 443) -> TLSFingerprint:
    """
    Perform a deep TLS inspection on an endpoint.

    Uses Python's ssl module for TLS probing and certificate extraction.

    Args:
        host: Target hostname.
        port: Target port number.

    Returns:
        TLSFingerprint with all extracted details.
    """
    fingerprint = TLSFingerprint(host=host, port=port)

    # Test multiple TLS versions
    tls_version_map = {
        "TLS 1.0": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, 'TLSv1') else None,
        "TLS 1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, 'TLSv1_1') else None,
        "TLS 1.2": ssl.TLSVersion.TLSv1_2,
        "TLS 1.3": ssl.TLSVersion.TLSv1_3,
    }

    # Try to connect with the best available TLS version
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        loop = asyncio.get_event_loop()

        def _connect_and_extract():
            """Connect to host and extract TLS information."""
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=host,
            )
            conn.settimeout(10)
            conn.connect((host, port))

            cert_bin = conn.getpeercert(True)
            cipher = conn.cipher()
            tls_version = conn.version()
            shared_ciphers = conn.shared_ciphers() or []

            conn.close()
            return cipher, tls_version, shared_ciphers, cert_bin

        cipher, tls_version, shared_ciphers, cert_bin = await loop.run_in_executor(
            None, _connect_and_extract
        )

        # Parse TLS version
        if tls_version:
            fingerprint.tls_versions.append(tls_version)

        is_tls_13 = tls_version and ("1.3" in tls_version)

        # Parse current cipher
        if cipher:
            cipher_name, tls_v, key_bits = cipher
            parsed = _parse_cipher_name(cipher_name)

            # For TLS 1.3, key exchange is always ephemeral (ECDHE/X25519)
            # Python's ssl module uses X25519 by default for TLS 1.3
            if is_tls_13 and parsed["key_exchange"] in ("unknown", "ECDHE"):
                fingerprint.key_exchange = "ECDHE"  # TLS 1.3 = ephemeral key exchange
            else:
                fingerprint.key_exchange = parsed["key_exchange"]

            fingerprint.cipher_suites.append({
                "name": cipher_name,
                "key_exchange": fingerprint.key_exchange,
                "authentication": parsed["authentication"],
                "encryption": parsed["encryption"],
                "mac": parsed["mac"],
                "key_size": key_bits,
                "tls_version": tls_v or tls_version,
                "negotiated": True,
            })

        # Parse all shared ciphers
        for sc in shared_ciphers:
            if len(sc) >= 3:
                sc_name, sc_tls, sc_bits = sc[:3]
                if sc_name != (cipher[0] if cipher else None):
                    parsed = _parse_cipher_name(sc_name)
                    fingerprint.cipher_suites.append({
                        "name": sc_name,
                        "key_exchange": parsed["key_exchange"],
                        "authentication": parsed["authentication"],
                        "encryption": parsed["encryption"],
                        "mac": parsed["mac"],
                        "key_size": sc_bits,
                        "tls_version": sc_tls,
                        "negotiated": False,
                    })

        # Parse certificate from binary DER data (always works, unlike getpeercert())
        if cert_bin:
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448

                cert_obj = x509.load_der_x509_certificate(cert_bin)
                pub_key = cert_obj.public_key()

                cert_info = CertificateInfo()

                # Subject
                for attr in cert_obj.subject:
                    cert_info.subject[attr.oid._name] = attr.value

                # Issuer
                for attr in cert_obj.issuer:
                    cert_info.issuer[attr.oid._name] = attr.value

                # SAN
                try:
                    san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    cert_info.san = [f"DNS:{name}" for name in san_ext.value.get_values_for_type(x509.DNSName)]
                except x509.ExtensionNotFound:
                    pass

                # Serial & dates
                cert_info.serial_number = format(cert_obj.serial_number, 'x').upper()
                cert_info.not_before = cert_obj.not_valid_before_utc.isoformat()
                cert_info.not_after = cert_obj.not_valid_after_utc.isoformat()

                # Public key algorithm and size
                if isinstance(pub_key, rsa.RSAPublicKey):
                    cert_info.public_key_algorithm = "RSA"
                    cert_info.key_size = pub_key.key_size
                elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                    cert_info.public_key_algorithm = f"EC-{pub_key.curve.name}"
                    cert_info.key_size = pub_key.key_size
                elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                    cert_info.public_key_algorithm = "Ed25519"
                    cert_info.key_size = 256
                elif isinstance(pub_key, ed448.Ed448PublicKey):
                    cert_info.public_key_algorithm = "Ed448"
                    cert_info.key_size = 448
                else:
                    cert_info.public_key_algorithm = type(pub_key).__name__

                # Signature algorithm
                cert_info.signature_algorithm = cert_obj.signature_algorithm_oid._name
                cert_info.version = cert_obj.version.value

                fingerprint.certificate = cert_info.to_dict()
                fingerprint.cert_chain_length = 1  # Leaf cert

            except Exception as e:
                logger.error(f"Certificate parsing failed for {host}: {e}")
                fingerprint.errors.append(f"Certificate parsing error: {str(e)}")

    except Exception as e:
        fingerprint.errors.append(f"TLS connection failed: {str(e)}")
        logger.error(f"TLS inspection failed for {host}:{port} — {e}")

    # Test individual TLS version support
    for version_name, version_enum in tls_version_map.items():
        if version_enum is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version_enum
            ctx.maximum_version = version_enum

            def _test_version(v_ctx, v_host=host, v_port=port):
                sock = v_ctx.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    server_hostname=v_host,
                )
                sock.settimeout(5)
                try:
                    sock.connect((v_host, v_port))
                    sock.close()
                    return True
                except Exception:
                    return False

            loop = asyncio.get_event_loop()
            supported = await loop.run_in_executor(None, _test_version, ctx)
            if supported and version_name not in fingerprint.tls_versions:
                fingerprint.tls_versions.append(version_name)

        except Exception:
            continue

    return fingerprint
