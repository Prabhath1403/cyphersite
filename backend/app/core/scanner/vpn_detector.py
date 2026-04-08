"""
VPN detector — detects TLS-based VPN services.

Identifies common VPN protocols by port signatures
and TLS behavior characteristics.
"""

import asyncio
import logging
import ssl
import socket
from dataclasses import dataclass, asdict
from typing import Optional

logger = logging.getLogger(__name__)

# Common VPN ports and protocols
VPN_SIGNATURES = {
    443: ["OpenVPN", "SSTP", "AnyConnect"],
    1194: ["OpenVPN"],
    4433: ["OpenVPN", "WireGuard-TLS"],
    500: ["IKEv2/IPsec"],
    4500: ["IKEv2/IPsec NAT-T"],
    1701: ["L2TP"],
    1723: ["PPTP"],
    8443: ["AnyConnect", "GlobalProtect"],
}


@dataclass
class VPNDetectionResult:
    """Result of VPN detection on an endpoint."""
    host: str = ""
    port: int = 0
    is_vpn: bool = False
    vpn_type: str = ""
    confidence: float = 0.0
    tls_based: bool = False
    details: str = ""

    def to_dict(self):
        return asdict(self)


async def detect_vpn(host: str, port: int) -> VPNDetectionResult:
    """
    Detect if an endpoint is a TLS-based VPN service.

    Uses port-based heuristics and TLS behavior analysis to
    identify VPN services.

    Args:
        host: Target hostname.
        port: Target port.

    Returns:
        VPNDetectionResult with detection details.
    """
    result = VPNDetectionResult(host=host, port=port)

    # Check for VPN port signatures
    potential_vpns = VPN_SIGNATURES.get(port, [])

    if not potential_vpns:
        return result

    # Try TLS connection to detect VPN-style behavior
    try:
        loop = asyncio.get_event_loop()

        def _check_tls_vpn():
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = context.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=host,
            )
            sock.settimeout(5)

            try:
                sock.connect((host, port))
                cert = sock.getpeercert()
                cipher = sock.cipher()
                sock.close()

                vpn_indicators = {
                    "is_vpn": False,
                    "vpn_type": "",
                    "confidence": 0.0,
                    "tls_based": True,
                }

                # Check certificate for VPN indicators
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    org = subject.get("organizationName", "").lower()
                    cn = subject.get("commonName", "").lower()

                    vpn_keywords = ["vpn", "gateway", "remote", "tunnel", "anyconnect", "globalprotect"]
                    for kw in vpn_keywords:
                        if kw in org or kw in cn:
                            vpn_indicators["is_vpn"] = True
                            vpn_indicators["confidence"] = 0.8
                            break

                # Port-based confidence boost
                if port in (4433, 1194):
                    vpn_indicators["is_vpn"] = True
                    vpn_indicators["confidence"] = max(vpn_indicators["confidence"], 0.7)
                    vpn_indicators["vpn_type"] = potential_vpns[0]

                if not vpn_indicators["vpn_type"] and potential_vpns:
                    vpn_indicators["vpn_type"] = potential_vpns[0]

                return vpn_indicators

            except Exception:
                return {"is_vpn": False, "vpn_type": "", "confidence": 0.0, "tls_based": False}

        indicators = await loop.run_in_executor(None, _check_tls_vpn)

        result.is_vpn = indicators["is_vpn"]
        result.vpn_type = indicators["vpn_type"]
        result.confidence = indicators["confidence"]
        result.tls_based = indicators["tls_based"]

        if result.is_vpn:
            result.details = f"Detected {result.vpn_type} VPN on port {port} (confidence: {result.confidence:.0%})"

    except Exception as e:
        logger.debug(f"VPN detection error for {host}:{port}: {e}")

    return result
