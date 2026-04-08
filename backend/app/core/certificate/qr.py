"""
QR Code Generator — generates QR codes linking to certificate verification.

Creates QR code images for embedding in certificates and reports.
"""

import io
import logging
import os
from typing import Optional

import qrcode
from qrcode.constants import ERROR_CORRECT_H

logger = logging.getLogger(__name__)


def generate_qr_code(
    data: str,
    output_path: Optional[str] = None,
    box_size: int = 10,
    border: int = 4,
) -> bytes:
    """
    Generate a QR code image.

    Args:
        data: Data to encode in the QR code.
        output_path: Optional file path to save the QR code.
        box_size: Size of each QR code box in pixels.
        border: QR code border width.

    Returns:
        PNG image bytes.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=ERROR_CORRECT_H,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#0A1929", back_color="#FFFFFF")

    # Save to bytes
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    png_bytes = buffer.getvalue()

    # Save to file if path provided
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(png_bytes)
        logger.info(f"QR code saved to {output_path}")

    return png_bytes


def generate_verification_qr(
    cert_id: str,
    base_url: str = "http://localhost:8000",
    output_path: Optional[str] = None,
) -> bytes:
    """
    Generate a QR code linking to the certificate verification endpoint.

    Args:
        cert_id: Certificate UUID.
        base_url: Base URL of the application.
        output_path: Optional file path to save.

    Returns:
        PNG image bytes.
    """
    verification_url = f"{base_url}/api/certificates/verify/{cert_id}"
    return generate_qr_code(verification_url, output_path)
