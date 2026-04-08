"""
PQC Badge Generator — creates SVG and PNG badges for certified assets.

Generates shield-style badges indicating PQC readiness status
with appropriate colors and icons.
"""

import io
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


def generate_badge_svg(status: str, hostname: str) -> str:
    """
    Generate an SVG badge for a PQC-certified asset.

    Creates a shield-style badge with status indicator.

    Args:
        status: Certificate status (FULLY_QUANTUM_SAFE or PQC_READY).
        hostname: Asset hostname.

    Returns:
        SVG string.
    """
    if status == "FULLY_QUANTUM_SAFE":
        bg_color = "#00C853"
        label = "FULLY QUANTUM SAFE ✓"
        icon_color = "#FFFFFF"
        border_color = "#00E676"
    else:
        bg_color = "#2979FF"
        label = "PQC READY ✓"
        icon_color = "#FFFFFF"
        border_color = "#448AFF"

    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="340" height="130" viewBox="0 0 340 130">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0A1929;stop-opacity:1"/>
      <stop offset="100%" style="stop-color:#1A2A40;stop-opacity:1"/>
    </linearGradient>
    <linearGradient id="statusGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:{bg_color};stop-opacity:1"/>
      <stop offset="100%" style="stop-color:{border_color};stop-opacity:1"/>
    </linearGradient>
    <filter id="shadow">
      <feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity="0.3"/>
    </filter>
  </defs>

  <!-- Background -->
  <rect width="340" height="130" rx="12" fill="url(#bg)" filter="url(#shadow)"/>
  <rect x="1" y="1" width="338" height="128" rx="11" fill="none" stroke="{border_color}" stroke-width="2" opacity="0.4"/>

  <!-- Shield Icon -->
  <g transform="translate(20, 20)">
    <path d="M25 2L5 12V27C5 40.5 13.5 53.2 25 57C36.5 53.2 45 40.5 45 27V12L25 2Z"
          fill="{bg_color}" opacity="0.9"/>
    <path d="M25 6L9 14.5V27C9 38.5 16 49.5 25 53C34 49.5 41 38.5 41 27V14.5L25 6Z"
          fill="none" stroke="{icon_color}" stroke-width="1.5" opacity="0.8"/>
    <text x="25" y="36" text-anchor="middle"
          font-family="Arial, sans-serif" font-size="20" fill="{icon_color}" font-weight="bold">🛡</text>
  </g>

  <!-- CipherSight Label -->
  <text x="75" y="35" font-family="Arial, sans-serif" font-size="11"
        fill="#B0BEC5" font-weight="400" letter-spacing="1.5">CIPHERSIGHT</text>

  <!-- Status Badge -->
  <rect x="75" y="44" width="{len(label) * 10 + 20}" height="28" rx="14"
        fill="url(#statusGrad)" opacity="0.9"/>
  <text x="{75 + (len(label) * 10 + 20) / 2}" y="63"
        text-anchor="middle" font-family="Arial, sans-serif"
        font-size="12" fill="{icon_color}" font-weight="bold">{label}</text>

  <!-- Hostname -->
  <text x="75" y="95" font-family="monospace" font-size="10"
        fill="#78909C">{hostname[:40]}</text>

  <!-- Scan date -->
  <text x="75" y="112" font-family="Arial, sans-serif" font-size="9"
        fill="#546E7A">Verified by CipherSight Scanner v1.0</text>
</svg>'''

    return svg


def save_badge_svg(svg_content: str, output_path: str) -> str:
    """
    Save SVG badge to a file.

    Args:
        svg_content: SVG string.
        output_path: File path to save to.

    Returns:
        Absolute path to the saved file.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(svg_content)
    logger.info(f"Badge SVG saved to {output_path}")
    return output_path


def save_badge_png(svg_content: str, output_path: str) -> str:
    """
    Convert SVG badge to PNG and save.

    Uses Pillow for PNG creation with a simplified rendering approach.

    Args:
        svg_content: SVG string.
        output_path: File path to save to.

    Returns:
        Absolute path to the saved file.
    """
    try:
        from PIL import Image, ImageDraw, ImageFont

        # Create a simplified PNG representation
        width, height = 340, 130
        img = Image.new("RGBA", (width, height), (10, 25, 41, 255))
        draw = ImageDraw.Draw(img)

        # Determine status
        if "FULLY QUANTUM SAFE" in svg_content:
            status_color = (0, 200, 83)
            label = "FULLY QUANTUM SAFE ✓"
        else:
            status_color = (41, 121, 255)
            label = "PQC READY ✓"

        # Draw border
        draw.rounded_rectangle(
            [(1, 1), (width - 2, height - 2)],
            radius=11,
            outline=(*status_color, 100),
            width=2,
        )

        # Draw shield placeholder
        draw.ellipse([20, 25, 60, 75], fill=(*status_color, 200))

        # Draw text (using default font)
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 11)
            small_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 9)
        except (OSError, IOError):
            font = ImageFont.load_default()
            small_font = font

        draw.text((75, 20), "CIPHERSIGHT", fill=(176, 190, 197), font=small_font)

        # Status pill
        pill_width = len(label) * 8 + 20
        draw.rounded_rectangle(
            [(75, 40), (75 + pill_width, 68)],
            radius=14,
            fill=status_color,
        )
        draw.text((85, 46), label, fill=(255, 255, 255), font=font)

        # Footer text
        draw.text((75, 85), "Verified by CipherSight Scanner v1.0", fill=(84, 110, 122), font=small_font)

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        img.save(output_path, "PNG")
        logger.info(f"Badge PNG saved to {output_path}")
        return output_path

    except ImportError:
        logger.warning("Pillow not available for PNG generation, saving SVG only")
        svg_path = output_path.replace(".png", ".svg")
        return save_badge_svg(svg_content, svg_path)
