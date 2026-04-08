"""
PDF Report Generator — creates professional CBOM reports using ReportLab.

Generates branded PDF reports with scan summary, asset details,
vulnerability analysis, and PQC readiness indicators.
"""

import io
import logging
from datetime import datetime
from typing import Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from app.core.cbom.exporter import extract_summary_data

logger = logging.getLogger(__name__)

# Brand colors
BRAND_NAVY = colors.HexColor("#0A1929")
BRAND_CYAN = colors.HexColor("#00E5FF")
BRAND_GREEN = colors.HexColor("#00E676")
BRAND_RED = colors.HexColor("#FF1744")
BRAND_YELLOW = colors.HexColor("#FFD600")
BRAND_GRAY = colors.HexColor("#B0BEC5")


def _get_status_color(status: str) -> colors.Color:
    """Get color for PQC status."""
    return {
        "QUANTUM_SAFE": BRAND_GREEN,
        "HYBRID_READY": BRAND_YELLOW,
        "VULNERABLE": BRAND_RED,
    }.get(status, BRAND_GRAY)


def generate_pdf_report(cbom: dict) -> bytes:
    """
    Generate a professional PDF report from CBOM data.

    Args:
        cbom: CycloneDX CBOM dictionary.

    Returns:
        PDF file content as bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=25 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle(
        "Title_Custom",
        parent=styles["Title"],
        fontSize=24,
        textColor=BRAND_NAVY,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "Subtitle_Custom",
        parent=styles["Normal"],
        fontSize=12,
        textColor=BRAND_GRAY,
        spaceAfter=20,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        "Section_Header",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=BRAND_NAVY,
        spaceBefore=16,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        "Body_Text",
        parent=styles["Normal"],
        fontSize=10,
        spaceAfter=4,
    ))

    elements = []
    summary = extract_summary_data(cbom)

    # === Title Page ===
    elements.append(Spacer(1, 40 * mm))
    elements.append(Paragraph("🛡️ CipherSight", styles["Title_Custom"]))
    elements.append(Paragraph(
        "Quantum-Proof Cryptographic Scan Report",
        styles["Subtitle_Custom"],
    ))
    elements.append(Spacer(1, 10 * mm))
    elements.append(HRFlowable(
        width="80%", thickness=2, color=BRAND_CYAN,
        spaceAfter=10 * mm,
    ))

    # Scan info table
    scan_info = [
        ["Target", summary["target"]],
        ["Scan Date", summary["scan_timestamp"]],
        ["Report Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ["Total Assets Scanned", str(summary["total_components"])],
        ["Vulnerabilities Found", str(summary["total_vulnerabilities"])],
        ["Average Risk Score", f"{summary['avg_risk_score']}/100"],
    ]
    info_table = Table(scan_info, colWidths=[50 * mm, 100 * mm])
    info_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, BRAND_GRAY),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F5F5F5")),
    ]))
    elements.append(info_table)
    elements.append(PageBreak())

    # === Executive Summary ===
    elements.append(Paragraph("Executive Summary", styles["Section_Header"]))

    status_counts = summary["status_counts"]
    summary_data = [
        ["Classification", "Count", "Percentage"],
        ["🟢 Quantum Safe", str(status_counts.get("QUANTUM_SAFE", 0)),
         f"{status_counts.get('QUANTUM_SAFE', 0) / max(summary['total_components'], 1) * 100:.1f}%"],
        ["🟡 Hybrid Ready", str(status_counts.get("HYBRID_READY", 0)),
         f"{status_counts.get('HYBRID_READY', 0) / max(summary['total_components'], 1) * 100:.1f}%"],
        ["🔴 Vulnerable", str(status_counts.get("VULNERABLE", 0)),
         f"{status_counts.get('VULNERABLE', 0) / max(summary['total_components'], 1) * 100:.1f}%"],
    ]
    summary_table = Table(summary_data, colWidths=[60 * mm, 40 * mm, 50 * mm])
    summary_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, BRAND_GRAY),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10 * mm))

    # === Asset Details ===
    elements.append(Paragraph("Asset Details", styles["Section_Header"]))

    components = cbom.get("components", [])
    if components:
        asset_header = ["Asset", "Service", "PQC Status", "Risk Score", "Key Exchange"]
        asset_rows = [asset_header]

        for comp in components:
            props = {p["name"]: p["value"] for p in comp.get("properties", [])}
            status = props.get("ciphersight:pqc_status", "UNKNOWN")
            status_icon = {"QUANTUM_SAFE": "🟢", "HYBRID_READY": "🟡", "VULNERABLE": "🔴"}.get(status, "⚪")

            asset_rows.append([
                comp.get("name", ""),
                props.get("ciphersight:service_type", ""),
                f"{status_icon} {status}",
                props.get("ciphersight:risk_score", ""),
                props.get("ciphersight:key_exchange", "N/A"),
            ])

        asset_table = Table(asset_rows, colWidths=[45 * mm, 30 * mm, 35 * mm, 25 * mm, 30 * mm])
        asset_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, BRAND_GRAY),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFAFA")]),
        ]))
        elements.append(asset_table)

    elements.append(Spacer(1, 10 * mm))

    # === Vulnerabilities ===
    vulns = cbom.get("vulnerabilities", [])
    if vulns:
        elements.append(Paragraph("Vulnerabilities", styles["Section_Header"]))

        for vuln in vulns[:20]:  # Cap at 20 for readability
            ratings = vuln.get("ratings", [{}])
            severity = ratings[0].get("severity", "unknown") if ratings else "unknown"
            sev_color = {
                "critical": "red", "high": "orangered",
                "medium": "orange", "low": "green",
            }.get(severity, "gray")

            elements.append(Paragraph(
                f'<font color="{sev_color}"><b>[{severity.upper()}]</b></font> '
                f'{vuln.get("description", "")}',
                styles["Body_Text"],
            ))
            if vuln.get("recommendation"):
                elements.append(Paragraph(
                    f'  → <i>{vuln["recommendation"][:200]}</i>',
                    styles["Body_Text"],
                ))

    # === Footer ===
    elements.append(Spacer(1, 20 * mm))
    elements.append(HRFlowable(width="100%", thickness=1, color=BRAND_GRAY))
    elements.append(Paragraph(
        f"Generated by CipherSight v1.0.0 | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8,
                       textColor=BRAND_GRAY, alignment=TA_CENTER),
    ))

    doc.build(elements)
    return buffer.getvalue()
