"""pdf_export.py — ReportLab PDF generation for Harvest Horizon assessment reports."""

from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from config import APP_SUBTITLE, APP_TITLE, SCOPE_NOTICE, VERIFICATION_DISCLAIMER
from models import Assessment


class PDFExportError(Exception):
    pass


_TIER_COLORS = {
    "CRITICAL": colors.HexColor("#b91c1c"),
    "HIGH": colors.HexColor("#c2410c"),
    "MEDIUM": colors.HexColor("#92600a"),
    "LOW": colors.HexColor("#166534"),
}

_STATUS_COLORS = {
    "PQC_APPROVED": colors.HexColor("#166534"),
    "QUANTUM_SAFE": colors.HexColor("#166534"),
    "REDUCED_SECURITY": colors.HexColor("#92600a"),
    "NON_COMPLIANT": colors.HexColor("#b91c1c"),
    "DEPRECATED": colors.HexColor("#7c3aed"),
    "UNKNOWN": colors.HexColor("#475569"),
}


def generate_pdf(assessment: Assessment) -> bytes:
    """Generate a PDF report for the assessment. Returns bytes."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    normal = styles["Normal"]
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], textColor=colors.HexColor("#122740"), fontSize=16)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#1d3a5f"), fontSize=13)
    small = ParagraphStyle("Small", parent=normal, fontSize=8, textColor=colors.HexColor("#475569"))
    body = ParagraphStyle("Body", parent=normal, fontSize=10, leading=14)
    warning = ParagraphStyle("Warning", parent=normal, fontSize=9,
                              textColor=colors.HexColor("#92600a"),
                              backColor=colors.HexColor("#fef3c7"), leading=13)

    story = []

    # ---------------------------------------------------------------------------
    # DEMO watermark banner
    # ---------------------------------------------------------------------------
    demo_style = ParagraphStyle(
        "Demo",
        parent=normal,
        fontSize=9,
        textColor=colors.HexColor("#92600a"),
        backColor=colors.HexColor("#fef3c7"),
        borderPad=6,
        leading=13,
    )
    story.append(Paragraph(
        "⚠ DEMONSTRATION ONLY — FICTIONAL ORGANIZATION — NOT FOR OPERATIONAL USE",
        demo_style,
    ))
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------------------------
    # Header
    # ---------------------------------------------------------------------------
    story.append(Paragraph(f"{APP_TITLE}: {APP_SUBTITLE}", h1))
    story.append(Paragraph("Post-Quantum Cryptographic Migration Assessment Report", h2))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#d7dee8")))
    story.append(Spacer(1, 8))

    # Org info
    info_data = [
        ["Organization:", assessment.org_name],
        ["Type:", assessment.org_type or "—"],
        ["Data Sensitivity:", assessment.data_sensitivity],
        ["Retention Requirement:", f"{assessment.data_retention_years} years"],
        ["HNDL Exposure Tier:", assessment.hndl_tier],
        ["HNDL Score:", f"{assessment.hndl_score}/100"],
    ]
    info_table = Table(info_data, colWidths=[1.8 * inch, 5.2 * inch])
    info_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#122740")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 10))

    # Scope notice
    story.append(Paragraph(SCOPE_NOTICE, small))
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------------------------
    # HNDL Exposure
    # ---------------------------------------------------------------------------
    story.append(Paragraph("Harvest-Now, Decrypt-Later (HNDL) Exposure", h2))
    tier_color = _TIER_COLORS.get(assessment.hndl_tier, colors.gray)
    tier_para = ParagraphStyle(
        "Tier", parent=normal, fontSize=12, textColor=tier_color,
        fontName="Helvetica-Bold"
    )
    story.append(Paragraph(
        f"Exposure Tier: {assessment.hndl_tier}   (Score: {assessment.hndl_score}/100)",
        tier_para,
    ))
    story.append(Spacer(1, 4))
    if assessment.hndl_rationale:
        story.append(Paragraph(assessment.hndl_rationale, body))
    story.append(Spacer(1, 12))

    # ---------------------------------------------------------------------------
    # Algorithm Inventory
    # ---------------------------------------------------------------------------
    story.append(Paragraph("Cryptographic Algorithm Inventory", h2))
    story.append(Spacer(1, 4))

    if assessment.items:
        col_widths = [1.8 * inch, 1.5 * inch, 1.3 * inch, 1.5 * inch, 1.1 * inch]
        header = ["Component", "Algorithm", "Use Case", "Status", "Vulnerability"]
        rows = [header]
        row_colors = [colors.HexColor("#122740")]
        for item in sorted(assessment.items, key=lambda x: x.compliance_status):
            rows.append([
                Paragraph(item.component, ParagraphStyle("cell", fontSize=8, leading=10)),
                item.algorithm,
                item.use_case,
                item.compliance_status.replace("_", " "),
                item.quantum_vulnerability,
            ])
            status_bg = {
                "PQC_APPROVED": colors.HexColor("#dcfce7"),
                "QUANTUM_SAFE": colors.HexColor("#dcfce7"),
                "REDUCED_SECURITY": colors.HexColor("#fef3c7"),
                "NON_COMPLIANT": colors.HexColor("#fee2e2"),
                "DEPRECATED": colors.HexColor("#ede9fe"),
            }.get(item.compliance_status, colors.white)
            row_colors.append(status_bg)

        inv_table = Table(rows, colWidths=col_widths, repeatRows=1)
        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#122740")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7dee8")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        for i, bg in enumerate(row_colors[1:], start=1):
            table_style.append(("BACKGROUND", (0, i), (-1, i), bg))
        inv_table.setStyle(TableStyle(table_style))
        story.append(inv_table)
    else:
        story.append(Paragraph("No algorithm inventory available.", body))

    story.append(Spacer(1, 12))

    # ---------------------------------------------------------------------------
    # Compliance Summary
    # ---------------------------------------------------------------------------
    story.append(Paragraph("Compliance Summary", h2))
    summary_rows = [
        ["Status", "Count"],
        ["PQC Approved (FIPS 203/204/205)", str(assessment.pqc_approved_count)],
        ["Quantum Safe (adequate symmetric/hash)", str(assessment.quantum_safe_count)],
        ["Reduced Security (upgrade recommended)", str(assessment.reduced_count)],
        ["Non-Compliant (quantum-vulnerable)", str(assessment.non_compliant_count)],
    ]
    sum_table = Table(summary_rows, colWidths=[4.5 * inch, 1.5 * inch])
    sum_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#122740")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7dee8")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 12))

    # ---------------------------------------------------------------------------
    # Migration Roadmap (if generated)
    # ---------------------------------------------------------------------------
    if assessment.roadmap_text:
        story.append(Paragraph("Migration Roadmap", h2))
        for line in assessment.roadmap_text.split("\n"):
            line = line.strip()
            if not line:
                story.append(Spacer(1, 4))
            elif line.startswith("## "):
                story.append(Paragraph(line[3:], h2))
            elif line.startswith("**") and line.endswith("**"):
                story.append(Paragraph(f"<b>{line[2:-2]}</b>", body))
            elif line.startswith("⚠"):
                story.append(Paragraph(line, warning))
            else:
                story.append(Paragraph(line, body))
        story.append(Spacer(1, 12))

    # ---------------------------------------------------------------------------
    # Verification disclaimer
    # ---------------------------------------------------------------------------
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#d7dee8")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(VERIFICATION_DISCLAIMER, small))

    doc.build(story)
    return buf.getvalue()
