from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import cm
from datetime import datetime
import os

# Same colour scheme used in the dashboard, so the PDF matches the app
SEVERITY_COLORS = {
    "Critical": colors.HexColor("#c0392b"),
    "High": colors.HexColor("#e67e22"),
    "Medium": colors.HexColor("#d4ac0d"),
    "Low": colors.HexColor("#27ae60"),
}


def generate_report(data):
    # Accept either the dashboard sample schema or the integrated scanner schema.
    if "assessment" in data:
        assessment = data.get("assessment", {})
        findings = assessment.get("enriched_findings", [])
        data = {
            "security_score": assessment.get("overall_risk_score", 0),
            "total_apis": 1,
            "total_endpoints": data.get("discovery", {}).get("total_endpoints", 0),
            "attack_attempts": data.get("scan", {}).get("total_vulnerabilities", len(findings)),
            "vulnerabilities": [
                {
                    **item,
                    "type": item.get("vulnerability_type", item.get("type", "Unknown")),
                    "severity": item.get("ml_predicted_severity", item.get("severity", "Medium")),
                    "description": item.get("evidence", ""),
                    "recommendation": item.get("explanation", {}).get("remediation_guidance", "Review and remediate this finding."),
                }
                for item in findings
            ]
        }
    elif "risk_assessment" in data:
        assessment = data.get("risk_assessment", {})
        findings = assessment.get("enriched_findings", [])
        data = {
            "security_score": assessment.get("overall_risk_score", 0),
            "total_apis": 1,
            "total_endpoints": data.get("discovery_summary", {}).get("endpoints_found", 0),
            "attack_attempts": data.get("vulnerability_scan", {}).get("total_detected", len(findings)),
            "vulnerabilities": [
                {**item, "type": item.get("vulnerability_type", "Unknown"),
                 "severity": item.get("ml_predicted_severity", item.get("severity", "Medium")),
                 "description": item.get("evidence", ""),
                 "recommendation": item.get("explanation", {}).get("remediation_guidance", "Review and remediate this finding.")}
                for item in findings
            ]
        }
    output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "API_Security_Report.pdf")

    document = SimpleDocTemplate(
        output_file,
        pagesize=A4,
        topMargin=2 * cm,
        bottomMargin=2 * cm
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"],
        fontSize=20, alignment=TA_CENTER,
        textColor=colors.HexColor("#1a1a2e")
    )
    subtitle_style = ParagraphStyle(
        "SubtitleStyle", parent=styles["Normal"],
        fontSize=11, alignment=TA_CENTER,
        textColor=colors.HexColor("#6c757d")
    )
    section_style = ParagraphStyle(
        "SectionStyle", parent=styles["Heading2"],
        textColor=colors.HexColor("#1a1a2e"),
        spaceBefore=10, spaceAfter=6
    )
    normal = styles["Normal"]

    story = []

    # ---- Cover / header ----
    story.append(Paragraph("AI-Driven Adaptive API Security Scanner", title_style))
    story.append(Paragraph("Security Assessment Report", subtitle_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Generated on {datetime.now().strftime('%d %B %Y, %I:%M %p')}",
        subtitle_style
    ))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#dee2e6")))
    story.append(Spacer(1, 16))

    # ---- Summary section ----
    story.append(Paragraph("Scan Summary", section_style))

    summary_table = Table(
        [
            ["Security Score", f'{data["security_score"]}%'],
            ["APIs Scanned", str(data["total_apis"])],
            ["Endpoints Scanned", str(data["total_endpoints"])],
            ["Attack Attempts Simulated", str(data["attack_attempts"])],
        ],
        colWidths=[8 * cm, 8 * cm]
    )
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f3f5")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # ---- Severity breakdown ----
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in data["vulnerabilities"]:
        severity_counts[item["severity"]] = severity_counts.get(item["severity"], 0) + 1

    story.append(Paragraph("Vulnerability Breakdown by Severity", section_style))

    sev_row = [["Critical", "High", "Medium", "Low"],
               [str(severity_counts.get(s, 0)) for s in ["Critical", "High", "Medium", "Low"]]]
    sev_table = Table(sev_row, colWidths=[4 * cm] * 4)
    sev_style = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]
    for i, sev in enumerate(["Critical", "High", "Medium", "Low"]):
        sev_style.append(("BACKGROUND", (i, 0), (i, 0), SEVERITY_COLORS[sev]))
    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)
    story.append(Spacer(1, 20))

    # ---- Detailed findings table ----
    story.append(Paragraph("Detailed Findings", section_style))

    table_data = [["Endpoint", "Method", "Vulnerability", "Severity"]]
    row_colors = []
    for item in data["vulnerabilities"]:
        table_data.append([
            item["endpoint"],
            item["method"],
            item["type"],
            item["severity"]
        ])
        row_colors.append(item["severity"])

    findings_table = Table(table_data, repeatRows=1, colWidths=[5 * cm, 2 * cm, 5.5 * cm, 3 * cm])
    findings_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for row_index, severity in enumerate(row_colors, start=1):
        findings_style.append(
            ("TEXTCOLOR", (3, row_index), (3, row_index), SEVERITY_COLORS.get(severity, colors.black))
        )
        findings_style.append(("FONTNAME", (3, row_index), (3, row_index), "Helvetica-Bold"))
    findings_table.setStyle(TableStyle(findings_style))
    story.append(findings_table)
    story.append(Spacer(1, 20))

    # ---- Recommended fixes ----
    story.append(Paragraph("Recommended Fixes", section_style))

    for item in data["vulnerabilities"]:
        story.append(Paragraph(
            f'<b>{item["endpoint"]} &mdash; {item["type"]}</b> '
            f'(<font color="{SEVERITY_COLORS.get(item["severity"], colors.black).hexval()}">'
            f'{item["severity"]}</font>)',
            normal
        ))
        story.append(Paragraph(item["recommendation"], normal))
        story.append(Spacer(1, 8))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#dee2e6")))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Generated by the AI-Driven Adaptive API Security Scanner.",
        subtitle_style
    ))

    document.build(story)
    return output_file
