"""Traceability report exports (CSV / PDF)."""
import csv
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

NAVY = colors.HexColor("#1F3864")
RISK_COLORS = {"Critical": "#F4B6B6", "High": "#F9CBAA", "Medium": "#FFE699", "Low": "#D5E8D4", "Very low": "#E2F0D9"}


def _risk_key(label: str) -> str:
    return label.replace(" (preliminary)", "")


def to_csv(report: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Asset", "Threat scenario", "Risk", "Control / requirement", "Requirement IDs", "Test link", "Threat status", "Rating status", "Mitigation status", "Sources"])
    for r in report["rows"]:
        w.writerow([r["asset"], r["threat"], r["risk"], "; ".join(r["controls"]), "; ".join(r["requirements"]), "; ".join(r["tests"]),
                    r["status"]["threat"], r["status"]["rating"], "/".join(r["status"]["mitigations"]), " || ".join(r["citations"])])
    return buf.getvalue()


def to_pdf(report: dict, project_name: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                            title="Cybersecurity traceability report")
    ss = getSampleStyleSheet()
    h = ParagraphStyle("h", parent=ss["Title"], textColor=NAVY, fontSize=18, alignment=0)
    cell = ParagraphStyle("c", parent=ss["BodyText"], fontSize=8, leading=10)
    head = ParagraphStyle("hd", parent=cell, textColor=colors.white, fontName="Helvetica-Bold")
    story = [Paragraph("Cybersecurity traceability report", h), Paragraph(f"Project: {project_name}", ss["BodyText"]), Spacer(1, 6)]
    data = [[Paragraph(x, head) for x in ["Asset", "Threat scenario", "Risk", "Control / requirement", "Test link", "Status"]]]
    style = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    for i, r in enumerate(report["rows"], 1):
        data.append([Paragraph(r["asset"], cell), Paragraph(r["threat"], cell), Paragraph(r["risk"], cell),
                     Paragraph("<br/>".join(r["controls"]) or "-", cell), Paragraph(", ".join(r["tests"]) or "-", cell),
                     Paragraph(f"threat: {r['status']['threat']}<br/>rating: {r['status']['rating']}", cell)])
        style.append(("BACKGROUND", (2, i), (2, i), colors.HexColor(RISK_COLORS.get(_risk_key(r["risk"]), "#FFFFFF"))))
    t = Table(data, colWidths=[48 * mm, 62 * mm, 24 * mm, 70 * mm, 32 * mm, 30 * mm], repeatRows=1)
    t.setStyle(TableStyle(style))
    story += [t, Spacer(1, 10)]
    if report["gaps"]:
        story.append(Paragraph("<b>Coverage gaps</b>", ss["BodyText"]))
        story += [Paragraph(f"- {g}", cell) for g in report["gaps"]]
        story.append(Spacer(1, 8))
    gov = Table([[Paragraph(f"<b>Governance principle</b><br/>{report['governance_principle']}", ss["BodyText"])]], colWidths=[240 * mm])
    gov.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF2CC")), ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#D6B656")),
                             ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(gov)
    doc.build(story)
    return buf.getvalue()
