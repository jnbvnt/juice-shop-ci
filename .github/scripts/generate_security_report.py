#!/usr/bin/env python3
"""
Security Report Generator for Juice Shop CI Pipeline
Generates a unified, professional PDF report from all security scan outputs.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.platypus import ListFlowable, ListItem
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics import renderPDF

# â”€â”€ Color palette â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
DARK_BG     = colors.HexColor("#1a1a2e")
ACCENT_BLUE = colors.HexColor("#0f3460")
ACCENT_CYAN = colors.HexColor("#16213e")
GREEN_OK    = colors.HexColor("#2ecc71")
RED_CRIT    = colors.HexColor("#e74c3c")
ORANGE_HIGH = colors.HexColor("#e67e22")
YELLOW_MED  = colors.HexColor("#f39c12")
BLUE_LOW    = colors.HexColor("#3498db")
GREY_INFO   = colors.HexColor("#95a5a6")
WHITE       = colors.white
LIGHT_GREY  = colors.HexColor("#f8f9fa")
MID_GREY    = colors.HexColor("#dee2e6")
TEXT_DARK   = colors.HexColor("#212529")
TEXT_MUTED  = colors.HexColor("#6c757d")

SEVERITY_COLORS = {
    "CRITICAL": RED_CRIT,
    "HIGH":     ORANGE_HIGH,
    "MEDIUM":   YELLOW_MED,
    "LOW":      BLUE_LOW,
    "INFO":     GREY_INFO,
    "UNKNOWN":  GREY_INFO,
}

# â”€â”€ Styles â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def build_styles():
    base = getSampleStyleSheet()
    custom = {}

    custom["cover_title"] = ParagraphStyle(
        "cover_title", fontSize=28, leading=34,
        textColor=WHITE, alignment=TA_CENTER, fontName="Helvetica-Bold",
        spaceAfter=6
    )
    custom["cover_sub"] = ParagraphStyle(
        "cover_sub", fontSize=14, leading=18,
        textColor=colors.HexColor("#a0aec0"), alignment=TA_CENTER,
        fontName="Helvetica", spaceAfter=4
    )
    custom["cover_meta"] = ParagraphStyle(
        "cover_meta", fontSize=10, leading=14,
        textColor=colors.HexColor("#718096"), alignment=TA_CENTER,
        fontName="Helvetica"
    )
    custom["section_title"] = ParagraphStyle(
        "section_title", fontSize=18, leading=22,
        textColor=ACCENT_BLUE, fontName="Helvetica-Bold",
        spaceBefore=18, spaceAfter=8
    )
    custom["subsection_title"] = ParagraphStyle(
        "subsection_title", fontSize=13, leading=17,
        textColor=TEXT_DARK, fontName="Helvetica-Bold",
        spaceBefore=12, spaceAfter=6
    )
    custom["body"] = ParagraphStyle(
        "body", fontSize=10, leading=15,
        textColor=TEXT_DARK, fontName="Helvetica",
        spaceAfter=6
    )
    custom["body_muted"] = ParagraphStyle(
        "body_muted", fontSize=9, leading=13,
        textColor=TEXT_MUTED, fontName="Helvetica",
        spaceAfter=4
    )
    custom["code"] = ParagraphStyle(
        "code", fontSize=8, leading=11,
        textColor=colors.HexColor("#e83e8c"),
        fontName="Courier", spaceAfter=4,
        backColor=colors.HexColor("#f8f9fa"),
        leftIndent=8, rightIndent=8, borderPad=4
    )
    custom["toc_entry"] = ParagraphStyle(
        "toc_entry", fontSize=11, leading=16,
        textColor=TEXT_DARK, fontName="Helvetica",
        leftIndent=12, spaceAfter=3
    )
    return custom

# â”€â”€ Page template (header/footer) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class SecurityReportTemplate(SimpleDocTemplate):
    def __init__(self, filename, repo, run_id, **kwargs):
        self.repo = repo
        self.run_id = run_id
        super().__init__(filename, **kwargs)

    def handle_pageBegin(self):
        super().handle_pageBegin()

    def afterPage(self):
        pass

def add_header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    page_num = canvas.getPageNumber()

    if page_num > 1:
        # Header bar
        canvas.setFillColor(ACCENT_BLUE)
        canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(2*cm, h - 0.85*cm, "ðŸ›¡  Security Audit Report â€” Juice Shop CI")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 2*cm, h - 0.85*cm, f"CONFIDENTIAL")

        # Footer
        canvas.setFillColor(MID_GREY)
        canvas.rect(0, 0, w, 0.8*cm, fill=1, stroke=0)
        canvas.setFillColor(TEXT_MUTED)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(2*cm, 0.28*cm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawCentredString(w/2, 0.28*cm, f"Page {page_num}")
        canvas.drawRightString(w - 2*cm, 0.28*cm, "jnbvnt/juice-shop-ci")

    canvas.restoreState()

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def severity_badge(sev):
    """Return a colored Table cell acting as a badge."""
    color = SEVERITY_COLORS.get(sev.upper(), GREY_INFO)
    t = Table([[sev.upper()]], colWidths=[1.8*cm], rowHeights=[0.45*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), color),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 7),
        ("TEXTCOLOR",  (0,0), (-1,-1), WHITE),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 2),
        ("BOTTOMPADDING", (0,0), (-1,-1), 2),
    ]))
    return t

def status_pill(ok: bool):
    text = "PASS" if ok else "FAIL"
    color = GREEN_OK if ok else RED_CRIT
    t = Table([[text]], colWidths=[1.6*cm], rowHeights=[0.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), color),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("TEXTCOLOR",  (0,0), (-1,-1), WHITE),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
    ]))
    return t

def section_divider(styles):
    return HRFlowable(width="100%", thickness=1, color=MID_GREY, spaceAfter=6, spaceBefore=6)

def info_box(text, styles, color=colors.HexColor("#e8f4fd"), border=BLUE_LOW):
    t = Table([[Paragraph(text, styles["body"])]], colWidths=[16*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), color),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("LINEBEFORE", (0,0), (0,-1), 3, border),
    ]))
    return t

# â”€â”€ Data parsers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def parse_gitleaks(path):
    results = {"findings": [], "ok": True}
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            results["findings"] = data
            results["ok"] = len(data) == 0
        elif isinstance(data, dict) and "runs" in data:
            for run in data.get("runs", []):
                for result in run.get("results", []):
                    results["findings"].append({
                        "RuleID": result.get("ruleId", "N/A"),
                        "Description": result.get("message", {}).get("text", "N/A"),
                        "File": result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "N/A"),
                        "Severity": result.get("level", "warning"),
                    })
            results["ok"] = len(results["findings"]) == 0
    except Exception as e:
        results["error"] = str(e)
    return results

def parse_semgrep(path):
    results = {"findings": [], "ok": True}
    try:
        with open(path) as f:
            data = json.load(f)
        runs = data.get("runs", [])
        for run in runs:
            for r in run.get("results", []):
                sev = r.get("level", "warning")
                results["findings"].append({
                    "rule": r.get("ruleId", "N/A"),
                    "message": r.get("message", {}).get("text", "N/A")[:200],
                    "file": r.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "N/A"),
                    "line": r.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", "?"),
                    "severity": sev,
                })
        results["ok"] = len(results["findings"]) == 0
    except Exception as e:
        results["error"] = str(e)
    return results

def parse_npm_audit(path):
    results = {"critical": 0, "high": 0, "moderate": 0, "low": 0, "info": 0, "vulns": [], "ok": True}
    try:
        with open(path) as f:
            data = json.load(f)
        meta = data.get("metadata", {}).get("vulnerabilities", {})
        results["critical"] = meta.get("critical", 0)
        results["high"]     = meta.get("high", 0)
        results["moderate"] = meta.get("moderate", 0)
        results["low"]      = meta.get("low", 0)
        results["info"]     = meta.get("info", 0)
        results["ok"]       = (results["critical"] + results["high"]) == 0
        for name, vuln in data.get("vulnerabilities", {}).items():
            results["vulns"].append({
                "name": name,
                "severity": vuln.get("severity", "unknown"),
                "via": str(vuln.get("via", ["N/A"])[0])[:80] if vuln.get("via") else "N/A",
                "range": vuln.get("range", "N/A"),
            })
    except Exception as e:
        results["error"] = str(e)
    return results

def parse_trivy(path):
    results = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "vulns": [], "ok": True}
    try:
        with open(path) as f:
            data = json.load(f)
        for res in data.get("Results", []):
            for vuln in res.get("Vulnerabilities", []):
                sev = vuln.get("Severity", "UNKNOWN").upper()
                results[sev.lower()] = results.get(sev.lower(), 0) + 1
                results["vulns"].append({
                    "id":       vuln.get("VulnerabilityID", "N/A"),
                    "pkg":      vuln.get("PkgName", "N/A"),
                    "version":  vuln.get("InstalledVersion", "N/A"),
                    "fixed":    vuln.get("FixedVersion", "N/A"),
                    "severity": sev,
                    "title":    vuln.get("Title", "N/A")[:80],
                })
        results["ok"] = (results["critical"] + results["high"]) == 0
    except Exception as e:
        results["error"] = str(e)
    return results

def parse_zap(path):
    results = {"high": 0, "medium": 0, "low": 0, "info": 0, "alerts": [], "ok": True}
    try:
        with open(path) as f:
            data = json.load(f)
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk = alert.get("riskdesc", "").split(" ")[0].upper()
                results["alerts"].append({
                    "name":     alert.get("name", "N/A"),
                    "risk":     risk,
                    "url":      alert.get("instances", [{}])[0].get("uri", "N/A")[:80],
                    "solution": alert.get("solution", "N/A")[:150],
                    "desc":     alert.get("desc", "N/A")[:200],
                })
                if risk == "HIGH":      results["high"] += 1
                elif risk == "MEDIUM":  results["medium"] += 1
                elif risk == "LOW":     results["low"] += 1
                else:                   results["info"] += 1
        results["ok"] = results["high"] == 0
    except Exception as e:
        results["error"] = str(e)
    return results

# â”€â”€ Cover page â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def build_cover(styles, run_id, repo, date_str):
    story = []
    story.append(Spacer(1, 3*cm))

    # Big title block
    title_table = Table(
        [[Paragraph("SECURITY AUDIT REPORT", styles["cover_title"])],
         [Paragraph("DevSecOps Pipeline â€” Comprehensive Analysis", styles["cover_sub"])],
         [Spacer(1, 0.3*cm)],
         [Paragraph(f"Repository: <b>{repo}</b>", styles["cover_meta"])],
         [Paragraph(f"Pipeline Run: <b>#{run_id}</b>", styles["cover_meta"])],
         [Paragraph(f"Generated: <b>{date_str}</b>", styles["cover_meta"])],
         [Paragraph("Classification: INTERNAL â€” TRAINING", styles["cover_meta"])],
        ],
        colWidths=[17*cm]
    )
    title_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK_BG),
        ("TOPPADDING",    (0,0), (-1,-1), 14),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14),
        ("LEFTPADDING",   (0,0), (-1,-1), 20),
        ("RIGHTPADDING",  (0,0), (-1,-1), 20),
    ]))
    story.append(title_table)
    story.append(Spacer(1, 1.5*cm))

    # Tool badges row
    tools = ["Gitleaks", "Semgrep", "npm audit", "OWASP DC", "Trivy", "OWASP ZAP"]
    badge_data = [[Paragraph(f"<b>{t}</b>", ParagraphStyle("b", fontSize=8, textColor=WHITE,
                  fontName="Helvetica-Bold", alignment=TA_CENTER)) for t in tools]]
    badge_table = Table(badge_data, colWidths=[2.7*cm]*6)
    badge_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), ACCENT_BLUE),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#2d3748")),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
    ]))
    story.append(badge_data and badge_table)
    story.append(Spacer(1, 1*cm))

    # Disclaimer box
    story.append(info_box(
        "<b>âš  Disclaimer:</b> This report was generated automatically as part of a DevSecOps training exercise "
        "targeting the intentionally vulnerable application <b>OWASP Juice Shop</b>. "
        "Findings are expected and serve educational purposes. "
        "Do not use this application in production.",
        styles,
        color=colors.HexColor("#fff3cd"),
        border=YELLOW_MED
    ))
    story.append(PageBreak())
    return story

# â”€â”€ Table of contents â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def build_toc(styles):
    story = []
    story.append(Paragraph("Table of Contents", styles["section_title"]))
    story.append(section_divider(styles))
    entries = [
        ("1", "Executive Summary"),
        ("2", "Secret Detection â€” Gitleaks"),
        ("3", "Static Analysis (SAST) â€” Semgrep"),
        ("4", "Dependency Analysis (SCA) â€” npm audit"),
        ("5", "Container Image Analysis â€” Trivy"),
        ("6", "Dynamic Analysis (DAST) â€” OWASP ZAP"),
        ("7", "Recommendations & Remediation"),
        ("8", "Methodology & Tools"),
    ]
    for num, title in entries:
        story.append(Paragraph(f"<b>{num}.</b> &nbsp;&nbsp; {title}", styles["toc_entry"]))
        story.append(Spacer(1, 2))
    story.append(PageBreak())
    return story

# â”€â”€ Executive Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def build_executive_summary(styles, all_data):
    story = []
    story.append(Paragraph("1. Executive Summary", styles["section_title"]))
    story.append(section_divider(styles))

    gl = all_data.get("gitleaks", {})
    sg = all_data.get("semgrep", {})
    na = all_data.get("npm_audit", {})
    tv = all_data.get("trivy", {})
    zp = all_data.get("zap", {})

    # Summary table
    rows = [
        [Paragraph("<b>Control</b>", styles["body"]),
         Paragraph("<b>Tool</b>", styles["body"]),
         Paragraph("<b>Findings</b>", styles["body"]),
         Paragraph("<b>Status</b>", styles["body"])],
        [Paragraph("Secret Detection", styles["body"]),
         Paragraph("Gitleaks", styles["body_muted"]),
         Paragraph(str(len(gl.get("findings", []))), styles["body"]),
         status_pill(gl.get("ok", False))],
        [Paragraph("Static Analysis (SAST)", styles["body"]),
         Paragraph("Semgrep", styles["body_muted"]),
         Paragraph(str(len(sg.get("findings", []))), styles["body"]),
         status_pill(sg.get("ok", False))],
        [Paragraph("Dependency Analysis (SCA)", styles["body"]),
         Paragraph("npm audit", styles["body_muted"]),
         Paragraph(f"C:{na.get('critical',0)} H:{na.get('high',0)} M:{na.get('moderate',0)} L:{na.get('low',0)}", styles["body"]),
         status_pill(na.get("ok", False))],
        [Paragraph("Container Scan", styles["body"]),
         Paragraph("Trivy", styles["body_muted"]),
         Paragraph(f"C:{tv.get('critical',0)} H:{tv.get('high',0)} M:{tv.get('medium',0)} L:{tv.get('low',0)}", styles["body"]),
         status_pill(tv.get("ok", False))],
        [Paragraph("Dynamic Analysis (DAST)", styles["body"]),
         Paragraph("OWASP ZAP", styles["body_muted"]),
         Paragraph(f"H:{zp.get('high',0)} M:{zp.get('medium',0)} L:{zp.get('low',0)}", styles["body"]),
         status_pill(zp.get("ok", False))],
    ]

    t = Table(rows, colWidths=[5.5*cm, 4*cm, 5*cm, 2.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), ACCENT_BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GREY]),
        ("GRID",          (0,0), (-1,-1), 0.5, MID_GREY),
        ("ALIGN",         (3,0), (3,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.8*cm))

    # Risk gauge â€” total critical+high
    total_crit_high = (
        na.get("critical", 0) + na.get("high", 0) +
        tv.get("critical", 0) + tv.get("high", 0) +
        zp.get("high", 0) +
        len([f for f in sg.get("findings", []) if f.get("severity", "").upper() == "ERROR"])
    )

    if total_crit_high == 0:
        risk_level, risk_color, risk_text = "LOW", GREEN_OK, "No critical or high severity findings detected."
    elif total_crit_high <= 5:
        risk_level, risk_color, risk_text = "MEDIUM", YELLOW_MED, f"{total_crit_high} critical/high findings require attention before production deployment."
    elif total_crit_high <= 20:
        risk_level, risk_color, risk_text = "HIGH", ORANGE_HIGH, f"{total_crit_high} critical/high findings. Significant security work required."
    else:
        risk_level, risk_color, risk_text = "CRITICAL", RED_CRIT, f"{total_crit_high} critical/high findings. Application must not be deployed to production."

    risk_table = Table(
        [[Paragraph(f"Overall Risk Level: <b>{risk_level}</b>", ParagraphStyle(
            "risk", fontSize=13, textColor=WHITE, fontName="Helvetica-Bold"
          )),
          Paragraph(risk_text, ParagraphStyle(
            "riskd", fontSize=9, textColor=WHITE, fontName="Helvetica"
          ))]],
        colWidths=[5*cm, 12*cm]
    )
    risk_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), risk_color),
        ("TOPPADDING",    (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("LEFTPADDING",   (0,0), (-1,-1), 14),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(risk_table)
    story.append(PageBreak())
    return story

# â”€â”€ Generic findings table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def findings_table(headers, rows, col_widths, styles):
    header_row = [Paragraph(f"<b>{h}</b>", ParagraphStyle(
        "th", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold")) for h in headers]
    data = [header_row] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), ACCENT_BLUE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GREY]),
        ("GRID",          (0,0), (-1,-1), 0.4, MID_GREY),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("WORDWRAP",      (0,0), (-1,-1), True),
    ]))
    return t

# â”€â”€ Section builders â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def build_gitleaks_section(styles, data):
    story = []
    story.append(Paragraph("2. Secret Detection â€” Gitleaks", styles["section_title"]))
    story.append(section_divider(styles))
    story.append(Paragraph(
        "Gitleaks scans the entire Git history of the repository to detect hardcoded secrets, "
        "API keys, tokens, passwords, and other sensitive data that should never be committed to source control.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.4*cm))

    if "error" in data:
        story.append(info_box(f"âš  Report not available: {data['error']}", styles, color=colors.HexColor("#fff3cd"), border=YELLOW_MED))
        story.append(PageBreak())
        return story

    findings = data.get("findings", [])
    if not findings:
        story.append(info_box("âœ… No secrets detected in the repository history.", styles, color=colors.HexColor("#d4edda"), border=GREEN_OK))
    else:
        story.append(Paragraph(f"<b>{len(findings)} secret(s) found:</b>", styles["subsection_title"]))
        rows = []
        for f in findings[:30]:
            sev = f.get("Severity", f.get("level", "WARNING"))
            rows.append([
                Paragraph(str(f.get("RuleID", f.get("ruleId", "N/A"))), styles["body"]),
                Paragraph(str(f.get("Description", f.get("message", {}).get("text", "N/A")))[:120], styles["body"]),
                Paragraph(str(f.get("File", "N/A"))[-50:], styles["body_muted"]),
            ])
        story.append(findings_table(
            ["Rule ID", "Description", "File"],
            rows,
            [4*cm, 9*cm, 4*cm],
            styles
        ))
        if len(findings) > 30:
            story.append(Paragraph(f"<i>... and {len(findings)-30} more findings. See raw SARIF report.</i>", styles["body_muted"]))

    story.append(PageBreak())
    return story

def build_semgrep_section(styles, data):
    story = []
    story.append(Paragraph("3. Static Analysis (SAST) â€” Semgrep", styles["section_title"]))
    story.append(section_divider(styles))
    story.append(Paragraph(
        "Semgrep performs static analysis on the source code using rule sets covering "
        "JavaScript security, Node.js patterns, and the OWASP Top 10. "
        "It identifies code-level vulnerabilities without executing the application.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.4*cm))

    if "error" in data:
        story.append(info_box(f"âš  Report not available: {data['error']}", styles, color=colors.HexColor("#fff3cd"), border=YELLOW_MED))
        story.append(PageBreak())
        return story

    findings = data.get("findings", [])
    if not findings:
        story.append(info_box("âœ… No SAST findings detected.", styles, color=colors.HexColor("#d4edda"), border=GREEN_OK))
    else:
        # Count by severity
        sev_counts = {}
        for f in findings:
            s = f.get("severity", "warning").upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        count_rows = [[Paragraph(f"<b>{s}</b>", styles["body"]),
                       Paragraph(str(c), styles["body"])] for s, c in sorted(sev_counts.items())]
        ct = Table(count_rows, colWidths=[4*cm, 2*cm])
        ct.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.4, MID_GREY),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(Paragraph(f"<b>Total findings: {len(findings)}</b>", styles["subsection_title"]))
        story.append(ct)
        story.append(Spacer(1, 0.4*cm))

        rows = []
        for f in findings[:25]:
            rows.append([
                Paragraph(f.get("rule", "N/A")[-40:], styles["body_muted"]),
                Paragraph(f.get("message", "N/A")[:150], styles["body"]),
                Paragraph(f"{f.get('file','N/A')[-40:]}:{f.get('line','?')}", styles["body_muted"]),
                Paragraph(f.get("severity", "N/A").upper(), ParagraphStyle("sv", fontSize=8,
                    textColor=SEVERITY_COLORS.get(f.get("severity","").upper(), GREY_INFO),
                    fontName="Helvetica-Bold")),
            ])
        story.append(findings_table(
            ["Rule", "Message", "Location", "Severity"],
            rows,
            [4*cm, 7.5*cm, 4*cm, 1.5*cm],
            styles
        ))
        if len(findings) > 25:
            story.append(Paragraph(f"<i>... and {len(findings)-25} more findings.</i>", styles["body_muted"]))

    story.append(PageBreak())
    return story

def build_npm_audit_section(styles, data):
    story = []
    story.append(Paragraph("4. Dependency Analysis (SCA) â€” npm audit", styles["section_title"]))
    story.append(section_divider(styles))
    story.append(Paragraph(
        "npm audit cross-references all declared dependencies against the npm advisory database "
        "to identify components with known CVEs. "
        "Vulnerable dependencies represent supply chain risk and should be updated or replaced.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.4*cm))

    if "error" in data:
        story.append(info_box(f"âš  Report not available: {data['error']}", styles, color=colors.HexColor("#fff3cd"), border=YELLOW_MED))
        story.append(PageBreak())
        return story

    # Severity summary bar
    sev_data = [
        ("CRITICAL", data.get("critical", 0), RED_CRIT),
        ("HIGH",     data.get("high", 0),     ORANGE_HIGH),
        ("MODERATE", data.get("moderate", 0), YELLOW_MED),
        ("LOW",      data.get("low", 0),      BLUE_LOW),
    ]
    bar_rows = [[
        Paragraph(f"<b>{label}</b>", ParagraphStyle("sl", fontSize=9, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(str(count), ParagraphStyle("sc", fontSize=14, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER))
    ] for label, count, _ in sev_data]

    bar_table_data = [[item for pair in [
        [Paragraph(f"<b>{label}</b>", ParagraphStyle("sl2", fontSize=9, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER)),
         Paragraph(str(count), ParagraphStyle("sc2", fontSize=16, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER))]
        for label, count, _ in sev_data
    ] for item in pair]]

    summary_rows = [
        [Paragraph(f"<b>{label}</b>", ParagraphStyle("lbl", fontSize=9, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER)) for label, _, _ in sev_data],
        [Paragraph(str(count), ParagraphStyle("cnt", fontSize=18, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER)) for _, count, _ in sev_data],
    ]
    st = Table(summary_rows, colWidths=[4.2*cm]*4)
    st.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), RED_CRIT),
        ("BACKGROUND", (1,0), (1,-1), ORANGE_HIGH),
        ("BACKGROUND", (2,0), (2,-1), YELLOW_MED),
        ("BACKGROUND", (3,0), (3,-1), BLUE_LOW),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("GRID",          (0,0), (-1,-1), 1, WHITE),
    ]))
    story.append(st)
    story.append(Spacer(1, 0.5*cm))

    vulns = data.get("vulns", [])
    if vulns:
        story.append(Paragraph(f"<b>Top vulnerable packages ({min(20, len(vulns))} shown):</b>", styles["subsection_title"]))
        rows = []
        for v in sorted(vulns, key=lambda x: ["critical","high","moderate","low"].index(x.get("severity","low")) if x.get("severity","low") in ["critical","high","moderate","low"] else 99)[:20]:
            rows.append([
                Paragraph(v.get("name", "N/A"), styles["body"]),
                Paragraph(v.get("severity", "N/A").upper(), ParagraphStyle("sv", fontSize=8,
                    textColor=SEVERITY_COLORS.get(v.get("severity","").upper(), GREY_INFO),
                    fontName="Helvetica-Bold")),
                Paragraph(v.get("range", "N/A"), styles["body_muted"]),
                Paragraph(str(v.get("via", "N/A"))[:80], styles["body_muted"]),
            ])
        story.append(findings_table(
            ["Package", "Severity", "Affected Range", "Via"],
            rows,
            [4.5*cm, 2*cm, 3*cm, 7.5*cm],
            styles
        ))

    story.append(PageBreak())
    return story

def build_trivy_section(styles, data):
    story = []
    story.append(Paragraph("5. Container Image Analysis â€” Trivy", styles["section_title"]))
    story.append(section_divider(styles))
    story.append(Paragraph(
        "Trivy scans the Docker image built by the pipeline for OS-level and application-level "
        "vulnerabilities. It checks all installed packages against multiple CVE databases "
        "(NVD, GitHub Advisory, etc.).",
        styles["body"]
    ))
    story.append(Spacer(1, 0.4*cm))

    if "error" in data:
        story.append(info_box(f"âš  Report not available: {data['error']}", styles, color=colors.HexColor("#fff3cd"), border=YELLOW_MED))
        story.append(PageBreak())
        return story

    sev_data = [
        ("CRITICAL", data.get("critical", 0), RED_CRIT),
        ("HIGH",     data.get("high", 0),     ORANGE_HIGH),
        ("MEDIUM",   data.get("medium", 0),   YELLOW_MED),
        ("LOW",      data.get("low", 0),       BLUE_LOW),
    ]
    summary_rows = [
        [Paragraph(f"<b>{label}</b>", ParagraphStyle("lbl", fontSize=9, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER)) for label, _, _ in sev_data],
        [Paragraph(str(count), ParagraphStyle("cnt", fontSize=18, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER)) for _, count, _ in sev_data],
    ]
    st = Table(summary_rows, colWidths=[4.2*cm]*4)
    st.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), RED_CRIT),
        ("BACKGROUND", (1,0), (1,-1), ORANGE_HIGH),
        ("BACKGROUND", (2,0), (2,-1), YELLOW_MED),
        ("BACKGROUND", (3,0), (3,-1), BLUE_LOW),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("GRID",          (0,0), (-1,-1), 1, WHITE),
    ]))
    story.append(st)
    story.append(Spacer(1, 0.5*cm))

    vulns = data.get("vulns", [])
    crit_high = [v for v in vulns if v.get("severity") in ("CRITICAL", "HIGH")]
    if crit_high:
        story.append(Paragraph(f"<b>Critical & High CVEs ({min(20, len(crit_high))} shown):</b>", styles["subsection_title"]))
        rows = []
        for v in crit_high[:20]:
            rows.append([
                Paragraph(v.get("id", "N/A"), styles["body"]),
                Paragraph(v.get("pkg", "N/A"), styles["body"]),
                Paragraph(v.get("version", "N/A"), styles["body_muted"]),
                Paragraph(v.get("fixed", "â€”"), ParagraphStyle("fix", fontSize=8,
                    textColor=GREEN_OK, fontName="Helvetica")),
                Paragraph(v.get("severity", "N/A"), ParagraphStyle("sv", fontSize=8,
                    textColor=SEVERITY_COLORS.get(v.get("severity",""), GREY_INFO),
                    fontName="Helvetica-Bold")),
                Paragraph(v.get("title", "N/A")[:60], styles["body_muted"]),
            ])
        story.append(findings_table(
            ["CVE ID", "Package", "Version", "Fixed In", "Severity", "Title"],
            rows,
            [3.2*cm, 2.5*cm, 2*cm, 2*cm, 1.8*cm, 5.5*cm],
            styles
        ))

    story.append(PageBreak())
    return story

def build_zap_section(styles, data):
    story = []
    story.append(Paragraph("6. Dynamic Analysis (DAST) â€” OWASP ZAP", styles["section_title"]))
    story.append(section_divider(styles))
    story.append(Paragraph(
        "OWASP ZAP performs a baseline scan against the running application, "
        "simulating an attacker probing for vulnerabilities such as XSS, injection, "
        "insecure headers, and misconfigurations â€” without authentication.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.4*cm))

    if "error" in data:
        story.append(info_box(f"âš  Report not available: {data['error']}", styles, color=colors.HexColor("#fff3cd"), border=YELLOW_MED))
        story.append(PageBreak())
        return story

    sev_data = [
        ("HIGH",   data.get("high", 0),   RED_CRIT),
        ("MEDIUM", data.get("medium", 0), YELLOW_MED),
        ("LOW",    data.get("low", 0),    BLUE_LOW),
        ("INFO",   data.get("info", 0),   GREY_INFO),
    ]
    summary_rows = [
        [Paragraph(f"<b>{label}</b>", ParagraphStyle("lbl", fontSize=9, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER)) for label, _, _ in sev_data],
        [Paragraph(str(count), ParagraphStyle("cnt", fontSize=18, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER)) for _, count, _ in sev_data],
    ]
    st = Table(summary_rows, colWidths=[4.2*cm]*4)
    st.setStyle(TableStyle([
        ("BACKGROUND", (i, 0), (i, -1), color) for i, (_, _, color) in enumerate(sev_data)
    ] + [
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("GRID",          (0,0), (-1,-1), 1, WHITE),
    ]))
    story.append(st)
    story.append(Spacer(1, 0.5*cm))

    alerts = data.get("alerts", [])
    if alerts:
        story.append(Paragraph(f"<b>Alerts ({min(20, len(alerts))} shown):</b>", styles["subsection_title"]))
        rows = []
        for a in sorted(alerts, key=lambda x: ["HIGH","MEDIUM","LOW","INFO"].index(x.get("risk","INFO")) if x.get("risk","INFO") in ["HIGH","MEDIUM","LOW","INFO"] else 99)[:20]:
            rows.append([
                Paragraph(a.get("name", "N/A"), styles["body"]),
                Paragraph(a.get("risk", "N/A"), ParagraphStyle("sv", fontSize=8,
                    textColor=SEVERITY_COLORS.get(a.get("risk",""), GREY_INFO),
                    fontName="Helvetica-Bold")),
                Paragraph(a.get("url", "N/A")[:60], styles["body_muted"]),
                Paragraph(a.get("solution", "N/A")[:120], styles["body_muted"]),
            ])
        story.append(findings_table(
            ["Alert Name", "Risk", "URL", "Solution"],
            rows,
            [5*cm, 1.8*cm, 5*cm, 5.2*cm],
            styles
        ))

    story.append(PageBreak())
    return story

def build_recommendations(styles, all_data):
    story = []
    story.append(Paragraph("7. Recommendations & Remediation", styles["section_title"]))
    story.append(section_divider(styles))

    recs = [
        ("ðŸ” Secrets Management",
         "Never commit secrets to the repository. Use GitHub Secrets or a vault solution (HashiCorp Vault, AWS Secrets Manager). "
         "Rotate any secrets detected by Gitleaks immediately. Add pre-commit hooks with Gitleaks to prevent future leaks."),
        ("ðŸ“¦ Dependency Management",
         "Run `npm audit fix` to automatically patch compatible vulnerabilities. "
         "For breaking-change updates, evaluate the migration path. "
         "Set up Dependabot or Renovate Bot for automated PR-based dependency updates. "
         "Consider pinning dependencies with exact versions in package-lock.json."),
        ("ðŸ³ Container Hardening",
         "Use a minimal base image (e.g., node:22-alpine instead of node:22). "
         "Run the container as a non-root user. "
         "Regularly rebuild images to include OS-level security patches. "
         "Add Trivy to the CI gate with a CRITICAL threshold that fails the build."),
        ("ðŸ›¡ï¸ Code Security",
         "Address SAST findings categorized as ERROR priority first. "
         "Enable ESLint security plugins (eslint-plugin-security). "
         "Conduct periodic manual code reviews focusing on authentication, authorization, and input validation."),
        ("ðŸŒ Application Security",
         "Add Content-Security-Policy, X-Frame-Options, and other security headers. "
         "Implement rate limiting on all API endpoints. "
         "Enable ZAP Active Scan (not just Baseline) for deeper DAST coverage. "
         "Consider OWASP ZAP authenticated scan to cover protected endpoints."),
        ("ðŸ”„ Pipeline Improvements",
         "Add a quality gate: fail the pipeline on CRITICAL findings. "
         "Integrate SonarQube for combined SAST + code quality metrics. "
         "Add SBOM (Software Bill of Materials) generation with Syft. "
         "Archive reports to a dedicated storage (S3, artifact registry) with long retention."),
    ]

    for title, body in recs:
        story.append(KeepTogether([
            Paragraph(title, styles["subsection_title"]),
            Paragraph(body, styles["body"]),
            Spacer(1, 0.2*cm),
        ]))

    story.append(PageBreak())
    return story

def build_methodology(styles):
    story = []
    story.append(Paragraph("8. Methodology & Tools", styles["section_title"]))
    story.append(section_divider(styles))

    tools = [
        ("Gitleaks", "v8.x", "Secret Detection", "MIT", "Scans Git history for exposed credentials and secrets"),
        ("Semgrep",  "Latest", "SAST", "LGPL-2.1", "Pattern-based static analysis with security rulesets"),
        ("npm audit","Built-in","SCA","npm Inc.","Checks dependencies against npm advisory database"),
        ("OWASP DC", "Latest","SCA","Apache 2.0","Identifies known CVEs in project dependencies"),
        ("Trivy",    "Latest","Container Scan","Apache 2.0","Scans container images for OS and library CVEs"),
        ("OWASP ZAP","Latest","DAST","Apache 2.0","Automated web application security scanner"),
    ]

    rows = [[Paragraph(f"<b>{h}</b>", ParagraphStyle("th", fontSize=8, textColor=WHITE,
             fontName="Helvetica-Bold")) for h in ["Tool","Version","Category","License","Purpose"]]]
    for row in tools:
        rows.append([Paragraph(cell, styles["body"]) for cell in row])

    t = Table(rows, colWidths=[2.5*cm, 1.8*cm, 3*cm, 2.5*cm, 7.2*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), ACCENT_BLUE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GREY]),
        ("GRID",          (0,0), (-1,-1), 0.4, MID_GREY),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.8*cm))

    story.append(Paragraph("Pipeline Architecture", styles["subsection_title"]))
    story.append(Paragraph(
        "The pipeline follows a shift-left security approach, integrating security checks at every stage:",
        styles["body"]
    ))

    phases = [
        ("1. Code Push", "Developer pushes code to GitHub repository"),
        ("2. Secret Scan", "Gitleaks scans entire Git history â€” blocks on findings"),
        ("3. Build", "Node.js dependencies installed, frontend compiled"),
        ("4. Unit Tests", "Application unit and API tests executed"),
        ("5. SAST", "Semgrep analyzes source code for security patterns"),
        ("6. SCA", "npm audit + OWASP DC check all dependencies"),
        ("7. Docker Build", "Container image built from Dockerfile"),
        ("8. Container Scan", "Trivy scans image for CVEs"),
        ("9. Deploy (test)", "Image deployed to ephemeral test environment"),
        ("10. DAST", "OWASP ZAP baseline scan against live application"),
        ("11. Report", "All reports collected and unified PDF generated"),
    ]

    phase_rows = [[Paragraph(f"<b>{p}</b>", styles["body"]), Paragraph(d, styles["body_muted"])]
                  for p, d in phases]
    pt = Table(phase_rows, colWidths=[5*cm, 12*cm])
    pt.setStyle(TableStyle([
        ("ROWBACKGROUNDS",(0,0), (-1,-1), [WHITE, LIGHT_GREY]),
        ("GRID",          (0,0), (-1,-1), 0.4, MID_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
    ]))
    story.append(pt)
    return story

# â”€â”€ Main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def main():
    reports_dir = Path(os.environ.get("REPORTS_DIR", "."))
    output_path = Path(os.environ.get("OUTPUT_PDF", "security-report.pdf"))
    repo        = os.environ.get("REPO_NAME", "jnbvnt/juice-shop-ci")
    run_id      = os.environ.get("RUN_ID", "N/A")
    date_str    = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    print(f"[*] Generating security report...")
    print(f"    Reports dir : {reports_dir}")
    print(f"    Output      : {output_path}")

    # Parse all reports
    all_data = {}

    gitleaks_path = reports_dir / "results.sarif"
    all_data["gitleaks"] = parse_gitleaks(gitleaks_path) if gitleaks_path.exists() else {"error": "File not found", "ok": False, "findings": []}

    semgrep_path = reports_dir / "semgrep.sarif"
    all_data["semgrep"] = parse_semgrep(semgrep_path) if semgrep_path.exists() else {"error": "File not found", "ok": False, "findings": []}

    npm_path = reports_dir / "npm-audit.json"
    all_data["npm_audit"] = parse_npm_audit(npm_path) if npm_path.exists() else {"error": "File not found", "ok": False}

    trivy_path = reports_dir / "trivy-report.json"
    all_data["trivy"] = parse_trivy(trivy_path) if trivy_path.exists() else {"error": "File not found", "ok": False}

    zap_path = reports_dir / "zap-report.json"
    all_data["zap"] = parse_zap(zap_path) if zap_path.exists() else {"error": "File not found", "ok": False}

    styles = build_styles()

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.2*cm, bottomMargin=1.5*cm,
        title="Security Audit Report â€” Juice Shop CI",
        author="DevSecOps Pipeline",
        subject="Automated Security Analysis",
    )

    story = []
    story += build_cover(styles, run_id, repo, date_str)
    story += build_toc(styles)
    story += build_executive_summary(styles, all_data)
    story += build_gitleaks_section(styles, all_data["gitleaks"])
    story += build_semgrep_section(styles, all_data["semgrep"])
    story += build_npm_audit_section(styles, all_data["npm_audit"])
    story += build_trivy_section(styles, all_data["trivy"])
    story += build_zap_section(styles, all_data["zap"])
    story += build_recommendations(styles, all_data)
    story += build_methodology(styles)

    doc.build(story, onFirstPage=add_header_footer, onLaterPages=add_header_footer)
    print(f"[+] Report generated: {output_path}")

if __name__ == "__main__":
    main()
