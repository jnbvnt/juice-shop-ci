#!/usr/bin/env python3
"""
Security Report Generator for Juice Shop CI Pipeline
Generates a unified, professional PDF report from all security scan outputs.
Uses DejaVu Sans TTF for full Unicode/emoji support.
"""

import json
import os
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
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ── Register TTF fonts (DejaVu = full Unicode support) ─────────────────────────
FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu",
    "/usr/local/lib/python3.12/dist-packages/matplotlib/mpl-data/fonts/ttf",
]

def find_font(filename):
    for base in FONT_PATHS:
        p = Path(base) / filename
        if p.exists():
            return str(p)
    return None

_reg  = find_font("DejaVuSans.ttf")
_bold = find_font("DejaVuSans-Bold.ttf")
_ital = find_font("DejaVuSans-Oblique.ttf") or _reg
_bi   = find_font("DejaVuSans-BoldOblique.ttf") or _bold

if _reg and _bold:
    pdfmetrics.registerFont(TTFont("DV",     _reg))
    pdfmetrics.registerFont(TTFont("DV-B",   _bold))
    pdfmetrics.registerFont(TTFont("DV-I",   _ital))
    pdfmetrics.registerFont(TTFont("DV-BI",  _bi))
    from reportlab.pdfbase.pdfmetrics import registerFontFamily
    registerFontFamily("DV", normal="DV", bold="DV-B", italic="DV-I", boldItalic="DV-BI")
    FONT      = "DV"
    FONT_BOLD = "DV-B"
    FONT_ITAL = "DV-I"
else:
    FONT      = "Helvetica"
    FONT_BOLD = "Helvetica-Bold"
    FONT_ITAL = "Helvetica-Oblique"

# ── Color palette ──────────────────────────────────────────────────────────────
DARK_BG     = colors.HexColor("#1a1a2e")
ACCENT_BLUE = colors.HexColor("#0f3460")
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

# ── Styles ─────────────────────────────────────────────────────────────────────
def build_styles():
    s = {}
    def ps(name, **kw):
        kw.setdefault("fontName", FONT)
        return ParagraphStyle(name, **kw)

    s["cover_title"]     = ps("cover_title",     fontSize=26, leading=32, textColor=WHITE,     alignment=TA_CENTER, fontName=FONT_BOLD, spaceAfter=6)
    s["cover_sub"]       = ps("cover_sub",        fontSize=13, leading=17, textColor=colors.HexColor("#a0aec0"), alignment=TA_CENTER, spaceAfter=4)
    s["cover_meta"]      = ps("cover_meta",       fontSize=10, leading=14, textColor=colors.HexColor("#718096"), alignment=TA_CENTER)
    s["section_title"]   = ps("section_title",    fontSize=17, leading=21, textColor=ACCENT_BLUE, fontName=FONT_BOLD, spaceBefore=16, spaceAfter=7)
    s["subsection"]      = ps("subsection",       fontSize=12, leading=16, textColor=TEXT_DARK,   fontName=FONT_BOLD, spaceBefore=10, spaceAfter=5)
    s["body"]            = ps("body",             fontSize=10, leading=14, textColor=TEXT_DARK,   spaceAfter=5)
    s["body_muted"]      = ps("body_muted",       fontSize=9,  leading=13, textColor=TEXT_MUTED,  spaceAfter=4)
    s["toc"]             = ps("toc",              fontSize=11, leading=16, textColor=TEXT_DARK,   leftIndent=12, spaceAfter=3)
    s["badge_white"]     = ps("badge_white",      fontSize=8,  textColor=WHITE, fontName=FONT_BOLD, alignment=TA_CENTER)
    s["sev_label"]       = ps("sev_label",        fontSize=8,  textColor=WHITE, fontName=FONT_BOLD, alignment=TA_CENTER)
    s["sev_count"]       = ps("sev_count",        fontSize=18, textColor=WHITE, fontName=FONT_BOLD, alignment=TA_CENTER)
    s["risk_title"]      = ps("risk_title",       fontSize=13, textColor=WHITE, fontName=FONT_BOLD)
    s["risk_desc"]       = ps("risk_desc",        fontSize=9,  textColor=WHITE)
    s["th"]              = ps("th",               fontSize=8,  textColor=WHITE, fontName=FONT_BOLD)
    s["td"]              = ps("td",               fontSize=8,  textColor=TEXT_DARK)
    s["td_muted"]        = ps("td_muted",         fontSize=8,  textColor=TEXT_MUTED)
    s["footer_center"]   = ps("footer_center",    fontSize=7,  textColor=TEXT_MUTED, alignment=TA_CENTER)
    return s

# ── Header / footer ────────────────────────────────────────────────────────────
def add_header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    page = canvas.getPageNumber()

    if page > 1:
        canvas.setFillColor(ACCENT_BLUE)
        canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont(FONT_BOLD, 9)
        canvas.drawString(2*cm, h - 0.82*cm, "Security Audit Report \u2014 Juice Shop CI")
        canvas.setFont(FONT, 8)
        canvas.drawRightString(w - 2*cm, h - 0.82*cm, "CONFIDENTIAL")

        canvas.setFillColor(MID_GREY)
        canvas.rect(0, 0, w, 0.8*cm, fill=1, stroke=0)
        canvas.setFillColor(TEXT_MUTED)
        canvas.setFont(FONT, 7)
        canvas.drawString(2*cm, 0.28*cm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawCentredString(w/2, 0.28*cm, f"Page {page}")
        canvas.drawRightString(w - 2*cm, 0.28*cm, "jnbvnt/juice-shop-ci")

    canvas.restoreState()

# ── Helpers ────────────────────────────────────────────────────────────────────
def divider():
    return HRFlowable(width="100%", thickness=1, color=MID_GREY, spaceAfter=6, spaceBefore=2)

def info_box(text, styles, bg=colors.HexColor("#e8f4fd"), border=BLUE_LOW):
    t = Table([[Paragraph(text, styles["body"])]], colWidths=[16*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), bg),
        ("LINEBEFORE",   (0,0), (0,-1),  3, border),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
    ]))
    return t

def severity_summary_bar(counts_and_colors, styles):
    """Generic 4-column coloured counter bar."""
    labels = [Paragraph(label, styles["sev_label"]) for label, _, _ in counts_and_colors]
    vals   = [Paragraph(str(count), styles["sev_count"]) for _, count, _ in counts_and_colors]
    t = Table([labels, vals], colWidths=[4.2*cm]*4)
    style = [
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("GRID",          (0,0), (-1,-1), 1, WHITE),
    ]
    for i, (_, _, color) in enumerate(counts_and_colors):
        style.append(("BACKGROUND", (i,0), (i,-1), color))
    t.setStyle(TableStyle(style))
    return t

def findings_table(headers, rows, col_widths, styles):
    header_row = [Paragraph(h, styles["th"]) for h in headers]
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
    ]))
    return t

def status_pill(ok):
    text  = "PASS" if ok else "FAIL"
    color = GREEN_OK if ok else RED_CRIT
    t = Table([[Paragraph(text, ParagraphStyle("pill", fontName=FONT_BOLD, fontSize=8,
                textColor=WHITE, alignment=TA_CENTER))]], colWidths=[1.6*cm], rowHeights=[0.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), color),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 2),
        ("BOTTOMPADDING", (0,0), (-1,-1), 2),
    ]))
    return t

def sev_text(sev, styles):
    return Paragraph(sev, ParagraphStyle("sv", fontName=FONT_BOLD, fontSize=8,
           textColor=SEVERITY_COLORS.get(sev.upper(), GREY_INFO)))

# ── Data parsers ───────────────────────────────────────────────────────────────
def parse_gitleaks(path):
    r = {"findings": [], "ok": True}
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            r["findings"] = data
        elif isinstance(data, dict) and "runs" in data:
            for run in data.get("runs", []):
                for res in run.get("results", []):
                    loc = res.get("locations", [{}])[0]
                    r["findings"].append({
                        "rule": res.get("ruleId", "N/A"),
                        "desc": res.get("message", {}).get("text", "N/A"),
                        "file": loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "N/A"),
                    })
        r["ok"] = len(r["findings"]) == 0
    except Exception as e:
        r["error"] = str(e)
    return r

def parse_semgrep(path):
    r = {"findings": [], "ok": True}
    try:
        data = json.loads(path.read_text())
        for run in data.get("runs", []):
            for res in run.get("results", []):
                loc = res.get("locations", [{}])[0].get("physicalLocation", {})
                r["findings"].append({
                    "rule":     res.get("ruleId", "N/A")[-45:],
                    "message":  res.get("message", {}).get("text", "N/A")[:180],
                    "file":     loc.get("artifactLocation", {}).get("uri", "N/A")[-45:],
                    "line":     loc.get("region", {}).get("startLine", "?"),
                    "severity": res.get("level", "warning").upper(),
                })
        r["ok"] = len(r["findings"]) == 0
    except Exception as e:
        r["error"] = str(e)
    return r

def parse_npm_audit(path):
    r = {"critical":0,"high":0,"moderate":0,"low":0,"vulns":[],"ok":True}
    try:
        data = json.loads(path.read_text())
        m = data.get("metadata", {}).get("vulnerabilities", {})
        r.update({k: m.get(k, 0) for k in ("critical","high","moderate","low")})
        r["ok"] = (r["critical"] + r["high"]) == 0
        order = ["critical","high","moderate","low","unknown"]
        for name, v in data.get("vulnerabilities", {}).items():
            r["vulns"].append({
                "name":     name,
                "severity": v.get("severity","unknown"),
                "range":    v.get("range","N/A"),
                "via":      str(v.get("via",["N/A"])[0])[:80] if v.get("via") else "N/A",
            })
        r["vulns"].sort(key=lambda x: order.index(x["severity"]) if x["severity"] in order else 99)
    except Exception as e:
        r["error"] = str(e)
    return r

def parse_trivy(path):
    r = {"critical":0,"high":0,"medium":0,"low":0,"unknown":0,"vulns":[],"ok":True}
    try:
        data = json.loads(path.read_text())
        for res in data.get("Results", []):
            for v in res.get("Vulnerabilities", []):
                sev = v.get("Severity","UNKNOWN").upper()
                key = sev.lower()
                r[key] = r.get(key, 0) + 1
                r["vulns"].append({
                    "id":      v.get("VulnerabilityID","N/A"),
                    "pkg":     v.get("PkgName","N/A"),
                    "version": v.get("InstalledVersion","N/A"),
                    "fixed":   v.get("FixedVersion","N/A") or "-",
                    "severity":sev,
                    "title":   v.get("Title","N/A")[:70],
                })
        r["ok"] = (r["critical"] + r["high"]) == 0
    except Exception as e:
        r["error"] = str(e)
    return r

def parse_zap(path):
    r = {"high":0,"medium":0,"low":0,"info":0,"alerts":[],"ok":True}
    try:
        data = json.loads(path.read_text())
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk = alert.get("riskdesc","").split()[0].upper()
                r["alerts"].append({
                    "name":     alert.get("name","N/A"),
                    "risk":     risk,
                    "url":      alert.get("instances",[{}])[0].get("uri","N/A")[:70],
                    "solution": alert.get("solution","N/A")[:150],
                })
                if risk == "HIGH":    r["high"] += 1
                elif risk == "MEDIUM":r["medium"] += 1
                elif risk == "LOW":   r["low"] += 1
                else:                 r["info"] += 1
        r["ok"] = r["high"] == 0
    except Exception as e:
        r["error"] = str(e)
    return r

# ── Page builders ──────────────────────────────────────────────────────────────
def build_cover(styles, run_id, repo, date_str):
    story = [Spacer(1, 2.5*cm)]

    cover_block = Table([
        [Paragraph("SECURITY AUDIT REPORT", styles["cover_title"])],
        [Paragraph("DevSecOps Pipeline \u2014 Comprehensive Analysis", styles["cover_sub"])],
        [Spacer(1, 0.3*cm)],
        [Paragraph(f"Repository: <b>{repo}</b>", styles["cover_meta"])],
        [Paragraph(f"Pipeline Run: <b>#{run_id}</b>", styles["cover_meta"])],
        [Paragraph(f"Generated: <b>{date_str}</b>", styles["cover_meta"])],
        [Paragraph("Classification: INTERNAL \u2014 TRAINING", styles["cover_meta"])],
    ], colWidths=[17*cm])
    cover_block.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), DARK_BG),
        ("TOPPADDING",    (0,0), (-1,-1), 14),
        ("BOTTOMPADDING", (0,0), (-1,-1), 14),
        ("LEFTPADDING",   (0,0), (-1,-1), 20),
        ("RIGHTPADDING",  (0,0), (-1,-1), 20),
    ]))
    story.append(cover_block)
    story.append(Spacer(1, 1.2*cm))

    tools = ["Gitleaks", "Semgrep", "npm audit", "OWASP DC", "Trivy", "OWASP ZAP"]
    badge_row = [[Paragraph(t, styles["badge_white"]) for t in tools]]
    badges = Table(badge_row, colWidths=[2.7*cm]*6)
    badges.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), ACCENT_BLUE),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#2d3748")),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
    ]))
    story.append(badges)
    story.append(Spacer(1, 1*cm))

    story.append(info_box(
        "<b>Disclaimer:</b> This report was generated automatically as part of a DevSecOps "
        "training exercise targeting the intentionally vulnerable application <b>OWASP Juice Shop</b>. "
        "All findings are expected and serve educational purposes only.",
        styles, bg=colors.HexColor("#fff3cd"), border=YELLOW_MED
    ))
    story.append(PageBreak())
    return story

def build_toc(styles):
    story = [Paragraph("Table of Contents", styles["section_title"]), divider()]
    entries = [
        ("1", "Executive Summary"),
        ("2", "Secret Detection \u2014 Gitleaks"),
        ("3", "Static Analysis (SAST) \u2014 Semgrep"),
        ("4", "Dependency Analysis (SCA) \u2014 npm audit"),
        ("5", "Container Image Analysis \u2014 Trivy"),
        ("6", "Dynamic Analysis (DAST) \u2014 OWASP ZAP"),
        ("7", "Recommendations & Remediation"),
        ("8", "Methodology & Tools"),
    ]
    for num, title in entries:
        story.append(Paragraph(f"<b>{num}.</b>\u00a0\u00a0{title}", styles["toc"]))
        story.append(Spacer(1, 2))
    story.append(PageBreak())
    return story

def build_executive_summary(styles, all_data):
    story = [Paragraph("1. Executive Summary", styles["section_title"]), divider()]

    gl = all_data.get("gitleaks", {})
    sg = all_data.get("semgrep", {})
    na = all_data.get("npm_audit", {})
    tv = all_data.get("trivy", {})
    zp = all_data.get("zap", {})

    rows = [
        [Paragraph("<b>Control</b>", styles["th"]),
         Paragraph("<b>Tool</b>", styles["th"]),
         Paragraph("<b>Findings</b>", styles["th"]),
         Paragraph("<b>Status</b>", styles["th"])],
        [Paragraph("Secret Detection",          styles["body"]), Paragraph("Gitleaks",          styles["body_muted"]),
         Paragraph(str(len(gl.get("findings",[]))), styles["body"]), status_pill(gl.get("ok", False))],
        [Paragraph("Static Analysis (SAST)",    styles["body"]), Paragraph("Semgrep",           styles["body_muted"]),
         Paragraph(str(len(sg.get("findings",[]))), styles["body"]), status_pill(sg.get("ok", False))],
        [Paragraph("Dependency Analysis (SCA)", styles["body"]), Paragraph("npm audit",         styles["body_muted"]),
         Paragraph(f"C:{na.get('critical',0)} H:{na.get('high',0)} M:{na.get('moderate',0)} L:{na.get('low',0)}", styles["body"]),
         status_pill(na.get("ok", False))],
        [Paragraph("Container Scan",            styles["body"]), Paragraph("Trivy",             styles["body_muted"]),
         Paragraph(f"C:{tv.get('critical',0)} H:{tv.get('high',0)} M:{tv.get('medium',0)} L:{tv.get('low',0)}", styles["body"]),
         status_pill(tv.get("ok", False))],
        [Paragraph("Dynamic Analysis (DAST)",   styles["body"]), Paragraph("OWASP ZAP",         styles["body_muted"]),
         Paragraph(f"H:{zp.get('high',0)} M:{zp.get('medium',0)} L:{zp.get('low',0)}", styles["body"]),
         status_pill(zp.get("ok", False))],
    ]
    t = Table(rows, colWidths=[5.5*cm, 4*cm, 5*cm, 2.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), ACCENT_BLUE),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, LIGHT_GREY]),
        ("GRID",          (0,0), (-1,-1), 0.5, MID_GREY),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("ALIGN",         (3,0), (3,-1), "CENTER"),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.8*cm))

    total_crit_high = (
        na.get("critical",0) + na.get("high",0) +
        tv.get("critical",0) + tv.get("high",0) +
        zp.get("high",0)
    )
    if total_crit_high == 0:
        level, color, desc = "LOW",      GREEN_OK,    "No critical or high severity findings detected."
    elif total_crit_high <= 5:
        level, color, desc = "MEDIUM",   YELLOW_MED,  f"{total_crit_high} critical/high findings require attention before production deployment."
    elif total_crit_high <= 20:
        level, color, desc = "HIGH",     ORANGE_HIGH, f"{total_crit_high} critical/high findings. Significant security work required."
    else:
        level, color, desc = "CRITICAL", RED_CRIT,    f"{total_crit_high} critical/high findings. Application must not be deployed to production."

    risk = Table([[
        Paragraph(f"Overall Risk Level: <b>{level}</b>", styles["risk_title"]),
        Paragraph(desc, styles["risk_desc"]),
    ]], colWidths=[5*cm, 12*cm])
    risk.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), color),
        ("TOPPADDING",    (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("LEFTPADDING",   (0,0), (-1,-1), 14),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(risk)
    story.append(PageBreak())
    return story

def _section_header(num, title, tool, desc, styles):
    return [
        Paragraph(f"{num}. {title}", styles["section_title"]),
        divider(),
        Paragraph(f"<b>Tool:</b> {tool}", styles["body_muted"]),
        Paragraph(desc, styles["body"]),
        Spacer(1, 0.4*cm),
    ]

def _error_or_pass(data, pass_msg, styles):
    if "error" in data:
        return [info_box(f"Report not available: {data['error']}", styles,
                         bg=colors.HexColor("#fff3cd"), border=YELLOW_MED), PageBreak()]
    if not data.get("findings", [True]):  # empty list = pass
        return [info_box(pass_msg, styles, bg=colors.HexColor("#d4edda"), border=GREEN_OK), PageBreak()]
    return None

def build_gitleaks_section(styles, data):
    story = _section_header("2", "Secret Detection", "Gitleaks",
        "Gitleaks scans the entire Git history for hardcoded secrets, API keys, tokens and passwords "
        "that should never be committed to source control.", styles)

    short = _error_or_pass({"findings": data.get("findings",[]), "error": data.get("error","") or None} if "error" in data else {"findings": data.get("findings",[])},
                           "No secrets detected in the repository history.", styles)
    if short:
        story += short
        return story

    findings = data.get("findings", [])
    story.append(Paragraph(f"<b>{len(findings)} secret(s) found:</b>", styles["subsection"]))
    rows = []
    for f in findings[:30]:
        rows.append([
            Paragraph(str(f.get("rule", f.get("RuleID","N/A"))), styles["td"]),
            Paragraph(str(f.get("desc", f.get("Description","N/A")))[:130], styles["td"]),
            Paragraph(str(f.get("file", f.get("File","N/A")))[-50:], styles["td_muted"]),
        ])
    story.append(findings_table(["Rule ID","Description","File"], rows,
                                [4*cm, 9*cm, 4*cm], styles))
    if len(findings) > 30:
        story.append(Paragraph(f"<i>... and {len(findings)-30} more. See raw SARIF report.</i>", styles["body_muted"]))
    story.append(PageBreak())
    return story

def build_semgrep_section(styles, data):
    story = _section_header("3", "Static Analysis (SAST)", "Semgrep",
        "Pattern-based static analysis using JavaScript, Node.js and OWASP Top 10 rulesets. "
        "Identifies code-level vulnerabilities without executing the application.", styles)

    if "error" in data:
        story += [info_box(f"Report not available: {data['error']}", styles,
                           bg=colors.HexColor("#fff3cd"), border=YELLOW_MED), PageBreak()]
        return story

    findings = data.get("findings", [])
    if not findings:
        story += [info_box("No SAST findings detected.", styles,
                           bg=colors.HexColor("#d4edda"), border=GREEN_OK), PageBreak()]
        return story

    sev_counts = {}
    for f in findings:
        s = f.get("severity","WARNING")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    story.append(Paragraph(f"<b>Total findings: {len(findings)}</b>", styles["subsection"]))
    count_rows = [[Paragraph(f"<b>{s}</b>", styles["td"]), Paragraph(str(c), styles["td"])]
                  for s, c in sorted(sev_counts.items())]
    ct = Table(count_rows, colWidths=[4*cm, 2*cm])
    ct.setStyle(TableStyle([
        ("GRID",          (0,0), (-1,-1), 0.4, MID_GREY),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0,0), (-1,-1), [WHITE, LIGHT_GREY]),
    ]))
    story += [ct, Spacer(1, 0.4*cm)]

    rows = []
    for f in findings[:25]:
        rows.append([
            Paragraph(f.get("rule","N/A"), styles["td_muted"]),
            Paragraph(f.get("message","N/A"), styles["td"]),
            Paragraph(f"{f.get('file','N/A')}:{f.get('line','?')}", styles["td_muted"]),
            sev_text(f.get("severity","N/A"), styles),
        ])
    story.append(findings_table(["Rule","Message","Location","Sev"],
                                rows, [4*cm, 7.5*cm, 4*cm, 1.5*cm], styles))
    if len(findings) > 25:
        story.append(Paragraph(f"<i>... and {len(findings)-25} more findings.</i>", styles["body_muted"]))
    story.append(PageBreak())
    return story

def build_npm_section(styles, data):
    story = _section_header("4", "Dependency Analysis (SCA)", "npm audit",
        "Cross-references all declared dependencies against the npm advisory database "
        "to identify components with known CVEs (supply chain risk).", styles)

    if "error" in data:
        story += [info_box(f"Report not available: {data['error']}", styles,
                           bg=colors.HexColor("#fff3cd"), border=YELLOW_MED), PageBreak()]
        return story

    story.append(severity_summary_bar([
        ("CRITICAL", data.get("critical",0), RED_CRIT),
        ("HIGH",     data.get("high",0),     ORANGE_HIGH),
        ("MODERATE", data.get("moderate",0), YELLOW_MED),
        ("LOW",      data.get("low",0),      BLUE_LOW),
    ], styles))
    story.append(Spacer(1, 0.5*cm))

    vulns = data.get("vulns", [])
    if vulns:
        story.append(Paragraph(f"<b>Top vulnerable packages ({min(20,len(vulns))} of {len(vulns)} shown):</b>", styles["subsection"]))
        rows = [[Paragraph(v.get("name","N/A"), styles["td"]),
                 sev_text(v.get("severity","N/A").upper(), styles),
                 Paragraph(v.get("range","N/A"), styles["td_muted"]),
                 Paragraph(v.get("via","N/A"), styles["td_muted"])]
                for v in vulns[:20]]
        story.append(findings_table(["Package","Severity","Affected Range","Via"],
                                    rows, [4.5*cm, 2*cm, 3*cm, 7.5*cm], styles))
    story.append(PageBreak())
    return story

def build_trivy_section(styles, data):
    story = _section_header("5", "Container Image Analysis", "Trivy",
        "Scans the Docker image for OS-level and application-level vulnerabilities "
        "against NVD, GitHub Advisory and other CVE databases.", styles)

    if "error" in data:
        story += [info_box(f"Report not available: {data['error']}", styles,
                           bg=colors.HexColor("#fff3cd"), border=YELLOW_MED), PageBreak()]
        return story

    story.append(severity_summary_bar([
        ("CRITICAL", data.get("critical",0), RED_CRIT),
        ("HIGH",     data.get("high",0),     ORANGE_HIGH),
        ("MEDIUM",   data.get("medium",0),   YELLOW_MED),
        ("LOW",      data.get("low",0),      BLUE_LOW),
    ], styles))
    story.append(Spacer(1, 0.5*cm))

    crit_high = [v for v in data.get("vulns",[]) if v.get("severity") in ("CRITICAL","HIGH")]
    if crit_high:
        story.append(Paragraph(f"<b>Critical & High CVEs ({min(20,len(crit_high))} of {len(crit_high)} shown):</b>", styles["subsection"]))
        rows = [[Paragraph(v.get("id","N/A"), styles["td"]),
                 Paragraph(v.get("pkg","N/A"), styles["td"]),
                 Paragraph(v.get("version","N/A"), styles["td_muted"]),
                 Paragraph(v.get("fixed","-"), ParagraphStyle("fix", fontName=FONT, fontSize=8, textColor=GREEN_OK)),
                 sev_text(v.get("severity","N/A"), styles),
                 Paragraph(v.get("title","N/A"), styles["td_muted"])]
                for v in crit_high[:20]]
        story.append(findings_table(["CVE ID","Package","Version","Fixed In","Sev","Title"],
                                    rows, [3.2*cm, 2.5*cm, 2*cm, 2*cm, 1.8*cm, 5.5*cm], styles))
    story.append(PageBreak())
    return story

def build_zap_section(styles, data):
    story = _section_header("6", "Dynamic Analysis (DAST)", "OWASP ZAP",
        "Baseline scan against the running application simulating an attacker probing for XSS, "
        "injection, insecure headers and misconfigurations (unauthenticated).", styles)

    if "error" in data:
        story += [info_box(f"Report not available: {data['error']}", styles,
                           bg=colors.HexColor("#fff3cd"), border=YELLOW_MED), PageBreak()]
        return story

    story.append(severity_summary_bar([
        ("HIGH",   data.get("high",0),   RED_CRIT),
        ("MEDIUM", data.get("medium",0), YELLOW_MED),
        ("LOW",    data.get("low",0),    BLUE_LOW),
        ("INFO",   data.get("info",0),   GREY_INFO),
    ], styles))
    story.append(Spacer(1, 0.5*cm))

    alerts = data.get("alerts", [])
    if alerts:
        order = ["HIGH","MEDIUM","LOW","INFO"]
        alerts.sort(key=lambda x: order.index(x.get("risk","INFO")) if x.get("risk","INFO") in order else 99)
        story.append(Paragraph(f"<b>Alerts ({min(20,len(alerts))} of {len(alerts)} shown):</b>", styles["subsection"]))
        rows = [[Paragraph(a.get("name","N/A"), styles["td"]),
                 sev_text(a.get("risk","N/A"), styles),
                 Paragraph(a.get("url","N/A"), styles["td_muted"]),
                 Paragraph(a.get("solution","N/A"), styles["td_muted"])]
                for a in alerts[:20]]
        story.append(findings_table(["Alert Name","Risk","URL","Solution"],
                                    rows, [5*cm, 1.8*cm, 4.5*cm, 5.7*cm], styles))
    story.append(PageBreak())
    return story

def build_recommendations(styles):
    story = [Paragraph("7. Recommendations & Remediation", styles["section_title"]), divider()]
    recs = [
        ("[1] Secrets Management",
         "Never commit secrets to the repository. Use GitHub Secrets or a vault solution "
         "(HashiCorp Vault, AWS Secrets Manager). Rotate any secret detected by Gitleaks immediately. "
         "Add pre-commit hooks with Gitleaks to prevent future leaks."),
        ("[2] Dependency Management",
         "Run `npm audit fix` to automatically patch compatible vulnerabilities. "
         "Set up Dependabot or Renovate Bot for automated PR-based dependency updates. "
         "Consider pinning dependencies with exact versions in package-lock.json."),
        ("[3] Container Hardening",
         "Use a minimal base image (e.g. node:22-alpine). Run the container as a non-root user. "
         "Regularly rebuild images to include OS-level security patches. "
         "Add Trivy to the CI gate with a CRITICAL threshold that fails the build."),
        ("[4] Code Security",
         "Address SAST findings categorized as ERROR priority first. "
         "Enable ESLint security plugins (eslint-plugin-security). "
         "Conduct periodic manual code reviews focusing on authentication, authorization, and input validation."),
        ("[5] Application Security",
         "Add Content-Security-Policy, X-Frame-Options, and other security headers. "
         "Implement rate limiting on all API endpoints. "
         "Consider OWASP ZAP authenticated scan to cover protected endpoints."),
        ("[6] Pipeline Improvements",
         "Add a quality gate: fail the pipeline on CRITICAL findings. "
         "Add SBOM (Software Bill of Materials) generation with Syft. "
         "Archive reports to dedicated storage with long retention (S3, artifact registry)."),
    ]
    for title, body in recs:
        story.append(KeepTogether([
            Paragraph(title, styles["subsection"]),
            Paragraph(body, styles["body"]),
            Spacer(1, 0.2*cm),
        ]))
    story.append(PageBreak())
    return story

def build_methodology(styles):
    story = [Paragraph("8. Methodology & Tools", styles["section_title"]), divider()]

    tools = [
        ("Gitleaks",  "v8.x",   "Secret Detection", "MIT",        "Scans Git history for exposed credentials"),
        ("Semgrep",   "Latest", "SAST",             "LGPL-2.1",   "Pattern-based static analysis with security rulesets"),
        ("npm audit", "Built-in","SCA",             "npm Inc.",    "Checks deps against npm advisory database"),
        ("OWASP DC",  "Latest", "SCA",              "Apache 2.0", "Identifies known CVEs in project dependencies"),
        ("Trivy",     "Latest", "Container Scan",   "Apache 2.0", "Scans container images for OS and library CVEs"),
        ("OWASP ZAP", "Latest", "DAST",             "Apache 2.0", "Automated web application security scanner"),
    ]
    rows = [[Paragraph(f"<b>{h}</b>", styles["th"]) for h in ["Tool","Version","Category","License","Purpose"]]]
    for row in tools:
        rows.append([Paragraph(cell, styles["td"]) for cell in row])

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
    story += [t, Spacer(1, 0.8*cm)]

    story.append(Paragraph("Pipeline Architecture", styles["subsection"]))
    story.append(Paragraph("The pipeline follows a shift-left security approach, integrating security checks at every stage:", styles["body"]))

    phases = [
        ("1. Code Push",     "Developer pushes code to GitHub repository"),
        ("2. Secret Scan",   "Gitleaks scans entire Git history \u2014 blocks on findings"),
        ("3. Build",         "Node.js dependencies installed, frontend compiled"),
        ("4. Unit Tests",    "Application unit and API tests executed"),
        ("5. SAST",          "Semgrep analyzes source code for security patterns"),
        ("6. SCA",           "npm audit + OWASP DC check all dependencies"),
        ("7. Docker Build",  "Container image built from Dockerfile"),
        ("8. Container Scan","Trivy scans image for CVEs"),
        ("9. Deploy (test)", "Image deployed to ephemeral test environment"),
        ("10. DAST",         "OWASP ZAP baseline scan against live application"),
        ("11. Report",       "All results collected and unified PDF generated"),
    ]
    phase_rows = [[Paragraph(f"<b>{p}</b>", styles["td"]), Paragraph(d, styles["td_muted"])]
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

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    rep   = Path(os.environ.get("REPORTS_DIR", "."))
    out   = Path(os.environ.get("OUTPUT_PDF",  "security-report.pdf"))
    repo  = os.environ.get("REPO_NAME", "jnbvnt/juice-shop-ci")
    run   = os.environ.get("RUN_ID",    "N/A")
    date  = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    print(f"[*] Reports dir : {rep}")
    print(f"[*] Output      : {out}")
    print(f"[*] Font        : {FONT}")

    def load(name, parser):
        p = rep / name
        return parser(p) if p.exists() else {"error": "File not found", "ok": False, "findings": []}

    all_data = {
        "gitleaks":  load("results.sarif",   parse_gitleaks),
        "semgrep":   load("semgrep.sarif",   parse_semgrep),
        "npm_audit": load("npm-audit.json",  parse_npm_audit),
        "trivy":     load("trivy-report.json", parse_trivy),
        "zap":       load("zap-report.json", parse_zap),
    }

    styles = build_styles()

    doc = SimpleDocTemplate(
        str(out), pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.2*cm, bottomMargin=1.5*cm,
        title="Security Audit Report \u2014 Juice Shop CI",
        author="DevSecOps Pipeline",
        subject="Automated Security Analysis",
    )

    story = []
    story += build_cover(styles, run, repo, date)
    story += build_toc(styles)
    story += build_executive_summary(styles, all_data)
    story += build_gitleaks_section(styles, all_data["gitleaks"])
    story += build_semgrep_section(styles, all_data["semgrep"])
    story += build_npm_section(styles, all_data["npm_audit"])
    story += build_trivy_section(styles, all_data["trivy"])
    story += build_zap_section(styles, all_data["zap"])
    story += build_recommendations(styles)
    story += build_methodology(styles)

    doc.build(story, onFirstPage=add_header_footer, onLaterPages=add_header_footer)
    print(f"[+] Done: {out}")

if __name__ == "__main__":
    main()
