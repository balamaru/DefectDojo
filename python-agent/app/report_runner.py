#!/usr/bin/env python3
"""
report_runner.py — Final Merged Version
Wazuh Vulnerability + DDoS Security Report

Tampilan     : Dark Navy + Orange theme, professional corporate
Fitur tambahan:
  - Recommended Action per CVE (P1/P2/P3 + SLA + steps)
  - ToC otomatis dengan page number
  - Cover page dengan KPI boxes
  - Charts: bar, pie, heatmap
  - All agents grouped by severity
  - Header/footer setiap halaman
"""

from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Optional
from io import BytesIO
import json
import requests
import warnings
import logging

from requests.auth import HTTPBasicAuth

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image as RLImage, KeepTogether
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.platypus.flowables import Flowable

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

try:
    from app.config import settings
except ImportError:
    from config import settings

OUTPUT_DIR = Path("/home/bakti/wazuh-report-worker/output")
TMP_DIR    = Path("/home/bakti/wazuh-report-worker/tmp")

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# COLOUR PALETTE  —  Dark Navy + Orange
C_NAVY      = colors.HexColor("#0D1B2A")   # header utama
C_NAVY2     = colors.HexColor("#1B2A3B")   # header sekunder
C_ORANGE    = colors.HexColor("#E85D04")   # aksen utama
C_ORANGE2   = colors.HexColor("#F48C06")   # aksen sekunder / High
C_CRITICAL  = colors.HexColor("#C0392B")
C_HIGH      = colors.HexColor("#E85D04")
C_MEDIUM    = colors.HexColor("#F4A261")
C_LOW       = colors.HexColor("#2ECC71")
C_WHITE     = colors.white
C_LIGHT     = colors.HexColor("#F4F6F9")
C_LIGHT2    = colors.HexColor("#EAF0FB")
C_BORDER    = colors.HexColor("#CDD3DA")
C_TEXT      = colors.HexColor("#1B2A3B")
C_MUTED     = colors.HexColor("#6C757D")

SEV_COLOR = {
    "Critical": C_CRITICAL,
    "High":     C_HIGH,
    "Medium":   C_MEDIUM,
    "Low":      C_LOW,
}

# RECOMMENDED ACTION ENGINE

_ACTION_MATRIX = {
    ("Critical", "9+"): ("P1 — IMMEDIATE",  "Patch within 24 hours",
        ["Isolate host if exploitation suspected",
         "Apply vendor patch / hotfix immediately",
         "Verify patch — re-scan after remediation",
         "Investigate logs for exploitation indicators",
         "Escalate to Security Lead"]),
    ("Critical", "7+"): ("P1 — URGENT",     "Patch within 48 hours",
        ["Apply vendor patch immediately",
         "Apply workaround if patch unavailable",
         "Monitor logs for anomalous activity",
         "Verify remediation and re-scan"]),
    ("High",     "9+"): ("P1 — URGENT",     "Patch within 48 hours",
        ["Patch within 48 hours — high CVSS score",
         "Apply network-level mitigations if applicable",
         "Monitor for exploitation indicators",
         "Verify patch and re-scan"]),
    ("High",     "7+"): ("P2 — HIGH",       "Patch within 7 days",
        ["Schedule patch within 7 days",
         "Apply compensating control (restrict access)",
         "Monitor service logs during remediation",
         "Verify remediation and close finding"]),
    ("Medium",   "4+"): ("P3 — MODERATE",   "Patch within 30 days",
        ["Schedule patch in next maintenance window",
         "Assess exploitability in your environment",
         "Document remediation plan",
         "Verify at next scheduled scan"]),
    ("Low",      "0+"): ("P4 — LOW",        "Patch within 90 days",
        ["Add to backlog for next patch cycle",
         "Assess if compensating controls exist",
         "Document and track"]),
}

_IP_ACTION = {
    "High":   ("P1 — BLOCK CANDIDATE", "Review within 24 hours",
        ["Block IP at perimeter firewall",
         "Review all traffic logs from this IP (30 days)",
         "Check if internal systems connected to IP",
         "Add to threat intelligence blocklist"]),
    "Medium": ("P2 — WATCHLIST",       "Review within 7 days",
        ["Add to monitoring watchlist",
         "Review traffic patterns for C2/exfil",
         "Consider rate-limiting or geo-blocking"]),
    "Low":    ("P3 — MONITOR",         "Review within 30 days",
        ["Monitor passively",
         "Review if IP recurs in future scans"]),
}


def get_recommended_action(severity: str, cvss: float = None,
                            finding_type: str = "vulnerability",
                            ip_confidence: str = None) -> dict:
    if finding_type == "ip":
        d = _IP_ACTION.get(ip_confidence or "Low", _IP_ACTION["Low"])
        return {"priority": d[0], "sla": d[1], "actions": d[2]}

    score = float(cvss) if cvss is not None else 0.0
    if severity == "Critical":
        tier = "9+" if score >= 9.0 else "7+"
    elif severity == "High":
        tier = "9+" if score >= 9.0 else "7+"
    elif severity == "Medium":
        tier = "4+"
    else:
        tier = "0+"

    key = (severity, tier)
    d   = _ACTION_MATRIX.get(key)
    if not d:
        d = _ACTION_MATRIX.get(("High", "7+"))

    return {"priority": d[0], "sla": d[1], "actions": d[2]}


# STYLE FACTORY

def make_styles():
    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        # Cover
        "cover_title": ps("cover_title",
            fontSize=30, fontName="Helvetica-Bold",
            textColor=C_WHITE, alignment=TA_CENTER, leading=36),
        "cover_sub": ps("cover_sub",
            fontSize=12, fontName="Helvetica",
            textColor=colors.HexColor("#B0BEC5"),
            alignment=TA_CENTER, leading=18),
        "cover_meta": ps("cover_meta",
            fontSize=9, fontName="Helvetica",
            textColor=colors.HexColor("#90A4AE"),
            alignment=TA_CENTER),
        "kpi_val": ps("kpi_val",
            fontSize=26, fontName="Helvetica-Bold",
            textColor=C_ORANGE, alignment=TA_CENTER),
        "kpi_lbl": ps("kpi_lbl",
            fontSize=7, fontName="Helvetica",
            textColor=C_MUTED, alignment=TA_CENTER),
        # Headings
        "h1": ps("Heading1Custom",
            fontSize=15, fontName="Helvetica-Bold",
            textColor=C_NAVY, spaceBefore=14, spaceAfter=6),
        "h2": ps("Heading2Custom",
            fontSize=11, fontName="Helvetica-Bold",
            textColor=C_NAVY2, spaceBefore=10, spaceAfter=4),
        "h3": ps("h3",
            fontSize=9, fontName="Helvetica-Bold",
            textColor=C_TEXT, spaceBefore=6, spaceAfter=2),
        # Body
        "body": ps("body",
            fontSize=8.5, fontName="Helvetica",
            textColor=C_TEXT, leading=13),
        "body_sm": ps("body_sm",
            fontSize=7.5, fontName="Helvetica",
            textColor=C_TEXT, leading=11),
        "muted": ps("muted",
            fontSize=7.5, fontName="Helvetica",
            textColor=C_MUTED, leading=11),
        # ToC
        "toc1": ps("TOCLevel1",
            fontName="Helvetica-Bold", fontSize=10,
            leftIndent=10, spaceBefore=4, leading=13),
        "toc2": ps("TOCLevel2",
            fontName="Helvetica", fontSize=9,
            leftIndent=22, spaceBefore=2, leading=11),
        # Action
        "action_p1": ps("action_p1",
            fontSize=7.5, fontName="Helvetica-Bold",
            textColor=C_CRITICAL, leading=10),
        "action_p2": ps("action_p2",
            fontSize=7.5, fontName="Helvetica-Bold",
            textColor=C_HIGH, leading=10),
        "action_p3": ps("action_p3",
            fontSize=7.5, fontName="Helvetica-Bold",
            textColor=C_MEDIUM, leading=10),
        "action_body": ps("action_body",
            fontSize=7, fontName="Helvetica",
            textColor=C_TEXT, leading=10),
    }


# PAGE TEMPLATE  (header + footer + page number)

def _draw_page(canvas, doc):
    w, h = A4
    pn   = canvas.getPageNumber()

    if pn == 1:           # Cover — no decoration
        return

    canvas.saveState()

    # ── Header bar ──
    canvas.setFillColor(C_NAVY)
    canvas.rect(0, h - 18*mm, w, 18*mm, fill=1, stroke=0)

    canvas.setFillColor(C_ORANGE)
    canvas.rect(0, h - 19.5*mm, w, 1.5*mm, fill=1, stroke=0)

    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(15*mm, h - 12*mm,
                      getattr(doc, "_report_title", "Wazuh Security Report"))
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(w - 15*mm, h - 12*mm,
                           getattr(doc, "_generated_at", ""))

    # ── Footer ──
    canvas.setFillColor(C_LIGHT)
    canvas.rect(0, 0, w, 10*mm, fill=1, stroke=0)
    canvas.setFillColor(C_ORANGE)
    canvas.rect(0, 10*mm, w, 0.8*mm, fill=1, stroke=0)

    canvas.setFillColor(C_MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(15*mm, 3.5*mm, "CONFIDENTIAL — Internal Security Report")
    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(C_NAVY)
    canvas.drawRightString(w - 15*mm, 3.5*mm, f"Page {pn}")

    canvas.restoreState()


class WazuhDocTemplate(BaseDocTemplate):
    def __init__(self, filename, report_title="", generated_at="", **kwargs):
        super().__init__(filename, pagesize=A4,
                         leftMargin=18*mm, rightMargin=18*mm,
                         topMargin=24*mm, bottomMargin=16*mm,
                         **kwargs)
        self._report_title = report_title
        self._generated_at = generated_at

        frame = Frame(18*mm, 16*mm, A4[0]-36*mm, A4[1]-40*mm, id="main")
        self.addPageTemplates([
            PageTemplate(id="main", frames=[frame], onPage=_draw_page)
        ])

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            sn = flowable.style.name
            if sn == "Heading1Custom":
                self.notify("TOCEntry", (0, flowable.getPlainText(), self.page))
            elif sn == "Heading2Custom":
                self.notify("TOCEntry", (1, flowable.getPlainText(), self.page))


# HELPER UTILITIES

def _plot_to_image(fig, width=16*cm, height=7*cm):
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    return RLImage(buf, width=width, height=height)


def _tbl_style(header_color=None, alt=True):
    hc  = header_color or C_NAVY
    ts  = TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  hc),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0),  8),
        ("TOPPADDING",   (0, 0), (-1, 0),  5),
        ("BOTTOMPADDING",(0, 0), (-1, 0),  5),
        ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",     (0, 1), (-1, -1), 7.5),
        ("TOPPADDING",   (0, 1), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 1), (-1, -1), 3),
        ("GRID",         (0, 0), (-1, -1), 0.25, C_BORDER),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ])
    if alt:
        ts.add("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LIGHT])
    return ts


def _divider(color=C_ORANGE, width=None):
    w = width or (A4[0] - 36*mm)
    from reportlab.platypus.flowables import HRFlowable
    return HRFlowable(width=w, thickness=1.5, color=color, spaceAfter=4)


def _section(story, styles, num, title, subtitle=""):
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"{num}. {title}", styles["h1"]))
    story.append(_divider())
    if subtitle:
        story.append(Paragraph(subtitle, styles["muted"]))
    story.append(Spacer(1, 4))


# CHARTS

def chart_severity_bar(summary: dict):
    labels = ["Critical", "High"]
    vals   = [summary.get("critical_count", 0), summary.get("high_count", 0)]
    clrs   = ["#C0392B", "#E85D04"]

    fig, ax = plt.subplots(figsize=(5, 2.8), facecolor="#F4F6F9")
    ax.set_facecolor("#F4F6F9")
    bars = ax.bar(labels, vals, color=clrs, width=0.45, zorder=3,
                  edgecolor="white", linewidth=1.2)
    ax.set_title("Severity Distribution", fontsize=10, fontweight="bold",
                 color="#0D1B2A", pad=8)
    ax.set_ylabel("Count", fontsize=8)
    ax.grid(axis="y", alpha=0.35, zorder=0)
    ax.spines[["top","right"]].set_visible(False)
    for b in bars:
        h = b.get_height()
        if h > 0:
            ax.text(b.get_x()+b.get_width()/2, h+0.5, str(int(h)),
                    ha="center", va="bottom", fontsize=9, fontweight="bold")
    fig.tight_layout()
    return _plot_to_image(fig, 8*cm, 5.5*cm)


def chart_top_agents_bar(top_agents: list):
    names  = [a.get("agent_name","")[:18] for a in top_agents]
    crits  = [a.get("critical_cve_count", 0) for a in top_agents]
    highs  = [a.get("high_cve_count", 0) for a in top_agents]

    fig, ax = plt.subplots(figsize=(9, 3.5), facecolor="#F4F6F9")
    ax.set_facecolor("#F4F6F9")
    x = np.arange(len(names))
    w = 0.38
    b1 = ax.bar(x-w/2, crits, w, label="Critical", color="#C0392B",
                zorder=3, edgecolor="white")
    b2 = ax.bar(x+w/2, highs, w, label="High",     color="#E85D04",
                zorder=3, edgecolor="white")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=30, ha="right", fontsize=7.5)
    ax.set_ylabel("CVE Count", fontsize=8)
    ax.set_title("Top Agents by Vulnerability Count", fontsize=10,
                 fontweight="bold", color="#0D1B2A", pad=8)
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.35, zorder=0)
    ax.spines[["top","right"]].set_visible(False)
    for b in list(b1)+list(b2):
        if b.get_height()>0:
            ax.text(b.get_x()+b.get_width()/2, b.get_height()+0.2,
                    str(int(b.get_height())), ha="center", va="bottom", fontsize=7)
    fig.tight_layout()
    return _plot_to_image(fig, 14*cm, 6*cm)


def chart_agents_grouped(all_agents_grouped: dict):
    sevs  = ["Critical","High","Medium","Low","Clean"]
    cnts  = [len(all_agents_grouped.get(s,[])) for s in sevs]
    clrs  = ["#C0392B","#E85D04","#F4A261","#2ECC71","#95A5A6"]

    fig, ax = plt.subplots(figsize=(6, 3), facecolor="#F4F6F9")
    ax.set_facecolor("#F4F6F9")
    bars = ax.bar(sevs, cnts, color=clrs, width=0.5, zorder=3,
                  edgecolor="white", linewidth=1.2)
    ax.set_title("Agent Count by Highest Severity", fontsize=10,
                 fontweight="bold", color="#0D1B2A", pad=8)
    ax.set_ylabel("Agents", fontsize=8)
    ax.grid(axis="y", alpha=0.35, zorder=0)
    ax.spines[["top","right"]].set_visible(False)
    for b in bars:
        h = b.get_height()
        if h > 0:
            ax.text(b.get_x()+b.get_width()/2, h+0.1, str(int(h)),
                    ha="center", va="bottom", fontsize=9, fontweight="bold")
    fig.tight_layout()
    return _plot_to_image(fig, 10*cm, 5.5*cm)


def chart_malicious_ip(malicious: dict):
    items = malicious.get("high_confidence",[])
    if not items:
        return None
    ips   = [x.get("ip","")     for x in items[:10]]
    cnts  = [x.get("alert_count",0) for x in items[:10]]

    fig, ax = plt.subplots(figsize=(7, 3.5), facecolor="#F4F6F9")
    ax.set_facecolor("#F4F6F9")
    ax.barh(ips, cnts, color="#C0392B", zorder=3, edgecolor="white")
    ax.set_title("Validated Malicious IPs by Alert Count", fontsize=10,
                 fontweight="bold", color="#0D1B2A", pad=8)
    ax.set_xlabel("Alert Count", fontsize=8)
    ax.invert_yaxis()
    ax.grid(axis="x", alpha=0.35, zorder=0)
    ax.spines[["top","right"]].set_visible(False)
    fig.tight_layout()
    return _plot_to_image(fig, 12*cm, 6*cm)


# SECTION BUILDERS

def _build_cover(story, styles, canonical):
    meta    = canonical.get("meta", {})
    period  = meta.get("period", {})
    summary = canonical.get("vulnerability_summary", {})
    malicious = canonical.get("malicious_ip_summary", {})
    w       = A4[0] - 36*mm

    # Dark header block
    hdr = Table([[""]], colWidths=[w], rowHeights=[45*mm])
    hdr.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), C_NAVY),
    ]))
    story.append(Spacer(1, 10*mm))
    story.append(hdr)

    # Title overlay
    story.append(Spacer(1, -43*mm))
    story.append(Paragraph(
        meta.get("report_name","Wazuh Security Report"), styles["cover_title"]))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph("Automated Security Reporting Pipeline", styles["cover_sub"]))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        f"Period: {period.get('start','')[:10]}  →  {period.get('end','')[:10]}  "
        f"|  Generated: {meta.get('generated_at','')[:19].replace('T',' ')}",
        styles["cover_meta"]))
    story.append(Spacer(1, 14*mm))

    # Orange accent line
    story.append(_divider(C_ORANGE, w))
    story.append(Spacer(1, 4*mm))

    # KPI row
    kpis = [
        (str(summary.get("total_agents_affected",0)), "Affected Agents"),
        (str(summary.get("critical_count",0)),        "Critical CVEs"),
        (str(summary.get("high_count",0)),            "High CVEs"),
        (str(summary.get("total_findings",0)),        "Total Findings"),
        (str(len(malicious.get("high_confidence",[]))),"Malicious IPs"),
    ]
    kpi_top = [[Paragraph(v, styles["kpi_val"])  for v,_ in kpis]]
    kpi_bot = [[Paragraph(l, styles["kpi_lbl"])  for _,l in kpis]]
    kpi_tbl = Table(kpi_top + kpi_bot,
                    colWidths=[w/5]*5)
    kpi_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), C_LIGHT),
        ("BOX",          (0,0),(-1,-1), 0.5, C_BORDER),
        ("INNERGRID",    (0,0),(-1,-1), 0.3, C_BORDER),
        ("TOPPADDING",   (0,0),(-1,-1), 8),
        ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ("ALIGN",        (0,0),(-1,-1), "CENTER"),
    ]))
    story.append(kpi_tbl)
    story.append(Spacer(1, 8*mm))

    # Product / Engagement info
    dojo = meta.get("dojo",{})
    info_data = [
        ["DefectDojo Product", dojo.get("product","—")],
        ["DefectDojo Engagement", dojo.get("engagement","—")],
        ["Timezone", meta.get("timezone","—")],
    ]
    info_tbl = Table(info_data, colWidths=[60*mm, w-60*mm])
    info_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(0,-1), C_NAVY),
        ("TEXTCOLOR",    (0,0),(0,-1), C_WHITE),
        ("FONTNAME",     (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0),(-1,-1),8),
        ("TOPPADDING",   (0,0),(-1,-1),4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("GRID",         (0,0),(-1,-1),0.3, C_BORDER),
        ("BACKGROUND",   (1,0),(1,-1), C_LIGHT2),
    ]))
    story.append(info_tbl)
    story.append(PageBreak())


def _build_toc(story, styles):
    story.append(Paragraph("Table of Contents", styles["h1"]))
    story.append(_divider())
    story.append(Spacer(1, 4))
    toc = TableOfContents()
    toc.levelStyles = [styles["toc1"], styles["toc2"]]
    story.append(toc)
    story.append(PageBreak())


def _build_exec_summary(story, styles, canonical):
    _section(story, styles, 1, "Executive Summary",
             "High-level overview of the security posture for this reporting period.")

    meta      = canonical.get("meta", {})
    period    = meta.get("period", {})
    summary   = canonical.get("vulnerability_summary", {})
    malicious = canonical.get("malicious_ip_summary", {})
    dojo      = canonical.get("dojo_summary", {})

    # Period info table
    period_data = [
        ["Report Period",   f"{period.get('start','')[:10]}  to  {period.get('end','')[:10]}"],
        ["Timezone",        meta.get("timezone","")],
        ["Generated At",    meta.get("generated_at","")[:19].replace("T"," ")],
        ["Scope",           f"Top {meta.get('top_n',10)} agents analyzed in detail"],
    ]
    pt = Table(period_data, colWidths=[55*mm, 110*mm])
    pt.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(0,-1), C_NAVY),
        ("TEXTCOLOR",    (0,0),(0,-1), C_WHITE),
        ("FONTNAME",     (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0),(-1,-1),8),
        ("TOPPADDING",   (0,0),(-1,-1),4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("GRID",         (0,0),(-1,-1),0.3, C_BORDER),
        ("BACKGROUND",   (1,0),(1,-1), C_LIGHT2),
    ]))
    story.append(pt)
    story.append(Spacer(1, 8))

    # Key findings table
    story.append(Paragraph("Key Findings", styles["h2"]))
    story.append(Spacer(1, 4))

    def _status(val, good_str, bad_str, neutral=False):
        if neutral:
            return "→ Monitor"
        return bad_str if int(val or 0) > 0 else good_str

    findings_rows = [
        ["Metric", "Value", "Status"],
        ["Total Agents Affected",
         str(summary.get("total_agents_affected",0)), "⚠ Review Required"],
        ["Critical CVE Count",
         str(summary.get("critical_count",0)),
         _status(summary.get("critical_count",0),"✓ Clear","✗ Immediate Action")],
        ["High CVE Count",
         str(summary.get("high_count",0)),
         _status(summary.get("high_count",0),"✓ Clear","⚠ Action Required")],
        ["Medium CVE Count",
         str(summary.get("medium_count",0)), "→ Monitor"],
        ["Total Findings (Critical+High)",
         str(summary.get("total_findings",0)), "—"],
        ["High Confidence Malicious IPs",
         str(len(malicious.get("high_confidence",[]))),
         _status(len(malicious.get("high_confidence",[])),"✓ Clear","✗ Block Candidates")],
        ["Medium Confidence IPs (Watchlist)",
         str(len(malicious.get("medium_confidence",[]))),"⚠ Monitor"],
        ["DefectDojo Import Status",
         dojo.get("import_status","pending").upper(),
         "✓ Imported" if dojo.get("import_status")=="success" else "⚠ Check Required"],
    ]

    ft = Table(findings_rows, colWidths=[85*mm, 38*mm, 57*mm])
    ts = _tbl_style(C_NAVY2)
    for i, row in enumerate(findings_rows[1:], 1):
        if "Critical" in row[0] and int(row[1] or 0) > 0:
            ts.add("BACKGROUND",(0,i),(-1,i),colors.HexColor("#FDEDEC"))
        elif "High" in row[0] and int(row[1] or 0) > 0:
            ts.add("BACKGROUND",(0,i),(-1,i),colors.HexColor("#FEF3E8"))
    ft.setStyle(ts)
    story.append(ft)
    story.append(Spacer(1, 10))

    # Charts side by side
    story.append(Paragraph("Severity Distribution & Top Agents", styles["h2"]))
    story.append(Spacer(1, 4))
    top_agents = canonical.get("top_agents",[])
    if top_agents:
        pie = chart_severity_bar(summary)
        bar = chart_top_agents_bar(top_agents)
        ct  = Table([[pie, bar]], colWidths=[8.5*cm, 14.5*cm])
        ct.setStyle(TableStyle([
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("ALIGN",(0,0),(-1,-1),"CENTER"),
            ("LEFTPADDING",(0,0),(-1,-1),0),
            ("RIGHTPADDING",(0,0),(-1,-1),0),
        ]))
        story.append(ct)
    story.append(PageBreak())


def _build_all_agents(story, styles, canonical):
    _section(story, styles, 2, "Vulnerability Overview — All Agents",
             "All monitored agents grouped by highest vulnerability severity.")

    all_grp = canonical.get("all_agents_grouped", {})

    # Chart
    story.append(chart_agents_grouped(all_grp))
    story.append(Spacer(1, 8))

    for sev in ["Critical","High","Medium","Low","Clean"]:
        agents = all_grp.get(sev,[])
        if not agents:
            continue

        sc = SEV_COLOR.get(sev, C_MUTED)
        story.append(KeepTogether([
            Paragraph(f"● {sev}  —  {len(agents)} agents",
                      ParagraphStyle(f"grp_{sev}", fontSize=10,
                          fontName="Helvetica-Bold", textColor=sc,
                          spaceBefore=10, spaceAfter=3)),
            _divider(sc),
            Spacer(1, 3),
        ]))

        header = ["#","Agent ID","Agent Name","OS","Critical","High","Medium","Max CVSS"]
        rows   = [header]
        for idx, a in enumerate(agents, 1):
            rows.append([
                str(idx),
                str(a.get("agent_id","")),
                str(a.get("agent_name","")),
                str(a.get("os",""))[:35],
                str(a.get("critical_cve_count",0)),
                str(a.get("high_cve_count",0)),
                str(a.get("medium_cve_count",0)),
                str(a.get("max_cvss","N/A")),
            ])

        cw  = [9*mm,16*mm,44*mm,48*mm,16*mm,14*mm,16*mm,17*mm]
        tbl = Table(rows, colWidths=cw, repeatRows=1)
        ts  = _tbl_style(sc)
        for i in range(1, len(rows)):
            if rows[i][4] not in ("0",""):
                ts.add("TEXTCOLOR",(4,i),(4,i),C_CRITICAL)
                ts.add("FONTNAME", (4,i),(4,i),"Helvetica-Bold")
        tbl.setStyle(ts)
        story.append(tbl)
        story.append(Spacer(1, 6))

    story.append(PageBreak())


def _build_top_agents_detail(story, styles, canonical):
    _section(story, styles, 3, "Top Agents — CVE Detail",
             "Detailed CVE breakdown with recommended remediation actions.")

    top_agents = canonical.get("top_agents",[])
    agent_cves = canonical.get("agent_cves",{})

    for rank, agent in enumerate(top_agents, 1):
        name = agent.get("agent_name","")
        cves = agent_cves.get(name,[])

        # Agent header block
        agent_info = [
            Paragraph(f"#{rank}  {name}",
                      ParagraphStyle(f"agh_{rank}", fontSize=11,
                          fontName="Helvetica-Bold", textColor=C_NAVY,
                          spaceBefore=12, spaceAfter=2)),
            Paragraph(
                f"ID: {agent.get('agent_id','')}  |  "
                f"OS: {agent.get('os','N/A')}  |  "
                f"Critical: <b>{agent.get('critical_cve_count',0)}</b>  |  "
                f"High: <b>{agent.get('high_cve_count',0)}</b>  |  "
                f"Max CVSS: <b>{agent.get('max_cvss','N/A')}</b>  |  "
                f"Avg CVSS: <b>{agent.get('avg_cvss','N/A')}</b>",
                styles["muted"]),
            _divider(C_ORANGE),
            Spacer(1, 4),
        ]
        story.append(KeepTogether(agent_info))

        if not cves:
            story.append(Paragraph("No CVE detail available.", styles["muted"]))
            continue

        # CVE table with all columns including Recommended Action
        header = ["CVE ID","Sev","CVSS","Package","Version",
                  "Description","Recommended Action","References"]
        rows   = [header]

        for cve in cves:
            sev  = str(cve.get("severity",""))
            cvss = cve.get("cvss")
            rec  = cve.get("recommended_action") or \
                   get_recommended_action(sev, cvss, "vulnerability")

            # Description (truncated)
            desc = str(cve.get("description") or "")[:110]
            if len(str(cve.get("description") or "")) > 110:
                desc += "…"

            # Action cell
            pri   = rec.get("priority","—")
            sla   = rec.get("sla","")
            acts  = rec.get("actions",[])
            astyle = styles["action_p1"] if "P1" in pri else \
                     styles["action_p2"] if "P2" in pri else \
                     styles["action_p3"]
            act_content = (
                f"<b>{pri}</b><br/>"
                f"<font color='#6C757D'>{sla}</font><br/>"
                + "<br/>".join(f"• {a}" for a in acts[:3])
            )

            # References (first 2 only)
            refs = cve.get("references",[])
            if isinstance(refs, list):
                ref_text = "\n".join(refs[:2])
            else:
                ref_text = str(refs)[:80]

            rows.append([
                Paragraph(str(cve.get("cve_id","")),   styles["body_sm"]),
                Paragraph(sev,                          styles["body_sm"]),
                Paragraph(str(cvss or "N/A"),           styles["body_sm"]),
                Paragraph(str(cve.get("package_name",""))[:20],  styles["body_sm"]),
                Paragraph(str(cve.get("package_version",""))[:14], styles["body_sm"]),
                Paragraph(desc,                         styles["body_sm"]),
                Paragraph(act_content,                  styles["body_sm"]),
                Paragraph(ref_text,                     styles["body_sm"]),
            ])

        cw  = [24*mm, 13*mm, 12*mm, 22*mm, 16*mm, 38*mm, 42*mm, 30*mm]
        tbl = Table(rows, colWidths=cw, repeatRows=1)
        ts  = _tbl_style(C_NAVY2)

        for i, row in enumerate(rows[1:], 1):
            orig_cve = cves[i-1]
            sev_val  = orig_cve.get("severity","")
            sc       = SEV_COLOR.get(sev_val, C_MUTED)
            ts.add("TEXTCOLOR", (1,i),(1,i), sc)
            ts.add("FONTNAME",  (1,i),(1,i), "Helvetica-Bold")
            if sev_val == "Critical":
                ts.add("BACKGROUND",(0,i),(5,i),colors.HexColor("#FFF5F5"))
            rec = orig_cve.get("recommended_action") or {}
            pri = rec.get("priority","")
            if "P1" in pri:
                ts.add("BACKGROUND",(6,i),(6,i),colors.HexColor("#FFF5F5"))
            elif "P2" in pri:
                ts.add("BACKGROUND",(6,i),(6,i),colors.HexColor("#FFF8F0"))

        tbl.setStyle(ts)
        story.append(tbl)
        story.append(Spacer(1, 8))

    story.append(PageBreak())


def _build_malicious_ips(story, styles, canonical):
    _section(story, styles, 4, "Validated Malicious IPs",
             "IPs validated against VirusTotal, AlienVault OTX, and AbuseIPDB.")

    malicious  = canonical.get("malicious_ip_summary",{})
    high_conf  = malicious.get("high_confidence",[])
    med_conf   = malicious.get("medium_confidence",[])

    ch = chart_malicious_ip(malicious)
    if ch:
        story.append(ch)
        story.append(Spacer(1, 8))

    # High confidence
    story.append(Paragraph(
        f"High Confidence Malicious IPs  ({len(high_conf)})", styles["h2"]))
    story.append(Spacer(1, 4))

    if high_conf:
        header = ["IP","Alerts","VT Mal","VT Sus","OTX Pulses",
                  "AbuseIPDB Score","Total Reports","Confidence","Recommended Action"]
        rows   = [header]
        for item in high_conf:
            vt    = item.get("virustotal",{})
            otx   = item.get("otx",{})
            abuse = item.get("abuseipdb",{})
            rec   = get_recommended_action("High", finding_type="ip",
                                           ip_confidence=item.get("confidence","High"))
            rows.append([
                str(item.get("ip","")),
                str(item.get("alert_count",0)),
                str(vt.get("malicious",0)),
                str(vt.get("suspicious",0)),
                str(otx.get("pulse_count",0)),
                str(abuse.get("abuseConfidenceScore",0)),
                str(abuse.get("totalReports",0)),
                str(item.get("confidence","")),
                Paragraph(rec["priority"]+"<br/>"+rec["sla"], styles["body_sm"]),
            ])
        cw  = [28*mm,14*mm,13*mm,13*mm,16*mm,20*mm,18*mm,16*mm,35*mm]
        tbl = Table(rows, colWidths=cw, repeatRows=1)
        ts  = _tbl_style(C_CRITICAL)
        for i in range(1, len(rows)):
            ts.add("BACKGROUND",(0,i),(-1,i),colors.HexColor("#FFF5F5"))
        tbl.setStyle(ts)
        story.append(tbl)
    else:
        story.append(Paragraph("No high-confidence malicious IPs found.", styles["body"]))

    story.append(Spacer(1, 12))

    # Medium confidence / Watchlist
    story.append(Paragraph(
        f"Suspicious IP Watchlist  —  Medium Confidence  ({len(med_conf)})",
        styles["h2"]))
    story.append(Spacer(1, 4))

    if med_conf:
        header = ["IP","Alerts","VT Mal","OTX Pulses",
                  "AbuseIPDB Score","Confidence","Recommended Action"]
        rows   = [header]
        for item in med_conf:
            vt    = item.get("virustotal",{})
            otx   = item.get("otx",{})
            abuse = item.get("abuseipdb",{})
            rec   = get_recommended_action("Medium", finding_type="ip",
                                           ip_confidence=item.get("confidence","Medium"))
            rows.append([
                str(item.get("ip","")),
                str(item.get("alert_count",0)),
                str(vt.get("malicious",0)),
                str(otx.get("pulse_count",0)),
                str(abuse.get("abuseConfidenceScore",0)),
                str(item.get("confidence","")),
                Paragraph(rec["priority"]+"<br/>"+rec["sla"], styles["body_sm"]),
            ])
        cw  = [32*mm,14*mm,15*mm,18*mm,22*mm,18*mm,48*mm]
        tbl = Table(rows, colWidths=cw, repeatRows=1)
        ts  = _tbl_style(C_HIGH)
        for i in range(1, len(rows)):
            ts.add("BACKGROUND",(0,i),(-1,i),colors.HexColor("#FFF8F0"))
        tbl.setStyle(ts)
        story.append(tbl)
    else:
        story.append(Paragraph("No medium-confidence IPs found.", styles["body"]))

    story.append(PageBreak())


def _build_dojo_summary(story, styles, canonical):
    _section(story, styles, 5, "DefectDojo Import Summary",
             "Summary of findings imported into DefectDojo vulnerability management.")

    dojo      = canonical.get("dojo_summary",{})
    meta      = canonical.get("meta",{})
    dojo_meta = meta.get("dojo",{})

    status_ok = dojo.get("import_status") == "success"
    sc = C_LOW if status_ok else C_HIGH

    data = [
        ["Field",                        "Value"],
        ["Product",                      dojo_meta.get("product","")],
        ["Engagement",                   dojo_meta.get("engagement","")],
        ["Import Status",                dojo.get("import_status","pending").upper()],
        ["Total Findings Planned",       str(dojo.get("planned_total_findings",0))],
        ["Vulnerability Findings",       str(dojo.get("planned_vulnerability_findings",0))],
        ["Malicious IP Findings",        str(dojo.get("planned_malicious_ip_findings",0))],
        ["Skipped (Medium IP)",          str(dojo.get("skipped_medium_ip_findings",0))],
    ]

    tbl = Table(data, colWidths=[70*mm, 100*mm])
    ts  = _tbl_style(C_NAVY)
    ts.add("TEXTCOLOR",(1,3),(1,3), sc)
    ts.add("FONTNAME", (1,3),(1,3), "Helvetica-Bold")
    tbl.setStyle(ts)
    story.append(tbl)
    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "Note: Medium confidence IPs are included in the report for monitoring "
        "but excluded from DefectDojo import to avoid alert fatigue.",
        styles["muted"]))
    story.append(Spacer(1, 12))

    # Appendix
    story.append(Paragraph("Appendix / Notes", styles["h2"]))
    story.append(Spacer(1, 4))
    notes_data = [
        ["Source IP field",    "data.srcip"],
        ["Vulnerability index","wazuh-states-vulnerabilities-*"],
        ["Alert index",        "wazuh-alerts-*"],
        ["TI vendors",         "VirusTotal, AlienVault OTX, AbuseIPDB"],
        ["Medium conf IPs",    "Report only (watchlist), not imported to DefectDojo"],
    ]
    nt = Table(notes_data, colWidths=[55*mm, 115*mm])
    ts = _tbl_style(C_NAVY2)
    nt.setStyle(ts)
    story.append(nt)


# MAIN PDF BUILDER

def generate_pdf_report(canonical: dict, pdf_path: Path):
    styles      = make_styles()
    story       = []
    meta        = canonical.get("meta",{})
    report_title = meta.get("report_name","Wazuh Security Report")
    generated_at = meta.get("generated_at","")[:19].replace("T"," ")

    doc = WazuhDocTemplate(
        str(pdf_path),
        report_title=report_title,
        generated_at=generated_at,
        title=report_title,
        author="Wazuh Report Worker",
        subject="Security Vulnerability Report",
    )

    _build_cover(story, styles, canonical)
    _build_toc(story, styles)
    _build_exec_summary(story, styles, canonical)
    _build_all_agents(story, styles, canonical)
    _build_top_agents_detail(story, styles, canonical)
    _build_malicious_ips(story, styles, canonical)
    _build_dojo_summary(story, styles, canonical)

    doc.multiBuild(story)


# DATA FETCHING  (struktur persis dari rekan — balamaru/DefectDojo)

def dig(obj, path, default=None):
    cur = obj
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
        if cur is None:
            return default
    return cur


def to_float(val):
    if val is None:
        return None
    try:
        return float(val)
    except Exception:
        return None


def extract_cvss(src: dict):
    candidates = [
        ["vulnerability","score","base"],
        ["vulnerability","score","version_3","base"],
        ["vulnerability","score","version3","base"],
        ["vulnerability","cvss","base_score"],
        ["vulnerability","cvss","score"],
        ["vulnerability","cvss3","base_score"],
        ["vulnerability","cvss3","score"],
        ["vulnerability","cvssv3","base_score"],
        ["vulnerability","cvssv3","score"],
        ["vulnerability","score"],
    ]
    for path in candidates:
        val = dig(src, path)
        f   = to_float(val)
        if f is not None:
            return round(f, 2)
        if isinstance(val, dict):
            for k in ["base","score","base_score","value"]:
                f = to_float(val.get(k))
                if f is not None:
                    return round(f, 2)
    return None


def normalize_references(ref_value):
    if ref_value is None:
        return []
    parts = []
    if isinstance(ref_value, list):
        for item in ref_value:
            if item is None:
                continue
            if isinstance(item, str):
                parts.extend([x.strip() for x in item.split(",") if x.strip()])
            else:
                parts.append(str(item).strip())
    elif isinstance(ref_value, str):
        parts = [x.strip() for x in ref_value.split(",") if x.strip()]
    else:
        parts = [str(ref_value).strip()]
    seen, cleaned = set(), []
    for p in parts:
        if p not in seen:
            seen.add(p)
            cleaned.append(p)
    return cleaned


def resolve_period(payload: dict) -> dict:
    date_mode = payload.get("date_mode","preset")
    timezone  = payload.get("timezone", settings.DEFAULT_TIMEZONE)
    today     = date.today()

    if date_mode == "custom":
        return {"mode":"custom",
                "start": f"{payload['start_date']}T00:00:00",
                "end":   f"{payload['end_date']}T23:59:59",
                "timezone": timezone}

    preset = payload.get("preset","last_month")
    if preset == "last_7_days":
        s, e = today-timedelta(days=7), today
    elif preset == "last_30_days":
        s, e = today-timedelta(days=30), today
    elif preset == "this_month":
        s, e = today.replace(day=1), today
    else:   # last_month
        first = today.replace(day=1)
        e     = first - timedelta(days=1)
        s     = e.replace(day=1)
    return {"mode":"preset","preset":preset,
            "start":f"{s.isoformat()}T00:00:00",
            "end":  f"{e.isoformat()}T23:59:59",
            "timezone":timezone}


def _session():
    s = requests.Session()
    s.auth = HTTPBasicAuth(settings.WAZUH_INDEXER_USER, settings.WAZUH_INDEXER_PASS)
    return s


def indexer_get(path: str, body: Optional[dict] = None) -> dict:
    url = f"{settings.WAZUH_INDEXER_URL.rstrip('/')}/{path.lstrip('/')}"
    s   = _session()
    if body is None:
        r = s.get(url, verify=settings.WAZUH_VERIFY_SSL, timeout=60)
    else:
        r = s.get(url, json=body, verify=settings.WAZUH_VERIFY_SSL, timeout=120)
    if not r.ok:
        raise Exception(f"Indexer query failed: {r.status_code} - {r.text}")
    return r.json()


def fetch_alert_candidates(period: dict, top_n: int = 10, groups=None) -> list:
    if groups is None:
        groups = ["attack","web","accesslog"]
    body = {
        "size": 0,
        "track_total_hits": False,
        "timeout": "30s",
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {
                "gte": period["start"], "lte": period["end"],
                "format": "strict_date_optional_time||yyyy-MM-dd'T'HH:mm:ss"
            }}},
            {"terms": {"rule.groups": groups}},
            {"exists": {"field": "data.srcip"}},
        ]}},
        "aggs": {"top_src_ips": {"terms": {"field":"data.srcip","size":top_n}}}
    }
    data = indexer_get("/wazuh-alerts*/_search?pretty", body)
    return [{"ip": b.get("key"), "alert_count": b.get("doc_count",0),
             "confidence":"Pending","include_in_report":False,"include_in_dojo":False}
            for b in data.get("aggregations",{}).get("top_src_ips",{}).get("buckets",[])]


def lookup_virustotal(ip):
    if not settings.VT_API_KEY:
        return {"enabled":False,"positive":False,"malicious":0,"suspicious":0}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey":settings.VT_API_KEY}, timeout=30)
        r.raise_for_status()
        stats = dig(r.json(),["data","attributes","last_analysis_stats"],{}) or {}
        m, s  = stats.get("malicious",0), stats.get("suspicious",0)
        return {"enabled":True,"positive":m>0 or s>0,"malicious":m,"suspicious":s}
    except Exception as e:
        return {"enabled":True,"positive":False,"error":str(e),"malicious":0,"suspicious":0}


def lookup_otx(ip):
    if not settings.OTX_API_KEY:
        return {"enabled":False,"positive":False,"pulse_count":0}
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY":settings.OTX_API_KEY}, timeout=30)
        r.raise_for_status()
        pc = dig(r.json(),["pulse_info","count"],0) or 0
        return {"enabled":True,"positive":pc>0,"pulse_count":pc}
    except Exception as e:
        return {"enabled":True,"positive":False,"error":str(e),"pulse_count":0}


def lookup_abuseipdb(ip):
    if not settings.ABUSEIPDB_API_KEY:
        return {"enabled":False,"positive":False,"abuseConfidenceScore":0,"totalReports":0}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key":settings.ABUSEIPDB_API_KEY,"Accept":"application/json"},
                         params={"ipAddress":ip,"maxAgeInDays":90}, timeout=30)
        r.raise_for_status()
        sc = dig(r.json(),["data","abuseConfidenceScore"],0) or 0
        tr = dig(r.json(),["data","totalReports"],0) or 0
        return {"enabled":True,"positive":sc>0,"abuseConfidenceScore":sc,"totalReports":tr}
    except Exception as e:
        return {"enabled":True,"positive":False,"error":str(e),
                "abuseConfidenceScore":0,"totalReports":0}


def compute_ip_confidence(vt, otx, abuse):
    pos = sum([vt.get("positive",False), otx.get("positive",False),
               abuse.get("positive",False)])
    return {3:"High",2:"Medium",1:"Low",0:"Ignore"}.get(pos,"Ignore")


def enrich_candidate_ips(candidate_ips):
    high_conf, medium_conf = [], []
    for item in candidate_ips:
        ip = item.get("ip")
        if not ip:
            continue
        print(f"[INFO] TI lookup: {ip}")
        vt, otx, abuse = lookup_virustotal(ip), lookup_otx(ip), lookup_abuseipdb(ip)
        confidence = compute_ip_confidence(vt, otx, abuse)
        enriched = {
            **item,
            "virustotal": {"malicious":vt.get("malicious",0),"suspicious":vt.get("suspicious",0)},
            "otx":        {"pulse_count":otx.get("pulse_count",0)},
            "abuseipdb":  {"abuseConfidenceScore":abuse.get("abuseConfidenceScore",0),
                           "totalReports":abuse.get("totalReports",0)},
            "confidence": confidence,
        }
        if confidence == "High":
            enriched.update({"include_in_report":True,"include_in_dojo":True,
                             "recommendation":"Confirmed malicious IP – candidate for blocklist review"})
            high_conf.append(enriched)
        elif confidence == "Medium":
            enriched.update({"include_in_report":True,"include_in_dojo":False,
                             "recommendation":"Suspicious IP – monitoring recommended"})
            medium_conf.append(enriched)
        print(f"[INFO] TI done: {ip} => {confidence}")
    return {"high_confidence":high_conf,"medium_confidence":medium_conf}


def build_dojo_payload(canonical: dict) -> dict:
    findings    = []
    report_date = datetime.now().date().isoformat()

    for agent_name, cves in canonical.get("agent_cves",{}).items():
        for cve in cves:
            refs = cve.get("references",[])
            refs_text = " ; ".join(refs) if isinstance(refs,list) else str(refs)
            findings.append({
                "title":             f"[Wazuh][{agent_name}] {cve.get('cve_id')}",
                "severity":          cve.get("severity","High"),
                "description":       (f"Agent: {agent_name}\n"
                                      f"Package: {cve.get('package_name')} {cve.get('package_version')}\n\n"
                                      f"{cve.get('description','')}"),
                "date":              report_date,
                "cve":               cve.get("cve_id"),
                "cvssv3_score":      cve.get("cvss"),
                "mitigation":        cve.get("mitigation"),
                "references":        refs_text,
                "component_name":    cve.get("package_name"),
                "component_version": cve.get("package_version"),
                "tags":              ["wazuh",f"agent:{agent_name}","source:wazuh","report:weekly"],
            })

    for ip_item in canonical.get("malicious_ip_summary",{}).get("high_confidence",[]):
        ip  = ip_item.get("ip")
        vt  = ip_item.get("virustotal",{})
        otx = ip_item.get("otx",{})
        abu = ip_item.get("abuseipdb",{})
        findings.append({
            "title":    f"[Wazuh][Malicious IP] {ip}",
            "severity": "High",
            "description": (
                f"Malicious traffic candidate from IP {ip}.\n"
                f"Alert count: {ip_item.get('alert_count',0)}\n"
                f"VT malicious={vt.get('malicious',0)} suspicious={vt.get('suspicious',0)}\n"
                f"OTX pulse_count={otx.get('pulse_count',0)}\n"
                f"AbuseIPDB confidence={abu.get('abuseConfidenceScore',0)} "
                f"totalReports={abu.get('totalReports',0)}"
            ),
            "date":      report_date,
            "mitigation":ip_item.get("recommendation",""),
            "references":f"https://www.virustotal.com/gui/ip-address/{ip}",
            "tags":      ["wazuh","malicious-ip","confidence:high"],
        })

    return {"name": f"{canonical.get('meta',{}).get('report_name','Wazuh Security Report')} - Dojo Import",
            "type": "Generic Findings Import",
            "findings": findings}


def dojo_headers():
    return {"Authorization": f"Token {settings.DEFECTDOJO_TOKEN}"}


def dojo_get(path, params=None):
    url = f"{settings.DEFECTDOJO_URL.rstrip('/')}/{path.lstrip('/')}"
    r   = requests.get(url, headers=dojo_headers(), params=params,
                       verify=settings.DEFECTDOJO_VERIFY_SSL, timeout=60)
    if not r.ok:
        raise Exception(f"Dojo GET failed: {r.status_code} - {r.text}")
    return r.json()


def find_dojo_product_id(product_name):
    data = dojo_get("/api/v2/products/", params={"name": product_name})
    res  = data.get("results",[])
    if not res:
        raise Exception(f"DefectDojo product not found: {product_name}")
    return res[0]["id"]


def find_dojo_engagement_id(product_id, engagement_name):
    data = dojo_get("/api/v2/engagements/",
                    params={"name": engagement_name, "product": product_id})
    res  = data.get("results",[])
    if not res:
        raise Exception(f"DefectDojo engagement not found: {engagement_name}")
    return res[0]["id"]


def upload_dojo_payload(canonical, dojo_payload_path):
    product_name    = canonical["meta"]["dojo"]["product"]
    engagement_name = canonical["meta"]["dojo"]["engagement"]
    product_id      = find_dojo_product_id(product_name)
    engagement_id   = find_dojo_engagement_id(product_id, engagement_name)
    url             = f"{settings.DEFECTDOJO_URL.rstrip('/')}/api/v2/import-scan/"
    report_date     = datetime.now().date().isoformat()

    with open(dojo_payload_path,"rb") as f:
        r = requests.post(url, headers=dojo_headers(),
                          data={"engagement":str(engagement_id),
                                "scan_type":"Generic Findings Import",
                                "scan_date":report_date,
                                "verified":"true","active":"true",
                                "minimum_severity":"Info"},
                          files={"file":("dojo_payload.json",f,"application/json")},
                          verify=settings.DEFECTDOJO_VERIFY_SSL, timeout=180)
    if not r.ok:
        raise Exception(f"Dojo import failed: {r.status_code} - {r.text}")
    try:
        resp = r.json()
    except Exception:
        resp = {"raw": r.text}
    return {"product_id":product_id,"engagement_id":engagement_id,"response":resp}


def fetch_vulnerability_summary() -> dict:
    body = {
        "size": 0,
        "query": {"terms": {"vulnerability.severity":["Critical","High"]}},
        "aggs": {
            "sev": {"terms": {"field":"vulnerability.severity","size":10}},
            "affected_agents": {"cardinality": {"field":"agent.name"}},
        }
    }
    data   = indexer_get("/wazuh-states-vulnerabilities*/_search?pretty", body)
    counts = {b["key"]:b["doc_count"]
              for b in data.get("aggregations",{}).get("sev",{}).get("buckets",[])}
    return {
        "total_findings":        counts.get("Critical",0)+counts.get("High",0),
        "total_agents_affected": data.get("aggregations",{})
                                     .get("affected_agents",{}).get("value",0),
        "critical_count":        counts.get("Critical",0),
        "high_count":            counts.get("High",0),
        "medium_count":          counts.get("Medium",0),
    }


def fetch_all_agents_with_severity(top_n: int = 200) -> dict:
    body = {
        "size": 0,
        "aggs": {
            "all_agents": {
                "terms": {"field":"agent.name","size":top_n},
                "aggs": {
                    "sevs":      {"terms":{"field":"vulnerability.severity","size":5}},
                    "sample":    {"top_hits":{"size":1,"_source":
                                     ["agent.id","agent.name","host.os.full"]}},
                    "max_score": {"max":{"field":"vulnerability.score.base"}},
                    "avg_score": {"avg":{"field":"vulnerability.score.base"}},
                }
            }
        }
    }
    data    = indexer_get("/wazuh-states-vulnerabilities*/_search?pretty", body)
    buckets = data.get("aggregations",{}).get("all_agents",{}).get("buckets",[])
    grouped = {"Critical":[],"High":[],"Medium":[],"Low":[],"Clean":[]}

    for b in buckets:
        src = b["sample"]["hits"]["hits"][0]["_source"]
        sev_counts = {s["key"]:s["doc_count"]
                      for s in b.get("sevs",{}).get("buckets",[])}
        max_s = b.get("max_score",{}).get("value")
        avg_s = b.get("avg_score",{}).get("value")
        agent = {
            "agent_id":           src.get("agent",{}).get("id"),
            "agent_name":         src.get("agent",{}).get("name") or b["key"],
            "os":                 src.get("host",{}).get("os",{}).get("full",""),
            "critical_cve_count": sev_counts.get("Critical",0),
            "high_cve_count":     sev_counts.get("High",0),
            "medium_cve_count":   sev_counts.get("Medium",0),
            "low_cve_count":      sev_counts.get("Low",0),
            "max_cvss": round(max_s,2) if max_s and max_s>0 else None,
            "avg_cvss": round(avg_s,2) if avg_s and avg_s>0 else None,
        }
        if agent["critical_cve_count"]>0:  grouped["Critical"].append(agent)
        elif agent["high_cve_count"]>0:    grouped["High"].append(agent)
        elif agent["medium_cve_count"]>0:  grouped["Medium"].append(agent)
        elif agent["low_cve_count"]>0:     grouped["Low"].append(agent)
        else:                              grouped["Clean"].append(agent)

    for sev in grouped:
        grouped[sev].sort(key=lambda x:(x["critical_cve_count"],
                          x["high_cve_count"], x.get("max_cvss") or 0), reverse=True)
    return grouped


def fetch_top_agents(top_n: int = 10) -> list:
    body = {
        "size": 0,
        "query": {"terms": {"vulnerability.severity":["Critical","High"]}},
        "aggs": {
            "top_agents": {
                "terms": {"field":"agent.name","size":top_n},
                "aggs": {"sample": {"top_hits": {
                    "size": 1,
                    "_source": ["agent.id","agent.name","host.os.full"]
                }}}
            }
        }
    }
    data    = indexer_get("/wazuh-states-vulnerabilities*/_search?pretty", body)
    buckets = data.get("aggregations",{}).get("top_agents",{}).get("buckets",[])
    result  = []
    for b in buckets:
        src = b["sample"]["hits"]["hits"][0]["_source"]
        result.append({
            "agent_id":           src.get("agent",{}).get("id"),
            "agent_name":         src.get("agent",{}).get("name"),
            "os":                 src.get("host",{}).get("os",{}).get("full"),
            "critical_cve_count": b["doc_count"],
            "high_cve_count":     0,
            "max_cvss":           None,
            "avg_cvss":           None,
        })
    return result


def fetch_top_cves_for_agent(agent_name: str, top_n: int = 10) -> list:
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"term":  {"agent.name": agent_name}},
            {"terms": {"vulnerability.severity":["Critical","High"]}},
        ]}},
        "aggs": {
            "top_cves": {
                "terms": {"field":"vulnerability.id","size":top_n},
                "aggs": {"sample": {"top_hits": {
                    "size": 1,
                    "_source": [
                        "vulnerability.id","vulnerability.severity",
                        "vulnerability.description","vulnerability.reference",
                        "vulnerability.score","vulnerability.cvss",
                        "vulnerability.cvss3","vulnerability.cvssv3",
                        "package.name","package.version"
                    ]
                }}}
            }
        }
    }
    data    = indexer_get("/wazuh-states-vulnerabilities*/_search?pretty", body)
    buckets = data.get("aggregations",{}).get("top_cves",{}).get("buckets",[])
    items   = []
    for b in buckets:
        src      = b["sample"]["hits"]["hits"][0]["_source"]
        refs     = normalize_references(dig(src,["vulnerability","reference"]))
        pkg_name = dig(src,["package","name"])
        pkg_ver  = dig(src,["package","version"])
        sev      = dig(src,["vulnerability","severity"])
        cvss     = extract_cvss(src)
        rec      = get_recommended_action(sev, cvss, "vulnerability")
        items.append({
            "cve_id":              dig(src,["vulnerability","id"]),
            "severity":            sev,
            "cvss":                cvss,
            "package_name":        pkg_name,
            "package_version":     pkg_ver,
            "description":         dig(src,["vulnerability","description"]),
            "references":          refs,
            "resolution":          "Update package/component to vendor-fixed version.",
            "mitigation":          f"Review and patch {pkg_name or 'affected component'}; "
                                   "restrict exposure until remediation is completed.",
            "recommended_action":  rec,
        })

    items.sort(key=lambda x: (x.get("cvss") or -1,
               x.get("severity")=="Critical", x.get("cve_id") or ""), reverse=True)
    return items[:top_n]


# CANONICAL DATASET + ENTRY POINT

def build_canonical_dataset(payload: dict) -> dict:
    period = resolve_period(payload)
    top_n  = int(payload.get("top_n", settings.DEFAULT_TOP_N))

    print("[INFO] fetch_vulnerability_summary()")
    vuln_summary = fetch_vulnerability_summary()

    print("[INFO] fetch_all_agents_with_severity()")
    all_agents_grouped = fetch_all_agents_with_severity(top_n=200)

    print("[INFO] fetch_top_agents()")
    top_agents = fetch_top_agents(top_n=top_n)

    agent_cves = {}
    for agent in top_agents:
        name = agent.get("agent_name")
        if name:
            print(f"[INFO] fetch_top_cves_for_agent({name})")
            cves = fetch_top_cves_for_agent(name, top_n=top_n)
            agent_cves[name] = cves
            scores = [c["cvss"] for c in cves if c.get("cvss") is not None]
            if scores:
                agent["max_cvss"] = round(max(scores), 2)
                agent["avg_cvss"] = round(sum(scores)/len(scores), 2)

    print("[INFO] fetch_alert_candidates()")
    candidate_ips = fetch_alert_candidates(
        period=period, top_n=top_n,
        groups=payload.get("ddos_rule_groups",["attack","web","accesslog"]))

    print(f"[INFO] enrich_candidate_ips() — {len(candidate_ips)} IPs")
    ti_enriched = enrich_candidate_ips(candidate_ips)

    return {
        "meta": {
            "report_name":  payload.get("report_name","Wazuh Security Report"),
            "period":       period,
            "timezone":     payload.get("timezone", settings.DEFAULT_TIMEZONE),
            "generated_at": datetime.now().isoformat(),
            "top_n":        top_n,
            "output_format":payload.get("output_format", settings.DEFAULT_OUTPUT_FORMAT),
            "dojo": {
                "product":         payload.get("dojo_product",  settings.DEFECTDOJO_PRODUCT),
                "engagement":      payload.get("dojo_engagement",settings.DEFECTDOJO_ENGAGEMENT),
                "engagement_type": "CI/CD",
            }
        },
        "vulnerability_summary":  {**vuln_summary, "top_n_agents": top_n},
        "all_agents_grouped":     all_agents_grouped,
        "top_agents":             top_agents,
        "agent_cves":             agent_cves,
        "malicious_ip_summary": {
            "candidate_ips":     candidate_ips,
            "high_confidence":   ti_enriched["high_confidence"],
            "medium_confidence": ti_enriched["medium_confidence"],
        },
        "dojo_summary": {
            "planned_total_findings":
                sum(len(v) for v in agent_cves.values()) + len(ti_enriched["high_confidence"]),
            "planned_vulnerability_findings":
                sum(len(v) for v in agent_cves.values()),
            "planned_malicious_ip_findings":
                len(ti_enriched["high_confidence"]),
            "skipped_medium_ip_findings":
                len(ti_enriched["medium_confidence"]),
            "import_status": "pending",
        }
    }


def run_report_real_vuln(payload: dict) -> dict:
    now          = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    pdf_filename = f"wazuh_report_{now}.pdf"
    pdf_path     = OUTPUT_DIR / pdf_filename

    canonical = build_canonical_dataset(payload)

    dojo_payload      = build_dojo_payload(canonical)
    dojo_payload_path = TMP_DIR / "dojo_payload.json"
    dojo_payload_path.write_text(json.dumps(dojo_payload, indent=2))

    dojo_import_status = "pending"
    dojo_import_detail = None
    try:
        dojo_import_detail = upload_dojo_payload(canonical, dojo_payload_path)
        dojo_import_status = "success"
    except Exception as e:
        dojo_import_status = "failed"
        dojo_import_detail = {"error": str(e)}

    canonical["dojo_summary"]["import_status"] = dojo_import_status

    canonical_path = TMP_DIR / "canonical_dataset.json"
    canonical_path.write_text(json.dumps(canonical, indent=2, default=str))

    print("[INFO] Generating PDF report...")
    generate_pdf_report(canonical, pdf_path)
    print(f"[INFO] PDF saved: {pdf_path}")

    summary      = canonical["vulnerability_summary"]
    final_status = "success" if dojo_import_status == "success" else "partial_success"
    final_msg    = ("Report generated successfully"
                    if dojo_import_status == "success"
                    else "Report generated, but DefectDojo import failed")

    return {
        "status":  final_status,
        "message": final_msg,
        "report": {
            "name":          canonical["meta"]["report_name"],
            "period":        canonical["meta"]["period"],
            "output_format": canonical["meta"]["output_format"],
            "pdf_filename":  pdf_filename,
            "pdf_path":      str(pdf_path),
            "pdf_url":       f"{settings.WORKER_BASE_URL}/download/{pdf_filename}",
        },
        "summary": {
            "affected_agents":       summary["total_agents_affected"],
            "critical_findings":     summary["critical_count"],
            "high_findings":         summary["high_count"],
            "candidate_ips":         len(canonical["malicious_ip_summary"]["candidate_ips"]),
            "high_confidence_ips":   len(canonical["malicious_ip_summary"]["high_confidence"]),
            "medium_confidence_ips": len(canonical["malicious_ip_summary"]["medium_confidence"]),
        },
        "dojo": {
            "product":                        canonical["meta"]["dojo"]["product"],
            "engagement":                     canonical["meta"]["dojo"]["engagement"],
            "planned_total_findings":         canonical["dojo_summary"]["planned_total_findings"],
            "planned_vulnerability_findings": canonical["dojo_summary"]["planned_vulnerability_findings"],
            "planned_malicious_ip_findings":  canonical["dojo_summary"]["planned_malicious_ip_findings"],
            "skipped_medium_ip_findings":     canonical["dojo_summary"]["skipped_medium_ip_findings"],
            "import_status":                  dojo_import_status,
            "detail":                         dojo_import_detail,
        },
        "artifacts": {
            "canonical_dataset_path": str(canonical_path),
            "dojo_payload_path":      str(dojo_payload_path),
            "log_path":               "/home/bakti/wazuh-report-worker/logs/worker.log",
        }
    }