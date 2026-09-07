"""
report_generator.py
===================
Generates professionally formatted PDF forensic reports for TraceVault cases.

Stack:
  - Jinja2     — HTML templating with custom filters (defang, severity_color, …)
  - WeasyPrint — HTML → PDF with full CSS paged-media support
  - Embedded CSS paged-media rules for headers, footers, and page numbers.

Usage::

    generator = ReportGeneratorService()
    pdf_bytes = await generator.generate_pdf(case_data)
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jinja2
import weasyprint


class ReportGeneratorService:
    """
    Generates PDF forensic investigation reports from structured case data.

    The report is rendered from ``forensic_report.html`` (stored in
    ``/app/templates/``). The template receives the full ``case`` dict plus
    helper values such as ``generated_at`` and ``platform_name``.
    """

    def __init__(self) -> None:
        template_dir = Path(os.getenv("TEMPLATE_DIR", "/app/templates"))
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(template_dir)),
            autoescape=True,
        )
        # Custom Jinja2 filters for forensic report formatting.
        self.env.filters["defang"] = self._defang
        self.env.filters["severity_color"] = self._severity_color
        self.env.filters["truncate_hash"] = self._truncate_hash
        self.env.filters["format_score"] = self._format_score
        self.env.filters["badge_class"] = self._badge_class

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate_pdf(self, case_data: dict) -> bytes:
        """
        Render the forensic report HTML template and convert it to PDF bytes.

        Parameters
        ----------
        case_data : dict
            Serialised case record including threat analysis, IOCs, relay hops,
            auth results, geo intelligence, and blockchain ledger entries.

        Returns
        -------
        bytes
            Raw PDF bytes ready to be streamed to the client.
        """
        template = self.env.get_template("forensic_report.html")
        html_content = template.render(
            case=case_data,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            platform_name="TraceVault",
            platform_version="1.0.0",
        )

        css = weasyprint.CSS(string=self._get_report_css())
        pdf_bytes = weasyprint.HTML(string=html_content).write_pdf(
            stylesheets=[css]
        )
        return pdf_bytes

    async def generate_html(self, case_data: dict) -> str:
        """
        Return the rendered HTML string (useful for preview or testing).
        """
        template = self.env.get_template("forensic_report.html")
        return template.render(
            case=case_data,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            platform_name="TraceVault",
            platform_version="1.0.0",
        )

    # ------------------------------------------------------------------
    # Jinja2 custom filter implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _defang(value: str) -> str:
        """
        Defang a URL or domain so it cannot be accidentally clicked.
        e.g.  http://evil.com  →  hXXp://evil[.]com
        """
        if not value:
            return value
        return value.replace(".", "[.]").replace("http", "hXXp")

    @staticmethod
    def _severity_color(severity: str) -> str:
        """Map severity level to a hex colour code."""
        colors = {
            "CRITICAL": "#dc2626",
            "HIGH":     "#ea580c",
            "MEDIUM":   "#d97706",
            "LOW":      "#2563eb",
            "BENIGN":   "#16a34a",
        }
        return colors.get(severity, "#6b7280")

    @staticmethod
    def _truncate_hash(value: str) -> str:
        """
        Shorten a long hash to first-8 … last-8 characters for display.
        """
        if value and len(value) > 16:
            return f"{value[:8]}…{value[-8:]}"
        return value or ""

    @staticmethod
    def _format_score(score: int) -> str:
        """Format a threat score with a descriptive label."""
        if score >= 80:
            return f"{score} — CRITICAL"
        if score >= 60:
            return f"{score} — HIGH"
        if score >= 40:
            return f"{score} — MEDIUM"
        if score >= 20:
            return f"{score} — LOW"
        return f"{score} — BENIGN"

    @staticmethod
    def _badge_class(value: str) -> str:
        """Return the CSS badge class for a severity / auth result string."""
        mapping = {
            "CRITICAL": "badge-critical",
            "HIGH":     "badge-high",
            "MEDIUM":   "badge-medium",
            "LOW":      "badge-low",
            "BENIGN":   "badge-benign",
            "pass":     "badge-pass",
            "fail":     "badge-fail",
            "softfail": "badge-warn",
            "neutral":  "badge-warn",
            "none":     "badge-warn",
        }
        return mapping.get(str(value).lower(), "badge-low")

    # ------------------------------------------------------------------
    # CSS
    # ------------------------------------------------------------------

    @staticmethod
    def _get_report_css() -> str:
        """
        Full CSS for the PDF report.  Uses CSS paged-media rules for
        header/footer content and page numbering via WeasyPrint.
        """
        return """
        /* ---- Page layout ---- */
        @page {
            size: A4;
            margin: 2cm 1.5cm 2.5cm 1.5cm;
            @top-right {
                content: "TraceVault Forensic Report | CONFIDENTIAL";
                font-size: 8pt;
                color: #666;
                font-family: Arial, sans-serif;
            }
            @bottom-center {
                content: counter(page) " of " counter(pages);
                font-size: 8pt;
                color: #666;
                font-family: Arial, sans-serif;
            }
            @bottom-left {
                content: "Generated by TraceVault v1.0.0";
                font-size: 7pt;
                color: #999;
                font-family: Arial, sans-serif;
            }
        }

        /* ---- Base ---- */
        body {
            font-family: 'DejaVu Sans', Arial, sans-serif;
            font-size: 10pt;
            color: #1a1a2e;
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }

        /* ---- Headings ---- */
        h1 {
            font-size: 22pt;
            color: #1a1a2e;
            border-bottom: 3px solid #2563eb;
            padding-bottom: 10pt;
            margin-top: 0;
        }
        h2 {
            font-size: 14pt;
            color: #1e3a8a;
            border-bottom: 1px solid #bfdbfe;
            padding-bottom: 4pt;
            margin-top: 20pt;
        }
        h3 { font-size: 11pt; color: #1e40af; }

        /* ---- Tables ---- */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10pt 0;
            font-size: 9pt;
        }
        th {
            background: #1e3a8a;
            color: white;
            padding: 6pt 8pt;
            text-align: left;
            font-weight: bold;
        }
        td {
            padding: 5pt 8pt;
            border-bottom: 1px solid #e5e7eb;
            vertical-align: top;
        }
        tr:nth-child(even) { background: #f0f4ff; }

        /* ---- Threat score ---- */
        .threat-score-critical { color: #dc2626; font-size: 28pt; font-weight: bold; }
        .threat-score-high     { color: #ea580c; font-size: 28pt; font-weight: bold; }
        .threat-score-medium   { color: #d97706; font-size: 28pt; font-weight: bold; }
        .threat-score-low      { color: #2563eb; font-size: 28pt; font-weight: bold; }
        .threat-score-benign   { color: #16a34a; font-size: 28pt; font-weight: bold; }

        /* ---- Severity badges ---- */
        .badge {
            display: inline-block;
            padding: 2pt 6pt;
            border-radius: 3pt;
            color: white;
            font-size: 8pt;
            font-weight: bold;
        }
        .badge-critical { background: #dc2626; }
        .badge-high     { background: #ea580c; }
        .badge-medium   { background: #d97706; }
        .badge-low      { background: #2563eb; }
        .badge-benign   { background: #16a34a; }
        .badge-pass     { background: #16a34a; }
        .badge-fail     { background: #dc2626; }
        .badge-warn     { background: #d97706; }

        /* ---- Cover page ---- */
        .cover-page     { text-align: center; padding: 60pt 0; }
        .cover-logo     { font-size: 36pt; font-weight: bold; color: #1e3a8a; }
        .cover-subtitle { font-size: 14pt; color: #6b7280; margin: 10pt 0; }
        .cover-meta     { font-size: 10pt; color: #374151; margin: 4pt 0; }

        /* ---- Utility ---- */
        .disclaimer {
            background: #fef3c7;
            border: 1pt solid #f59e0b;
            padding: 10pt;
            font-size: 9pt;
            margin: 10pt 0;
            border-radius: 3pt;
        }
        .hash-value {
            font-family: 'DejaVu Sans Mono', monospace;
            font-size: 8pt;
            word-break: break-all;
            background: #f3f4f6;
            padding: 4pt 6pt;
            border-radius: 3pt;
        }
        .chain-entry {
            border-left: 3pt solid #2563eb;
            padding-left: 10pt;
            margin: 8pt 0;
        }
        .info-box {
            background: #eff6ff;
            border: 1pt solid #bfdbfe;
            padding: 8pt;
            border-radius: 3pt;
            margin: 8pt 0;
            font-size: 9pt;
        }
        .page-break { page-break-before: always; }
        .no-break   { page-break-inside: avoid; }

        /* ---- Score bar ---- */
        .score-bar-container {
            background: #e5e7eb;
            border-radius: 4pt;
            height: 16pt;
            margin: 4pt 0;
            width: 100%;
        }
        .score-bar {
            height: 16pt;
            border-radius: 4pt;
        }
        """
