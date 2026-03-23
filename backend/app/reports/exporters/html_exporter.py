"""
HTML exporter for security reports.

Produces a minimal but structured HTML representation of a `SecurityReport`.
This can be used as a basis for more advanced theming or templating systems.
"""

from __future__ import annotations

from html import escape
from typing import List

from ..report_models import SecurityReport


class HtmlReportExporter:
    """Basic HTML exporter with a simple built-in template."""

    def to_html(self, report: SecurityReport) -> str:
        """Render the given `SecurityReport` as an HTML string."""

        head = (
            "<!DOCTYPE html>"
            "<html lang='en'>"
            "<head>"
            "<meta charset='utf-8'/>"
            "<title>Security Report</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; margin: 2rem; }"
            "h1, h2, h3 { color: #1f2933; }"
            "table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }"
            "th, td { border: 1px solid #cbd2d9; padding: 0.5rem; text-align: left; }"
            "th { background-color: #e4e7eb; }"
            ".severity-HIGH, .severity-CRITICAL { color: #b91c1c; font-weight: bold; }"
            ".severity-MEDIUM { color: #b7791f; font-weight: bold; }"
            ".severity-LOW { color: #047481; }"
            "</style>"
            "</head>"
            "<body>"
        )

        body_sections: List[str] = []
        body_sections.append("<h1>Security Assessment Report</h1>")

        # Executive summary
        body_sections.append("<h2>Executive Summary</h2>")
        body_sections.append(f"<p>{escape(report.executive_summary)}</p>")

        # Technical summary
        body_sections.append("<h2>Technical Summary</h2>")
        body_sections.append(f"<p>{escape(report.technical_summary)}</p>")

        # Risk score and metadata
        meta = report.scan_metadata
        body_sections.append("<h2>Scan Overview</h2>")
        body_sections.append("<ul>")
        body_sections.append(f"<li><strong>Scan ID:</strong> {escape(meta.scan_id)}</li>")
        if meta.target:
            body_sections.append(f"<li><strong>Target:</strong> {escape(meta.target)}</li>")
        if meta.started_at:
            body_sections.append(f"<li><strong>Started at:</strong> {escape(meta.started_at)}</li>")
        if meta.finished_at:
            body_sections.append(f"<li><strong>Finished at:</strong> {escape(meta.finished_at)}</li>")
        body_sections.append(f"<li><strong>Orchestrator state:</strong> {escape(meta.orchestrator_state)}</li>")
        body_sections.append(f"<li><strong>Risk score:</strong> {report.risk_score:.2f}</li>")
        body_sections.append("</ul>")

        # Vulnerability table
        body_sections.append("<h2>Vulnerabilities</h2>")
        body_sections.append(
            "<table>"
            "<thead>"
            "<tr>"
            "<th>ID</th><th>Type</th><th>Severity</th><th>Location</th><th>Source Tool</th><th>Description</th>"
            "</tr>"
            "</thead>"
            "<tbody>"
        )
        for row in report.vulnerability_table:
            sev_class = f"severity-{row.severity.name}"
            body_sections.append(
                "<tr>"
                f"<td>{escape(row.vulnerability_id)}</td>"
                f"<td>{escape(row.type)}</td>"
                f"<td class='{sev_class}'>{escape(row.severity.value.upper())}</td>"
                f"<td>{escape(row.location or '-')}</td>"
                f"<td>{escape(row.source_tool)}</td>"
                f"<td>{escape(row.description or '-')}</td>"
                "</tr>"
            )
        body_sections.append("</tbody></table>")

        # Exploit paths
        body_sections.append("<h2>Exploit Paths</h2>")
        if not report.exploit_paths:
            body_sections.append("<p>No exploit chains identified.</p>")
        else:
            for idx, path in enumerate(report.exploit_paths, start=1):
                body_sections.append(f"<h3>Path {idx}</h3>")
                body_sections.append("<ul>")
                body_sections.append(f"<li><strong>Entry point:</strong> {escape(path.entry_point)}</li>")
                body_sections.append(
                    "<li><strong>Chain nodes:</strong> "
                    f"{' &rarr; '.join(escape(node_id) for node_id in path.chain_nodes)}</li>"
                )
                body_sections.append(f"<li><strong>Impact:</strong> {escape(path.final_impact)}</li>")
                body_sections.append(
                    f"<li><strong>Confidence:</strong> {path.confidence_score:.2f}</li>"
                )
                body_sections.append("</ul>")

        # Remediation plan
        body_sections.append("<h2>Remediation Plan</h2>")
        if not report.remediation_plan:
            body_sections.append("<p>No remediation actions available.</p>")
        else:
            body_sections.append(
                "<table>"
                "<thead><tr>"
                "<th>Vulnerability ID</th><th>Priority</th><th>Summary</th><th>Technical Steps</th><th>References</th>"
                "</tr></thead><tbody>"
            )
            for item in report.remediation_plan:
                steps_html = "<br/>".join(escape(step) for step in item.technical_steps)
                refs_html = "<br/>".join(escape(ref) for ref in item.references)
                body_sections.append(
                    "<tr>"
                    f"<td>{escape(item.vulnerability_id)}</td>"
                    f"<td>{escape(item.priority.upper())}</td>"
                    f"<td>{escape(item.fix_summary)}</td>"
                    f"<td>{steps_html}</td>"
                    f"<td>{refs_html}</td>"
                    "</tr>"
                )
            body_sections.append("</tbody></table>")

        tail = "</body></html>"

        return head + "".join(body_sections) + tail

