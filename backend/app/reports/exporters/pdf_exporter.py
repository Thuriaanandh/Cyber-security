"""
PDF exporter stub for security reports.

This module defines the public interface for generating PDF documents from
`SecurityReport` instances but does not provide a concrete implementation yet.
"""

from __future__ import annotations

from ..report_models import SecurityReport


class PdfReportExporter:
    """
    Stub PDF exporter.

    A concrete implementation can be added later using a library such as
    ReportLab, WeasyPrint, or a headless browser renderer.
    """

    def to_pdf_bytes(self, report: SecurityReport) -> bytes:
        """
        Convert the given `SecurityReport` into a PDF document.

        Current behavior:
        - Raises `NotImplementedError` to indicate that PDF export is not yet
          available.
        """

        raise NotImplementedError("PDF export is not implemented yet.")

