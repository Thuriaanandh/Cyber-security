"""
Reporting engine.

This package contains models and utilities to build structured security reports
from scan execution results, impact analysis, exploit chains, and remediation
advice. Formatting concerns (JSON, HTML, PDF) are kept separate from data
generation.
"""

from .report_models import (
    ReportExploitPath,
    ReportRemediationItem,
    ReportScanMetadata,
    ReportVulnerabilityRow,
    SecurityReport,
)
from .report_builder import ReportBuilder

__all__ = [
    "ReportExploitPath",
    "ReportRemediationItem",
    "ReportScanMetadata",
    "ReportVulnerabilityRow",
    "SecurityReport",
    "ReportBuilder",
]

