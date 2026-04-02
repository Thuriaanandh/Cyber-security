"""
Security tools layer.

This package defines abstract scanner contracts and concrete adapter skeletons
for external security tools (ZAP, SQLMap, Nmap). The adapters are designed to
be:
- Independently testable.
- Framework-agnostic (no FastAPI or Celery imports).
- Integrated with the MCP `ToolAdapter` interface via dependency inversion.
"""

from .base import AbstractScannerAdapter
from .zap_scanner import ZAPScannerAdapter
from .sqlmap_scanner import SQLMapScannerAdapter
from .nmap_scanner import NmapScannerAdapter

__all__ = [
    "AbstractScannerAdapter",
    "ZAPScannerAdapter",
    "SQLMapScannerAdapter",
    "NmapScannerAdapter",
]

