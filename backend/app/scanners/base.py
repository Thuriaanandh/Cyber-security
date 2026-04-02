"""
Abstract base interfaces for security scanners.

These abstractions sit between the MCP orchestration layer and concrete
scanner implementations (e.g. ZAP, SQLMap, Nmap). Higher-level components
depend only on these interfaces, not on concrete classes, in line with the
dependency inversion principle.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping

from ..mcp.tool_registry import ToolAdapter, ToolExecutionResult, ToolMetadata


@dataclass
class ScannerContext:
    """
    Lightweight context passed to scanners.

    This is intentionally minimal and can be extended as needed without
    coupling scanners to any particular web framework or task queue.
    """

    scan_id: str
    target: str


class AbstractScannerAdapter(ToolAdapter, ABC):
    """
    Abstract base class for all security scanner adapters.

    Concrete scanners:
    - Provide a `ToolMetadata` instance describing their capabilities.
    - Implement the asynchronous `execute` method, which will later contain
      the logic to start scans (e.g. subprocess, HTTP API, etc.).
    """

    metadata: ToolMetadata

    @abstractmethod
    async def execute(self, scan_id: str, params: Mapping[str, Any]) -> ToolExecutionResult:  # type: ignore[override]
        """
        Execute the scanner for the given scan id and parameters.

        Implementations should be pure from the perspective of the caller,
        i.e. no global state mutation; all dependencies (configuration, clients)
        must be injected via the constructor.
        """

        raise NotImplementedError

