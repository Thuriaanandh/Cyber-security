"""
Nmap scanner adapter skeleton.

This module provides a concrete implementation of `AbstractScannerAdapter`
that will later:
- Execute Nmap scans for host discovery, port scanning, and service detection.
- Use Nmap scripts relevant to web application security (e.g. TLS, HTTP enum).
- Normalize open ports and detected services into a graph-friendly format.

The current implementation is intentionally minimal and does not invoke Nmap.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Optional

from ..mcp.tool_registry import (
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolMetadata,
    ToolType,
    now_utc,
)
from .base import AbstractScannerAdapter


@dataclass
class NmapScannerConfig:
    """Configuration parameters for Nmap integration."""

    binary_path: str = "nmap"
    default_timeout_seconds: int = 1800


class NmapScannerAdapter(AbstractScannerAdapter):
    """Adapter skeleton for Nmap."""

    def __init__(self, config: Optional[NmapScannerConfig] = None) -> None:
        self._config = config or NmapScannerConfig()
        self.metadata = ToolMetadata(
            id="nmap",
            name="Nmap",
            type=ToolType.NMAP,
            version="0.0.1",
            description="Nmap network discovery and port scanning tool.",
            supported_vulnerability_types=("exposed_services", "network_misconfig"),
            supports_async=True,
            default_timeout_seconds=self._config.default_timeout_seconds,
        )

    async def execute(self, scan_id: str, params: Mapping[str, Any]) -> ToolExecutionResult:  # type: ignore[override]
        """
        Stubbed execution method.

        Future implementation responsibilities:
        - Execute Nmap with suitable scan profiles for web application targets.
        - Parse XML/JSON output for ports, services, and scripts results.
        - Feed normalized results into the attack graph engine.
        """

        started_at: datetime = now_utc()
        finished_at: datetime = now_utc()

        return ToolExecutionResult(
            tool_id=self.metadata.id,
            scan_id=scan_id,
            status=ToolExecutionStatus.FAILED,
            started_at=started_at,
            finished_at=finished_at,
            raw_output={"message": "Nmap execution not implemented"},
            normalized_output={"issues": []},
            error_message="Nmap scanner execution not implemented.",
        )

