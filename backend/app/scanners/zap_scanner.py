"""
OWASP ZAP scanner adapter skeleton.

This module provides a concrete implementation of `AbstractScannerAdapter`
that will, in future iterations, be responsible for:
- Coordinating with a ZAP daemon (local or remote).
- Managing ZAP sessions and scan configurations.
- Collecting and normalizing ZAP results.

At this stage, the adapter only exposes metadata and a stubbed `execute`
implementation with no real tool interaction.
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
class ZAPScannerConfig:
    """Configuration parameters for OWASP ZAP integration."""

    base_url: str = "http://localhost:8090"
    api_key: Optional[str] = None
    default_timeout_seconds: int = 1800


class ZAPScannerAdapter(AbstractScannerAdapter):
    """Adapter skeleton for OWASP ZAP."""

    def __init__(self, config: Optional[ZAPScannerConfig] = None) -> None:
        self._config = config or ZAPScannerConfig()
        self.metadata = ToolMetadata(
            id="zap",
            name="OWASP ZAP",
            type=ToolType.ZAP,
            version="0.0.1",
            description="OWASP ZAP web application vulnerability scanner.",
            supported_vulnerability_types=(
                "xss",
                "sqli",
                "auth_bypass",
                "insecure_cookies",
                "security_headers",
            ),
            supports_async=True,
            default_timeout_seconds=self._config.default_timeout_seconds,
        )

    async def execute(self, scan_id: str, params: Mapping[str, Any]) -> ToolExecutionResult:  # type: ignore[override]
        """
        Stubbed execution method.

        Future implementation responsibilities:
        - Start/coordinate ZAP active and passive scans for the target.
        - Poll for completion, collect alerts, and normalize them.
        - Return a populated `ToolExecutionResult` with normalized findings.
        """

        started_at: datetime = now_utc()
        finished_at: datetime = now_utc()

        # No real tool execution is performed yet; the result is a placeholder
        # that can be used by unit tests and higher-level orchestration logic.
        return ToolExecutionResult(
            tool_id=self.metadata.id,
            scan_id=scan_id,
            status=ToolExecutionStatus.FAILED,
            started_at=started_at,
            finished_at=finished_at,
            raw_output={"message": "ZAP execution not implemented"},
            normalized_output={"issues": []},
            error_message="ZAP scanner execution not implemented.",
        )

