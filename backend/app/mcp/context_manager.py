"""
High-level MCP context manager.

This module coordinates between the tool registry and the state tracker to
maintain a coherent view of scan state for the orchestrator. It intentionally
contains no web framework specific code so it can be reused across different
entrypoints (HTTP, CLI, workers).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

from .state_tracker import (
    DecisionRecord,
    DetectedIssue,
    InMemoryStateTracker,
    ScanContextState,
    ScanPhase,
    ScanStatus,
    StateTracker,
    ToolRunRecord,
)
from .tool_registry import ToolAdapter, ToolExecutionResult, ToolExecutionStatus, ToolRegistry, now_utc
from ..core.logger import get_logger


logger = get_logger(__name__)


@dataclass
class ScanRequest:
    """Value object capturing requested scan parameters."""

    scan_id: str
    target: str
    requested_tools: List[str]
    metadata: Dict[str, Any]


class MCPContextManager:
    """
    Orchestrator-facing facade over state tracking and tool management.

    Responsibilities:
    - Initialize scan context and maintain lifecycle.
    - Provide access to registered tools.
    - Record tool runs, detected issues, and decision history.
    """

    def __init__(
        self,
        state_tracker: Optional[StateTracker] = None,
        tool_registry: Optional[ToolRegistry] = None,
    ) -> None:
        self._state_tracker: StateTracker = state_tracker or InMemoryStateTracker()
        self._tool_registry: ToolRegistry = tool_registry or ToolRegistry()

    # ----------------------------------------------------------------- lifecycle
    async def start_scan(self, request: ScanRequest) -> ScanContextState:
        """
        Initialize state for a new scan and mark it as running.

        The returned `ScanContextState` can be used by orchestrators to make
        further decisions about which tools to execute.
        """

        logger.info("Starting scan %s for target %s", request.scan_id, request.target)
        context = await self._state_tracker.create_scan(
            scan_id=request.scan_id,
            target=request.target,
            requested_tools=request.requested_tools,
        )
        context.metadata.update(request.metadata)
        await self._state_tracker.update_status(
            scan_id=request.scan_id,
            status=ScanStatus.RUNNING,
            phase=ScanPhase.DISCOVERY,
        )
        return context

    async def complete_scan(self, scan_id: str, failed: bool = False) -> None:
        """Mark a scan as completed (or failed) and finalize its phase."""

        status = ScanStatus.FAILED if failed else ScanStatus.COMPLETED
        await self._state_tracker.update_status(
            scan_id=scan_id,
            status=status,
            phase=ScanPhase.REPORT_GENERATION,
        )
        logger.info("Scan %s completed with status=%s", scan_id, status.value)

    async def cancel_scan(self, scan_id: str) -> None:
        """Mark a scan as cancelled."""

        await self._state_tracker.update_status(
            scan_id=scan_id,
            status=ScanStatus.CANCELLED,
        )
        logger.info("Scan %s cancelled by request.", scan_id)

    # ------------------------------------------------------------------- queries
    async def get_scan_state(self, scan_id: str) -> Optional[ScanContextState]:
        """Return the current context state for a scan."""

        return await self._state_tracker.get_scan(scan_id)

    # ----------------------------------------------------------------- tool API
    def get_tool_adapter(self, tool_id: str) -> ToolAdapter:
        """Retrieve a concrete tool adapter by id."""

        return self._tool_registry.get_adapter(tool_id)

    def list_tools(self) -> Dict[str, str]:
        """Return a lightweight mapping of tool id to human-readable name."""

        return {
            tool_id: meta.name
            for tool_id, meta in self._tool_registry.list_metadata().items()
        }

    # ---------------------------------------------------------- recording events
    async def record_tool_result(self, result: ToolExecutionResult) -> None:
        """
        Persist the outcome of a tool execution into scan state.

        This connects the low-level execution result with higher-level scan
        context (issues, status, etc.) while keeping each concern independent.
        """

        # Update tool run history
        tool_run = ToolRunRecord(
            tool_id=result.tool_id,
            status=result.status.value,
            started_at=result.started_at,
            finished_at=result.finished_at,
            summary=result.error_message,
        )
        await self._state_tracker.add_tool_run(result.scan_id, tool_run)

        # If normalized output includes issues, register them
        issues_payload = (result.normalized_output or {}).get("issues", [])
        for raw_issue in issues_payload:
            raw_evidence = raw_issue.get("evidence")
            if isinstance(raw_evidence, dict):
                evidence = dict(raw_evidence)
            elif raw_evidence is None:
                evidence = {}
            else:
                evidence = {"details": raw_evidence}

            evidence.setdefault("source_tool", result.tool_id)

            issue = DetectedIssue(
                id=str(raw_issue.get("id", "")),
                type=str(raw_issue.get("type", "")),
                severity=str(raw_issue.get("severity", "")),
                description=str(raw_issue.get("description", "")),
                location=raw_issue.get("location"),
                evidence=evidence,
            )
            await self._state_tracker.add_issue(result.scan_id, issue)

        # Do not force whole-scan failure on a single tool failure.
        # Final scan status is decided by the orchestrator after all tools finish.

    async def record_decision(
        self,
        scan_id: str,
        reason: str,
        triggered_by: Optional[str] = None,
        taken_action: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Append a decision record to the scan context."""

        decision = DecisionRecord(
            timestamp=now_utc(),
            reason=reason,
            triggered_by=triggered_by,
            taken_action=taken_action,
            metadata=dict(metadata or {}),
        )
        await self._state_tracker.add_decision(scan_id, decision)

