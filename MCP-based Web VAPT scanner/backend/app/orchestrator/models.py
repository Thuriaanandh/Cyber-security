"""
Orchestration models for scan execution.

These value objects represent the orchestrator's own state machine and the
structured results returned to callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..mcp.state_tracker import DetectedIssue, ScanContextState


class OrchestratorState(str, Enum):
    """
    Coarse-grained lifecycle of the scan orchestrator.

    This state is orthogonal, but related, to the lower-level `ScanStatus` and
    `ScanPhase` values maintained by the MCP state tracker.
    """

    INIT = "init"
    RUNNING = "running"
    TOOL_EXECUTION = "tool_execution"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ToolSummary:
    """Summary of a single tool's execution within a scan."""

    tool_id: str
    status: str
    started_at: str
    finished_at: str
    summary: Optional[str] = None


@dataclass
class DecisionSummary:
    """Summary of a single orchestrator decision."""

    timestamp: str
    reason: str
    triggered_by: Optional[str]
    taken_action: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanExecutionResult:
    """
    Structured result returned by the scan orchestrator.

    This object is designed to be directly serializable for API responses or
    worker messages without leaking internal implementation details.
    """

    scan_id: str
    orchestrator_state: OrchestratorState
    scan_context: Optional[ScanContextState]
    issues: List[DetectedIssue] = field(default_factory=list)
    tool_summaries: List[ToolSummary] = field(default_factory=list)
    decision_summaries: List[DecisionSummary] = field(default_factory=list)

