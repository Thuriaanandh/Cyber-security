"""
State tracking for MCP-managed scans.

This module defines strongly-typed representations of scan state and an
in-memory tracker implementation. It is intentionally storage-agnostic so it
can be replaced with a database-backed implementation later without changing
callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, MutableMapping, Optional


class ScanStatus(str, Enum):
    """High-level lifecycle status for a scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanPhase(str, Enum):
    """Coarse-grained phase in the scan pipeline."""

    DISCOVERY = "discovery"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    ATTACK_GRAPH_BUILDING = "attack_graph_building"
    AI_REASONING = "ai_reasoning"
    REPORT_GENERATION = "report_generation"


@dataclass
class DetectedIssue:
    """Normalized representation of a single detected vulnerability or issue."""

    id: str
    type: str
    severity: str
    description: str
    location: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None


@dataclass
class ToolRunRecord:
    """Record of a single tool invocation within a scan."""

    tool_id: str
    status: str
    started_at: datetime
    finished_at: datetime
    summary: Optional[str] = None
    raw_reference_id: Optional[str] = None


@dataclass
class DecisionRecord:
    """
    Record of a single orchestrator decision.

    This is used to maintain a decision history, which can help in debugging,
    audit trails, and feeding context to the AI engine.
    """

    timestamp: datetime
    reason: str
    triggered_by: Optional[str] = None
    taken_action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContextState:
    """
    Complete, in-memory representation of scan context.

    This structure is designed to be serializable so it can be persisted to a
    database or cache in a future implementation.
    """

    scan_id: str
    target: str
    created_at: datetime
    status: ScanStatus = ScanStatus.PENDING
    phase: Optional[ScanPhase] = None
    requested_tools: List[str] = field(default_factory=list)
    active_tools: List[str] = field(default_factory=list)
    completed_tools: List[str] = field(default_factory=list)
    issues: List[DetectedIssue] = field(default_factory=list)
    tool_runs: List[ToolRunRecord] = field(default_factory=list)
    decisions: List[DecisionRecord] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class StateTracker:
    """
    Abstract interface for scan state tracking.

    Implementations may use in-memory data structures, relational databases,
    document stores, or other persistence layers.
    """

    async def create_scan(self, scan_id: str, target: str, requested_tools: List[str]) -> ScanContextState:
        raise NotImplementedError

    async def get_scan(self, scan_id: str) -> Optional[ScanContextState]:
        raise NotImplementedError

    async def update_status(self, scan_id: str, status: ScanStatus, phase: Optional[ScanPhase] = None) -> None:
        raise NotImplementedError

    async def add_tool_run(self, scan_id: str, record: ToolRunRecord) -> None:
        raise NotImplementedError

    async def add_issue(self, scan_id: str, issue: DetectedIssue) -> None:
        raise NotImplementedError

    async def add_decision(self, scan_id: str, decision: DecisionRecord) -> None:
        raise NotImplementedError


class InMemoryStateTracker(StateTracker):
    """
    Simple in-memory implementation of `StateTracker`.

    This implementation is primarily intended for:
    - Unit tests.
    - Local development.

    It is not designed for multi-process or multi-instance deployments.
    """

    def __init__(self) -> None:
        self._store: MutableMapping[str, ScanContextState] = {}

    async def create_scan(self, scan_id: str, target: str, requested_tools: List[str]) -> ScanContextState:
        created_at = datetime.now(timezone.utc)
        context = ScanContextState(
            scan_id=scan_id,
            target=target,
            created_at=created_at,
            requested_tools=list(requested_tools),
            status=ScanStatus.PENDING,
            phase=ScanPhase.DISCOVERY,
        )
        self._store[scan_id] = context
        return context

    async def get_scan(self, scan_id: str) -> Optional[ScanContextState]:
        return self._store.get(scan_id)

    async def update_status(self, scan_id: str, status: ScanStatus, phase: Optional[ScanPhase] = None) -> None:
        context = self._require_context(scan_id)
        context.status = status
        if phase is not None:
            context.phase = phase

    async def add_tool_run(self, scan_id: str, record: ToolRunRecord) -> None:
        context = self._require_context(scan_id)
        context.tool_runs.append(record)
        if record.tool_id not in context.completed_tools:
            context.completed_tools.append(record.tool_id)
        if record.tool_id in context.active_tools:
            context.active_tools.remove(record.tool_id)

    async def add_issue(self, scan_id: str, issue: DetectedIssue) -> None:
        context = self._require_context(scan_id)
        context.issues.append(issue)

    async def add_decision(self, scan_id: str, decision: DecisionRecord) -> None:
        context = self._require_context(scan_id)
        context.decisions.append(decision)

    # ------------------------------------------------------------------ helpers
    def _require_context(self, scan_id: str) -> ScanContextState:
        try:
            return self._store[scan_id]
        except KeyError as exc:  # noqa: B904
            raise KeyError(f"Unknown scan_id: {scan_id}") from exc

