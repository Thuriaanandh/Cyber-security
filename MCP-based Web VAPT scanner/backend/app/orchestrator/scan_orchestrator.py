"""
Scan orchestrator implementation.

This module coordinates:
- MCP context management (`MCPContextManager`).
- Registered tool adapters via the MCP tool registry.
- Stateless decision logic from `DecisionEngine`.

It implements an orchestrator-level state machine:
INIT -> RUNNING -> TOOL_EXECUTION -> ANALYZING -> COMPLETED / FAILED

The orchestrator itself does not contain any tool-specific execution logic; it
invokes adapters through the generic `ToolAdapter` interface.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..core.logger import get_logger
from ..mcp.context_manager import MCPContextManager, ScanRequest
from ..mcp.state_tracker import ScanContextState, ScanPhase, ScanStatus
from ..mcp.tool_registry import ToolAdapter, ToolExecutionResult, ToolExecutionStatus
from .decision_engine import DecisionAction, DecisionActionType, DecisionEngine
from .models import DecisionSummary, OrchestratorState, ScanExecutionResult, ToolSummary


logger = get_logger(__name__)


class ScanOrchestrator:
    """
    High-level orchestrator for VAPT scans.

    All dependencies are injected:
    - `mcp_manager`: provides scan state tracking and tool registry access.
    - `decision_engine`: encapsulates adaptive sequencing rules.
    """

    def __init__(
        self,
        mcp_manager: MCPContextManager,
        decision_engine: Optional[DecisionEngine] = None,
        max_parallel_tools: int = 3,
    ) -> None:
        self._mcp_manager = mcp_manager
        self._decision_engine = decision_engine or DecisionEngine()
        self._max_parallel_tools = max_parallel_tools

    # ------------------------------------------------------------------ helpers
    def _log_state_change(self, scan_id: str, state: OrchestratorState) -> None:
        logger.info("Scan %s orchestrator state -> %s", scan_id, state.value)

    async def _execute_tools_parallel(
        self,
        scan_id: str,
        tool_ids: Sequence[str],
        base_params: Mapping[str, Any],
    ) -> List[ToolExecutionResult]:
        """
        Execute the given tools in parallel using their adapters.

        This function is generic and contains no tool-specific logic; it only
        interacts with the `ToolAdapter` interface.
        """

        results: List[ToolExecutionResult] = []

        async def _run_single(tool_id: str) -> None:
            try:
                adapter: ToolAdapter = self._mcp_manager.get_tool_adapter(tool_id)
            except KeyError:
                logger.warning("Tool %s not registered; skipping execution.", tool_id)
                return

            logger.info("Executing tool %s for scan %s", tool_id, scan_id)
            try:
                result = await adapter.execute(scan_id=scan_id, params=base_params)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Tool %s execution raised an exception.", tool_id)
                # Create a synthetic failure result to maintain invariants.
                from ..mcp.tool_registry import now_utc

                started_at = now_utc()
                finished_at = now_utc()
                result = ToolExecutionResult(
                    tool_id=tool_id,
                    scan_id=scan_id,
                    status=ToolExecutionStatus.FAILED,
                    started_at=started_at,
                    finished_at=finished_at,
                    raw_output={"error": str(exc)},
                    normalized_output={"issues": []},
                    error_message=f"Unhandled exception during tool execution: {exc}",
                )

            await self._mcp_manager.record_tool_result(result)
            results.append(result)

        # Respect maximum concurrency by chunking tool ids.
        chunks: List[Sequence[str]] = [
            tool_ids[i : i + self._max_parallel_tools]
            for i in range(0, len(tool_ids), self._max_parallel_tools)
        ]

        for chunk in chunks:
            await asyncio.gather(*[_run_single(tool_id) for tool_id in chunk])

        return results

    @staticmethod
    def _build_tool_summaries(context: Optional[ScanContextState]) -> List[ToolSummary]:
        if context is None:
            return []

        summaries: List[ToolSummary] = []
        for run in context.tool_runs:
            summaries.append(
                ToolSummary(
                    tool_id=run.tool_id,
                    status=run.status,
                    started_at=run.started_at.isoformat(),
                    finished_at=run.finished_at.isoformat(),
                    summary=run.summary,
                )
            )
        return summaries

    @staticmethod
    def _build_decision_summaries(context: Optional[ScanContextState]) -> List[DecisionSummary]:
        if context is None:
            return []

        summaries: List[DecisionSummary] = []
        for decision in context.decisions:
            summaries.append(
                DecisionSummary(
                    timestamp=decision.timestamp.isoformat(),
                    reason=decision.reason,
                    triggered_by=decision.triggered_by,
                    taken_action=decision.taken_action,
                    metadata=decision.metadata,
                )
            )
        return summaries

    # ------------------------------------------------------------------ main API
    async def run_scan(
        self,
        scan_id: str,
        target: str,
        requested_tools: Optional[Iterable[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScanExecutionResult:
        """
        Execute a full scan lifecycle for the given target.

        This method:
        - Initializes scan context via `MCPContextManager`.
        - Selects initial tools using `DecisionEngine`.
        - Executes tools (with parallelism where appropriate).
        - Applies adaptive follow-up logic based on findings.
        - Returns a structured `ScanExecutionResult`.
        """

        orchestrator_state = OrchestratorState.INIT
        self._log_state_change(scan_id, orchestrator_state)

        req_tools_list = list(requested_tools or [])
        req_metadata = dict(metadata or {})

        # 1) Initialize scan state
        request = ScanRequest(
            scan_id=scan_id,
            target=target,
            requested_tools=req_tools_list,
            metadata=req_metadata,
        )
        context = await self._mcp_manager.start_scan(request)
        orchestrator_state = OrchestratorState.RUNNING
        self._log_state_change(scan_id, orchestrator_state)

        # 2) Determine initial tools to run
        available_metadata = self._mcp_manager._tool_registry.list_metadata()  # type: ignore[attr-defined]
        available_tool_ids = set(available_metadata.keys())

        initial_tools = self._decision_engine.plan_initial_tools(
            requested_tools=req_tools_list,
            available_tool_ids=available_tool_ids,
        )

        if not initial_tools:
            logger.warning("No tools selected for scan %s; marking as failed.", scan_id)
            await self._mcp_manager.complete_scan(scan_id, failed=True)
            orchestrator_state = OrchestratorState.FAILED
            final_context = await self._mcp_manager.get_scan_state(scan_id)
            return ScanExecutionResult(
                scan_id=scan_id,
                orchestrator_state=orchestrator_state,
                scan_context=final_context,
                issues=list(final_context.issues) if final_context else [],
                tool_summaries=self._build_tool_summaries(final_context),
                decision_summaries=self._build_decision_summaries(final_context),
            )

        # 3) Execute initial tools in parallel
        orchestrator_state = OrchestratorState.TOOL_EXECUTION
        self._log_state_change(scan_id, orchestrator_state)

        await self._mcp_manager._state_tracker.update_status(  # type: ignore[attr-defined]
            scan_id=scan_id,
            status=ScanStatus.RUNNING,
            phase=ScanPhase.VULNERABILITY_SCANNING,
        )

        await self._execute_tools_parallel(
            scan_id=scan_id,
            tool_ids=initial_tools,
            base_params={"target": target},
        )

        # 4) Analyze results and determine follow-up actions
        orchestrator_state = OrchestratorState.ANALYZING
        self._log_state_change(scan_id, orchestrator_state)

        context = await self._mcp_manager.get_scan_state(scan_id)
        if context is None:
            logger.error("Scan context missing after initial tool execution for %s.", scan_id)
            await self._mcp_manager.complete_scan(scan_id, failed=True)
            orchestrator_state = OrchestratorState.FAILED
            return ScanExecutionResult(
                scan_id=scan_id,
                orchestrator_state=orchestrator_state,
                scan_context=None,
                issues=[],
            )

        followup_actions: List[DecisionAction] = self._decision_engine.derive_followup_actions(
            context=context,
            available_tool_ids=available_tool_ids,
        )

        # Log / persist decision history
        for action in followup_actions:
            await self._mcp_manager.record_decision(
                scan_id=scan_id,
                reason=action.reason,
                triggered_by="decision_engine",
                taken_action=(
                    f"{action.type.value}:{action.tool_id}" if action.tool_id else action.type.value
                ),
                metadata=action.params or {},
            )

        # Execute follow-up tools where appropriate
        followup_tool_ids: List[str] = [
            action.tool_id
            for action in followup_actions
            if action.type is DecisionActionType.RUN_TOOL and action.tool_id is not None
        ]

        if followup_tool_ids:
            await self._mcp_manager._state_tracker.update_status(  # type: ignore[attr-defined]
                scan_id=scan_id,
                status=ScanStatus.RUNNING,
                phase=ScanPhase.VULNERABILITY_SCANNING,
            )

            await self._execute_tools_parallel(
                scan_id=scan_id,
                tool_ids=followup_tool_ids,
                base_params={"target": target},
            )

        # 5) Finalize scan state
        context = await self._mcp_manager.get_scan_state(scan_id)

        failure_statuses = {"failed", "timeout", "cancelled"}
        tool_runs = list(context.tool_runs) if context is not None else []
        all_tools_failed = bool(tool_runs) and all(
            str(run.status).lower() in failure_statuses for run in tool_runs
        )
        failed = context is None or all_tools_failed

        await self._mcp_manager.complete_scan(scan_id, failed=failed)

        orchestrator_state = OrchestratorState.FAILED if failed else OrchestratorState.COMPLETED
        self._log_state_change(scan_id, orchestrator_state)

        final_context = await self._mcp_manager.get_scan_state(scan_id)

        return ScanExecutionResult(
            scan_id=scan_id,
            orchestrator_state=orchestrator_state,
            scan_context=final_context,
            issues=list(final_context.issues) if final_context else [],
            tool_summaries=self._build_tool_summaries(final_context),
            decision_summaries=self._build_decision_summaries(final_context),
        )

