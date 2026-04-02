"""
Scan-related HTTP routes.

These routes are intentionally thin and delegate all orchestration logic to
`ScanController`. They only handle HTTP concerns such as request parsing,
dependency injection, and response serialization.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from ...orchestrator import OrchestratorState
from ...mcp.context_manager import MCPContextManager
from ..controllers.scan_controller import ScanController
from ..dependencies import (
    api_key_auth,
    get_attack_graph_builder,
    get_json_exporter,
    get_mcp_manager,
    get_reasoning_engine,
    get_remediation_engine,
    get_report_builder,
    get_result_normalizer,
    get_scan_orchestrator,
    get_scan_result_repository,
    rate_limiter_stub,
)
from ..schemas.scan import (
    GraphEdgeOut,
    GraphNodeOut,
    ScanGraphResponse,
    ScanReportResponse,
    ScanResultsResponse,
    ScanStartRequest,
    ScanStartResponse,
    ScanStatusResponse,
    VulnerabilityOut,
)


router = APIRouter(prefix="/scan", tags=["scan"])


def get_scan_controller() -> ScanController:
    """Construct a `ScanController` with its dependencies."""

    return ScanController(
        orchestrator=get_scan_orchestrator(),
        normalizer=get_result_normalizer(),
        graph_builder=get_attack_graph_builder(),
        reasoning_engine=get_reasoning_engine(),
        remediation_engine=get_remediation_engine(),
        report_builder=get_report_builder(),
        result_repository=get_scan_result_repository(),
    )


@router.post(
    "/start",
    response_model=ScanStartResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a new scan",
)
async def start_scan(
    payload: ScanStartRequest,
    background_tasks: BackgroundTasks,
    controller: ScanController = Depends(get_scan_controller),
    api_key: str = Depends(api_key_auth),
    _: None = Depends(rate_limiter_stub),
) -> ScanStartResponse:
    """
    Start a new scan for the given target.

    The scan is executed asynchronously in the background. The response
    contains a `scan_id` that can be used to query status and results.
    """

    scan_id = controller.generate_scan_id()
    background_tasks.add_task(
        controller.run_scan_pipeline,
        scan_id,
        str(payload.target),
        payload.requested_tools or [],
    )
    return ScanStartResponse(scan_id=scan_id)


@router.post(
    "/stop/{scan_id}",
    response_model=None,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request scan stop",
)
async def stop_scan(
    scan_id: str,
    api_key: str = Depends(api_key_auth),
    _: None = Depends(rate_limiter_stub),
) -> None:
    """
    Request cancellation of a scan.

    The current implementation provides a placeholder endpoint; integration
    with a cancellation mechanism can be added by wiring through the
    `MCPContextManager.cancel_scan` method.
    """

    # Placeholder implementation; no-op for now.
    return None


@router.get(
    "/status/{scan_id}",
    response_model=ScanStatusResponse,
    summary="Get scan status",
)
async def get_scan_status(
    scan_id: str,
    controller: ScanController = Depends(get_scan_controller),
    mcp_manager: MCPContextManager = Depends(get_mcp_manager),
    api_key: str = Depends(api_key_auth),
    _: None = Depends(rate_limiter_stub),
) -> ScanStatusResponse:
    """
    Return high-level status information for a scan.

    If full execution results are not yet available, basic status fields are
    still provided.
    """

    result = controller.get_execution_result(scan_id)
    if result is None:
        # If final result has not yet been persisted, return live state from MCP context.
        context = await mcp_manager.get_scan_state(scan_id)
        if context is None:
            # Unknown or not started.
            return ScanStatusResponse(
                scan_id=scan_id,
                orchestrator_state=OrchestratorState.INIT,
                scan_status=None,
                phase=None,
                issues_count=0,
                tool_status=None,
            )

        tool_status = {
            run.tool_id: run.status
            for run in context.tool_runs
        }

        orchestrator_state = OrchestratorState.RUNNING
        if context.status.value == "failed":
            orchestrator_state = OrchestratorState.FAILED
        elif context.status.value == "completed":
            orchestrator_state = OrchestratorState.COMPLETED

        return ScanStatusResponse(
            scan_id=scan_id,
            orchestrator_state=orchestrator_state,
            scan_status=context.status.value,
            phase=context.phase.value if context.phase is not None else None,
            issues_count=len(context.issues),
            tool_status=tool_status if tool_status else None,
        )

    ctx = result.scan_context
    issues_count = len(result.issues)
    scan_status = ctx.status.value if ctx is not None else None
    phase = ctx.phase.value if (ctx is not None and ctx.phase is not None) else None
    
    # Build tool_status mapping from tool_summaries
    tool_status = {}
    for tool_summary in result.tool_summaries:
        tool_status[tool_summary.tool_id] = tool_summary.status

    return ScanStatusResponse(
        scan_id=scan_id,
        orchestrator_state=result.orchestrator_state,
        scan_status=scan_status,
        phase=phase,
        issues_count=issues_count,
        tool_status=tool_status if tool_status else None,
    )


@router.get(
    "/results/{scan_id}",
    response_model=ScanResultsResponse,
    summary="Get normalized scan results",
)
async def get_scan_results(
    scan_id: str,
    controller: ScanController = Depends(get_scan_controller),
    api_key: str = Depends(api_key_auth),
    _: None = Depends(rate_limiter_stub),
) -> ScanResultsResponse:
    """
    Return normalized vulnerabilities for a completed scan.
    """

    result = controller.get_execution_result(scan_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    severity_map = {
        "info": "info",
        "low": "low",
        "medium": "medium",
        "moderate": "medium",
        "high": "high",
        "critical": "critical",
    }

    vulnerabilities: list[VulnerabilityOut] = []
    for idx, issue in enumerate(result.issues):
        raw_severity = str(issue.severity or "medium").lower()
        normalized_severity = severity_map.get(raw_severity, "medium")
        source_tool = str((issue.evidence or {}).get("source_tool") or "scanner")

        vulnerabilities.append(
            VulnerabilityOut(
                id=issue.id or f"issue-{idx}",
                type=issue.type or "generic_issue",
                severity=normalized_severity,
                location=issue.location,
                source_tool=source_tool,
                description=issue.description,
            )
        )

    return ScanResultsResponse(
        scan_id=scan_id,
        orchestrator_state=result.orchestrator_state,
        vulnerabilities=vulnerabilities,
    )


@router.get(
    "/report/{scan_id}",
    response_model=ScanReportResponse,
    summary="Get structured security report",
)
async def get_scan_report(
    scan_id: str,
    controller: ScanController = Depends(get_scan_controller),
    api_key: str = Depends(api_key_auth),
    _: None = Depends(rate_limiter_stub),
) -> ScanReportResponse:
    """
    Return the structured security report data for a scan.

    Formatting into JSON/HTML/PDF is handled separately by exporters.
    """

    report = controller.get_report(scan_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")

    from dataclasses import asdict

    report_dict = asdict(report)
    return ScanReportResponse(scan_id=scan_id, report=report_dict)


@router.get(
    "/graph/{scan_id}",
    response_model=ScanGraphResponse,
    summary="Get attack graph for scan",
)
async def get_scan_graph(
    scan_id: str,
    controller: ScanController = Depends(get_scan_controller),
    api_key: str = Depends(api_key_auth),
    _: None = Depends(rate_limiter_stub),
) -> ScanGraphResponse:
    """
    Return the attack graph representation for a scan.
    """

    graph = controller.get_graph(scan_id)
    if graph is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Graph not found.")

    nodes: list[GraphNodeOut] = []
    edges: list[GraphEdgeOut] = []

    for node_id, data in graph.nodes(data=True):
        node_data = data.get("data")
        label = getattr(node_data, "label", str(node_id))
        type_name = getattr(getattr(node_data, "type", None), "value", "unknown")
        nodes.append(
            GraphNodeOut(
                id=str(node_id),
                label=label,
                type=type_name,
            )
        )

    for u, v, data in graph.edges(data=True):
        edge_data = data.get("data")
        edge_type = getattr(getattr(edge_data, "type", None), "value", "dependency")
        edges.append(
            GraphEdgeOut(
                source=str(u),
                target=str(v),
                type=edge_type,
            )
        )

    return ScanGraphResponse(scan_id=scan_id, nodes=nodes, edges=edges)


