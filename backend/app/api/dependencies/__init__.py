"""
Dependency providers for the API layer.

These helpers wire up orchestrator, normalization, graph, AI reasoning,
remediation, and reporting components using dependency injection.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Dict

import networkx as nx

from fastapi import Depends

from ...ai_engine import ReasoningEngine, RemediationEngine
from ...core.config import Settings, get_settings
from ...core.security import RateLimiter, get_api_key
from ...graph_engine import AttackGraphBuilder
from ...mcp import MCPContextManager
from ...mcp.tool_registry import ToolRegistry
from ...normalization import ResultNormalizer
from ...orchestrator import ScanExecutionResult, ScanOrchestrator
from ...reports import ReportBuilder, SecurityReport
from ...reports.exporters import JsonReportExporter, PdfReportExporter
from ...scanners import NmapScannerAdapter, SQLMapScannerAdapter, ZAPScannerAdapter
from ..schemas.scan import ScanStatusResponse


@lru_cache
def get_tool_registry() -> ToolRegistry:
    """Create and cache a tool registry with default scanner adapters."""

    registry = ToolRegistry(
        tools=(
            ZAPScannerAdapter(),
            SQLMapScannerAdapter(),
            NmapScannerAdapter(),
        )
    )
    return registry


@lru_cache
def get_mcp_manager() -> MCPContextManager:
    """Provide a singleton MCP context manager."""

    return MCPContextManager(tool_registry=get_tool_registry())


@lru_cache
def get_scan_orchestrator() -> ScanOrchestrator:
    """Provide a singleton scan orchestrator."""

    return ScanOrchestrator(mcp_manager=get_mcp_manager())


@lru_cache
def get_result_normalizer() -> ResultNormalizer:
    return ResultNormalizer()


@lru_cache
def get_attack_graph_builder() -> AttackGraphBuilder:
    return AttackGraphBuilder()


@lru_cache
def get_reasoning_engine() -> ReasoningEngine:
    return ReasoningEngine()


@lru_cache
def get_remediation_engine() -> RemediationEngine:
    return RemediationEngine()


@lru_cache
def get_report_builder() -> ReportBuilder:
    return ReportBuilder()


@lru_cache
def get_json_exporter() -> JsonReportExporter:
    return JsonReportExporter()


@lru_cache
def get_pdf_exporter() -> PdfReportExporter:
    return PdfReportExporter()


class InMemoryScanResultRepository:
    """
    Simple in-memory store for scan artifacts.

    Controllers use this repository to persist orchestrator outputs and
    analysis results. It is intended for local development and testing.
    """

    def __init__(self) -> None:
        self._results: Dict[str, ScanExecutionResult] = {}
        self._graphs: Dict[str, nx.DiGraph] = {}
        self._reports: Dict[str, SecurityReport] = {}

    def save_execution_result(self, scan_id: str, result: ScanExecutionResult) -> None:
        self._results[scan_id] = result

    def save_graph(self, scan_id: str, graph: nx.DiGraph) -> None:
        self._graphs[scan_id] = graph

    def save_report(self, scan_id: str, report: SecurityReport) -> None:
        self._reports[scan_id] = report

    def get_execution_result(self, scan_id: str) -> ScanExecutionResult | None:
        return self._results.get(scan_id)

    def get_graph(self, scan_id: str) -> nx.DiGraph | None:
        return self._graphs.get(scan_id)

    def get_report(self, scan_id: str) -> SecurityReport | None:
        return self._reports.get(scan_id)


@lru_cache
def get_scan_result_repository() -> InMemoryScanResultRepository:
    """Provide a singleton in-memory repository for scan artifacts."""

    return InMemoryScanResultRepository()


# ---------------------------------------------------------------------------
# Security & rate limiting dependencies
# ---------------------------------------------------------------------------

async def api_key_auth(api_key: str = Depends(get_api_key)) -> str:
    """
    Thin wrapper around the core API key dependency.

    This keeps the API layer decoupled from the core security module while
    reusing its logic.
    """

    return api_key


async def rate_limiter_stub() -> None:
    """
    Placeholder rate limiting dependency.

    A concrete implementation can be added later using `RateLimiter` and Redis.
    """

    return None

