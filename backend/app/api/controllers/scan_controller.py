"""
Scan controller.

Contains orchestration logic for handling scan-related API use cases. HTTP
routes delegate to this controller so that API handlers remain thin and free
of business logic.
"""

from __future__ import annotations

from typing import Iterable, List, Optional
from uuid import uuid4

import networkx as nx

from ...ai_engine import ReasoningEngine, RemediationEngine
from ...graph_engine import AttackGraphBuilder
from ...normalization import CanonicalSeverity, CanonicalVulnerability, ResultNormalizer
from ...orchestrator import OrchestratorState, ScanExecutionResult, ScanOrchestrator
from ...reports import ReportBuilder, SecurityReport
from ..dependencies import InMemoryScanResultRepository


class ScanController:
    """
    Application-facing controller for scan operations.

    Depends on orchestrator, normalization, graph, AI, and reporting services,
    injected via the constructor to support clean architecture.
    """

    def __init__(
        self,
        orchestrator: ScanOrchestrator,
        normalizer: ResultNormalizer,
        graph_builder: AttackGraphBuilder,
        reasoning_engine: ReasoningEngine,
        remediation_engine: RemediationEngine,
        report_builder: ReportBuilder,
        result_repository: InMemoryScanResultRepository,
    ) -> None:
        self._orchestrator = orchestrator
        self._normalizer = normalizer
        self._graph_builder = graph_builder
        self._reasoning_engine = reasoning_engine
        self._remediation_engine = remediation_engine
        self._report_builder = report_builder
        self._repo = result_repository

    # ----------------------------------------------------------------- lifecycle
    @staticmethod
    def generate_scan_id() -> str:
        """Generate a new scan identifier."""

        return str(uuid4())

    async def run_scan_pipeline(self, scan_id: str, target: str, requested_tools: Iterable[str] | None) -> None:
        """
        Execute the full scan pipeline for a given scan id.

        This method is intended to be invoked from a background task by the
        HTTP layer. It:
        - Runs the scan orchestrator.
        - Normalizes tool results into canonical vulnerabilities (stub usage).
        - Builds an attack graph.
        - Performs reasoning and remediation analysis.
        - Constructs a structured `SecurityReport`.
        - Persists artifacts in the in-memory repository.
        """

        requested_tools_list = list(requested_tools or [])

        # 1) Run orchestrator to perform scanning.
        scan_result: ScanExecutionResult = await self._orchestrator.run_scan(
            scan_id=scan_id,
            target=target,
            requested_tools=requested_tools_list,
        )
        self._repo.save_execution_result(scan_id, scan_result)

        # 2) Build canonical vulnerabilities from issues persisted in scan context.
        severity_map = {
            "info": CanonicalSeverity.INFO,
            "low": CanonicalSeverity.LOW,
            "medium": CanonicalSeverity.MEDIUM,
            "moderate": CanonicalSeverity.MEDIUM,
            "high": CanonicalSeverity.HIGH,
            "critical": CanonicalSeverity.CRITICAL,
        }

        canonical_vulns: List[CanonicalVulnerability] = []
        for idx, issue in enumerate(scan_result.issues):
            raw_severity = str(issue.severity or "medium").lower()
            severity = severity_map.get(raw_severity, CanonicalSeverity.MEDIUM)

            canonical_vulns.append(
                CanonicalVulnerability(
                    id=issue.id or f"issue-{idx}",
                    type=issue.type or "generic_issue",
                    severity=severity,
                    confidence=0.8,
                    location=issue.location,
                    evidence=issue.evidence or {},
                    source_tool=str((issue.evidence or {}).get("source_tool") or "unknown"),
                    description=issue.description,
                )
            )

        # 3) Build attack graph from normalized vulnerabilities.
        graph: nx.DiGraph = self._graph_builder.build_graph(canonical_vulns)
        self._repo.save_graph(scan_id, graph)

        # 4) Run reasoning engine to derive exploit chains and impact analysis.
        exploit_chains = self._reasoning_engine.graph_based_reasoning(graph, canonical_vulns)
        impact = self._reasoning_engine.analyze_impact(graph, canonical_vulns)

        # 5) Generate remediation advice.
        remediation_map = self._remediation_engine.get_bulk_remediation(canonical_vulns)

        # 6) Build final structured report.
        report: SecurityReport = self._report_builder.build_report(
            scan_result=scan_result,
            impact=impact,
            vulnerabilities=canonical_vulns,
            exploit_chains=exploit_chains,
            remediation_map=remediation_map,
        )
        self._repo.save_report(scan_id, report)

    # ------------------------------------------------------------------ queries
    def get_execution_result(self, scan_id: str) -> Optional[ScanExecutionResult]:
        """Return stored execution result for a scan, if available."""

        return self._repo.get_execution_result(scan_id)

    def get_graph(self, scan_id: str) -> Optional[nx.DiGraph]:
        """Return stored attack graph for a scan, if available."""

        return self._repo.get_graph(scan_id)

    def get_report(self, scan_id: str) -> Optional[SecurityReport]:
        """Return stored security report for a scan, if available."""

        return self._repo.get_report(scan_id)

