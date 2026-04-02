"""
Report builder.

Consumes execution and analysis artifacts to produce a structured `SecurityReport`
that can be formatted by exporter modules.
"""

from __future__ import annotations

from dataclasses import asdict
from math import log10
from typing import Callable, Dict, Iterable, List, Mapping, Optional

from ..ai_engine.models import ExploitChain, ImpactAnalysis, RemediationAdvice
from ..normalization import CanonicalSeverity, CanonicalVulnerability
from ..orchestrator.models import ScanExecutionResult
from .report_models import (
    ReportExploitPath,
    ReportRemediationItem,
    ReportScanMetadata,
    ReportVulnerabilityRow,
    SecurityReport,
)


RiskScorer = Callable[[ImpactAnalysis, int], float]


def default_risk_scorer(impact: ImpactAnalysis, issue_count: int) -> float:
    """
    Simple default risk scoring function.

    Heuristic:
    - Map overall severity to a base weight.
    - Scale by a logarithmic factor of the number of issues.
    """

    severity_weight_map: Dict[CanonicalSeverity, float] = {
        CanonicalSeverity.INFO: 0.1,
        CanonicalSeverity.LOW: 0.3,
        CanonicalSeverity.MEDIUM: 0.6,
        CanonicalSeverity.HIGH: 0.8,
        CanonicalSeverity.CRITICAL: 1.0,
    }
    base = severity_weight_map.get(impact.overall_severity, 0.5)
    factor = 1.0 + log10(max(issue_count, 1))
    return base * factor


class ReportBuilder:
    """
    Builds `SecurityReport` instances from scan results and AI analysis.

    All inputs are provided as arguments to keep this component pure and easy
    to test. Risk scoring can be customized via dependency injection.
    """

    def __init__(self, risk_scorer: RiskScorer | None = None) -> None:
        self._risk_scorer = risk_scorer or default_risk_scorer

    def build_report(
        self,
        scan_result: ScanExecutionResult,
        impact: ImpactAnalysis,
        vulnerabilities: Iterable[CanonicalVulnerability],
        exploit_chains: Iterable[ExploitChain],
        remediation_map: Mapping[str, RemediationAdvice],
    ) -> SecurityReport:
        """
        Construct a `SecurityReport` from the given inputs.

        The builder does not perform any formatting; it only organizes data.
        """

        vuln_list = list(vulnerabilities)
        chains_list = list(exploit_chains)

        scan_metadata = self._build_scan_metadata(scan_result)
        vulnerability_table = self._build_vulnerability_table(vuln_list)
        report_exploit_paths = self._build_exploit_paths(chains_list)
        remediation_plan = self._build_remediation_plan(vuln_list, remediation_map)
        risk_score = self._risk_scorer(impact, len(vuln_list))

        executive_summary = self._build_executive_summary(impact, len(vuln_list))
        technical_summary = self._build_technical_summary(impact, vuln_list, chains_list)

        return SecurityReport(
            executive_summary=executive_summary,
            technical_summary=technical_summary,
            risk_score=risk_score,
            vulnerability_table=vulnerability_table,
            exploit_paths=report_exploit_paths,
            remediation_plan=remediation_plan,
            scan_metadata=scan_metadata,
        )

    # ----------------------------------------------------------------- builders
    @staticmethod
    def _build_scan_metadata(scan_result: ScanExecutionResult) -> ReportScanMetadata:
        ctx = scan_result.scan_context
        target = ctx.target if ctx is not None else None

        started_at: Optional[str] = None
        finished_at: Optional[str] = None
        tool_ids: List[str] = []

        if ctx is not None and ctx.tool_runs:
            started_at = min(run.started_at.isoformat() for run in ctx.tool_runs)
            finished_at = max(run.finished_at.isoformat() for run in ctx.tool_runs)
            tool_ids = [run.tool_id for run in ctx.tool_runs]

        additional: Dict[str, object] = {}
        if ctx is not None:
            additional = ctx.metadata.copy()

        return ReportScanMetadata(
            scan_id=scan_result.scan_id,
            target=target,
            started_at=started_at,
            finished_at=finished_at,
            orchestrator_state=scan_result.orchestrator_state.value,
            tool_ids=tool_ids,
            additional=additional,
        )

    @staticmethod
    def _build_vulnerability_table(
        vulnerabilities: Iterable[CanonicalVulnerability],
    ) -> List[ReportVulnerabilityRow]:
        rows: List[ReportVulnerabilityRow] = []
        for vuln in vulnerabilities:
            rows.append(
                ReportVulnerabilityRow(
                    vulnerability_id=vuln.id,
                    type=vuln.type,
                    severity=vuln.severity,
                    location=vuln.location,
                    source_tool=vuln.source_tool,
                    description=vuln.description,
                )
            )
        return rows

    @staticmethod
    def _build_exploit_paths(
        exploit_chains: Iterable[ExploitChain],
    ) -> List[ReportExploitPath]:
        paths: List[ReportExploitPath] = []
        for chain in exploit_chains:
            paths.append(
                ReportExploitPath(
                    entry_point=chain.entry_point,
                    chain_nodes=list(chain.chain_nodes),
                    final_impact=chain.final_impact,
                    confidence_score=chain.confidence_score,
                )
            )
        return paths

    @staticmethod
    def _build_remediation_plan(
        vulnerabilities: Iterable[CanonicalVulnerability],
        remediation_map: Mapping[str, RemediationAdvice],
    ) -> List[ReportRemediationItem]:
        items: List[ReportRemediationItem] = []

        for vuln in vulnerabilities:
            advice = remediation_map.get(vuln.id)
            if advice is None:
                # If advice is missing for this vulnerability, skip it;
                # callers are encouraged to use RemediationEngine.get_bulk_remediation.
                continue
            items.append(
                ReportRemediationItem(
                    vulnerability_id=vuln.id,
                    fix_summary=advice.fix_summary,
                    technical_steps=list(advice.technical_steps),
                    priority=advice.priority.value,
                    references=list(advice.references),
                )
            )

        return items

    @staticmethod
    def _build_executive_summary(impact: ImpactAnalysis, issue_count: int) -> str:
        return (
            f"The scan identified {issue_count} security issue(s) with an overall "
            f"severity of {impact.overall_severity.value.upper()}."
        )

    @staticmethod
    def _build_technical_summary(
        impact: ImpactAnalysis,
        vulnerabilities: Iterable[CanonicalVulnerability],
        exploit_chains: Iterable[ExploitChain],
    ) -> str:
        vuln_count = len(list(vulnerabilities))
        chain_count = len(list(exploit_chains))
        return (
            f"Technical analysis recorded {vuln_count} normalized vulnerabilities and "
            f"{chain_count} potential exploit chain(s). Impact notes: "
            f"{impact.notes or 'No additional notes provided.'}"
        )

