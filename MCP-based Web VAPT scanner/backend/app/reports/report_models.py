"""
Models for structured security reports.

These dataclasses are transport-agnostic and can be serialized to JSON, HTML,
or PDF by dedicated exporter components.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..ai_engine.models import ExploitChain, RemediationAdvice
from ..normalization import CanonicalSeverity


@dataclass
class ReportScanMetadata:
    """Metadata describing a particular scan run."""

    scan_id: str
    target: Optional[str]
    started_at: Optional[str]
    finished_at: Optional[str]
    orchestrator_state: str
    tool_ids: List[str] = field(default_factory=list)
    additional: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportVulnerabilityRow:
    """Row in the vulnerabilities section of a report."""

    vulnerability_id: str
    type: str
    severity: CanonicalSeverity
    location: Optional[str]
    source_tool: str
    description: Optional[str]


@dataclass
class ReportExploitPath:
    """Representation of an exploit chain for reporting purposes."""

    entry_point: str
    chain_nodes: List[str]
    final_impact: str
    confidence_score: float


@dataclass
class ReportRemediationItem:
    """Single item in the remediation plan, linked to a vulnerability."""

    vulnerability_id: str
    fix_summary: str
    technical_steps: List[str]
    priority: str
    references: List[str] = field(default_factory=list)


@dataclass
class SecurityReport:
    """
    Top-level security report object.

    This structure is the canonical data model consumed by exporter modules.
    """

    executive_summary: str
    technical_summary: str
    risk_score: float
    vulnerability_table: List[ReportVulnerabilityRow]
    exploit_paths: List[ReportExploitPath]
    remediation_plan: List[ReportRemediationItem]
    scan_metadata: ReportScanMetadata

