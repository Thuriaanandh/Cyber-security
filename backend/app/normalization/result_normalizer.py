"""
Result normalization for security tool executions.

This module transforms `ToolExecutionResult` instances from different tools
into a canonical vulnerability representation that downstream components
(attack graph engine, AI reasoning, reporting) can consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence

from ..mcp.tool_registry import ToolExecutionResult, ToolType


class CanonicalSeverity(str, Enum):
    """Severity levels used across all tools."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CanonicalVulnerability:
    """
    Canonical vulnerability schema used across the system.

    Fields:
    - id: Unique identifier within the scope of a scan.
    - type: Short, machine-friendly classification (e.g. "sqli", "xss").
    - severity: Normalized severity level.
    - confidence: Confidence score in the range [0.0, 1.0].
    - location: Target-specific location (URL, parameter name, endpoint, etc.).
    - evidence: Opaque dictionary with raw evidence details.
    - source_tool: Identifier of the tool that reported this issue.
    """

    id: str
    type: str
    severity: CanonicalSeverity
    confidence: float
    location: Optional[str]
    evidence: Dict[str, Any]
    source_tool: str
    description: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ToolResultMapper(Protocol):
    """
    Strategy interface for mapping a single tool's results.

    Implementations are responsible for understanding tool-specific output
    structures and translating them into canonical vulnerabilities.
    """

    def supports(self, result: ToolExecutionResult) -> bool:
        """Return True if this mapper can normalize the given result."""

        ...

    def map(self, result: ToolExecutionResult) -> List[CanonicalVulnerability]:
        """Transform a tool execution result into canonical vulnerabilities."""

        ...


class _BaseJsonIssuesMapper:
    """
    Convenience base class for tools that already expose an `issues` list in
    `normalized_output`.

    Expected structure:
    - `normalized_output["issues"]` is a list of dicts; each contains any
      subset of the canonical fields. Missing fields are filled with defaults.
    """

    def _map_from_issues_array(
        self,
        result: ToolExecutionResult,
        default_type: str,
    ) -> List[CanonicalVulnerability]:
        issues_payload = (result.normalized_output or {}).get("issues", [])
        canonical: List[CanonicalVulnerability] = []

        for idx, raw in enumerate(issues_payload):
            issue_id = str(raw.get("id") or f"{result.tool_id}-{idx}")
            vuln = CanonicalVulnerability(
                id=issue_id,
                type=str(raw.get("type") or default_type),
                severity=self._normalize_severity(str(raw.get("severity", CanonicalSeverity.MEDIUM.value))),
                confidence=float(raw.get("confidence", 0.8)),
                location=raw.get("location"),
                evidence=dict(raw.get("evidence") or {}),
                source_tool=result.tool_id,
                description=raw.get("description"),
                metadata={k: v for k, v in raw.items() if k not in {"id", "type", "severity", "confidence", "location", "evidence", "description"}},
            )
            canonical.append(vuln)

        return canonical

    @staticmethod
    def _normalize_severity(raw: str) -> CanonicalSeverity:
        value = raw.lower()
        mapping = {
            "info": CanonicalSeverity.INFO,
            "low": CanonicalSeverity.LOW,
            "medium": CanonicalSeverity.MEDIUM,
            "moderate": CanonicalSeverity.MEDIUM,
            "high": CanonicalSeverity.HIGH,
            "critical": CanonicalSeverity.CRITICAL,
        }
        return mapping.get(value, CanonicalSeverity.MEDIUM)


class ZAPResultMapper(_BaseJsonIssuesMapper, ToolResultMapper):
    """Normalization strategy for OWASP ZAP results."""

    def supports(self, result: ToolExecutionResult) -> bool:
        return result.tool_id == "zap" or getattr(result, "tool_type", None) == ToolType.ZAP  # type: ignore[comparison-overlap]

    def map(self, result: ToolExecutionResult) -> List[CanonicalVulnerability]:
        return self._map_from_issues_array(result, default_type="web_vuln")


class SQLMapResultMapper(_BaseJsonIssuesMapper, ToolResultMapper):
    """Normalization strategy for SQLMap results."""

    def supports(self, result: ToolExecutionResult) -> bool:
        return result.tool_id == "sqlmap" or getattr(result, "tool_type", None) == ToolType.SQLMAP  # type: ignore[comparison-overlap]

    def map(self, result: ToolExecutionResult) -> List[CanonicalVulnerability]:
        return self._map_from_issues_array(result, default_type="sqli")


class NmapResultMapper(_BaseJsonIssuesMapper, ToolResultMapper):
    """Normalization strategy for Nmap results."""

    def supports(self, result: ToolExecutionResult) -> bool:
        return result.tool_id == "nmap" or getattr(result, "tool_type", None) == ToolType.NMAP  # type: ignore[comparison-overlap]

    def map(self, result: ToolExecutionResult) -> List[CanonicalVulnerability]:
        return self._map_from_issues_array(result, default_type="network_exposure")


class DefaultResultMapper(_BaseJsonIssuesMapper, ToolResultMapper):
    """
    Fallback normalization strategy for tools without a dedicated mapper.

    It attempts to interpret `normalized_output["issues"]` if present; if not,
    it returns an empty list.
    """

    def supports(self, result: ToolExecutionResult) -> bool:
        return True

    def map(self, result: ToolExecutionResult) -> List[CanonicalVulnerability]:
        return self._map_from_issues_array(result, default_type="generic_issue")


class ResultNormalizer:
    """
    Entry point for normalizing tool execution results.

    This component is designed to be:
    - Fully independent of orchestrator and transport concerns.
    - Extensible via dependency injection of additional `ToolResultMapper`
      implementations.
    """

    def __init__(self, mappers: Optional[Sequence[ToolResultMapper]] = None) -> None:
        if mappers is not None and len(mappers) > 0:
            self._mappers: Sequence[ToolResultMapper] = tuple(mappers)
        else:
            self._mappers = (
                ZAPResultMapper(),
                SQLMapResultMapper(),
                NmapResultMapper(),
                DefaultResultMapper(),
            )

    def normalize(self, result: ToolExecutionResult) -> List[CanonicalVulnerability]:
        """Normalize a single tool execution result."""

        mapper = next((m for m in self._mappers if m.supports(result)), DefaultResultMapper())
        return mapper.map(result)

    def normalize_many(self, results: Iterable[ToolExecutionResult]) -> List[CanonicalVulnerability]:
        """Normalize multiple tool execution results."""

        normalized: List[CanonicalVulnerability] = []
        for result in results:
            normalized.extend(self.normalize(result))
        return normalized

