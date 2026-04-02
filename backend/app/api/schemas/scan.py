"""
Pydantic schemas for scan-related API endpoints.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl

from ...normalization import CanonicalSeverity
from ...orchestrator import OrchestratorState


class ScanStartRequest(BaseModel):
    """Request payload for starting a new scan."""

    target: HttpUrl = Field(..., description="Target URL or host for the scan.")
    requested_tools: Optional[List[str]] = Field(
        default=None,
        description="Optional list of tool identifiers to use. If omitted, defaults are applied.",
    )


class ScanStartResponse(BaseModel):
    """Response containing the generated scan identifier."""

    scan_id: str = Field(..., description="Identifier of the started scan.")


class ScanStopResponse(BaseModel):
    """Response after requesting a scan to stop."""

    scan_id: str
    status: str


class ScanStatusResponse(BaseModel):
    """High-level status view of a scan."""

    scan_id: str
    orchestrator_state: OrchestratorState
    scan_status: Optional[str] = Field(
        default=None,
        description="Lower-level scan status from the MCP state tracker, if available.",
    )
    phase: Optional[str] = None
    issues_count: int = 0
    tool_status: Optional[dict] = Field(
        default=None,
        description="Per-tool status mapping (tool_id -> status string).",
    )


class VulnerabilityOut(BaseModel):
    """Normalized vulnerability representation for API responses."""

    id: str
    type: str
    severity: CanonicalSeverity
    location: Optional[str]
    source_tool: str
    description: Optional[str]


class ScanResultsResponse(BaseModel):
    """Response model for scan results."""

    scan_id: str
    orchestrator_state: OrchestratorState
    vulnerabilities: List[VulnerabilityOut]


class ScanReportResponse(BaseModel):
    """Wrapper for structured report data (prior to export)."""

    scan_id: str
    report: dict


class GraphNodeOut(BaseModel):
    """Simplified representation of an attack graph node."""

    id: str
    label: str
    type: str


class GraphEdgeOut(BaseModel):
    """Simplified representation of an attack graph edge."""

    source: str
    target: str
    type: str


class ScanGraphResponse(BaseModel):
    """Response model for the attack graph of a scan."""

    scan_id: str
    nodes: List[GraphNodeOut]
    edges: List[GraphEdgeOut]


