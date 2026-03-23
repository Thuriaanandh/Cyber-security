"""
ORM models for the persistent storage layer.

These models capture scans, tool executions, vulnerabilities, attack graphs,
and reports.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


class ScanRecord(Base):
    """Represents a single scan run."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    orchestrator_state: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    scan_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    phase: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=datetime.utcnow, onupdate=datetime.utcnow)

    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)

    tool_executions: Mapped[List["ToolExecutionRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    vulnerabilities: Mapped[List["VulnerabilityRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    graph_nodes: Mapped[List["GraphNodeRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    graph_edges: Mapped[List["GraphEdgeRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    reports: Mapped[List["ReportRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
    )


class ToolExecutionRecord(Base):
    """Represents a single tool execution within a scan."""

    __tablename__ = "tool_executions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    tool_id: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime]
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_reference_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    raw_output: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    normalized_output: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    scan: Mapped["ScanRecord"] = relationship(back_populates="tool_executions")


class VulnerabilityRecord(Base):
    """Normalized vulnerability associated with a scan."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    vuln_id: Mapped[str] = mapped_column(String(128), index=True)
    type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float]
    location: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    source_tool: Mapped[str] = mapped_column(String(64))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)

    scan: Mapped["ScanRecord"] = relationship(back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vulnerabilities_scan_vuln", "scan_id", "vuln_id"),
    )


class GraphNodeRecord(Base):
    """Node in the persisted attack graph for a scan."""

    __tablename__ = "graph_nodes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    node_id: Mapped[str] = mapped_column(String(128), index=True)
    label: Mapped[str] = mapped_column(String(256))
    type: Mapped[str] = mapped_column(String(64))
    attributes: Mapped[Dict[str, Any]] = mapped_column(JSONB, default=dict)

    scan: Mapped["ScanRecord"] = relationship(back_populates="graph_nodes")


class GraphEdgeRecord(Base):
    """Edge in the persisted attack graph for a scan."""

    __tablename__ = "graph_edges"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    source_node_id: Mapped[str] = mapped_column(String(128))
    target_node_id: Mapped[str] = mapped_column(String(128))
    type: Mapped[str] = mapped_column(String(64))
    weight: Mapped[float] = mapped_column(default=1.0)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped["ScanRecord"] = relationship(back_populates="graph_edges")


class ReportRecord(Base):
    """Stored representation of a generated report for a scan."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    report_json: Mapped[Dict[str, Any]] = mapped_column(JSONB)

    scan: Mapped["ScanRecord"] = mapped_column(  # type: ignore[assignment]
        relationship(back_populates="reports")
    )

