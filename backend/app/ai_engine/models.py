"""
Models for the AI reasoning and remediation engine.

These models are intentionally framework-agnostic and focus purely on the
domain of exploit reasoning and remediation guidance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import networkx as nx

from ..graph_engine.models import AttackNode
from ..normalization import CanonicalSeverity, CanonicalVulnerability


@dataclass
class ExploitChain:
    """
    Represents a potential exploit chain in the attack graph.

    Fields:
    - entry_point: First node (typically a vulnerability) where an attacker
      gains initial foothold.
    - chain_nodes: Ordered list of node ids representing the exploit path.
    - final_impact: Human-readable description of the end-state impact.
    - confidence_score: Float in [0.0, 1.0] reflecting how plausible the
      chain is according to the reasoning engine.
    """

    entry_point: str
    chain_nodes: List[str]
    final_impact: str
    confidence_score: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ImpactAnalysis:
    """
    High-level impact analysis summary for a set of vulnerabilities.

    This object can be used by reporting and AI explanation components.
    """

    overall_severity: CanonicalSeverity
    exploit_chains: List[ExploitChain]
    key_assets_at_risk: List[str] = field(default_factory=list)
    notes: Optional[str] = None


class Priority(str, Enum):
    """Remediation priority levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RemediationAdvice:
    """
    Structured remediation recommendation for a single vulnerability or group.

    Fields:
    - fix_summary: Short, high-level summary of the fix.
    - technical_steps: Ordered list of concrete technical actions to take.
    - priority: Remediation priority.
    - references: List of reference URLs or identifiers (e.g. CWE, OWASP).
    """

    fix_summary: str
    technical_steps: List[str]
    priority: Priority
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

