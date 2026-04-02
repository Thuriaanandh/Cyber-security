"""
Core models for the attack graph engine.

Defines strongly-typed node and edge representations used by graph builders
and analysis algorithms.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class AttackNodeType(str, Enum):
    """Types of nodes in the attack graph."""

    VULNERABILITY = "vulnerability"
    ENDPOINT = "endpoint"
    AUTH_STATE = "auth_state"
    ASSET = "asset"


@dataclass
class AttackNode:
    """
    Node in the attack graph.

    The `id` is unique within a graph and is used as the NetworkX node key.
    """

    id: str
    type: AttackNodeType
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)


class AttackEdgeType(str, Enum):
    """Types of edges in the attack graph."""

    DEPENDENCY = "dependency"
    PRIV_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass
class AttackEdge:
    """
    Directed edge in the attack graph.

    `source` and `target` refer to node ids.
    """

    source: str
    target: str
    type: AttackEdgeType
    weight: float = 1.0
    description: str | None = None

