"""
Risk scoring utilities for attack graphs.

This module currently contains a simple, extensible stub for assigning risk
scores to nodes in an attack graph. Future versions can incorporate more
advanced algorithms that take into account business impact, exploitability,
and chaining.
"""

from __future__ import annotations

from typing import Dict

import networkx as nx

from .models import AttackNode, AttackNodeType


class RiskRanker:
    """
    Stub implementation of a risk ranking engine.

    The public API is stable and can be used by reporting and AI components,
    while the internal scoring logic can evolve independently.
    """

    def score_graph(self, graph: nx.DiGraph) -> Dict[str, float]:
        """
        Assign a risk score to each node in the graph.

        Current behavior (stub):
        - Vulnerability nodes receive a base score of 1.0, scaled by:
          - Out-degree: more outgoing edges -> higher risk.
        - Other node types receive a base score of 0.5.

        The returned dict maps node ids to float scores in an unbounded range.
        """

        scores: Dict[str, float] = {}
        for node_id, data in graph.nodes(data=True):
            node: AttackNode | None = data.get("data")
            if node is None:
                continue

            base = 1.0 if node.type is AttackNodeType.VULNERABILITY else 0.5
            out_degree = graph.out_degree(node_id)
            scores[node_id] = base * (1.0 + float(out_degree))

        return scores

