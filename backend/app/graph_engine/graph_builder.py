"""
Attack graph builder.

Responsible for constructing a directed attack graph from normalized
vulnerability data. The resulting graph can then be analyzed by risk ranking
and path-finding algorithms.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence

import networkx as nx

from ..normalization import CanonicalVulnerability
from .models import AttackEdge, AttackEdgeType, AttackNode, AttackNodeType


class AttackGraphBuilder:
    """
    Builder for directed attack graphs.

    This class is intentionally decoupled from orchestrator and AI concerns.
    It operates purely on normalized vulnerability inputs and produces a
    `networkx.DiGraph` annotated with `AttackNode` and `AttackEdge` metadata.
    """

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()

    @property
    def graph(self) -> nx.DiGraph:
        """Expose the underlying NetworkX graph."""

        return self._graph

    # ------------------------------------------------------------------ building
    def build_graph(self, issues: Sequence[CanonicalVulnerability]) -> nx.DiGraph:
        """
        Build and return an attack graph for the given normalized issues.

        Current behavior:
        - Adds one `VULNERABILITY` node per canonical vulnerability.
        - Adds simple dependency edges between vulnerabilities that share the
          same location (stub logic, to be refined).
        - Leaves space for privilege escalation and lateral movement edges,
          which can be populated when more context is available (auth states,
          user roles, network topology, etc.).
        """

        self._graph.clear()

        vulnerability_nodes: List[AttackNode] = []
        for vuln in issues:
            node = AttackNode(
                id=vuln.id,
                type=AttackNodeType.VULNERABILITY,
                label=f"{vuln.type.upper()} ({vuln.severity.value})",
                attributes={
                    "severity": vuln.severity.value,
                    "confidence": vuln.confidence,
                    "location": vuln.location,
                    "source_tool": vuln.source_tool,
                    "description": vuln.description,
                }
                | vuln.metadata,
            )
            vulnerability_nodes.append(node)
            self._graph.add_node(node.id, data=node)

        # Dependency edges (stub heuristic: same location implies dependency)
        dependency_edges = self._infer_dependency_edges(vulnerability_nodes)
        for edge in dependency_edges:
            self._graph.add_edge(edge.source, edge.target, data=edge)

        # Placeholders for additional edge types
        priv_edges = self._infer_privilege_escalation_edges(vulnerability_nodes)
        for edge in priv_edges:
            self._graph.add_edge(edge.source, edge.target, data=edge)

        lateral_edges = self._infer_lateral_movement_edges(vulnerability_nodes)
        for edge in lateral_edges:
            self._graph.add_edge(edge.source, edge.target, data=edge)

        return self._graph

    def _infer_dependency_edges(self, nodes: Sequence[AttackNode]) -> List[AttackEdge]:
        """
        Stub for dependency edge inference.

        Current heuristic:
        - If two vulnerability nodes share the same `location`, create a
          bidirectional dependency between them. This approximates that
          exploiting one may enable or influence exploitation of the other.
        """

        edges: List[AttackEdge] = []
        by_location: dict[str | None, list[AttackNode]] = {}
        for node in nodes:
            location = node.attributes.get("location")
            by_location.setdefault(location, []).append(node)

        for location, group in by_location.items():
            if not location or len(group) < 2:
                continue
            for i in range(len(group)):
                for j in range(i + 1, len(group)):
                    a = group[i]
                    b = group[j]
                    edges.append(
                        AttackEdge(
                            source=a.id,
                            target=b.id,
                            type=AttackEdgeType.DEPENDENCY,
                            description=f"Shared location dependency at {location}",
                        )
                    )
                    edges.append(
                        AttackEdge(
                            source=b.id,
                            target=a.id,
                            type=AttackEdgeType.DEPENDENCY,
                            description=f"Shared location dependency at {location}",
                        )
                    )

        return edges

    def _infer_privilege_escalation_edges(self, nodes: Sequence[AttackNode]) -> List[AttackEdge]:
        """
        Stub for privilege escalation edge inference.

        Future logic may use:
        - Vulnerabilities tagged with auth/role information.
        - Known privilege levels from metadata (e.g. `attributes["priv_level"]`).
        - Mappings between authentication states and endpoints.
        """

        return []

    def _infer_lateral_movement_edges(self, nodes: Sequence[AttackNode]) -> List[AttackEdge]:
        """
        Stub for lateral movement edge inference.

        Future logic may use:
        - Network topology information from Nmap output.
        - Relationships between assets (e.g. databases, application servers).
        - Shared credentials or tokens found in vulnerabilities.
        """

        return []

    # ------------------------------------------------------------ path analysis
    def compute_shortest_exploit_path(self, source_id: str, target_id: str) -> list[str]:
        """
        Compute the shortest exploit path between two nodes.

        This is a stub implementation that relies on NetworkX's standard
        shortest path algorithm. Future enhancements may:
        - Use edge weights derived from risk scores.
        - Restrict paths to certain edge types.
        """

        try:
            path: list[str] = nx.shortest_path(self._graph, source=source_id, target=target_id, weight="weight")
            return path
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

