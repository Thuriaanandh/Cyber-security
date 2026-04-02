"""
Reasoning engine for exploit chains and impact analysis.

This module contains pure, testable logic that:
- Consumes an attack graph and a set of canonical vulnerabilities.
- Derives potential exploit chains.
- Produces high-level impact analysis and narrative explanations.

No external AI calls are performed here; future AI adapters can invoke these
methods to obtain structured inputs for LLMs or other models.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence

import networkx as nx

from ..graph_engine.models import AttackEdgeType, AttackNode, AttackNodeType
from ..normalization import CanonicalSeverity, CanonicalVulnerability
from .models import ExploitChain, ImpactAnalysis


class ReasoningEngine:
    """
    AI reasoning engine skeleton.

    This class focuses on graph and rule-based reasoning primitives. Its public
    API is stable so that more sophisticated AI-backed implementations can be
    layered on top without changing callers.
    """

    # ------------------------------------------------------------ core methods
    def graph_based_reasoning(
        self,
        graph: nx.DiGraph,
        vulnerabilities: Sequence[CanonicalVulnerability],
    ) -> List[ExploitChain]:
        """
        Derive exploit chains using graph topology only.

        Current stub behavior:
        - For each vulnerability node in the graph, build a trivial chain
          consisting of the single node, with confidence derived from severity.
        - Future versions can:
          - Traverse dependency / privilege escalation / lateral movement edges.
          - Combine vulnerabilities into longer chains based on reachability.
        """

        chains: List[ExploitChain] = []

        severity_to_confidence: Dict[CanonicalSeverity, float] = {
            CanonicalSeverity.CRITICAL: 0.95,
            CanonicalSeverity.HIGH: 0.9,
            CanonicalSeverity.MEDIUM: 0.75,
            CanonicalSeverity.LOW: 0.6,
            CanonicalSeverity.INFO: 0.4,
        }

        vuln_by_id: Dict[str, CanonicalVulnerability] = {v.id: v for v in vulnerabilities}

        for node_id, data in graph.nodes(data=True):
            node: AttackNode | None = data.get("data")
            if node is None or node.type is not AttackNodeType.VULNERABILITY:
                continue

            vuln = vuln_by_id.get(node_id)
            if vuln is None:
                continue

            confidence = severity_to_confidence.get(vuln.severity, 0.5)
            final_impact = self._describe_final_impact(vuln)
            chains.append(
                ExploitChain(
                    entry_point=node_id,
                    chain_nodes=[node_id],
                    final_impact=final_impact,
                    confidence_score=confidence,
                    metadata={"source": "graph_based_reasoning"},
                )
            )

        return chains

    @staticmethod
    def _describe_final_impact(vuln: CanonicalVulnerability) -> str:
        location = vuln.location or "the target"
        vuln_type = (vuln.type or "unknown_issue").lower()

        if vuln_type == "open_port":
            return f"Open service exposure detected at {location}; investigate service hardening and access controls."

        if vuln_type == "host_service_fingerprint":
            return f"Host/service fingerprinting indicates reachable attack surface at {location}; use this as reconnaissance context."

        if vuln_type == "zap_baseline_scan":
            return f"Baseline web scan observation at {location}; no confirmed exploit chain from this signal alone."

        if vuln_type == "sqli_baseline_scan":
            return f"Baseline SQL injection assessment at {location}; no confirmed injectable parameter identified in this pass."

        if "sqli" in vuln_type or "sql_injection" in vuln_type:
            return f"Potential SQL injection impact at {location}; data extraction or authentication bypass may be possible."

        if "xss" in vuln_type:
            return f"Potential XSS impact at {location}; client-side script execution risk for users of this endpoint."

        return f"Potential security impact related to {vuln.type} at {location}."

    def hybrid_reasoning(
        self,
        graph: nx.DiGraph,
        vulnerabilities: Sequence[CanonicalVulnerability],
    ) -> List[ExploitChain]:
        """
        Placeholder for hybrid reasoning strategies.

        Conceptually, this method would:
        - Combine graph-based analysis with additional signals (e.g. historical
          data, AI inferences, business context).
        - Produce richer exploit chains and narrative explanations.

        Current stub behavior simply delegates to `graph_based_reasoning`.
        """

        return self.graph_based_reasoning(graph, vulnerabilities)

    # ---------------------------------------------------------- higher-level API
    def analyze_impact(
        self,
        graph: nx.DiGraph,
        vulnerabilities: Sequence[CanonicalVulnerability],
    ) -> ImpactAnalysis:
        """
        Produce a coarse-grained impact analysis from vulnerabilities and graph.

        Current behavior:
        - Uses the maximum severity among vulnerabilities as overall severity.
        - Uses `graph_based_reasoning` chains as input.
        - Leaves `key_assets_at_risk` and narrative notes relatively simple.
        """

        chains = self.graph_based_reasoning(graph, vulnerabilities)
        overall_severity = self._derive_overall_severity(vulnerabilities)
        key_assets = self._identify_key_assets(graph)

        notes = (
            "Preliminary impact analysis generated using graph-based heuristics. "
            "No external AI reasoning has been applied yet."
        )

        return ImpactAnalysis(
            overall_severity=overall_severity,
            exploit_chains=chains,
            key_assets_at_risk=key_assets,
            notes=notes,
        )

    # ------------------------------------------------------------- helper logic
    @staticmethod
    def _derive_overall_severity(vulnerabilities: Sequence[CanonicalVulnerability]) -> CanonicalSeverity:
        if not vulnerabilities:
            return CanonicalSeverity.INFO

        order = [
            CanonicalSeverity.INFO,
            CanonicalSeverity.LOW,
            CanonicalSeverity.MEDIUM,
            CanonicalSeverity.HIGH,
            CanonicalSeverity.CRITICAL,
        ]
        max_index = 0
        for vuln in vulnerabilities:
            try:
                idx = order.index(vuln.severity)
            except ValueError:
                continue
            if idx > max_index:
                max_index = idx
        return order[max_index]

    @staticmethod
    def _identify_key_assets(graph: nx.DiGraph) -> List[str]:
        """
        Stub for identifying key assets at risk.

        Current behavior:
        - Collects labels of nodes with highest out-degree as a proxy for
          centrality/importance.
        """

        if graph.number_of_nodes() == 0:
            return []

        degrees = {node_id: graph.out_degree(node_id) for node_id in graph.nodes()}
        if not degrees:
            return []

        max_degree = max(degrees.values())
        if max_degree == 0:
            return []

        key_assets: List[str] = []
        for node_id, degree in degrees.items():
            if degree != max_degree:
                continue
            data = graph.nodes[node_id].get("data")
            node: AttackNode | None = data if isinstance(data, AttackNode) else None
            if node is not None:
                key_assets.append(node.label)

        return key_assets

