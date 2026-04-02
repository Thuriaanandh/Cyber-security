"""
Attack graph builder — fixed to produce proper edges.

Architecture:
  TARGET root → HOST nodes → SERVICE nodes → VULNERABILITY nodes
  Plus severity-escalation and same-tool chain edges between vulns.
"""
from __future__ import annotations
from typing import List, Sequence
import networkx as nx
from ..normalization import CanonicalVulnerability
from .models import AttackEdge, AttackEdgeType, AttackNode, AttackNodeType


class AttackGraphBuilder:
    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()

    @property
    def graph(self) -> nx.DiGraph:
        return self._graph

    def build_graph(self, issues: Sequence[CanonicalVulnerability]) -> nx.DiGraph:
        self._graph.clear()
        if not issues:
            return self._graph

        sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

        # ── collect hosts and services ────────────────────────────────────────
        hosts: set[str] = set()
        services: dict[str, str] = {}  # "host:port" -> service_name
        for vuln in issues:
            loc = vuln.location or ""
            if ":" in loc:
                host = loc.rsplit(":", 1)[0]
                hosts.add(host)
                svc = str((vuln.evidence or {}).get("service") or loc.rsplit(":", 1)[1])
                services[loc] = svc
            elif loc:
                hosts.add(loc)

        if not hosts:
            hosts.add("target")

        # pick cleanest domain as target
        target_host = sorted(hosts, key=lambda h: (h.count(".") == 0, len(h)))[0]

        # ── TARGET node ───────────────────────────────────────────────────────
        target_id = f"target::{target_host}"
        self._graph.add_node(target_id, data=AttackNode(
            id=target_id, type=AttackNodeType.ASSET,
            label=target_host, attributes={"role": "target"}))

        # ── HOST nodes ────────────────────────────────────────────────────────
        host_ids: dict[str, str] = {}
        for host in hosts:
            hid = f"host::{host}"
            host_ids[host] = hid
            self._graph.add_node(hid, data=AttackNode(
                id=hid, type=AttackNodeType.ASSET,
                label=host, attributes={"role": "host"}))
            self._graph.add_edge(target_id, hid, data=AttackEdge(
                source=target_id, target=hid,
                type=AttackEdgeType.DEPENDENCY, description="Reachability"))

        # ── SERVICE nodes ─────────────────────────────────────────────────────
        svc_ids: dict[str, str] = {}
        for loc, svc_name in services.items():
            sid = f"svc::{loc}"
            svc_ids[loc] = sid
            host = loc.rsplit(":", 1)[0]
            self._graph.add_node(sid, data=AttackNode(
                id=sid, type=AttackNodeType.ENDPOINT,
                label=f"{svc_name} ({loc})", attributes={"role": "service", "location": loc}))
            hid = host_ids.get(host) or host_ids.get(target_host)
            if hid:
                self._graph.add_edge(hid, sid, data=AttackEdge(
                    source=hid, target=sid,
                    type=AttackEdgeType.DEPENDENCY, description=f"Exposed {svc_name}"))

        # ── VULNERABILITY nodes ───────────────────────────────────────────────
        vuln_nodes: List[AttackNode] = []
        for vuln in issues:
            node = AttackNode(
                id=vuln.id, type=AttackNodeType.VULNERABILITY,
                label=f"{vuln.type.upper()} ({vuln.severity.value})",
                attributes={
                    "severity": vuln.severity.value,
                    "confidence": vuln.confidence,
                    "location": vuln.location,
                    "source_tool": vuln.source_tool,
                    "description": vuln.description,
                    "sev_rank": sev_order.get(str(vuln.severity.value).lower(), 1),
                })
            vuln_nodes.append(node)
            self._graph.add_node(node.id, data=node)

            loc = vuln.location or ""
            if loc in svc_ids:
                parent = svc_ids[loc]
            else:
                host = loc.rsplit(":", 1)[0] if ":" in loc else loc
                parent = host_ids.get(host) or host_ids.get(target_host)

            if parent:
                self._graph.add_edge(parent, node.id, data=AttackEdge(
                    source=parent, target=node.id,
                    type=AttackEdgeType.DEPENDENCY, description=f"Finding on {loc or 'host'}"))

        # ── severity escalation chain ─────────────────────────────────────────
        sorted_v = sorted(vuln_nodes, key=lambda n: n.attributes.get("sev_rank", 1), reverse=True)
        for i in range(len(sorted_v) - 1):
            a, b = sorted_v[i], sorted_v[i + 1]
            if a.attributes.get("sev_rank", 1) > b.attributes.get("sev_rank", 1):
                if not self._graph.has_edge(a.id, b.id):
                    self._graph.add_edge(a.id, b.id, data=AttackEdge(
                        source=a.id, target=b.id,
                        type=AttackEdgeType.PRIV_ESCALATION,
                        description="Severity-based attack progression"))

        # ── same-tool lateral chain ───────────────────────────────────────────
        by_tool: dict[str, list[AttackNode]] = {}
        for node in vuln_nodes:
            t = str(node.attributes.get("source_tool") or "unknown")
            by_tool.setdefault(t, []).append(node)
        for tool, group in by_tool.items():
            for i in range(len(group) - 1):
                a, b = group[i], group[i + 1]
                if not self._graph.has_edge(a.id, b.id):
                    self._graph.add_edge(a.id, b.id, data=AttackEdge(
                        source=a.id, target=b.id,
                        type=AttackEdgeType.LATERAL_MOVEMENT,
                        description=f"Same-tool chain ({tool})"))

        return self._graph

    def compute_shortest_exploit_path(self, source_id: str, target_id: str) -> list[str]:
        try:
            return nx.shortest_path(self._graph, source=source_id, target=target_id, weight="weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
