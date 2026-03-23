"""
Repository for attack graph persistence.

Provides methods to store and retrieve graph nodes and edges for a given scan.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import GraphEdgeRecord, GraphNodeRecord


class GraphRepository:
    """Repository for `GraphNodeRecord` and `GraphEdgeRecord`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_graph(
        self,
        scan_id: str,
        nodes: List[GraphNodeRecord],
        edges: List[GraphEdgeRecord],
    ) -> None:
        """
        Persist the graph for a scan.

        Existing nodes and edges for the scan are removed before inserting the
        provided collections.
        """

        # Remove existing graph data for this scan
        await self._session.execute(delete(GraphEdgeRecord).where(GraphEdgeRecord.scan_id == scan_id))
        await self._session.execute(delete(GraphNodeRecord).where(GraphNodeRecord.scan_id == scan_id))

        for node in nodes:
            node.scan_id = scan_id
            self._session.add(node)
        for edge in edges:
            edge.scan_id = scan_id
            self._session.add(edge)

        await self._session.commit()

    async def load_graph(self, scan_id: str) -> Tuple[List[GraphNodeRecord], List[GraphEdgeRecord]]:
        """
        Load graph nodes and edges associated with a scan id.
        """

        node_stmt = select(GraphNodeRecord).where(GraphNodeRecord.scan_id == scan_id)
        edge_stmt = select(GraphEdgeRecord).where(GraphEdgeRecord.scan_id == scan_id)

        node_result = await self._session.execute(node_stmt)
        edge_result = await self._session.execute(edge_stmt)

        nodes_seq: Sequence[GraphNodeRecord] = node_result.scalars().all()
        edges_seq: Sequence[GraphEdgeRecord] = edge_result.scalars().all()

        return list(nodes_seq), list(edges_seq)

