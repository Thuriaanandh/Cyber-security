"""
Repository for report persistence.

Handles storage and retrieval of `ReportRecord` instances.
"""

from __future__ import annotations

from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ReportRecord


class ReportRepository:
    """Repository for `ReportRecord` objects."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_report(self, record: ReportRecord) -> None:
        """
        Persist a report record for a scan.

        Multiple reports per scan are allowed; callers can decide on retention
        strategies.
        """

        self._session.add(record)
        await self._session.commit()

    async def load_report(self, scan_id: str) -> Optional[ReportRecord]:
        """
        Load the most recent report for the given scan id, if any.
        """

        stmt = (
            select(ReportRecord)
            .where(ReportRecord.scan_id == scan_id)
            .order_by(ReportRecord.created_at.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

