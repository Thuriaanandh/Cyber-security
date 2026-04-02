"""
Repository for scan-related persistence.

Implements asynchronous CRUD-style operations around `ScanRecord` and related
entities without embedding any business logic.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ScanRecord


class ScanRepository:
    """Repository for `ScanRecord` objects."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_scan_result(self, record: ScanRecord) -> None:
        """
        Persist a scan record.

        New instances are added; existing ones are merged.
        """

        self._session.add(record)
        await self._session.commit()

    async def get_scan_result(self, scan_id: str) -> Optional[ScanRecord]:
        """Return the scan record for the given id, if any."""

        stmt = select(ScanRecord).where(ScanRecord.id == scan_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_scan_status(
        self,
        scan_id: str,
        orchestrator_state: Optional[str],
        scan_status: Optional[str],
        phase: Optional[str],
    ) -> None:
        """
        Update high-level status fields for a scan.
        """

        stmt = (
            update(ScanRecord)
            .where(ScanRecord.id == scan_id)
            .values(
                orchestrator_state=orchestrator_state,
                scan_status=scan_status,
                phase=phase,
            )
        )
        await self._session.execute(stmt)
        await self._session.commit()

    async def list_scans(self, limit: int = 50, offset: int = 0) -> List[ScanRecord]:
        """
        List scans in reverse chronological order.
        """

        stmt = (
            select(ScanRecord)
            .order_by(ScanRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        records: Sequence[ScanRecord] = result.scalars().all()
        return list(records)

