"""
JSON exporter for security reports.

Serializes `SecurityReport` instances into JSON strings suitable for API
responses, file storage, or message queues.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from ..report_models import SecurityReport


class JsonReportExporter:
    """Fully implemented JSON exporter."""

    def to_json(self, report: SecurityReport, *, indent: int = 2) -> str:
        """
        Serialize a `SecurityReport` to a JSON string.

        Dataclasses are converted using `asdict`, and non-serializable values
        are stringified via the `default=str` hook.
        """

        as_dict: dict[str, Any] = asdict(report)
        return json.dumps(as_dict, default=str, indent=indent)

