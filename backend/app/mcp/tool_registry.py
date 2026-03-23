"""
Tool registry for the MCP orchestration layer.

This module defines:
- A strongly-typed description of tools (metadata and execution results).
- A registry responsible for storing and resolving tool adapters.

It deliberately has no knowledge of FastAPI, Celery, or concrete tools such as
OWASP ZAP / SQLMap / Nmap, making it straightforward to unit test and reuse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Protocol


class ToolType(str, Enum):
    """High-level classification of security and analysis tools."""

    ZAP = "zap"
    SQLMAP = "sqlmap"
    NMAP = "nmap"
    AI_REASONER = "ai_reasoner"
    ATTACK_GRAPH = "attack_graph"
    CUSTOM = "custom"


class ToolExecutionStatus(str, Enum):
    """Execution status of a tool invocation."""

    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ToolMetadata:
    """
    Static metadata describing a tool.

    The MCP orchestrator can use this to decide which tools to run and how to
    sequence them without needing to know details of their implementation.
    """

    id: str
    name: str
    type: ToolType
    version: str
    description: str
    supported_vulnerability_types: tuple[str, ...] = field(default_factory=tuple)
    supports_async: bool = True
    default_timeout_seconds: int = 600


@dataclass
class ToolExecutionResult:
    """
    Result of executing a tool for a given scan.

    Raw output is intentionally stored as `Any` to allow for tool-specific
    structures (e.g. ZAP JSON, SQLMap text logs) while still providing a place
    for pre-normalized data.
    """

    tool_id: str
    scan_id: str
    status: ToolExecutionStatus
    started_at: datetime
    finished_at: datetime
    raw_output: Any
    normalized_output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class ToolAdapter(Protocol):
    """
    Adapter interface that concrete tool implementations must satisfy.

    Adapters wrap the actual execution of external tools (e.g. subprocess,
    HTTP API) behind a clean, asynchronous interface that can be orchestrated
    and tested in isolation.
    """

    metadata: ToolMetadata

    async def execute(self, scan_id: str, params: Mapping[str, Any]) -> ToolExecutionResult:
        """
        Execute the tool with the given parameters.

        The adapter is responsible for:
        - Interacting with the underlying external tool (e.g. subprocess).
        - Translating tool-specific outputs into `ToolExecutionResult`.
        - Respecting the `default_timeout_seconds` from its metadata, where
          appropriate.
        """

        ...


class ToolRegistry:
    """
    In-memory registry for tool adapters.

    This class is intentionally simple and side-effect free, so it can be
    swapped with a more advanced registry in the future if needed (e.g. a
    distributed registry stored in a database or service discovery).
    """

    def __init__(self, tools: Optional[Iterable[ToolAdapter]] = None) -> None:
        self._tools: MutableMapping[str, ToolAdapter] = {}
        if tools is not None:
            for tool in tools:
                self.register(tool)

    # --------------------------------------------------------------------- API
    def register(self, adapter: ToolAdapter) -> None:
        """Register or replace a tool adapter."""

        self._tools[adapter.metadata.id] = adapter

    def unregister(self, tool_id: str) -> None:
        """Remove a tool adapter from the registry if it exists."""

        self._tools.pop(tool_id, None)

    def get_adapter(self, tool_id: str) -> ToolAdapter:
        """
        Return the adapter for a given tool id.

        Raises `KeyError` if the tool is not registered. The orchestrator is
        expected to handle this gracefully.
        """

        return self._tools[tool_id]

    def get_metadata(self, tool_id: str) -> ToolMetadata:
        """Helper to fetch only the metadata of a tool."""

        return self.get_adapter(tool_id).metadata

    def list_metadata(self) -> Dict[str, ToolMetadata]:
        """Return a mapping of tool id to metadata for all registered tools."""

        return {tool_id: adapter.metadata for tool_id, adapter in self._tools.items()}

    def find_by_type(self, tool_type: ToolType) -> Dict[str, ToolMetadata]:
        """Return metadata for all tools of the given type."""

        return {
            tool_id: adapter.metadata
            for tool_id, adapter in self._tools.items()
            if adapter.metadata.type == tool_type
        }


def now_utc() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)

