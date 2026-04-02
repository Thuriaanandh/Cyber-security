"""
MCP orchestration layer.

This package contains building blocks for:
- Maintaining scan and attack context across tools (`state_tracker`).
- Managing available tools and their adapters (`tool_registry`).
- Providing a high-level facade for orchestrators to interact with MCP state
  (`context_manager`).

These modules are intentionally independent of FastAPI and any specific
transport layer to keep them easy to test and reuse.
"""

from .context_manager import MCPContextManager
from .state_tracker import InMemoryStateTracker, ScanContextState
from .tool_registry import ToolMetadata, ToolRegistry, ToolType

__all__ = [
    "MCPContextManager",
    "InMemoryStateTracker",
    "ScanContextState",
    "ToolMetadata",
    "ToolRegistry",
    "ToolType",
]

