"""
Scan orchestration layer.

This package coordinates MCP context, tool adapters, and decision logic to
perform adaptive attack sequencing for web application VAPT scans.

It deliberately contains no FastAPI-specific code so it can be invoked from
HTTP handlers, workers, or CLI entrypoints.
"""

from .models import OrchestratorState, ScanExecutionResult
from .decision_engine import DecisionAction, DecisionActionType, DecisionEngine
from .scan_orchestrator import ScanOrchestrator

__all__ = [
    "OrchestratorState",
    "ScanExecutionResult",
    "DecisionAction",
    "DecisionActionType",
    "DecisionEngine",
    "ScanOrchestrator",
]

