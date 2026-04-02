"""
Normalization layer for tool execution results.

This package exposes:
- A canonical vulnerability schema.
- A result normalizer that maps `ToolExecutionResult` objects coming from
  heterogeneous tools into a unified representation.

It is independent of the orchestrator so it can be used by workers, APIs, or
offline analysis jobs.
"""

from .result_normalizer import (
    CanonicalSeverity,
    CanonicalVulnerability,
    ResultNormalizer,
)

__all__ = [
    "CanonicalSeverity",
    "CanonicalVulnerability",
    "ResultNormalizer",
]

