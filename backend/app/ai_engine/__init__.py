"""
AI reasoning and remediation engine.

This package contains pure reasoning and remediation components that:
- Analyze normalized vulnerabilities and attack graphs.
- Propose exploit chains and impact analyses.
- Suggest structured remediation recommendations.

No external AI calls are made here; integration with LLMs or other AI
providers can be added in a separate adapter layer.
"""

from .models import ExploitChain, ImpactAnalysis, Priority, RemediationAdvice
from .reasoning_engine import ReasoningEngine
from .remediation_engine import RemediationEngine

__all__ = [
    "ExploitChain",
    "ImpactAnalysis",
    "Priority",
    "RemediationAdvice",
    "ReasoningEngine",
    "RemediationEngine",
]

