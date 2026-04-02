"""
Decision engine for adaptive attack sequencing.

This module contains pure decision logic that:
- Chooses which tools to run initially.
- Determines follow-up actions based on normalized findings.

It is intentionally stateless and independent of any orchestration or transport
mechanism, so it can be unit tested in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Set

from ..mcp.state_tracker import DetectedIssue, ScanContextState
from ..mcp.tool_registry import ToolType


class DecisionActionType(str, Enum):
    """Types of actions the orchestrator can take based on decisions."""

    RUN_TOOL = "run_tool"
    NOOP = "noop"


@dataclass
class DecisionAction:
    """
    Orchestrator-level action proposed by the decision engine.

    The orchestrator is responsible for interpreting these actions and
    triggering tool execution or other side effects.
    """

    type: DecisionActionType
    reason: str
    tool_id: str | None = None
    params: Dict[str, Any] | None = None


class DecisionEngine:
    """
    Stateless decision engine for adaptive scan sequencing.

    Responsibilities:
    - Provide an initial tool plan based on requested tools and availability.
    - Suggest follow-up actions given the current scan context and available
      tools.
    """

    def plan_initial_tools(
        self,
        requested_tools: Iterable[str],
        available_tool_ids: Set[str],
    ) -> List[str]:
        """
        Decide which tools to run at the beginning of a scan.

        Rules:
        - If the caller requested specific tools, intersect with availability.
        - Otherwise, default to a standard discovery + web-vuln combo
          (Nmap + ZAP) when available.
        """

        requested = [tool_id for tool_id in requested_tools if tool_id in available_tool_ids]
        if requested:
            return requested

        defaults: List[str] = []
        for candidate in ("nmap", "zap"):
            if candidate in available_tool_ids:
                defaults.append(candidate)
        return defaults

    def derive_followup_actions(
        self,
        context: ScanContextState,
        available_tool_ids: Set[str],
    ) -> List[DecisionAction]:
        """
        Analyze current scan context and derive follow-up actions.

        Implements the high-level adaptive rules:
        - If SQL injection is detected -> trigger deeper SQLMap scan.
        - If XSS is detected -> launch payload mutation engine (tool id
          `xss_mutation` if available).
        - If auth bypass detected -> initiate privilege escalation tests (tool
          id `priv_esc` if available).
        """

        actions: List[DecisionAction] = []

        issues_by_type: Mapping[str, List[DetectedIssue]] = {}
        for issue in context.issues:
            issues_by_type.setdefault(issue.type.lower(), []).append(issue)

        # SQL injection -> deeper SQLMap scan
        if "sqli" in issues_by_type and "sqlmap" in available_tool_ids:
            actions.append(
                DecisionAction(
                    type=DecisionActionType.RUN_TOOL,
                    tool_id="sqlmap",
                    reason="SQL injection detected; triggering deeper SQLMap scan.",
                    params={"mode": "deep"},
                )
            )

        # XSS -> payload mutation engine (placeholder tool id `xss_mutation`)
        if "xss" in issues_by_type and "xss_mutation" in available_tool_ids:
            actions.append(
                DecisionAction(
                    type=DecisionActionType.RUN_TOOL,
                    tool_id="xss_mutation",
                    reason="XSS vulnerabilities detected; launching payload mutation engine.",
                    params={},
                )
            )

        # Auth bypass -> privilege escalation tests (placeholder tool id `priv_esc`)
        if "auth_bypass" in issues_by_type and "priv_esc" in available_tool_ids:
            actions.append(
                DecisionAction(
                    type=DecisionActionType.RUN_TOOL,
                    tool_id="priv_esc",
                    reason="Authentication bypass detected; initiating privilege escalation tests.",
                    params={},
                )
            )

        if not actions:
            actions.append(
                DecisionAction(
                    type=DecisionActionType.NOOP,
                    tool_id=None,
                    reason="No adaptive follow-up actions determined from current findings.",
                    params=None,
                )
            )

        return actions

