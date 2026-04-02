"""
Remediation guidance engine.

This module provides a pluggable strategy-based system for mapping canonical
vulnerabilities to structured remediation advice.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Iterable, List, Mapping, Sequence

from ..normalization import CanonicalVulnerability
from .models import Priority, RemediationAdvice


class RemediationStrategy(ABC):
    """
    Base class for remediation strategies.

    Each strategy decides whether it can handle a given vulnerability and, if
    so, returns structured remediation guidance.
    """

    @abstractmethod
    def supports(self, vulnerability: CanonicalVulnerability) -> bool:
        """Return True if this strategy can remediate the given vulnerability."""

        raise NotImplementedError

    @abstractmethod
    def build_remediation(self, vulnerability: CanonicalVulnerability) -> RemediationAdvice:
        """Create remediation advice for the given vulnerability."""

        raise NotImplementedError


class SqlInjectionRemediationStrategy(RemediationStrategy):
    """Strategy for SQL injection vulnerabilities (type 'sqli')."""

    def supports(self, vulnerability: CanonicalVulnerability) -> bool:
        return vulnerability.type.lower() == "sqli"

    def build_remediation(self, vulnerability: CanonicalVulnerability) -> RemediationAdvice:
        steps = [
            "Replace string concatenated SQL queries with parameterized queries or prepared statements.",
            "Use an ORM or query builder that parameterizes queries by default.",
            "Centralize database access logic and enforce safe query construction patterns.",
            "Add server-side input validation and encoding appropriate to the context.",
        ]
        references = [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ]
        priority = Priority.CRITICAL if vulnerability.severity.value in {"high", "critical"} else Priority.HIGH

        return RemediationAdvice(
            fix_summary="Eliminate SQL injection by using parameterized queries and strict input handling.",
            technical_steps=steps,
            priority=priority,
            references=references,
            metadata={"vuln_id": vulnerability.id, "vuln_type": vulnerability.type},
        )


class XssRemediationStrategy(RemediationStrategy):
    """Strategy for cross-site scripting vulnerabilities (type 'xss')."""

    def supports(self, vulnerability: CanonicalVulnerability) -> bool:
        return vulnerability.type.lower() == "xss"

    def build_remediation(self, vulnerability: CanonicalVulnerability) -> RemediationAdvice:
        steps = [
            "Apply output encoding for all untrusted data in HTML, JavaScript, CSS, and URL contexts.",
            "Use context-aware encoding functions from a vetted security library.",
            "Implement a strict Content Security Policy (CSP) to reduce XSS impact.",
            "Avoid using `innerHTML` or similar APIs with untrusted data.",
        ]
        references = [
            "https://owasp.org/www-community/attacks/xss/",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ]
        priority = Priority.HIGH if vulnerability.severity.value in {"medium", "high", "critical"} else Priority.MEDIUM

        return RemediationAdvice(
            fix_summary="Mitigate XSS via proper output encoding and Content Security Policy.",
            technical_steps=steps,
            priority=priority,
            references=references,
            metadata={"vuln_id": vulnerability.id, "vuln_type": vulnerability.type},
        )


class DefaultRemediationStrategy(RemediationStrategy):
    """Fallback strategy for vulnerabilities without a specific handler."""

    def supports(self, vulnerability: CanonicalVulnerability) -> bool:
        return True

    def build_remediation(self, vulnerability: CanonicalVulnerability) -> RemediationAdvice:
        steps = [
            "Review the vulnerability details and affected components.",
            "Apply secure coding guidelines relevant to the vulnerability type.",
            "Add automated tests to prevent regression once the fix is applied.",
        ]
        references = [
            "https://owasp.org/Top10/",
        ]
        priority = Priority.MEDIUM

        return RemediationAdvice(
            fix_summary=f"Address {vulnerability.type} by applying general secure coding practices.",
            technical_steps=steps,
            priority=priority,
            references=references,
            metadata={"vuln_id": vulnerability.id, "vuln_type": vulnerability.type},
        )


class RemediationEngine:
    """
    Entry point for remediation guidance generation.

    Uses a pluggable strategy pattern so that new vulnerability types or
    organization-specific guidance can be added without changing callers.
    """

    def __init__(self, strategies: Sequence[RemediationStrategy] | None = None) -> None:
        if strategies is not None and len(strategies) > 0:
            self._strategies: Sequence[RemediationStrategy] = tuple(strategies)
        else:
            self._strategies = (
                SqlInjectionRemediationStrategy(),
                XssRemediationStrategy(),
                DefaultRemediationStrategy(),
            )

    def get_remediation_for(self, vulnerability: CanonicalVulnerability) -> RemediationAdvice:
        """Return the first matching remediation advice for a single vulnerability."""

        strategy = next((s for s in self._strategies if s.supports(vulnerability)), DefaultRemediationStrategy())
        return strategy.build_remediation(vulnerability)

    def get_bulk_remediation(
        self,
        vulnerabilities: Iterable[CanonicalVulnerability],
    ) -> Dict[str, RemediationAdvice]:
        """
        Return remediation advice keyed by vulnerability id for a collection.

        This method guarantees that each vulnerability is associated with at
        least one recommendation via `DefaultRemediationStrategy`.
        """

        advice_map: Dict[str, RemediationAdvice] = {}
        for vuln in vulnerabilities:
            advice_map[vuln.id] = self.get_remediation_for(vuln)
        return advice_map

