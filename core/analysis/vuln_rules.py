from __future__ import annotations

from core.models.schema import RepositoryIndex, SecurityIssue


class SecurityScanner:
    """
    ACI-first placeholder scanner.

    In the current ACI-only design, security findings should come from
    the agent's direct interaction with the repository through workspace tools,
    not from hard-coded static pattern matching.

    This scanner intentionally returns no precomputed issues.
    """

    def scan(self, index: RepositoryIndex) -> list[SecurityIssue]:
        return []