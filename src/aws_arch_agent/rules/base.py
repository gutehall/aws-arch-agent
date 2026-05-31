"""Base rule class and code_glob helper for static CDK rules."""
from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, List
from aws_arch_agent.models import Finding

# Paths commonly excluded from static analysis (tests, build output, deps).
DEFAULT_EXCLUDE_GLOBS: tuple[str, ...] = (
    "**/*.test.ts",
    "**/*.spec.ts",
    "**/test/**",
    "**/tests/**",
    "**/__tests__/**",
    "**/build_rule_cases.py",
    "**/calibrate_rule_cases.py",
    "**/cdk.out/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
)


def code_glob(language: str) -> str:
    """Return ripgrep glob for code files in the given CDK language."""
    if language == "python":
        return "**/*.py"
    return "**/*.ts"


class Rule(ABC):
    """Base class for a single static rule (id, title, category, severity, run())."""

    id: str
    title: str
    category: str
    severity: str
    exclude_globs: ClassVar[tuple[str, ...]] = DEFAULT_EXCLUDE_GLOBS

    @abstractmethod
    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        """Run rule against repo; return list of findings (possibly empty)."""
        raise NotImplementedError
