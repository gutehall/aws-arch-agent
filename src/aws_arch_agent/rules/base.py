"""Base rule class and code_glob helper for static CDK rules."""
from __future__ import annotations
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, List
from aws_arch_agent.models import Finding

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

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


def cdk_bool_prop(camel: str) -> str:
    """Ripgrep pattern for a CDK boolean that is true in TypeScript or Python.

    ``enableKeyRotation: true`` and ``enable_key_rotation=True`` both match.
    Either separator is accepted, and the value may be ``true`` or ``True``.
    """
    snake = _CAMEL_BOUNDARY.sub("_", camel).lower()
    names = "|".join(re.escape(name) for name in sorted({camel, snake}))
    return rf"(?:{names})\s*[:=]\s*(?:[Tt]rue)"


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
