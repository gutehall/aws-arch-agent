"""Base rule class and code_glob helper for static CDK rules."""
from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding


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

    @abstractmethod
    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        """Run rule against repo; return list of findings (possibly empty)."""
        raise NotImplementedError
