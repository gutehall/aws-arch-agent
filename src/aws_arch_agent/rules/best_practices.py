from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class MissingStandardTags(Rule):
    id = "BP-001"
    title = "Standard tags may be missing"
    category = "Best Practices"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        tags = rg(repo_path, r'tags\s*:|tags\s*=', glob=code_glob(language))
        out: List[Finding] = []
        if not tags:
            # heuristic: no tags at all
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Introduce standard tags (owner, env, cost-center, system) on all resources or at stack level.",
            ))
        return out
