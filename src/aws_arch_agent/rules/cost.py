from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class LogRetentionNeverExpire(Rule):
    id = "COST-001"
    title = "Log retention may be infinite (cost risk)"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        pattern = r'RetentionDays\.INFINITE|retention\s*:\s*logs\.RetentionDays\.INFINITE' if language == "typescript" else r'INFINITE|retention.*infinite'
        logs = rg(repo_path, pattern, glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in logs:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set log retention to a reasonable level (e.g. 14/30/90 days) to control costs.",
            ))
        return out


class MissingAutoscalingHint(Rule):
    id = "COST-002"
    title = "Compute resources may miss autoscaling"
    category = "Cost"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        asg = rg(repo_path, r'AutoScalingGroup|add_auto_scaling|addAutoScaling', glob=code_glob(language))
        ecs_pat = r'new\s+ecs\.(FargateService|Ec2Service)\(' if language == "typescript" else r'ecs\.(FargateService|Ec2Service)\('
        ecs = rg(repo_path, ecs_pat, glob=code_glob(language))
        out: List[Finding] = []
        if ecs and not asg:
            f, ln, txt = ecs[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider autoscaling policies (CPU/Memory/Queue depth) to reduce cost and improve performance.",
            ))
        return out
