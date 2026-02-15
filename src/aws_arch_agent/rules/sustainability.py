"""Sustainability pillar: resource efficiency, Spot, right-sizing."""
from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class SpotNotConsidered(Rule):
    id = "SUST-001"
    title = "Fleet may not use Spot for interruptible workloads"
    category = "Sustainability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ec2_ecs = rg(repo_path, r"Ec2Service|FargateService|ec2\.Instance|AutoScalingGroup", glob=code_glob(language))
        spot = rg(repo_path, r"spot|Spot|capacity_type.*SPOT", glob=code_glob(language))
        if ec2_ecs and not spot:
            f, ln, txt = ec2_ecs[0]
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider Spot (or mixed OD+Spot) for fault-tolerant workloads to reduce cost and improve sustainability.",
            )]
        return []


class RightSizingHint(Rule):
    id = "SUST-002"
    title = "Right-sizing and efficiency review recommended"
    category = "Sustainability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Heuristic: fixed instance sizes without autoscaling
        asg = rg(repo_path, r"addAutoScaling|AutoScalingGroup|autoscaling", glob=code_glob(language))
        instances = rg(repo_path, r"InstanceSize|instanceType|machineImage", glob=code_glob(language))
        if instances and not asg:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Review instance sizes and consider autoscaling to match load and improve resource efficiency.",
            )]
        return []
