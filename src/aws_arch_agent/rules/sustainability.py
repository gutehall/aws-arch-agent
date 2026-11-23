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
    themes = ("sustainability", "finops",)
    recommendation = (
        "Consider Spot (or mixed OD+Spot) for fault-tolerant workloads to reduce cost and improve"
        " sustainability."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Fleets only, as the title says: Auto Scaling groups (ECS on EC2 runs on one), Fargate
        # and the services on them. CF-SUST-001..003 read the same fleets from the template.
        ec2_ecs = rg(repo_path, r"Ec2Service|FargateService|AutoScalingGroup", glob=code_glob(language))
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
                recommendation=self.recommendation,
            )]
        return []


class RightSizingHint(Rule):
    id = "SUST-002"
    title = "Right-sizing and efficiency review recommended"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops",)
    recommendation = (
        "Review instance sizes and consider autoscaling to match load and improve resource "
        "efficiency."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Answered by the usage file (rules/usage_signals.py); quiet when it states nothing.
        from aws_arch_agent.rules import usage_signals

        return usage_signals.low_utilization(self, repo_path)


class ScheduledScalingMissing(Rule):
    id = "SUST-003"
    title = "Scheduled scaling not configured for predictable patterns"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability",)
    recommendation = (
        "For predictable workload patterns, add scheduled scaling to reduce resources during "
        "off-peak hours."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Answered by the usage file (rules/usage_signals.py); quiet when it states nothing.
        from aws_arch_agent.rules import usage_signals

        return usage_signals.scheduled_scaling(self, repo_path)


# SUST-004 and SUST-005 are design judgments: a repo note answers them (rules/repo_practices.py).
# They read the whole repo tree, so they run for every source, like the REPO-* rules.
REPO_NOTE_RULE_IDS = frozenset({"SUST-004", "SUST-005"})


class AsyncProcessingHint(Rule):
    id = "SUST-004"
    title = "Consider async processing for batch workloads"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability",)
    recommendation = (
        "Use SQS or EventBridge for async processing instead of polling to improve efficiency."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        from aws_arch_agent.rules.repo_practices import batch_without_note

        found = batch_without_note(repo_path)
        if not found:
            return []
        places = ", ".join(f"{kind} in {rel}" for kind, rel in list(found.items())[:4])
        return [Finding(
            id=self.id, title=self.title, severity="Low", category=self.category,
            file=next(iter(found.values())), line=None,
            evidence=f"Batch work: {places}; searched the repo notes for one that names the batch "
                     "path and why it is synchronous or asynchronous; found none",
            recommendation=self.recommendation,
        )]


class ManagedServicesPreference(Rule):
    id = "SUST-005"
    title = "Consider managed services over self-managed"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability",)
    recommendation = (
        "Prefer managed services (Lambda, RDS, Fargate) over EC2 for better resource efficiency."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        from aws_arch_agent.rules.repo_practices import self_managed_without_note

        found = self_managed_without_note(repo_path)
        if not found:
            return []
        places = ", ".join(f"{name} in {rel}" for name, rel in sorted(found.items())[:4])
        return [Finding(
            id=self.id, title=self.title, severity="Low", category=self.category,
            file=next(iter(found.values())), line=None,
            evidence=f"Self-managed: {places}; searched the repo notes for one that names each "
                     "and why it is not a managed service; found none",
            recommendation=self.recommendation,
        )]


class CloudFrontCompression(Rule):
    id = "SUST-006"
    title = "CloudFront compression not enabled"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops",)
    recommendation = (
        "Enable compression (gzip/brotli) on CloudFront to reduce data transfer and improve "
        "sustainability."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cf_pat = r'new\s+cloudfront\.(Distribution|CloudFrontWebDistribution)\(' if language == "typescript" else r'cloudfront\.(Distribution|CloudFrontWebDistribution)\('
        distros = rg(repo_path, cf_pat, glob=code_glob(language))
        compress = rg(repo_path, r'compress\s*:\s*true|compress.*true', glob=code_glob(language))
        out: List[Finding] = []
        if distros and not compress:
            f, ln, txt = distros[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation=self.recommendation,
            ))
        return out


class LatestGenInstances(Rule):
    id = "SUST-007"
    title = "Latest generation instance types not used"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops",)
    recommendation = (
        "Migrate to current-generation instances (t3, m6i, c6i, r6i) for better efficiency."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        legacy = rg(repo_path, r't2\.|m3\.|m4\.|c3\.|c4\.|r3\.|r4\.', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in legacy[:2]:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation=self.recommendation,
            ))
        return out
