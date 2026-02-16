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


class ScheduledScalingMissing(Rule):
    id = "SUST-003"
    title = "Scheduled scaling not configured for predictable patterns"
    category = "Sustainability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        asg = rg(repo_path, r'AutoScalingGroup|addAutoScaling', glob=code_glob(language))
        scheduled = rg(repo_path, r'scalingSchedule|ScalingSchedule|schedule.*scale', glob=code_glob(language))
        out: List[Finding] = []
        if asg and not scheduled:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="For predictable workload patterns, add scheduled scaling to reduce resources during off-peak hours.",
            )]
        return out


class AsyncProcessingHint(Rule):
    id = "SUST-004"
    title = "Consider async processing for batch workloads"
    category = "Sustainability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        lambda_pat = r'new\s+lambda\.Function\(' if language == "typescript" else r'lambda_.Function\('
        lambdas = rg(repo_path, lambda_pat, glob=code_glob(language))
        sqs = rg(repo_path, r'sqs\.Queue|SQS', glob=code_glob(language))
        eventbridge = rg(repo_path, r'events\.Rule|EventBridge', glob=code_glob(language))
        out: List[Finding] = []
        if lambdas and not sqs and not eventbridge:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Use SQS or EventBridge for async processing instead of polling to improve efficiency.",
            )]
        return out


class ManagedServicesPreference(Rule):
    id = "SUST-005"
    title = "Consider managed services over self-managed"
    category = "Sustainability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ec2 = rg(repo_path, r'ec2\.Instance\(' if language == "typescript" else r'ec2\.Instance\(', glob=code_glob(language))
        rds = rg(repo_path, r'rds\.|RDS', glob=code_glob(language))
        lambda_ref = rg(repo_path, r'lambda\.Function|Lambda', glob=code_glob(language))
        out: List[Finding] = []
        if ec2 and not rds and not lambda_ref:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Prefer managed services (Lambda, RDS, Fargate) over EC2 for better resource efficiency.",
            )]
        return out


class CloudFrontCompression(Rule):
    id = "SUST-006"
    title = "CloudFront compression not enabled"
    category = "Sustainability"
    severity = "Low"

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
                recommendation="Enable compression (gzip/brotli) on CloudFront to reduce data transfer and improve sustainability.",
            ))
        return out


class LatestGenInstances(Rule):
    id = "SUST-007"
    title = "Latest generation instance types not used"
    category = "Sustainability"
    severity = "Low"

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
                recommendation="Migrate to current-generation instances (t3, m6i, c6i, r6i) for better efficiency.",
            ))
        return out
