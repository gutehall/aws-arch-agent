"""Performance Efficiency pillar: caching, compute choice, scaling."""
from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class GravitonNotUsed(Rule):
    id = "PERF-001"
    title = "Compute may not use Graviton/ARM (cost and performance)"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Lambda: ARCH_ARM64; EC2/ECS: arm64, graviton
        graviton = rg(repo_path, r"ARM64|arm64|architecture.*arm|Graviton|graviton", glob=code_glob(language))
        compute = rg(repo_path, r"lambda\.Function|ec2\.Instance|FargateService|Ec2Service", glob=code_glob(language))
        if compute and not graviton:
            f, ln, txt = compute[0]
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider Graviton/ARM (e.g. Lambda ARM64, ECS arm64) for better price-performance.",
            )]
        return []


class CachingHint(Rule):
    id = "PERF-002"
    title = "No caching layer detected (performance)"
    category = "Performance Efficiency"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cache = rg(repo_path, r"CloudFront|Distribution|ElastiCache|Redis|Memcached|DynamoDB\.Table|api\.(RestApi|HttpApi)", glob=code_glob(language))
        if not cache:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider CloudFront, ElastiCache, or API caching for latency and efficiency.",
            )]
        return []
