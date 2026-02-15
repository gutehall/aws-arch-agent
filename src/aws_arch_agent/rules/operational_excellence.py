"""Operational Excellence pillar: CloudTrail, Flow Logs, audit."""
from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class CloudTrailMissing(Rule):
    id = "OPS-001"
    title = "CloudTrail / audit trail may be missing"
    category = "Operational Excellence"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        trail_pat = r"cloudtrail\.(Trail|CfnTrail)|CloudTrail|aws_cloudtrail" if language == "typescript" else r"cloudtrail|CloudTrail|aws_cloudtrail"
        trails = rg(repo_path, trail_pat, glob=code_glob(language))
        if not trails:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider enabling CloudTrail for API audit and security analysis.",
            )]
        return []


class VpcFlowLogsMissing(Rule):
    id = "OPS-002"
    title = "VPC Flow Logs may be missing"
    category = "Operational Excellence"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        vpc_pat = r"new\s+ec2\.Vpc\(" if language == "typescript" else r"ec2\.Vpc\("
        flow_pat = r"FlowLog|flow_log|FlowLogDestination"
        vpcs = rg(repo_path, vpc_pat, glob=code_glob(language))
        flow_logs = rg(repo_path, flow_pat, glob=code_glob(language))
        if vpcs and not flow_logs:
            f, ln, txt = vpcs[0]
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider VPC Flow Logs for network troubleshooting and security analysis.",
            )]
        return []
