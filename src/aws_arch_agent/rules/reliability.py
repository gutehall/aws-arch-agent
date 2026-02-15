from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class RdsMultiAzMissing(Rule):
    id = "REL-001"
    title = "RDS may miss Multi-AZ"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds_pat = r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\('
        rds = rg(repo_path, rds_pat, glob=code_glob(language))
        maz = rg(repo_path, r'multi_az\s*:\s*True|multiAz\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if rds and not maz:
            f, ln, txt = rds[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider Multi-AZ for higher availability (especially in production).",
            ))
        return out


class BackupRetentionMissing(Rule):
    id = "REL-002"
    title = "RDS may miss backup retention"
    category = "Reliability"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        rds_pat = r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\(' if language == "typescript" else r'rds\.(DatabaseInstance|DatabaseCluster)\('
        rds = rg(repo_path, rds_pat, glob=code_glob(language))
        br = rg(repo_path, r'backup_retention|backupRetention\s*:', glob=code_glob(language))
        out: List[Finding] = []
        if rds and not br:
            f, ln, txt = rds[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set backupRetention per RPO/RTO (e.g. 7–35 days).",
            ))
        return out


class LambdaDlqMissing(Rule):
    id = "REL-003"
    title = "Lambda may miss DLQ / on-failure destination"
    category = "Reliability"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        lambda_pat = r'new\s+lambda\.Function\(' if language == "typescript" else r'lambda_.Function\(|aws_cdk.aws_lambda.Function\('
        lambdas = rg(repo_path, lambda_pat, glob=code_glob(language))
        dlq = rg(repo_path, r'dead_letter_queue|deadLetterQueue|on_failure|onFailure', glob=code_glob(language))
        out: List[Finding] = []
        if lambdas and not dlq:
            f, ln, txt = lambdas[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Consider DLQ or onFailure destinations for better error handling.",
            ))
        return out
