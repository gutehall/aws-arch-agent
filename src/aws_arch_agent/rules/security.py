from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.tools.rg import rg


class IamWildcardAction(Rule):
    id = "SEC-001"
    title = "IAM policy uses wildcard actions"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # TS: Action: "*" or ['*']; Python: "Action": "*" in policy dicts or add_to_principal_policy
        pattern = r'Action\s*:\s*\[?\s*["\']\*["\']' if language == "typescript" else r'["\']Action["\']\s*:\s*["\']\*["\']'
        hits = rg(repo_path, pattern, glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in hits:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Restrict IAM actions to the minimum required (least privilege). Avoid '*' where possible.",
            ))
        return out


class IamWildcardResource(Rule):
    id = "SEC-002"
    title = "IAM policy uses wildcard resources"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        pattern = r'Resources?\s*:\s*\[?\s*["\']\*["\']' if language == "typescript" else r'["\']Resource["\']\s*:\s*["\']\*["\']'
        hits = rg(repo_path, pattern, glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in hits:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Restrict IAM resources to specific ARNs. Avoid '*' for resources where possible.",
            ))
        return out


class OpenSshToWorld(Rule):
    id = "SEC-003"
    title = "Security Group allows SSH from 0.0.0.0/0"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # TS: port: 22 or 0.0.0.0/0; Python: same in ec2.Port or CidrIp
        hits = rg(repo_path, r'0\.0\.0\.0/0.*(22|ssh)|port\s*:\s*22|\.tcp\(22\)', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in hits:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Restrict SSH to bastion/VPN or specific IP ranges. Avoid 0.0.0.0/0.",
            ))
        return out


class OpenDbPortsToWorld(Rule):
    id = "SEC-004"
    title = "Security Group exposes common DB ports to 0.0.0.0/0"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        hits = rg(repo_path, r'0\.0\.0\.0/0.*(3306|5432)|port\s*:\s*(3306|5432)|\.tcp\((3306|5432)\)', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in hits:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Databases should not be exposed publicly. Restrict ingress to app-tier security groups or private subnets.",
            ))
        return out


class S3PublicAccessNotBlocked(Rule):
    id = "SEC-005"
    title = "S3 bucket may miss Block Public Access"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Heuristic: bucket declared but no blockPublicAccess config in same repo
        bucket_pat = r'new\s+s3\.Bucket\(' if language == "typescript" else r's3\.Bucket\('
        buckets = rg(repo_path, bucket_pat, glob=code_glob(language))
        bpa = rg(repo_path, r'block_public_access|blockPublicAccess\s*:\s*s3\.BlockPublicAccess', glob=code_glob(language))
        out: List[Finding] = []
        if buckets and not bpa:
            f, ln, txt = buckets[0]
            suggested = (
                'new s3.Bucket(this, "B", {\n  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,\n});'
                if language == "typescript"
                else 's3.Bucket(self, "B", block_public_access=s3.BlockPublicAccess.BLOCK_ALL)'
            )
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Set 'blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL' for buckets that should not be public.",
                suggested_code=suggested,
            ))
        return out


class S3EncryptionMissing(Rule):
    id = "SEC-006"
    title = "S3 bucket may miss encryption setting"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        bucket_pat = r'new\s+s3\.Bucket\(' if language == "typescript" else r's3\.Bucket\('
        buckets = rg(repo_path, bucket_pat, glob=code_glob(language))
        enc = rg(repo_path, r'encryption\s*:\s*s3\.|BucketEncryption\.', glob=code_glob(language))
        out: List[Finding] = []
        if buckets and not enc:
            f, ln, txt = buckets[0]
            suggested = (
                'new s3.Bucket(this, "B", { encryption: s3.BucketEncryption.S3_MANAGED });'
                if language == "typescript"
                else 's3.Bucket(self, "B", encryption=s3.BucketEncryption.S3_MANAGED)'
            )
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable S3 encryption (e.g. S3_MANAGED or KMS) per security requirements.",
                suggested_code=suggested,
            ))
        return out


class KmsKeyPolicyWildcard(Rule):
    id = "SEC-007"
    title = "KMS key policy may use wildcard principal"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        kms = rg(repo_path, r"kms\.(Key|Alias)|aws_kms\.(Key|Alias)|KMS", glob=code_glob(language))
        # Principal: * or Principal: "*" in policy
        wildcard = rg(repo_path, r'Principal\s*:\s*["\']?\*["\']?|Principal\s*:\s*\{[^}]*\*', glob=code_glob(language))
        out: List[Finding] = []
        if kms and wildcard:
            f, ln, txt = wildcard[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Restrict KMS key policy to specific principals (IAM roles/users). Avoid Principal '*'.",
            ))
        return out
