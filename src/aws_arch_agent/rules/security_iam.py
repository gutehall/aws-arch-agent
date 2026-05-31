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



class SecretsManagerRotation(Rule):
    id = "SEC-015"
    title = "Secrets Manager rotation not enabled"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        secret_pat = r'new\s+secretsmanager\.Secret\(' if language == "typescript" else r'secretsmanager\.Secret\('
        secrets = rg(repo_path, secret_pat, glob=code_glob(language))
        rotation = rg(repo_path, r'addRotationSchedule|rotationSchedule', glob=code_glob(language))
        out: List[Finding] = []
        if secrets and not rotation:
            f, ln, txt = secrets[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable automatic rotation for Secrets Manager secrets. In CDK: secret.addRotationSchedule()",
            ))
        return out



class HardcodedSecrets(Rule):
    id = "SEC-016"
    title = "Potential hardcoded credentials/secrets in code"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        # Look for common patterns of hardcoded secrets
        patterns = [
            r'password\s*[:=]\s*["\'][^"\']{8,}["\']',
            r'api[_-]?key\s*[:=]\s*["\'][^"\']{16,}["\']',
            r'secret\s*[:=]\s*["\'][^"\']{16,}["\']',
            r'access[_-]?key\s*[:=]\s*["\']AKIA[0-9A-Z]{16}["\']',
        ]
        out: List[Finding] = []
        for pattern in patterns:
            hits = rg(repo_path, pattern, glob=code_glob(language), max_hits=3)
            for f, ln, txt in hits:
                # Skip test files and examples
                if 'test' in f.lower() or 'example' in f.lower() or 'sample' in f.lower():
                    continue
                out.append(Finding(
                    id=self.id,
                    title=self.title,
                    severity="High",
                    category=self.category,
                    file=f,
                    line=ln,
                    evidence=txt[:100] + "...",
                    recommendation="Never hardcode secrets. Use AWS Secrets Manager, Systems Manager Parameter Store, or environment variables.",
                ))
        return out[:5]  # Limit to 5 findings to avoid noise



class LambdaEnvSecrets(Rule):
    id = "SEC-017"
    title = "Lambda environment variables may contain secrets"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        env_secrets = rg(repo_path, r'environment\s*:\s*\{[^}]*(password|secret|key|token)[^}]*\}', glob=code_glob(language))
        out: List[Finding] = []
        for f, ln, txt in env_secrets[:3]:
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt[:100],
                recommendation="Avoid storing secrets in Lambda environment variables. Use Secrets Manager or Parameter Store with proper IAM permissions.",
            ))
        return out



class KmsKeyRotation(Rule):
    id = "SEC-023"
    title = "KMS key rotation not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        kms_pat = r'new\s+kms\.Key\(' if language == "typescript" else r'kms\.Key\('
        keys = rg(repo_path, kms_pat, glob=code_glob(language))
        rotation = rg(repo_path, r'enableKeyRotation\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if keys and not rotation:
            f, ln, txt = keys[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable automatic key rotation for KMS customer-managed keys. In CDK: enableKeyRotation: true",
            ))
        return out



class SecurityHubNotEnabled(Rule):
    id = "SEC-026"
    title = "Security Hub not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        securityhub = rg(repo_path, r'CfnHub|securityhub\.CfnHub', glob=code_glob(language))
        if not securityhub:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider enabling AWS Security Hub for centralized security and compliance monitoring",
            )]
        return []



class GuardDutyNotEnabled(Rule):
    id = "SEC-027"
    title = "GuardDuty not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        guardduty = rg(repo_path, r'CfnDetector|guardduty\.CfnDetector', glob=code_glob(language))
        if not guardduty:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider enabling Amazon GuardDuty for intelligent threat detection",
            )]
        return []



class SsmParameterEncryption(Rule):
    id = "SEC-033"
    title = "SSM Parameter Store not using SecureString"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ssm_pat = r'new\s+ssm\.(StringParameter|CfnParameter)\(' if language == "typescript" else r'ssm\.(StringParameter|CfnParameter)\('
        params = rg(repo_path, ssm_pat, glob=code_glob(language))
        secure = rg(repo_path, r'ParameterType\.SECURE_STRING|type.*SecureString', glob=code_glob(language))
        out: List[Finding] = []
        if params and not secure:
            f, ln, txt = params[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Use SecureString type for sensitive SSM parameters. In CDK: type: ssm.ParameterType.SECURE_STRING",
            ))
        return out



class CognitoMfaMissing(Rule):
    id = "SEC-034"
    title = "Cognito User Pool MFA not required"
    category = "Security"
    severity = "High"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cognito_pat = r'new\s+cognito\.UserPool\(' if language == "typescript" else r'cognito\.UserPool\('
        pools = rg(repo_path, cognito_pat, glob=code_glob(language))
        mfa = rg(repo_path, r'mfa\s*:\s*cognito\.Mfa\.REQUIRED|mfa.*REQUIRED', glob=code_glob(language))
        out: List[Finding] = []
        if pools and not mfa:
            f, ln, txt = pools[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="High",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Require MFA for Cognito User Pools to enhance security. In CDK: mfa: cognito.Mfa.REQUIRED",
            ))
        return out



class CognitoPasswordPolicy(Rule):
    id = "SEC-035"
    title = "Cognito User Pool password policy may be weak"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cognito_pat = r'new\s+cognito\.UserPool\(' if language == "typescript" else r'cognito\.UserPool\('
        pools = rg(repo_path, cognito_pat, glob=code_glob(language))
        policy = rg(repo_path, r'passwordPolicy\s*:|minLength.*12|requireUppercase.*true', glob=code_glob(language))
        out: List[Finding] = []
        if pools and not policy:
            f, ln, txt = pools[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Configure strong password policy for Cognito (min 12 chars, require uppercase, lowercase, numbers, symbols). In CDK: passwordPolicy property",
            ))
        return out



class CognitoAdvancedSecurity(Rule):
    id = "SEC-036"
    title = "Cognito advanced security features not enabled"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cognito_pat = r'new\s+cognito\.UserPool\(' if language == "typescript" else r'cognito\.UserPool\('
        pools = rg(repo_path, cognito_pat, glob=code_glob(language))
        advanced = rg(repo_path, r'advancedSecurityMode.*ENFORCED|userPoolAddOns', glob=code_glob(language))
        out: List[Finding] = []
        if pools and not advanced:
            f, ln, txt = pools[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable advanced security features for Cognito (adaptive authentication, compromised credentials check). In CDK: advancedSecurityMode: cognito.AdvancedSecurityMode.ENFORCED",
            ))
        return out



class StackTerminationProtection(Rule):
    id = "SEC-056"
    title = "Stack termination protection not enabled"
    category = "Security"
    severity = "Medium"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        stack_pat = r'class\s+\w+\s+extends\s+Stack|super\(scope.*Stack' if language == "typescript" else r'class.*Stack\)|Stack\(scope'
        stacks = rg(repo_path, stack_pat, glob=code_glob(language))
        protection = rg(repo_path, r'terminationProtection\s*:\s*true', glob=code_glob(language))
        out: List[Finding] = []
        if stacks and not protection:
            f, ln, txt = stacks[0]
            out.append(Finding(
                id=self.id,
                title=self.title,
                severity="Medium",
                category=self.category,
                file=f,
                line=ln,
                evidence=txt,
                recommendation="Enable termination protection for production stacks. In CDK Stack props: terminationProtection: true",
            ))
        return out



class MacieNotEnabled(Rule):
    id = "SEC-065"
    title = "Amazon Macie not enabled for sensitive data discovery"
    category = "Security"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        s3_buckets = rg(repo_path, r'new\s+s3\.Bucket\(' if language == "typescript" else r's3\.Bucket\(', glob=code_glob(language))
        macie = rg(repo_path, r'macie|Macie|CfnSession', glob=code_glob(language))
        out: List[Finding] = []
        if s3_buckets and not macie:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider enabling Amazon Macie for automated discovery of sensitive data in S3 buckets.",
            )]
        return out

