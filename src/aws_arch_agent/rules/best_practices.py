from __future__ import annotations
from pathlib import Path
from typing import List
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.base import Rule, code_glob
from aws_arch_agent.rules.scope import findings_for_unmatched
from aws_arch_agent.tools.paths import normalize_rel_path
from aws_arch_agent.tools.rg import rg

# A plain environment block is not a secret. The key has to look like one.
_ENV_BLOCK = r"environment\s*[:=]\s*\{"
_SECRET_ENV_KEY = (
    "(?<![A-Za-z0-9])"
    "['\"]?"
    "(?:[A-Z][A-Z0-9_]*_)?"
    "(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)"
    "['\"]?"
    r"\s*[:=]"
)
_SECRETS_MANAGER = r"secretsmanager\.Secret|Secret\.fromSecretAttributes|Secret\.from_secret"
# Physical name properties. A short construct id is not a name.
_SHORT_PHYSICAL_NAME = (
    r"(?:bucket|function|table|queue|topic|role|stream|repository|cluster|log_?[Gg]roup)"
    r"_?[Nn]ame\s*[:=]\s*[\"'][A-Za-z0-9]{1,2}[\"']"
)


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


class SecretsInEnvVars(Rule):
    id = "BP-002"
    title = "Using environment variables instead of Secrets Manager"
    category = "Best Practices"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        glob = code_glob(language)
        env_files = {
            normalize_rel_path(path) or path
            for path, _line, _text in rg(repo_path, _ENV_BLOCK, glob=glob)
        }
        secret_keys = [
            hit
            for hit in rg(repo_path, _SECRET_ENV_KEY, glob=glob)
            if (normalize_rel_path(hit[0]) or hit[0]) in env_files
        ]
        secrets_mgr = rg(repo_path, _SECRETS_MANAGER, glob=glob)
        return findings_for_unmatched(
            self,
            secret_keys,
            secrets_mgr,
            "For sensitive configuration, use AWS Secrets Manager or Systems Manager Parameter Store instead of environment variables",
        )


class ResourceNamingConvention(Rule):
    id = "BP-003"
    title = "Resource naming convention may not be followed"
    category = "Best Practices"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        short_names = rg(repo_path, _SHORT_PHYSICAL_NAME, glob=code_glob(language))
        return [
            Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=path,
                line=line,
                evidence=text,
                recommendation=(
                    "Use a descriptive physical name (bucketName, functionName, tableName). "
                    "A short CDK construct id is not a naming-convention finding."
                ),
            )
            for path, line, text in short_names
        ]


class CdkAspectsMissing(Rule):
    id = "BP-004"
    title = "CDK Aspects not used for policy enforcement"
    category = "Best Practices"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        aspects = rg(repo_path, r'Aspects\.of|aspects\.', glob=code_glob(language))
        stacks = rg(repo_path, r'extends\s+Stack|Stack\(' if language == "typescript" else r'Stack\(', glob=code_glob(language))
        out: List[Finding] = []
        if stacks and not aspects:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Consider CDK Aspects for cross-cutting concerns like tagging and validation.",
            )]
        return out


class CdkContextMissing(Rule):
    id = "BP-005"
    title = "CDK context not used for environment-specific config"
    category = "Best Practices"
    severity = "Low"

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        context = rg(repo_path, r'node\.tryGetContext|try_get_context', glob=code_glob(language))
        stacks = rg(repo_path, r'extends\s+Stack|Stack\(' if language == "typescript" else r'Stack\(', glob=code_glob(language))
        out: List[Finding] = []
        if stacks and not context:
            return [Finding(
                id=self.id,
                title=self.title,
                severity="Low",
                category=self.category,
                file=None,
                line=None,
                evidence=None,
                recommendation="Use cdk.json context for environment-specific configuration (e.g., account, region).",
            )]
        return out
