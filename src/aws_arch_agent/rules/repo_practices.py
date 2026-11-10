"""Repo-level checks: tests, a pipeline, environments (OPS 5), account guardrails (SEC 1).

These rules read the repository tree, not one IaC file, so they run the same for CDK,
CloudFormation, and Terraform scans. They walk the whole repo (test directories included,
since tests are what REPO-001 looks for) and skip dependency and build output:
node_modules, cdk.out, .git, dist, build, .venv, venv, .terraform and caches.

Heuristics, kept simple on purpose:

- REPO-001 tests: a code file under a test/, tests/, __tests__/ or spec/ directory, or a
  file named like a test (*.test.ts, *.spec.js, test_*.py, *_test.py, *_test.go,
  *.tftest.hcl), a taskcat config, or cfn-guard rule tests (*_tests.yaml next to *.guard).
- REPO-002 pipeline: a CI config file (GitHub Actions, GitLab CI, CodeBuild buildspec,
  Jenkinsfile, Azure Pipelines, Bitbucket Pipelines, CircleCI, Buildkite, Travis), or a
  CodePipeline declared in the IaC (AWS::CodePipeline::Pipeline, aws_codepipeline,
  codepipeline.Pipeline, pipelines.CodePipeline).
- REPO-003 environments: environment words (rules/environments.py: prod, staging, dev and
  their synonyms) in the paths of IaC files (Terraform, tfvars, CloudFormation templates,
  parameter files), in CDK stack and stage ids, and in cdk.json context keys. Two distinct
  environments pass. Environments built in a loop or from a variable are not seen.
- REPO-004 organization guardrails (an org-level rule, off unless rules.org or
  rules.include): the IaC declares an SCP (AWS::Organizations::Policy,
  aws_organizations_policy, organizations.CfnPolicy, with SERVICE_CONTROL_POLICY named in
  the file or no other policy type named), a Control Tower control or landing zone, an
  organization trail (IsOrganizationTrail / is_organization_trail / isOrganizationTrail
  true), or Organizations accounts or OUs.
- REPO-005 account baseline: when the IaC defines an account (Organizations account,
  Control Tower Account Factory provisioned product, or an AFT aft-account-request module),
  it must also declare a CloudTrail trail, a Config recorder, a GuardDuty detector, a
  Security Hub hub and an IAM Access Analyzer. No account defined, no finding.

REPO-004 and REPO-005 match text in IaC files (CDK TypeScript/JavaScript/Python,
CloudFormation JSON/YAML, Terraform), less test files. A resource built from a variable
type, or in a module the repo does not hold, is not seen.
"""
from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar, List

from aws_arch_agent.models import Finding, Severity
from aws_arch_agent.rules.base import Rule
from aws_arch_agent.rules.environments import from_words
from aws_arch_agent.tools.cfn_yaml import is_cf_template
from aws_arch_agent.tools.files import read_text_safe

SKIP_DIRS = frozenset({
    ".git", "node_modules", "cdk.out", "dist", "build", ".venv", "venv", ".terraform",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
})
MAX_FILES = 20_000
_BUILD_GLOBS: tuple[str, ...] = tuple(f"**/{d}/**" for d in sorted(SKIP_DIRS))

_TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec"})
_CODE_SUFFIXES = frozenset({
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".java", ".kt", ".cs", ".rb",
})
_TEST_NAME = re.compile(
    r"(?:\.(?:test|spec)\.[cm]?[jt]sx?|^test_.*\.py|_test\.py|_test\.go|\.tftest\.hcl)$"
)
_TASKCAT = frozenset({".taskcat.yml", ".taskcat.yaml", "taskcat.yml", "taskcat.yaml"})
_GUARD_TEST = re.compile(r"[_-]tests?\.ya?ml$")

_CI_FILES = frozenset({
    ".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml", "azure-pipelines.yaml",
    "bitbucket-pipelines.yml", ".travis.yml",
})
_PIPELINE_IN_IAC = re.compile(
    r"AWS::CodePipeline::Pipeline|resource\s+\"aws_codepipeline\""
    r"|\bcodepipeline\.(?:Cfn)?Pipeline\(|\bCodePipeline\("
)
_IAC_TEXT_SUFFIXES = frozenset({
    ".ts", ".js", ".py", ".json", ".yaml", ".yml", ".template", ".tf",
})

# Directories that hold one subdirectory per environment: envs/test is an environment,
# not a test suite.
_ENV_PARENTS = frozenset({
    "env", "envs", "environment", "environments", "stage", "stages", "account", "accounts",
    "deployments", "workspaces", "live",
})
_PARAM_SUFFIXES = frozenset({".json", ".yaml", ".yml"})
_STACK_ID = re.compile(
    r"\b(\w*(?:Stack|Stage))\(\s*[\w.]+\s*,\s*['\"]([^'\"]+)['\"]"
)


def walk(repo_path: Path) -> Iterator[Path]:
    """Every file of the repo, less dependency and build output, in a stable order."""
    seen = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            yield Path(root) / name
            seen += 1
            if seen >= MAX_FILES:
                return


def _rel_parts(path: Path, repo_path: Path) -> tuple[str, ...]:
    return path.relative_to(repo_path).parts


def _in_test_dir(parts: tuple[str, ...]) -> bool:
    """Under a test directory that is not an environment (envs/test stays an environment)."""
    dirs = parts[:-1]
    return any(
        d.lower() in _TEST_DIRS and (i == 0 or dirs[i - 1].lower() not in _ENV_PARENTS)
        for i, d in enumerate(dirs)
    )


def _is_test_file(path: Path, parts: tuple[str, ...], guard_rules: bool) -> bool:
    name = path.name.lower()
    if _TEST_NAME.search(name) or name in _TASKCAT:
        return True
    if guard_rules and _GUARD_TEST.search(name):
        return True
    return path.suffix.lower() in _CODE_SUFFIXES and _in_test_dir(parts)


def _is_ci_file(parts: tuple[str, ...]) -> bool:
    lowered = tuple(p.lower() for p in parts)
    name = lowered[-1]
    if name in _CI_FILES or re.fullmatch(r"buildspec[\w.-]*\.ya?ml", name):
        return True
    if lowered[:2] == (".github", "workflows") and name.endswith((".yml", ".yaml")):
        return True
    if lowered[:1] == (".circleci",) and name == "config.yml":
        return True
    return lowered[:1] == (".buildkite",)


class _RepoRule(Rule):
    category = "Operational Excellence"
    severity: Severity
    exclude_globs: ClassVar[tuple[str, ...]] = _BUILD_GLOBS

    def _finding(
        self, evidence: str, file: str | None = None, line: int | None = None
    ) -> Finding:
        return Finding(
            id=self.id,
            title=self.title,
            severity=self.severity,
            category=self.category,
            file=file,
            line=line,
            evidence=evidence,
            recommendation=self.recommendation,
        )


class RepoTestsMissing(_RepoRule):
    id = "REPO-001"
    title = "Repo has no automated tests"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Add automated tests for the infrastructure code (CDK assertions, pytest, "
        "terraform test, taskcat or cfn-guard rule tests) and run them on every change."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        files = list(walk(repo_path))
        guard_rules = any(p.suffix.lower() == ".guard" for p in files)
        for path in files:
            if _is_test_file(path, _rel_parts(path, repo_path), guard_rules):
                return []
        return [self._finding(
            "Searched the repo for tests (test/, tests/, __tests__/, spec/, "
            "*.test.ts, *.spec.js, test_*.py, *_test.go, *.tftest.hcl, taskcat, cfn-guard "
            "tests); found none"
        )]


class RepoPipelineMissing(_RepoRule):
    id = "REPO-002"
    title = "No CI workflow or pipeline builds the workload"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Build, test and deploy from a pipeline: add a CI workflow (GitHub Actions, GitLab "
        "CI, CodeBuild buildspec) or a CodePipeline, so every change takes the same path to "
        "production."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        files = list(walk(repo_path))
        for path in files:
            if _is_ci_file(_rel_parts(path, repo_path)):
                return []
        for path in files:
            parts = _rel_parts(path, repo_path)
            if path.suffix.lower() not in _IAC_TEXT_SUFFIXES or _in_test_dir(parts):
                continue
            if _PIPELINE_IN_IAC.search(read_text_safe(path)):
                return []
        return [self._finding(
            "Searched the repo for a CI config (.github/workflows, .gitlab-ci.yml, "
            "buildspec.yml, Jenkinsfile, azure-pipelines.yml, bitbucket-pipelines.yml, "
            ".circleci, .buildkite) or a CodePipeline in the IaC; found none"
        )]


def _iac_path(path: Path) -> bool:
    name = path.name.lower()
    if path.suffix.lower() in (".tf", ".tfvars") or name.endswith(".tfvars.json"):
        return True
    if path.suffix.lower() in _PARAM_SUFFIXES and "param" in name:
        return True
    return is_cf_template(path)


def _cdk_context_keys(path: Path) -> List[str]:
    try:
        doc = json.loads(read_text_safe(path))
    except ValueError:
        return []
    context = doc.get("context") if isinstance(doc, dict) else None
    if not isinstance(context, dict):
        return []
    keys = list(context)
    for value in context.values():
        if isinstance(value, dict):
            keys.extend(value)
    # Feature flags (@aws-cdk/pipelines:reduceStageRoleTrustScope) name no environment.
    return [str(k) for k in keys if not str(k).startswith("@") and ":" not in str(k)]


def environments_found(repo_path: Path) -> dict[str, str]:
    """Each environment the repo defines, and where it was first seen."""
    found: dict[str, str] = {}

    def note(text: str, where: str) -> None:
        env = from_words(text)
        if env is not None:
            found.setdefault(env, where)

    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        rel = "/".join(parts)
        if _in_test_dir(parts) or _TEST_NAME.search(path.name.lower()):
            continue
        if path.name == "cdk.json":
            for key in _cdk_context_keys(path):
                note(key, f"{rel} context {key}")
            continue
        if path.suffix.lower() in (".ts", ".js", ".py"):
            for match in _STACK_ID.finditer(read_text_safe(path)):
                note(match.group(2), f"{rel} {match.group(1)} {match.group(2)}")
                note(match.group(1), f"{rel} {match.group(1)}")
            continue
        if _iac_path(path):
            for part in (*parts[:-1], path.name.split(".", 1)[0]):
                note(part, rel)
    return found


class SingleEnvironment(_RepoRule):
    id = "REPO-003"
    title = "Only one environment is defined"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Define at least one environment before production (dev or staging stacks, "
        "per-environment tfvars or parameter files) and promote changes through it."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = environments_found(repo_path)
        if len(found) >= 2:
            return []
        seen = ", ".join(f"{env} ({where})" for env, where in sorted(found.items())) or "none"
        return [self._finding(
            "Environments named in IaC paths, tfvars and parameter files, CDK stack ids and "
            f"cdk.json context: {seen}; two or more expected"
        )]


def iac_texts(repo_path: Path) -> Iterator[tuple[str, str]]:
    """(repo-relative path, text) of each IaC or code file outside tests."""
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if path.suffix.lower() not in _IAC_TEXT_SUFFIXES or _in_test_dir(parts):
            continue
        if _TEST_NAME.search(path.name.lower()):
            continue
        yield "/".join(parts), read_text_safe(path)


_ORG_POLICY = re.compile(
    r"AWS::Organizations::Policy\b|resource\s+\"aws_organizations_policy\""
    r"|organizations\.CfnPolicy\("
)
_OTHER_POLICY_TYPE = re.compile(
    r"\b(?:TAG_POLICY|BACKUP_POLICY|AISERVICES_OPT_OUT_POLICY|CHATBOT_POLICY"
    r"|RESOURCE_CONTROL_POLICY|DECLARATIVE_POLICY_EC2|SECURITYHUB_POLICY|INSPECTOR_POLICY)\b"
)
_CONTROL_TOWER = re.compile(
    r"AWS::ControlTower::(?:EnabledControl|LandingZone)\b"
    r"|resource\s+\"aws_controltower_(?:control|landing_zone)\""
    r"|controltower\.Cfn(?:EnabledControl|LandingZone)\("
)
_ORG_TRAIL = re.compile(
    r"\bIsOrganizationTrail[\"']?\s*:\s*[\"']?true\b"
    r"|\bis_organization_trail\s*=\s*(?:true|True)\b"
    r"|\bisOrganizationTrail\s*:\s*true\b"
)
_ORG_UNITS = re.compile(
    r"AWS::Organizations::(?:Account|OrganizationalUnit)\b"
    r"|resource\s+\"aws_organizations_(?:account|organizational_unit)\""
    r"|organizations\.Cfn(?:Account|OrganizationalUnit)\("
)


def org_guardrails(repo_path: Path) -> dict[str, str]:
    """Each kind of organization guardrail the IaC declares, and the first file with it."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _ORG_POLICY.search(text) and (
            "SERVICE_CONTROL_POLICY" in text or not _OTHER_POLICY_TYPE.search(text)
        ):
            found.setdefault("service control policy", rel)
        if _CONTROL_TOWER.search(text):
            found.setdefault("Control Tower control", rel)
        if _ORG_TRAIL.search(text):
            found.setdefault("organization trail", rel)
        if _ORG_UNITS.search(text):
            found.setdefault("Organizations account or OU", rel)
    return found


class OrgGuardrailsMissing(_RepoRule):
    id = "REPO-004"
    title = "No organization guardrails in the scanned IaC"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Run workloads in separate accounts under AWS Organizations and set guardrails in "
        "code: service control policies, Control Tower controls, and an organization trail."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        if org_guardrails(repo_path):
            return []
        return [self._finding(
            "Searched the IaC for a service control policy, a Control Tower control or "
            "landing zone, an organization CloudTrail trail, and Organizations accounts or "
            "OUs; found none"
        )]


_ACCOUNT = re.compile(
    r"AWS::Organizations::Account\b|resource\s+\"aws_organizations_account\""
    r"|organizations\.CfnAccount\(|aft-account-request"
)
_PROVISIONED_PRODUCT = re.compile(
    r"AWS::ServiceCatalog::CloudFormationProvisionedProduct\b"
    r"|resource\s+\"aws_servicecatalog_provisioned_product\""
    r"|servicecatalog\.CfnCloudFormationProvisionedProduct\("
)
_ACCOUNT_FACTORY = "AWSControlTowerAccountFactory"
BASELINE_SERVICES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("CloudTrail trail", re.compile(
        r"AWS::CloudTrail::Trail\b|resource\s+\"aws_cloudtrail\"|cloudtrail\.(?:Cfn)?Trail\("
    )),
    ("Config recorder", re.compile(
        r"AWS::Config::ConfigurationRecorder\b"
        r"|resource\s+\"aws_config_configuration_recorder\""
        r"|config\.CfnConfigurationRecorder\("
    )),
    ("GuardDuty detector", re.compile(
        r"AWS::GuardDuty::Detector\b|resource\s+\"aws_guardduty_detector\""
        r"|guardduty\.CfnDetector\("
    )),
    ("Security Hub", re.compile(
        r"AWS::SecurityHub::Hub(?:V2)?\b|resource\s+\"aws_securityhub_account\""
        r"|securityhub\.CfnHub(?:V2)?\("
    )),
    ("IAM Access Analyzer", re.compile(
        r"AWS::AccessAnalyzer::Analyzer\b|resource\s+\"aws_accessanalyzer_analyzer\""
        r"|accessanalyzer\.CfnAnalyzer\("
    )),
)


def _account_at(text: str) -> int | None:
    """Offset of the first account definition in text, or None."""
    match = _ACCOUNT.search(text)
    if match:
        return match.start()
    if _PROVISIONED_PRODUCT.search(text) and _ACCOUNT_FACTORY in text:
        return text.index(_ACCOUNT_FACTORY)
    return None


class AccountBaselineMissing(_RepoRule):
    id = "REPO-005"
    title = "Account is defined without a security baseline"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Deploy a security baseline with every account the repo creates: a CloudTrail "
        "trail, an AWS Config recorder, a GuardDuty detector, Security Hub and an IAM "
        "Access Analyzer (or the Control Tower or AFT customizations that set them up)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        account: tuple[str, int] | None = None
        missing = {name: pattern for name, pattern in BASELINE_SERVICES}
        for rel, text in iac_texts(repo_path):
            at = _account_at(text)
            if account is None and at is not None:
                account = (rel, text.count("\n", 0, at) + 1)
            for name, pattern in list(missing.items()):
                if pattern.search(text):
                    del missing[name]
        if account is None or not missing:
            return []
        rel, line = account
        names = [name for name, _ in BASELINE_SERVICES if name in missing]
        return [self._finding(
            f"Defines an account ({rel}:{line}); no {', '.join(names)} in the IaC",
            file=rel, line=line,
        )]


REPO_RULES: List[Rule] = [
    RepoTestsMissing(), RepoPipelineMissing(), SingleEnvironment(),
    OrgGuardrailsMissing(), AccountBaselineMissing(),
]
