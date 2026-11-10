"""Repo-level checks: tests, a pipeline, environments (OPS 5), account guardrails (SEC 1),
incident response (SEC 10), application security (SEC 11), service quotas (REL 1),
VPC address plan (REL 2).

REPO-006 (the account root user) answers SEC01-BP02 in SEC 1, though it was added with the
SEC 2 checks.

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
- REPO-006 root user: when the IaC defines an account (as for REPO-005), it must also check
  root MFA and root access keys: the AWS Config managed rules ROOT_ACCOUNT_MFA_ENABLED (or
  ROOT_ACCOUNT_HARDWARE_MFA_ENABLED) and IAM_ROOT_ACCESS_KEY_CHECK, a Config conformance
  pack, Security Hub with the CIS or FSBP standard (a hub with default standards on counts,
  as they include both), or an SCP that denies the root user (aws:PrincipalArn
  arn:aws:iam::*:root). No account defined, no finding.

- REPO-007 forensics (org-level): an EventBridge rule (AWS::Events::Rule,
  aws_cloudwatch_event_rule, events.Rule, events.CfnRule) whose file names a security finding
  source (aws.guardduty, aws.securityhub, aws.inspector2, aws.macie, "GuardDuty Finding",
  "Security Hub Findings - Imported"), and a capture action anywhere in the IaC or code:
  CreateSnapshot(s), createSnapshot(s) or create_snapshot(s), or the SSM documents
  AWS-CreateSnapshot, AWS-CreateImage, AWSSupport-CollectEC2* or
  AWSSupport-ContainEC2Instance. The rule and the
  capture are not linked target by target: a Lambda that snapshots for backups counts.
  Amazon Detective (a behavior graph) passes on its own.
- REPO-008 containment (org-level): a security group whose logical id, name, description or
  tags (within a few hundred characters of the declaration) say quarantine, isolation,
  isolate, forensic or containment; or an SSM document or code that contains or revokes:
  AWSSupport-ContainEC2Instance, AWS-DisablePublicAccessForSecurityGroup, an AWS*-Revoke*
  runbook, AWSRevokeOlderSessions or an aws:TokenIssueTime deny, DeleteLoginProfile, or
  UpdateAccessKey with Inactive in the same file.

REPO-004 to REPO-008 match text in IaC files (CDK TypeScript/JavaScript/Python,
CloudFormation JSON/YAML, Terraform), less test files. A resource built from a variable
type, or in a module the repo does not hold, is not seen.

Application security in the pipeline (SEC 11) runs by default:

- REPO-009 dependency scan: the build configs (the CI files REPO-002 knows, CodeBuild
  buildspecs and CDK pipeline steps inline in the IaC, and the package.json scripts those
  run) hold a dependency scan: npm/yarn/pnpm audit, pip-audit, safety, osv-scanner, snyk
  test, trivy fs or repo (with a non-zero --exit-code), grype on a directory (with
  --fail-on), OWASP dependency-check (with a failing CVSS score), cargo audit,
  govulncheck, bundler-audit, the dependency review action, or Amazon Inspector (the scan
  action with a vulnerability_threshold_exceeded gate, or inspector-sbomgen and
  inspector-scan). A scan that cannot fail the build does not count: `|| true`,
  `|| exit 0`, or a continue-on-error, allow_failure, ignore-errors or on-failure: CONTINUE
  key beside the step or a block it sits in. No build config at all also fires.
- REPO-010 artifact scan: when the repo builds container images (a Dockerfile, an ECR
  repository, a CDK image asset, a docker build in CI) they need ECR scan on push, ECR
  registry scanning, Amazon Inspector with ECR, or a CI image scan that can fail; when it
  deploys Lambda functions they need Amazon Inspector with LAMBDA or LAMBDA_CODE, or a
  REPO-009 dependency scan. Neither kind present, no finding.
- REPO-011 central package repository: when the repo has a package manifest, it needs AWS
  CodeArtifact in the IaC, `aws codeartifact login` in a build, or a registry other than
  the public default in .npmrc, .yarnrc(.yml), pip.conf/pip.ini, a requirements index-url,
  a poetry or uv source, Maven or Gradle repositories, or GOPROXY.

Service quotas (REL 1), which are per account and Region:

- REPO-012 quota alarms (org-level, off unless rules.org or rules.include): when the IaC
  uses Lambda functions, Elastic IPs, NAT gateways (resources, or a CDK natGateways of one
  or more) or load balancers, it needs a CloudWatch alarm in a file that names the
  AWS/Usage namespace, SERVICE_QUOTA() metric math, the Quota Monitor for AWS solution, or
  an EventBridge rule on aws.trustedadvisor events. A CDK Vpc that takes the default NAT
  gateways, with no natGateways set, is not seen as using NAT.
- REPO-013 failover headroom: sums the literal limits the IaC declares across the repo
  against the default quotas in DEFAULT_QUOTAS. Lambda reserved concurrency over half of
  the 900 that can be reserved fires, as do Elastic IPs (EIP resources plus a CDK VPC's
  natGateways, which allocate one each) over half of 5. Values from variables, parameters,
  count or for_each, or loops are not summed: each literal counts once where it is written.
  NAT gateways per Availability Zone (quota 5) are not checked: the zone of a NAT gateway
  comes from a subnet reference or from maxAzs and the environment, which a text scan does
  not resolve, and a stack rarely needs more than one per zone.

Network address plan (REL 2):

- REPO-014 overlapping VPC CIDRs: the literal IPv4 CIDRs of VPCs across the repo
  (CloudFormation AWS::EC2::VPC and AWS::EC2::VPCCidrBlock CidrBlock; Terraform aws_vpc
  and aws_vpc_ipv4_cidr_block_association cidr_block, and the cidr of a
  terraform-aws-modules/vpc module; CDK ec2.IpAddresses.cidr(), cidr on ec2.Vpc, and
  cidrBlock on CfnVPC and CfnVPCCidrBlock). Any two declarations whose ranges overlap fire,
  in one file or across stacks and modules, naming both. Files for different environments
  (rules/environments.py words in the path, such as dev and prod) are not compared: those
  networks are not connected. A compiled .js next to its .ts source counts once, and
  cdk.out is not walked. CIDRs from variables, parameters, tfvars or IPAM are not seen.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar, List

from aws_arch_agent.models import Finding, Severity
from aws_arch_agent.rules.base import Rule
from aws_arch_agent.rules.environments import from_words
from aws_arch_agent.tools.cfn_yaml import is_cf_template, parse_template_text
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


_ROOT_MFA_RULE = re.compile(r"\bROOT_ACCOUNT(?:_HARDWARE)?_MFA_ENABLED\b")
_ROOT_KEY_RULE = re.compile(r"\bIAM_ROOT_ACCESS_KEY_CHECK\b")
_CONFORMANCE_PACK = re.compile(
    r"AWS::Config::(?:Organization)?ConformancePack\b"
    r"|resource\s+\"aws_config_(?:organization_)?conformance_pack\""
    r"|config\.Cfn(?:Organization)?ConformancePack\("
)
_ROOT_STANDARD = re.compile(
    r"cis-aws-foundations-benchmark|aws-foundational-security-best-practices"
)
# A Security Hub hub turns on the default standards (FSBP and CIS) unless told not to.
_HUB = re.compile(
    r"AWS::SecurityHub::Hub\b|resource\s+\"aws_securityhub_account\"|securityhub\.CfnHub\("
)
_NO_DEFAULT_STANDARDS = re.compile(
    r"\bEnableDefaultStandards[\"']?\s*:\s*[\"']?false\b"
    r"|\benable_default_standards\s*=\s*(?:false|False)\b"
    r"|\benableDefaultStandards\s*:\s*false\b"
)
_ROOT_PRINCIPAL = re.compile(r":iam::\*:root\b")


def root_controls(repo_path: Path) -> tuple[tuple[str, int] | None, set[str]]:
    """The first account definition (path, line), and the root controls the IaC declares:
    "mfa rule", "key rule", "conformance pack", "security hub", "scp"."""
    account: tuple[str, int] | None = None
    found: set[str] = set()
    scp = root_condition = False
    for rel, text in iac_texts(repo_path):
        at = _account_at(text)
        if account is None and at is not None:
            account = (rel, text.count("\n", 0, at) + 1)
        if _ROOT_MFA_RULE.search(text):
            found.add("mfa rule")
        if _ROOT_KEY_RULE.search(text):
            found.add("key rule")
        if _CONFORMANCE_PACK.search(text):
            found.add("conformance pack")
        if _ROOT_STANDARD.search(text) or (
            _HUB.search(text) and not _NO_DEFAULT_STANDARDS.search(text)
        ):
            found.add("security hub")
        scp = scp or bool(_ORG_POLICY.search(text))
        root_condition = root_condition or bool(
            "aws:PrincipalArn" in text and _ROOT_PRINCIPAL.search(text)
        )
    if scp and root_condition:
        found.add("scp")
    return account, found


class RootUserUnchecked(_RepoRule):
    """SEC01-BP02 (Secure account root user and properties) is the Well-Architected best
    practice for the root user, so this rule answers SEC 1, not SEC 2."""

    id = "REPO-006"
    title = "Account baseline does not check root MFA or root access keys"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline", "identity")
    recommendation = (
        "Check the root user of every account the repo creates: add the AWS Config managed "
        "rules ROOT_ACCOUNT_MFA_ENABLED and IAM_ROOT_ACCESS_KEY_CHECK (or a conformance pack "
        "that has them), turn on the Security Hub CIS or FSBP standard, or deny the root user "
        "with an SCP on aws:PrincipalArn arn:aws:iam::*:root. With AWS Organizations, "
        "centralized root access management can remove root credentials from member accounts."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        account, found = root_controls(repo_path)
        if account is None or found - {"mfa rule", "key rule"} or {
            "mfa rule", "key rule"
        } <= found:
            return []
        rel, line = account
        rules = [
            name for key, name in (
                ("mfa rule", "ROOT_ACCOUNT_MFA_ENABLED"), ("key rule", "IAM_ROOT_ACCESS_KEY_CHECK")
            ) if key not in found
        ]
        return [self._finding(
            f"Defines an account ({rel}:{line}); no Config rule {' or '.join(rules)}, "
            "conformance pack, Security Hub CIS or FSBP standard, or SCP that denies the root "
            "user in the IaC",
            file=rel, line=line,
        )]


_EVENT_RULE = re.compile(
    r"AWS::Events::Rule\b|resource\s+\"aws_cloudwatch_event_rule\"|\bevents\.(?:Cfn)?Rule\("
)
_FINDING_SOURCE = re.compile(
    r"\baws\.(?:guardduty|securityhub|inspector2|macie)\b"
    r"|GuardDuty Finding|Security Hub Findings - Imported"
)
_CAPTURE = re.compile(
    r"\b[Cc]reateSnapshots?(?:Command)?\b|\bcreate_snapshots?\b"
    r"|\bAWS-Create(?:Snapshot|Image)\b|\bAWSSupport-CollectEC2\w*"
    r"|\bAWSSupport-ContainEC2Instance\b"
)
_DETECTIVE = re.compile(
    r"AWS::Detective::Graph\b|resource\s+\"aws_detective_graph\"|\bdetective\.CfnGraph\("
)


def forensic_controls(repo_path: Path) -> dict[str, str]:
    """Forensic pieces the IaC and code declare, and the first file with each:
    "finding rule", "capture", "detective"."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _EVENT_RULE.search(text) and _FINDING_SOURCE.search(text):
            found.setdefault("finding rule", rel)
        if _CAPTURE.search(text):
            found.setdefault("capture", rel)
        if _DETECTIVE.search(text):
            found.setdefault("detective", rel)
    return found


class ForensicCaptureMissing(_RepoRule):
    id = "REPO-007"
    title = "No forensic capture is automated for security findings"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Automate forensic capture: an EventBridge rule on GuardDuty or Security Hub findings "
        "that starts a Step Functions or SSM Automation workflow to snapshot the instance's EBS "
        "volumes (AWS-CreateSnapshot) and move it to an isolation security group "
        "(AWSSupport-ContainEC2Instance). Turn on Amazon Detective to investigate findings."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = forensic_controls(repo_path)
        if "detective" in found or {"finding rule", "capture"} <= found.keys():
            return []
        rule = found.get("finding rule")
        seen = f"a finding rule ({rule}) but no capture action" if rule else "none"
        return [self._finding(
            "Searched the IaC and code for an EventBridge rule on GuardDuty, Security Hub, "
            "Inspector or Macie findings together with an EBS snapshot or SSM capture "
            f"runbook, and for Amazon Detective; found {seen}"
        )]


_SECURITY_GROUP = re.compile(
    r"AWS::EC2::SecurityGroup\b|resource\s+\"aws_security_group\""
    r"|\bec2\.(?:Cfn)?SecurityGroup\("
)
_ISOLATION_WORD = re.compile(
    r"quarantin|(?<!private_)isolat(?:e|ion)|forensic|containment", re.IGNORECASE
)
# A CloudFormation logical id comes before the type; CDK and Terraform names come after.
_SG_BEFORE, _SG_AFTER = 120, 400
_CONTAIN_RUNBOOK = re.compile(
    r"\bAWSSupport-ContainEC2Instance\b|\bAWS-DisablePublicAccessForSecurityGroup\b"
    r"|\bAWS[\w-]*-Revoke\w*"
)
_REVOKE_SESSIONS = re.compile(r"\bAWSRevokeOlderSessions\b|\baws:TokenIssueTime\b")
_DELETE_LOGIN = re.compile(
    r"\bDeleteLoginProfile(?:Command)?\b|\bdelete_login_profile\b|\bdeleteLoginProfile\b"
)
_UPDATE_KEY = re.compile(
    r"\bUpdateAccessKey(?:Command)?\b|\bupdate_access_key\b|\bupdateAccessKey\b"
)


def _isolation_group(text: str) -> bool:
    for match in _SECURITY_GROUP.finditer(text):
        start = max(0, match.start() - _SG_BEFORE)
        if _ISOLATION_WORD.search(text, start, match.end() + _SG_AFTER):
            return True
    return False


def containment_controls(repo_path: Path) -> dict[str, str]:
    """Containment controls the IaC and code declare, and the first file with each."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _isolation_group(text):
            found.setdefault("isolation security group", rel)
        if _CONTAIN_RUNBOOK.search(text):
            found.setdefault("containment runbook", rel)
        if (
            _REVOKE_SESSIONS.search(text) or _DELETE_LOGIN.search(text)
            or (_UPDATE_KEY.search(text) and "Inactive" in text)
        ):
            found.setdefault("credential revocation", rel)
    return found


class ContainmentMissing(_RepoRule):
    id = "REPO-008"
    title = "No containment control is deployed"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Pre-deploy containment: a quarantine security group with no rules to move a "
        "compromised instance into, the AWSSupport-ContainEC2Instance runbook, and an "
        "automation that revokes credentials (deactivate access keys with UpdateAccessKey, "
        "or attach AWSRevokeOlderSessions to a role)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        if containment_controls(repo_path):
            return []
        return [self._finding(
            "Searched the IaC and code for a quarantine or isolation security group, an SSM "
            "containment runbook, and credential revocation (UpdateAccessKey to Inactive, "
            "AWSRevokeOlderSessions, DeleteLoginProfile); found none"
        )]


# SEC 11: application security in the pipeline (REPO-009 to REPO-011).

_BUILD_IN_IAC = re.compile(
    r"AWS::CodeBuild::Project\b|resource\s+\"aws_codebuild_project\""
    r"|\bcodebuild\.(?:Cfn|Pipeline)?Project\(|\bBuildSpec\.from_?[oO]bject"
    r"|\b(?:ShellStep|CodeBuildStep)\("
)


def build_texts(repo_path: Path) -> List[tuple[str, str]]:
    """(repo-relative path, text) of each build config: the CI files REPO-002 knows, and
    IaC files that declare a CodeBuild project, an inline buildspec or a pipeline."""
    out: dict[str, str] = {}
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if _is_ci_file(parts):
            out["/".join(parts)] = read_text_safe(path)
    for rel, text in iac_texts(repo_path):
        if rel not in out and (_BUILD_IN_IAC.search(text) or _PIPELINE_IN_IAC.search(text)):
            out[rel] = text
    return sorted(out.items())


def _dash(line: str) -> int | None:
    stripped = line.lstrip(" ")
    return len(line) - len(stripped) if stripped.startswith("- ") else None


def _column(line: str) -> int:
    """Where a YAML line's key starts; a list dash counts as indent."""
    stripped = line.lstrip(" ")
    col = len(line) - len(stripped)
    while stripped.startswith("- "):
        rest = stripped[2:].lstrip(" ")
        col += len(stripped) - len(rest)
        stripped = rest
    return col


def _blocks(lines: List[str], i: int) -> Iterator[tuple[int, int, int]]:
    """(first, last, column) of the block line i sits in, then of each block around it.
    A block is the lines at that column or deeper, cut at a list item that starts before
    it."""
    while True:
        col = _column(lines[i])
        if col == 0:
            return
        top = i
        dash = _dash(lines[i])
        if dash is None or dash >= col:
            while top > 0:
                above = lines[top - 1]
                if above.strip() and _column(above) < col:
                    break
                top -= 1
                dash = _dash(above)
                if above.strip() and dash is not None and dash < col:
                    break
        last = i
        while last + 1 < len(lines):
            below = lines[last + 1]
            dash = _dash(below)
            if below.strip() and (_column(below) < col or (dash is not None and dash < col)):
                break
            last += 1
        yield top, last, col
        parent = top - 1
        while parent >= 0 and not (lines[parent].strip() and _column(lines[parent]) < col):
            parent -= 1
        if parent < 0:
            return
        i = parent


def _step(lines: List[str], i: int) -> str:
    """The list item (CI step) line i sits in, or the line alone."""
    for top, last, _col in _blocks(lines, i):
        dash = _dash(lines[top])
        if dash is not None and dash < _column(lines[top]):
            return "\n".join(lines[top:last + 1])
    return lines[i]


_NO_FAIL_TAIL = re.compile(r"\|\|\s*(?:true\b|exit\s+0\b|:(?=\s|$)|echo\b)")
_NO_FAIL_KEY = re.compile(
    r"^[\s-]*(?:continue-on-error|allow_failure|ignore[-_]errors)\s*:\s*[\"']?true\b"
    r"|^[\s-]*on-failure\s*:\s*[\"']?continue\b",
    re.IGNORECASE,
)


def _cannot_fail(lines: List[str], i: int, tail: str) -> bool:
    """The command's failure is swallowed (|| true) or its step may fail (continue-on-error,
    allow_failure, ignore-errors, on-failure: CONTINUE beside it or around it)."""
    if _NO_FAIL_TAIL.search(tail):
        return True
    for top, last, col in _blocks(lines, i):
        for line in lines[top:last + 1]:
            if _column(line) == col and _NO_FAIL_KEY.search(line):
                return True
    return False


_EXIT_CODE = re.compile(r"--exit-code[=\s]+[\"']?[1-9]|\bexit-code\s*:\s*[\"']?[1-9]")
_GRYPE_FAIL = re.compile(r"--fail-on\b|\s-f\s+\w")
_CVSS_FAIL = re.compile(r"fail(?:On|BuildOn)CVSS", re.IGNORECASE)
_FS_SCAN_TYPE = re.compile(r"\bscan-type\s*:\s*[\"']?(?:fs|filesystem|repo|rootfs)\b")
_NO_FAIL_BUILD = re.compile(r"\bfail-build\s*:\s*[\"']?false\b")

# (name, kind, pattern). kind is "dependency", "image" or "both"; "trivy-action" and
# "anchore" take their kind from the step's scan-type or path.
_SCANS: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple(
    (name, kind, re.compile(pattern)) for name, kind, pattern in (
        ("npm audit", "dependency", r"\b(?:npm|yarn|pnpm)\s+audit\b"),
        ("pip-audit", "dependency", r"\bpip-audit\b"),
        ("safety", "dependency", r"\bsafety\s+(?:check|scan)\b"),
        ("osv-scanner", "dependency", r"\bosv-scanner\b"),
        ("snyk test", "dependency", r"\bsnyk\s+test\b|\bsnyk/actions/(?!docker\b)[\w-]+"),
        ("trivy fs", "dependency", r"\btrivy\s+(?:fs|filesystem|repo|repository|rootfs)\b"),
        ("grype", "dependency", r"\bgrype\s+(?:dir:|\.(?=\s|$|[\"']))"),
        ("dependency-check", "dependency",
         r"\bdependency-check(?:\.sh|-maven|-gradle)?\b|\bdependencyCheck(?:Analyze|Aggregate)\b"),
        ("cargo audit", "dependency", r"\bcargo\s+audit\b"),
        ("govulncheck", "dependency", r"\bgovulncheck\b"),
        ("bundler-audit", "dependency", r"\bbundler?-audit\b|\bbundle\s+audit\b"),
        ("dependency review", "dependency", r"\bactions/dependency-review-action\b"),
        ("Amazon Inspector", "both", r"vulnerability-scan-github-action-for-amazon-inspector"),
        ("Amazon Inspector", "both", r"\binspector-(?:scan|sbomgen)\b"),
        ("trivy image", "image", r"\btrivy\s+image\b"),
        ("trivy-action", "trivy-action", r"\baquasecurity/trivy-action\b"),
        ("anchore scan", "anchore", r"\banchore/scan-action\b"),
        ("grype", "image", r"\bgrype\s+(?!dir:|\.(?:\s|$)|sbom:|file:|-)\S"),
        ("docker scout", "image", r"\bdocker\s+scout\s+cves\b"),
        ("snyk container", "image", r"\bsnyk\s+container\s+test\b|\bsnyk/actions/docker\b"),
        ("ECR image scan", "image",
         r"\becr\s+start-image-scan\b|\bimage-scan-complete\b|\bdescribe-image-scan-findings\b"),
    )
)


def _set_to_fail(name: str, tail: str, step: str, text: str) -> bool:
    """Tools that pass on findings unless told otherwise."""
    if name in ("trivy fs", "trivy image", "trivy-action", "docker scout"):
        return bool(_EXIT_CODE.search(tail if name != "trivy-action" else step))
    if name == "grype":
        return bool(_GRYPE_FAIL.search(tail))
    if name == "anchore scan":
        return not _NO_FAIL_BUILD.search(step)
    if name == "dependency-check":
        return bool(_CVSS_FAIL.search(step) or _CVSS_FAIL.search(text))
    if "github-action-for-amazon-inspector" in step:
        return "vulnerability_threshold_exceeded" in text
    return True


_TAIL_END = re.compile(r"\\n|[\"'`;\n]|&&")


def _scans_in(text: str) -> Iterator[tuple[str, str, bool]]:
    """(name, kind, can fail the build) for each scan in a build text."""
    lines = text.split("\n")
    for name, kind, pattern in _SCANS:
        for match in pattern.finditer(text):
            i = text.count("\n", 0, match.start())
            rest = text[match.end():]
            end = _TAIL_END.search(rest)
            tail = rest[:end.start()] if end else rest
            step = _step(lines, i)
            if kind == "trivy-action":
                kind_here = "dependency" if _FS_SCAN_TYPE.search(step) else "image"
            elif kind == "anchore":
                kind_here = "dependency" if re.search(r"^[\s-]*path\s*:", step, re.M) else "image"
            else:
                kind_here = kind
            fails = _set_to_fail(name, tail, step, text) and not _cannot_fail(lines, i, tail)
            yield name, kind_here, fails


_RUN_SCRIPT = re.compile(
    r"\b(?:npm|pnpm)\s+(?:run(?:-script)?\s+)?([\w:.-]+)|\byarn\s+(?:run\s+)?([\w:.-]+)"
)


def _package_scripts(repo_path: Path) -> dict[str, str]:
    """Every package.json script outside tests, by name (the first one wins)."""
    scripts: dict[str, str] = {}
    for path in walk(repo_path):
        if path.name != "package.json" or _in_test_dir(_rel_parts(path, repo_path)):
            continue
        try:
            doc = json.loads(read_text_safe(path))
        except ValueError:
            continue
        found = doc.get("scripts") if isinstance(doc, dict) else None
        if isinstance(found, dict):
            for name, command in found.items():
                if isinstance(command, str):
                    scripts.setdefault(str(name), command)
    return scripts


def _scripts_run(texts: List[str], scripts: dict[str, str]) -> List[tuple[str, str]]:
    """(script name, command) of each package.json script the builds run, two levels deep."""
    out: dict[str, str] = {}
    todo = list(texts)
    for _depth in range(3):
        names = {
            m.group(1) or m.group(2) for text in todo for m in _RUN_SCRIPT.finditer(text)
        }
        todo = []
        for name in sorted(names):
            if name in scripts and name not in out:
                out[name] = scripts[name]
                todo.append(scripts[name])
    return sorted(out.items())


def pipeline_scans(repo_path: Path) -> tuple[List[str], List[tuple[str, str, str, bool]]]:
    """The build configs found, and each scan in them or in the package.json scripts they
    run: (name, kind, where, can fail the build)."""
    builds = build_texts(repo_path)
    scans: List[tuple[str, str, str, bool]] = []
    for rel, text in builds:
        scans.extend((name, kind, rel, fails) for name, kind, fails in _scans_in(text))
    run = _scripts_run([text for _rel, text in builds], _package_scripts(repo_path))
    for script, command in run:
        where = f"package.json script {script}"
        scans.extend((name, kind, where, fails) for name, kind, fails in _scans_in(command))
    return [rel for rel, _text in builds], scans


def _passing(scans: List[tuple[str, str, str, bool]], kind: str) -> bool:
    return any(fails and k in (kind, "both") for _n, k, _w, fails in scans)


def _weak(scans: List[tuple[str, str, str, bool]], kind: str) -> str:
    """ "found <scan> in <where>, but it cannot fail the build", or "found none". """
    for name, k, where, fails in scans:
        if not fails and k in (kind, "both"):
            return f"found {name} in {where}, but it cannot fail the build"
    return "found none"


def _listed(items: List[str], limit: int = 3) -> str:
    more = f" and {len(items) - limit} more" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


_DEPENDENCY_TOOLS = (
    "npm/yarn/pnpm audit, pip-audit, safety, osv-scanner, snyk test, trivy fs, grype, "
    "OWASP dependency-check, cargo audit, govulncheck, bundler-audit, Amazon Inspector"
)


class DependencyScanMissing(_RepoRule):
    id = "REPO-009"
    title = "The build does not scan dependencies"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Scan dependencies in every build and fail it on findings: npm audit "
        "--audit-level=high, pip-audit, osv-scanner, or Amazon Inspector (inspector-sbomgen "
        "and inspector-scan, or the Inspector scan action with a threshold gate). Do not add "
        "|| true or continue-on-error to the scan step."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        builds, scans = pipeline_scans(repo_path)
        if _passing(scans, "dependency"):
            return []
        if not builds:
            return [self._finding(
                "Searched the repo for a build to run a dependency scan (a CI config, or a "
                "CodeBuild buildspec or pipeline in the IaC); found none"
            )]
        return [self._finding(
            f"Searched the build configs ({_listed(builds)}) and the package.json scripts "
            f"they run for a dependency scan that fails the build ({_DEPENDENCY_TOOLS}); "
            f"{_weak(scans, 'dependency')}"
        )]


_CONTAINER_IN_IAC = re.compile(
    r"AWS::ECR::Repository\b|resource\s+\"aws_ecr_repository\"|\becr\.(?:Cfn)?Repository\("
    r"|\bContainerImage\.from_?[aA]sset|\bDockerImageAsset\(|\bDockerImage(?:Function|Code)\b"
)
_IMAGE_BUILD = re.compile(
    r"\bdocker\s+(?:buildx\s+)?build\b|\bdocker/build-push-action\b|\bpodman\s+build\b"
)
_FUNCTION_IN_IAC = re.compile(
    r"AWS::(?:Lambda|Serverless)::Function\b|resource\s+\"aws_lambda_function\""
    r"|\b_?lambda\.(?:Cfn)?Function\(|\b(?:Nodejs|Python|Go)Function\("
)
_SCAN_ON_PUSH = re.compile(
    r"\bScanOnPush[\"']?\s*:\s*[\"']?true\b|\bscan_on_push\s*=\s*true\b"
    r"|\bimageScanOnPush\s*:\s*true\b|\bimage_scan_on_push\s*=\s*True\b"
)
_REGISTRY_SCANNING = re.compile(
    r"AWS::ECR::RegistryScanningConfiguration\b"
    r"|resource\s+\"aws_ecr_registry_scanning_configuration\""
    r"|\becr\.CfnRegistryScanningConfiguration\("
)
# CloudFormation has no Inspector enabler; templates turn it on with a custom resource.
_INSPECTOR = re.compile(
    r"resource\s+\"aws_inspector2_(?:enabler|organization_configuration)\""
    r"|\binspector2:Enable\b|[\"']Inspector2[\"']|\binspector2\s+enable\b"
)
_INSPECTOR_ECR = re.compile(r"[\"']ECR[\"']|\becr\s*=\s*true\b|--resource-types[^\n]*\bECR\b")
_INSPECTOR_LAMBDA = re.compile(
    r"[\"']LAMBDA(?:_CODE)?[\"']|\blambda(?:_code)?\s*=\s*true\b"
    r"|--resource-types[^\n]*\bLAMBDA\b"
)


def artifact_controls(repo_path: Path) -> tuple[dict[str, str], set[str]]:
    """Artifact kinds the repo ships ("container images", "Lambda functions") and where
    first seen, and the scanning the IaC turns on: "ecr", "inspector ecr",
    "inspector lambda"."""
    kinds: dict[str, str] = {}
    controls: set[str] = set()
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        name = path.name.lower()
        if _in_test_dir(parts):
            continue
        if name in ("dockerfile", "containerfile") or name.startswith("dockerfile.") or (
            name.endswith(".dockerfile")
        ):
            kinds.setdefault("container images", "/".join(parts))
    texts = dict(iac_texts(repo_path))
    texts.update(build_texts(repo_path))
    for rel, text in sorted(texts.items()):
        if _CONTAINER_IN_IAC.search(text) or _IMAGE_BUILD.search(text):
            kinds.setdefault("container images", rel)
        if _FUNCTION_IN_IAC.search(text):
            kinds.setdefault("Lambda functions", rel)
        if _SCAN_ON_PUSH.search(text) or _REGISTRY_SCANNING.search(text):
            controls.add("ecr")
        if _INSPECTOR.search(text):
            if _INSPECTOR_ECR.search(text):
                controls.add("inspector ecr")
            if _INSPECTOR_LAMBDA.search(text):
                controls.add("inspector lambda")
    return kinds, controls


class ArtifactScanMissing(_RepoRule):
    id = "REPO-010"
    title = "Container or function artifacts are not scanned before deploy"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Scan what you deploy: turn on Amazon ECR enhanced scanning (a registry scanning "
        "configuration, or Amazon Inspector with ECR) or at least scan on push, and Amazon "
        "Inspector Lambda standard and code scanning for functions. In the pipeline, scan "
        "the image before it is pushed (trivy image --exit-code 1, the Inspector scan action)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        kinds, controls = artifact_controls(repo_path)
        if not kinds:
            return []
        _builds, scans = pipeline_scans(repo_path)
        unscanned: List[str] = []
        if "container images" in kinds and not (
            controls & {"ecr", "inspector ecr"} or _passing(scans, "image")
        ):
            unscanned.append(
                f"Builds container images ({kinds['container images']}); searched for ECR "
                "scan on push, ECR registry scanning, Amazon Inspector for ECR, and a CI "
                f"image scan that fails the build; {_weak(scans, 'image')}"
            )
        if "Lambda functions" in kinds and not (
            "inspector lambda" in controls or _passing(scans, "dependency")
        ):
            unscanned.append(
                f"Deploys Lambda functions ({kinds['Lambda functions']}); searched for "
                "Amazon Inspector Lambda scanning and a dependency scan that fails the "
                "build; found none"
            )
        if not unscanned:
            return []
        return [self._finding("; ".join(unscanned))]


_MANIFEST = re.compile(
    r"package\.json|requirements[\w.-]*\.txt|pyproject\.toml|pipfile|go\.mod|pom\.xml"
    r"|build\.gradle(?:\.kts)?"
)
_CODEARTIFACT = re.compile(
    r"AWS::CodeArtifact::Repository\b|resource\s+\"aws_codeartifact_repository\""
    r"|\bcodeartifact\.CfnRepository\(|\bcodeartifact\s+(?:login|get-authorization-token)\b"
)
_PUBLIC_HOSTS = frozenset({
    "registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com", "pypi.org",
    "pypi.python.org", "files.pythonhosted.org", "repo.maven.apache.org", "repo1.maven.org",
    "maven.google.com", "dl.google.com", "plugins.gradle.org", "jcenter.bintray.com",
    "proxy.golang.org",
})
# A registry url per config file name; "*" applies to the build configs.
_REGISTRY_URL: tuple[tuple[re.Pattern[str], re.Pattern[str]], ...] = tuple(
    (re.compile(name), re.compile(url, re.M | re.S)) for name, url in (
        (r"\.npmrc", r"^\s*registry\s*=\s*(\S+)"),
        (r"\.yarnrc\.ya?ml", r"^\s*npmRegistryServer\s*:\s*[\"']?([^\s\"']+)"),
        (r"\.yarnrc", r"^\s*registry\s+[\"']?([^\s\"']+)"),
        (r"pip\.(?:conf|ini)", r"^\s*index-url\s*=\s*(\S+)"),
        (r"requirements[\w.-]*\.txt", r"^\s*(?:--index-url|-i)[=\s]+(\S+)"),
        (r"pyproject\.toml",
         r"^\s*\[\[tool\.(?:poetry\.source|uv\.index)\]\][^\[]*?^\s*url\s*=\s*\"([^\"]+)\""),
        (r"pom\.xml|settings\.xml",
         r"<(?:repository|mirror)>(?:(?!</(?:repository|mirror)>).)*?<url>\s*([^<\s]+)"),
        (r"(?:build|settings)\.gradle(?:\.kts)?",
         r"\bmaven\s*\{[^}]*?\burl\s*=?\s*(?:uri\()?\s*[\"']([^\"']+)"),
        (r"\*",
         r"\bnpm\s+config\s+set\s+registry[=\s]+(\S+)|\bPIP_INDEX_URL\s*[:=]\s*[\"']?([^\s\"']+)"
         r"|\bGOPROXY\s*[:=]\s*[\"']?([^\s\"',]+)"),
    )
)


def _private_url(url: str) -> bool:
    if url in ("direct", "off"):
        return False
    host = re.match(r"[a-z][\w+.-]*://(?:[^@/]*@)?([^/:]+)", url, re.IGNORECASE)
    return host is None or host.group(1).lower() not in _PUBLIC_HOSTS


def _private_registry(name: str, text: str) -> bool:
    for file_name, url in _REGISTRY_URL:
        if file_name.fullmatch(name):
            for match in url.finditer(text):
                value = next((g for g in match.groups() if g), "")
                if value and _private_url(value):
                    return True
    return False


def package_sources(repo_path: Path) -> tuple[str | None, dict[str, str]]:
    """The first package manifest, and each central repository control and where."""
    manifest: str | None = None
    found: dict[str, str] = {}
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if _in_test_dir(parts):
            continue
        name = path.name.lower()
        rel = "/".join(parts)
        if manifest is None and _MANIFEST.fullmatch(name):
            manifest = rel
        if any(f.fullmatch(name) for f, _url in _REGISTRY_URL[:-1]) and _private_registry(
            name, read_text_safe(path)
        ):
            found.setdefault("private registry", rel)
    for rel, text in [*iac_texts(repo_path), *build_texts(repo_path)]:
        if _CODEARTIFACT.search(text):
            found.setdefault("CodeArtifact", rel)
    for rel, text in build_texts(repo_path):
        if _private_registry("*", text):
            found.setdefault("private registry", rel)
    return manifest, found


class CentralPackageRepoMissing(_RepoRule):
    id = "REPO-011"
    title = "Packages are not pulled through a central repository"
    category = "Security"
    severity = "Low"
    themes = ("security-baseline",)
    recommendation = (
        "Pull packages through AWS CodeArtifact (or another private repository) with "
        "upstreams to the public registries, and point the build at it: aws codeartifact "
        "login, or the registry in .npmrc, pip.conf or the Maven and Gradle settings."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        manifest, found = package_sources(repo_path)
        if manifest is None or found:
            return []
        return [self._finding(
            f"Has a package manifest ({manifest}); searched for AWS CodeArtifact in the IaC, "
            "aws codeartifact login in a build, and a private registry in .npmrc, .yarnrc, "
            "pip.conf, a requirements index-url, a poetry or uv source, Maven or Gradle "
            "repositories, or GOPROXY; found none"
        )]


# Services whose per-account quotas a busy stack runs into (REPO-012).
QUOTA_HEAVY: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Lambda", re.compile(
        r"AWS::(?:Lambda|Serverless)::Function\b|resource\s+\"aws_lambda_function\""
        r"|\b_?lambda_?\.(?:Cfn)?Function\(|\b(?:Nodejs|Python|DockerImage)Function\("
    )),
    ("Elastic IPs", re.compile(
        r"AWS::EC2::EIP\b|resource\s+\"aws_eip\"|\bec2\.CfnEIP\("
    )),
    ("NAT gateways", re.compile(
        r"AWS::EC2::NatGateway\b|resource\s+\"aws_nat_gateway\"|\bec2\.CfnNatGateway\("
        r"|\b(?:natGateways\s*:|nat_gateways\s*=)\s*[1-9]|\bNatProvider\.gateway\("
    )),
    ("load balancers", re.compile(
        r"AWS::ElasticLoadBalancing(?:V2)?::LoadBalancer\b"
        r"|resource\s+\"aws_(?:lb|alb|elb)\""
        r"|\b(?:Application|Network)LoadBalancer\(|\belbv2\.CfnLoadBalancer\("
        r"|\b(?:Application|Network)LoadBalanced\w+\("
    )),
)
_ALARM = re.compile(
    r"AWS::CloudWatch::Alarm\b|resource\s+\"aws_cloudwatch_metric_alarm\""
    r"|\bcloudwatch\.(?:Cfn)?Alarm\(|\.create_?[Aa]larm\("
)
_USAGE_NAMESPACE = re.compile(r"\bnamespace[\"']?\s*[:=]\s*[\"']?AWS/Usage\b", re.IGNORECASE)
_SERVICE_QUOTA_MATH = re.compile(r"\bSERVICE_QUOTA\s*\(")
_QUOTA_MONITOR = re.compile(r"quota[-_ ]?monitor", re.IGNORECASE)
_TRUSTED_ADVISOR = re.compile(r"\baws\.trustedadvisor\b")


def quota_usage(repo_path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """The quota-heavy services the IaC uses, and the quota alarms it declares.

    Each maps a name to the first file with it.
    """
    used: dict[str, str] = {}
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        for name, pattern in QUOTA_HEAVY:
            if pattern.search(text):
                used.setdefault(name, rel)
        if _ALARM.search(text) and _USAGE_NAMESPACE.search(text):
            found.setdefault("AWS/Usage alarm", rel)
        if _SERVICE_QUOTA_MATH.search(text):
            found.setdefault("SERVICE_QUOTA metric math", rel)
        if _QUOTA_MONITOR.search(text):
            found.setdefault("Quota Monitor for AWS", rel)
        if _EVENT_RULE.search(text) and _TRUSTED_ADVISOR.search(text):
            found.setdefault("Trusted Advisor service limit events", rel)
    return used, found


class QuotaAlarmMissing(_RepoRule):
    id = "REPO-012"
    title = "No Service Quotas usage alarm for the services the stack uses"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Alarm on quota usage before it blocks a deploy or a scale-out: a CloudWatch alarm "
        "on the AWS/Usage metric with SERVICE_QUOTA() metric math (for example at 80%), the "
        "Quota Monitor for AWS solution, or Trusted Advisor service limit checks routed "
        "through EventBridge."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        used, found = quota_usage(repo_path)
        if not used or found:
            return []
        services = ", ".join(f"{name} ({rel})" for name, rel in used.items())
        return [self._finding(
            f"Uses {services}; searched the IaC for a CloudWatch alarm on the AWS/Usage "
            "namespace, SERVICE_QUOTA metric math, Quota Monitor for AWS, and Trusted Advisor "
            "service limit events on EventBridge; found none"
        )]


# Default quotas REPO-013 measures the IaC against, per account and Region. Sources: the
# Lambda quotas page (/lambda/latest/dg/gettingstarted-limits.html: 1,000 concurrent
# executions, of which 100 always stay unreserved), the Amazon VPC quotas page
# (/vpc/latest/userguide/amazon-vpc-limits.html: 5 Elastic IPs per Region, 5 NAT gateways
# per Availability Zone) and the EC2 Elastic IP page. An account may have raised them; the
# scan cannot see that, so it uses the defaults.
DEFAULT_QUOTAS: dict[str, int] = {
    "lambda_concurrency": 1_000,
    "lambda_unreserved_minimum": 100,
    "elastic_ips": 5,
    "nat_gateways_per_az": 5,
}
# Failover can double the load on what is left, so a declared limit over half the quota
# leaves no room for it.
_FAILOVER_SHARE = 0.5

_RESERVED_CONCURRENCY = re.compile(
    r"\b(?:ReservedConcurrentExecutions|reserved_concurrent_executions"
    r"|reservedConcurrentExecutions)[\"']?\s*[:=]\s*[\"']?(\d+)\b"
)
_EIP_DECLARATION = QUOTA_HEAVY[1][1]
# A CDK VPC's NAT gateways each allocate an Elastic IP of their own. CloudFormation and
# Terraform NAT gateways take one from an EIP resource, which is counted already.
_CDK_NAT_GATEWAYS = re.compile(r"\b(?:natGateways\s*:|nat_gateways\s*=)\s*(\d+)\b")


def declared_limits(repo_path: Path) -> dict[str, list[tuple[str, int]]]:
    """Per limit, the (file, amount) of each literal the IaC declares."""
    limits: dict[str, list[tuple[str, int]]] = {"lambda_concurrency": [], "elastic_ips": []}
    for rel, text in iac_texts(repo_path):
        reserved = sum(int(m.group(1)) for m in _RESERVED_CONCURRENCY.finditer(text))
        if reserved:
            limits["lambda_concurrency"].append((rel, reserved))
        eips = len(_EIP_DECLARATION.findall(text))
        if not rel.endswith((".json", ".yaml", ".yml", ".template", ".tf")):
            eips += sum(int(m.group(1)) for m in _CDK_NAT_GATEWAYS.finditer(text))
        if eips:
            limits["elastic_ips"].append((rel, eips))
    return limits


def _files(parts: list[tuple[str, int]]) -> str:
    return ", ".join(f"{rel} {amount}" for rel, amount in parts)


class FailoverHeadroomMissing(_RepoRule):
    id = "REPO-013"
    title = "Limits the IaC sets leave no room for failover"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Keep what the IaC reserves well under the quota, so a failover that shifts the load "
        "here can still be served: lower reserved concurrency or Elastic IP use, or request "
        "a quota increase in Service Quotas before you need it."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        limits = declared_limits(repo_path)
        findings: List[Finding] = []
        reservable = (
            DEFAULT_QUOTAS["lambda_concurrency"] - DEFAULT_QUOTAS["lambda_unreserved_minimum"]
        )
        reserved = sum(amount for _rel, amount in limits["lambda_concurrency"])
        if reserved > reservable * _FAILOVER_SHARE:
            findings.append(self._finding(
                f"Lambda reserved concurrency sums to {reserved} "
                f"({_files(limits['lambda_concurrency'])}); the default quota is "
                f"{DEFAULT_QUOTAS['lambda_concurrency']:,} per Region with "
                f"{DEFAULT_QUOTAS['lambda_unreserved_minimum']} unreserved, so {reservable} "
                f"can be reserved; over half ({int(reservable * _FAILOVER_SHARE)}) leaves no "
                "room for failover"
            ))
        eips = sum(amount for _rel, amount in limits["elastic_ips"])
        if eips > DEFAULT_QUOTAS["elastic_ips"] * _FAILOVER_SHARE:
            findings.append(self._finding(
                f"Elastic IPs (EIP resources and CDK NAT gateways) number {eips} "
                f"({_files(limits['elastic_ips'])}); the default quota is "
                f"{DEFAULT_QUOTAS['elastic_ips']} per Region; over half leaves no room for "
                "failover"
            ))
        return findings


# VPC CIDR declarations REPO-014 compares (REL 2).
_TF_VPC_BLOCK = re.compile(
    r"\bresource\s+\"(aws_vpc|aws_vpc_ipv4_cidr_block_association)\"\s+\"([^\"]+)\"\s*\{"
)
_TF_VPC_MODULE = re.compile(r"\bmodule\s+\"([^\"]+)\"\s*\{")
_TF_VPC_MODULE_SOURCE = re.compile(r"\bsource\s*=\s*\"[^\"]*terraform-aws-modules/vpc\b")
_TF_CIDR = re.compile(r"^\s*cidr_block\s*=\s*\"([^\"]+)\"", re.MULTILINE)
_TF_MODULE_CIDR = re.compile(r"^\s*cidr\s*=\s*\"([^\"]+)\"", re.MULTILINE)
_CDK_IP_ADDRESSES = re.compile(r"\bIpAddresses\.cidr\(\s*['\"]([^'\"]+)['\"]")
_CDK_VPC_CALL = re.compile(r"(?<![\w.])(?:ec2\.)?Vpc\(")
_CDK_VPC_CIDR = re.compile(r"(?<![\w.])cidr\s*[:=]\s*['\"]([^'\"]+)['\"]")
_CDK_CFN_VPC_CALL = re.compile(r"\bCfnVPC(?:CidrBlock)?\(")
_CDK_CFN_CIDR = re.compile(r"\b(?:cidrBlock|cidr_block)\s*[:=]\s*['\"]([^'\"]+)['\"]")
_CF_VPC_TYPES = ("AWS::EC2::VPC", "AWS::EC2::VPCCidrBlock")


def _braced(text: str, open_brace: int, opener: str = "{", closer: str = "}") -> str:
    """The text between the bracket at open_brace and its match (or the end of text)."""
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == opener:
            depth += 1
        elif text[i] == closer:
            depth -= 1
            if depth == 0:
                return text[open_brace + 1:i]
    return text[open_brace + 1:]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def _cf_vpc_cidrs(rel: str, text: str) -> List[tuple[str, int, str, str]]:
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template, nothing to compare
        return []
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    out: List[tuple[str, int, str, str]] = []
    for name, body in (resources.items() if isinstance(resources, dict) else ()):
        if not isinstance(body, dict) or body.get("Type") not in _CF_VPC_TYPES:
            continue
        props = body.get("Properties")
        cidr = props.get("CidrBlock") if isinstance(props, dict) else None
        if type(cidr) is str:
            at = text.find(str(name))
            out.append((cidr, _line_of(text, text.find(cidr, max(at, 0))), str(name), rel))
    return out


def _tf_vpc_cidrs(rel: str, text: str) -> List[tuple[str, int, str, str]]:
    out: List[tuple[str, int, str, str]] = []
    for block in _TF_VPC_BLOCK.finditer(text):
        body = _braced(text, block.end() - 1)
        cidr = _TF_CIDR.search(body)
        if cidr:
            out.append((cidr.group(1), _line_of(text, block.start()),
                        f"{block.group(1)}.{block.group(2)}", rel))
    for block in _TF_VPC_MODULE.finditer(text):
        body = _braced(text, block.end() - 1)
        cidr = _TF_MODULE_CIDR.search(body)
        if cidr and _TF_VPC_MODULE_SOURCE.search(body):
            out.append((cidr.group(1), _line_of(text, block.start()),
                        f"module.{block.group(1)}", rel))
    return out


def _cdk_vpc_cidrs(rel: str, text: str) -> List[tuple[str, int, str, str]]:
    out: List[tuple[str, int, str, str]] = []
    for match in _CDK_IP_ADDRESSES.finditer(text):
        out.append((match.group(1), _line_of(text, match.start()), "IpAddresses.cidr", rel))
    for pattern, key, label in ((_CDK_VPC_CALL, _CDK_VPC_CIDR, "Vpc cidr"),
                                (_CDK_CFN_VPC_CALL, _CDK_CFN_CIDR, "CfnVPC cidrBlock")):
        for call in pattern.finditer(text):
            args = _braced(text, call.end() - 1, "(", ")")
            for match in key.finditer(args):
                out.append((match.group(1), _line_of(text, call.start()), label, rel))
    return out


def vpc_cidrs(repo_path: Path) -> List[tuple[ipaddress.IPv4Network, int, str, str]]:
    """Literal IPv4 VPC CIDRs the IaC declares: (network, line, what declares it, file).

    A compiled .js next to its .ts source is the same declaration and is skipped.
    """
    texts = list(iac_texts(repo_path))
    names = {rel for rel, _text in texts}
    out: List[tuple[ipaddress.IPv4Network, int, str, str]] = []
    for rel, text in texts:
        suffix = Path(rel).suffix.lower()
        if suffix == ".js" and rel[:-3] + ".ts" in names:
            continue
        if suffix == ".tf":
            found = _tf_vpc_cidrs(rel, text)
        elif suffix in (".ts", ".js", ".py"):
            found = _cdk_vpc_cidrs(rel, text)
        elif "AWS::EC2::VPC" in text:
            found = _cf_vpc_cidrs(rel, text)
        else:
            continue
        for cidr, line, what, where in found:
            try:
                network = ipaddress.IPv4Network(cidr.strip(), strict=False)
            except ValueError:
                continue  # an IPv6 block, a token or a template string
            out.append((network, line, what, where))
    return out


def _separate_environments(rel_a: str, rel_b: str) -> bool:
    """True when two files are for different environments (dev and prod), which never
    connect, so the same range in both is not an overlap."""
    env_a, env_b = from_words(rel_a), from_words(rel_b)
    return env_a is not None and env_b is not None and env_a != env_b


class VpcCidrOverlap(_RepoRule):
    id = "REPO-014"
    title = "VPC CIDR ranges overlap"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Give each VPC that may ever be connected (peering, a transit gateway, VPN or Direct "
        "Connect) its own range from one address plan, for example from Amazon VPC IP Address "
        "Manager (IPAM) pools. Overlapping ranges cannot be peered or routed to each other "
        "without NAT, and fixing them later means re-addressing the VPC."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cidrs = vpc_cidrs(repo_path)
        findings: List[Finding] = []
        for i, (net_a, line_a, what_a, rel_a) in enumerate(cidrs):
            for net_b, line_b, what_b, rel_b in cidrs[i + 1:]:
                if not net_a.overlaps(net_b) or _separate_environments(rel_a, rel_b):
                    continue
                findings.append(self._finding(
                    f"{net_a} ({what_a}, {rel_a}:{line_a}) overlaps {net_b} "
                    f"({what_b}, {rel_b}:{line_b})",
                    file=rel_b, line=line_b,
                ))
        return findings


REPO_RULES: List[Rule] = [
    RepoTestsMissing(), RepoPipelineMissing(), SingleEnvironment(),
    OrgGuardrailsMissing(), AccountBaselineMissing(), RootUserUnchecked(),
    ForensicCaptureMissing(), ContainmentMissing(),
    DependencyScanMissing(), ArtifactScanMissing(), CentralPackageRepoMissing(),
    QuotaAlarmMissing(), FailoverHeadroomMissing(), VpcCidrOverlap(),
]
