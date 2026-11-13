"""SEC 1: organization guardrails (REPO-004) and an account security baseline (REPO-005)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import org_guardrails

SOURCES = ("cdk", "cloudformation", "terraform")
BASELINE = (
    "CloudTrail trail", "Config recorder", "GuardDuty detector", "Security Hub",
    "IAM Access Analyzer",
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict[str, tuple[str, dict]]) -> str:
    return json.dumps({"Resources": {
        name: {"Type": rtype, "Properties": props} for name, (rtype, props) in resources.items()
    }})


def _workload(root: Path, source: str) -> None:
    """One app stack with a bucket: no org resources, no account."""
    if source == "cdk":
        _write(root / "package.json", "{}")
        _write(root / "lib" / "stack.ts", "new s3.Bucket(this, 'Data');\n")
    elif source == "cloudformation":
        _write(root / "stack.template.json", _cfn({"Data": ("AWS::S3::Bucket", {})}))
    else:
        _write(root / "main.tf", 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n')


# One guardrail of each kind, per source, as each source writes it.
GUARDRAILS: dict[str, dict[str, str]] = {
    "scp": {
        "cdk": "new organizations.CfnPolicy(this, 'Deny', "
               "{ name: 'deny', type: 'SERVICE_CONTROL_POLICY', content });\n",
        "cloudformation": _cfn({"Deny": ("AWS::Organizations::Policy", {
            "Name": "deny", "Type": "SERVICE_CONTROL_POLICY", "Content": {}})}),
        # Terraform's type defaults to SERVICE_CONTROL_POLICY.
        "terraform": 'resource "aws_organizations_policy" "deny" {\n  name = "deny"\n}\n',
    },
    "control_tower": {
        "cdk": "new controltower.CfnEnabledControl(this, 'C', "
               "{ controlIdentifier, targetIdentifier });\n",
        "cloudformation": _cfn({"C": ("AWS::ControlTower::EnabledControl", {
            "ControlIdentifier": "x", "TargetIdentifier": "y"})}),
        "terraform": 'resource "aws_controltower_control" "c" {\n}\n',
    },
    "org_trail": {
        "cdk": "new cloudtrail.Trail(this, 'T', { isOrganizationTrail: true });\n",
        "cloudformation": _cfn({"T": ("AWS::CloudTrail::Trail", {
            "IsLogging": True, "IsOrganizationTrail": True})}),
        "terraform": 'resource "aws_cloudtrail" "t" {\n  is_organization_trail = true\n}\n',
    },
    "ou": {
        "cdk": "new organizations.CfnOrganizationalUnit(this, 'Ou', { name: 'w', parentId });\n",
        "cloudformation": _cfn({"Ou": ("AWS::Organizations::OrganizationalUnit", {
            "Name": "w", "ParentId": "r-1"})}),
        "terraform": 'resource "aws_organizations_organizational_unit" "w" {\n}\n',
    },
}
_ORG_FILE = {"cdk": "lib/org.ts", "cloudformation": "org.template.json", "terraform": "org.tf"}


def _scan(root: Path, **kwargs):
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False, **kwargs)
    return ctx, findings


def _sec1(findings, ran):
    return {a.question.id: a for a in well_architected.answers(findings, ran)}["SEC 1"]


@pytest.mark.parametrize("source", SOURCES)
def test_repo_004_is_off_by_default_so_sec01_bp01_is_not_checked(
    tmp_path: Path, source: str
) -> None:
    _workload(tmp_path, source)
    ctx, findings = _scan(tmp_path)
    assert ctx.source == source
    assert "REPO-004" not in {f.id for f in findings}
    assert "REPO-004" not in ctx.rules_run
    sec1 = _sec1(findings, ctx.rules_run)
    assert not sec1.met
    assert "SEC01-BP01" in sec1.not_checked


@pytest.mark.parametrize("source", SOURCES)
def test_workload_without_guardrails_fails_repo_004_with_rules_org(
    tmp_path: Path, source: str
) -> None:
    _workload(tmp_path, source)
    ctx, findings = _scan(tmp_path, rules_org=True)
    assert ctx.source == source
    found = [f for f in findings if f.id == "REPO-004"]
    assert len(found) == 1
    assert found[0].question == "SEC 1"
    assert found[0].best_practices == ["SEC01-BP01"]
    assert "REPO-004" in ctx.rules_run
    sec1 = _sec1(findings, ctx.rules_run)
    assert not sec1.met
    assert "SEC01-BP01" not in sec1.not_checked
    assert "REPO-005" not in {f.id for f in findings}  # no account, no baseline finding


def test_rules_include_runs_repo_004_without_rules_org(tmp_path: Path) -> None:
    _workload(tmp_path, "terraform")
    ctx, findings = _scan(tmp_path, rules_include=["REPO-004"])
    assert [f.id for f in findings] == ["REPO-004"]
    assert ctx.rules_run == ["REPO-004"]


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("kind", sorted(GUARDRAILS))
def test_any_guardrail_passes_repo_004(tmp_path: Path, source: str, kind: str) -> None:
    _workload(tmp_path, source)
    _write(tmp_path / _ORG_FILE[source], GUARDRAILS[kind][source])
    _ctx, findings = _scan(tmp_path, rules_org=True)
    assert "REPO-004" not in {f.id for f in findings}


def test_a_tag_policy_is_not_an_scp(tmp_path: Path) -> None:
    _write(tmp_path / "org.template.json", _cfn({"Tags": ("AWS::Organizations::Policy", {
        "Name": "tags", "Type": "TAG_POLICY", "Content": {}})}))
    assert org_guardrails(tmp_path) == {}


def test_python_cdk_org_trail_and_tests_are_not_guardrails(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "test_org.py", "organizations.CfnPolicy(self, 'P')\n")
    assert org_guardrails(tmp_path) == {}
    _write(tmp_path / "app.py", "aws_cloudtrail.Trail(self, 'T', is_organization_trail=True)\n")
    assert org_guardrails(tmp_path) == {"organization trail": "app.py"}


# An account definition and each baseline service, per source.
ACCOUNT = {
    "cdk": "new organizations.CfnAccount(this, 'Workload', { accountName: 'w', email });\n",
    "cloudformation": _cfn({"Workload": ("AWS::Organizations::Account", {
        "AccountName": "w", "Email": "w@example.com"})}),
    "terraform": 'resource "aws_organizations_account" "workload" {\n  name = "w"\n}\n',
}
SERVICES = {
    "cdk": (
        "new cloudtrail.Trail(this, 'Trail');\n"
        "new config.CfnConfigurationRecorder(this, 'Rec', { roleArn });\n"
        "new guardduty.CfnDetector(this, 'Gd', { enable: true });\n"
        "new securityhub.CfnHub(this, 'Hub');\n"
        "new accessanalyzer.CfnAnalyzer(this, 'Aa', { type: 'ORGANIZATION' });\n"
    ),
    "cloudformation": _cfn({
        "Trail": ("AWS::CloudTrail::Trail", {"IsLogging": True}),
        "Rec": ("AWS::Config::ConfigurationRecorder", {"RoleARN": "x"}),
        "Gd": ("AWS::GuardDuty::Detector", {"Enable": True}),
        "Hub": ("AWS::SecurityHub::Hub", {}),
        "Aa": ("AWS::AccessAnalyzer::Analyzer", {"Type": "ORGANIZATION"}),
    }),
    "terraform": (
        'resource "aws_cloudtrail" "t" {\n}\n'
        'resource "aws_config_configuration_recorder" "r" {\n}\n'
        'resource "aws_guardduty_detector" "g" {\n}\n'
        'resource "aws_securityhub_account" "h" {\n}\n'
        'resource "aws_accessanalyzer_analyzer" "a" {\n}\n'
    ),
}
_ACCOUNT_FILE = {
    "cdk": "lib/accounts.ts", "cloudformation": "accounts.template.json",
    "terraform": "accounts.tf",
}
_BASELINE_FILE = {
    "cdk": "lib/baseline.ts", "cloudformation": "baseline.template.json",
    "terraform": "baseline.tf",
}


@pytest.mark.parametrize("source", SOURCES)
def test_account_without_baseline_fails_repo_005(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source)
    _write(tmp_path / _ACCOUNT_FILE[source], ACCOUNT[source])
    ctx, findings = _scan(tmp_path)
    assert ctx.source == source
    found = [f for f in findings if f.id == "REPO-005"]
    assert len(found) == 1
    f = found[0]
    assert f.question == "SEC 1"
    assert f.best_practices == ["SEC01-BP06"]
    assert f.severity == "Medium"
    assert f.file == _ACCOUNT_FILE[source]
    for name in BASELINE:
        assert name in f.evidence
    assert not _sec1(findings, ctx.rules_run).met


@pytest.mark.parametrize("source", SOURCES)
def test_account_with_the_full_baseline_passes_repo_005(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source)
    _write(tmp_path / _ACCOUNT_FILE[source], ACCOUNT[source])
    _write(tmp_path / _BASELINE_FILE[source], SERVICES[source])
    _ctx, findings = _scan(tmp_path)
    assert "REPO-005" not in {f.id for f in findings}


def test_repo_005_names_only_the_missing_services(tmp_path: Path) -> None:
    _write(tmp_path / "accounts.tf", ACCOUNT["terraform"])
    _write(tmp_path / "baseline.tf", 'resource "aws_guardduty_detector" "g" {\n}\n'
                                     'resource "aws_cloudtrail" "t" {\n}\n')
    _ctx, findings = _scan(tmp_path)
    (f,) = [f for f in findings if f.id == "REPO-005"]
    assert f.evidence.endswith(
        "no Config recorder, Security Hub, IAM Access Analyzer in the IaC"
    )


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        ("aft/account.tf", 'module "w" {\n  source = "./modules/aft-account-request"\n}\n'),
        ("factory.template.json", _cfn({"W": (
            "AWS::ServiceCatalog::CloudFormationProvisionedProduct",
            {"ProductName": "AWSControlTowerAccountFactory"})})),
    ],
)
def test_account_factory_and_aft_requests_count_as_accounts(
    tmp_path: Path, rel: str, text: str
) -> None:
    _write(tmp_path / rel, text)
    _ctx, findings = _scan(tmp_path)
    assert "REPO-005" in {f.id for f in findings}


@pytest.mark.parametrize("source", SOURCES)
def test_workload_stack_gets_no_repo_005(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source)
    ctx, findings = _scan(tmp_path)
    assert "REPO-005" not in {f.id for f in findings}
    assert "REPO-005" in ctx.rules_run
