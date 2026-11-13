"""SEC 6: interactive access (REPO-144) and automated compute protection (REPO-145)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_INSTANCE_TF = 'resource "aws_instance" "web" {{\n  ami = "x"\n{extra}}}\n'
_KEYED = _INSTANCE_TF.format(extra='  key_name = "ops"\n')


def _scan(root: Path, files: dict[str, str], org: bool = True) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False, rules_org=org)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def test_rules_answer_sec6() -> None:
    assert RULE_BEST_PRACTICES["REPO-144"] == ("SEC06-BP03",)
    assert RULE_BEST_PRACTICES["REPO-145"] == ("SEC06-BP05",)
    assert "SEC06-BP03" not in NOT_CHECKED and "SEC06-BP05" not in NOT_CHECKED


@pytest.mark.parametrize(
    ("files", "line"),
    [
        ({"i.tf": _KEYED}, 3),
        ({"i.json": '{"Resources": {"I": {"Type": "AWS::EC2::Instance", '
                    '"Properties": {"KeyName": "ops"}}}}'}, 1),
        ({"lib/s.ts": "const x = 1;\nnew ec2.Instance(this, 'W', { keyName: 'ops' });\n"}, 2),
        ({"lt.tf": 'resource "aws_launch_template" "t" {\n  key_name = "ops"\n}\n'}, 2),
    ],
    ids=["tf-instance", "cfn-instance", "cdk-instance", "tf-launch-template"],
)
def test_key_pair_without_session_manager_fires(tmp_path: Path, files: dict, line: int) -> None:
    (hit,) = _found(_scan(tmp_path, files), "REPO-144")
    assert hit.question == "SEC 6" and hit.severity == "Medium"
    assert hit.line == line and hit.file.endswith(next(iter(files)))


@pytest.mark.parametrize(
    "extra",
    [
        {"p.tf": 'resource "aws_iam_role_policy_attachment" "s" {\n'
                 '  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"\n}\n'},
        {"lib/p.ts": "new iam.Role(this, 'R', { managedPolicies: [iam.ManagedPolicy"
                     ".fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore')] });\n"},
        {"p.json": '{"Statement": [{"Action": "ssm:StartSession"}]}'},
    ],
    ids=["tf-policy", "cdk-policy", "start-session"],
)
def test_session_manager_passes(tmp_path: Path, extra: dict) -> None:
    assert not _found(_scan(tmp_path, {"i.tf": _KEYED, **extra}), "REPO-144")


def test_instance_without_key_pair_passes(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"i.tf": _INSTANCE_TF.format(extra="")})
    assert not _found(findings, "REPO-144")


def test_key_pair_in_tests_does_not_count(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"main.tf": 'resource "aws_s3_bucket" "b" {}\n',
                                "tests/i.tf": _KEYED})
    assert not _found(findings, "REPO-144")


@pytest.mark.parametrize(
    "files",
    [
        {"i.tf": _INSTANCE_TF.format(extra="")},
        {"f.tf": 'resource "aws_lambda_function" "f" {\n  runtime = "python3.12"\n}\n'},
        {"lib/s.ts": "new ec2.Instance(this, 'W', {});\n"},
    ],
    ids=["tf-instance", "tf-lambda", "cdk-instance"],
)
def test_unprotected_compute_fires(tmp_path: Path, files: dict) -> None:
    (hit,) = _found(_scan(tmp_path, files), "REPO-145")
    assert hit.question == "SEC 6" and hit.severity == "Low"
    assert hit.evidence.startswith("Runs ") and hit.evidence.endswith("found none")


@pytest.mark.parametrize(
    "extra",
    [
        {"e.tf": 'resource "aws_inspector2_enabler" "e" {\n  account_ids = ["1"]\n}\n'},
        {"a.tf": 'resource "aws_ssm_association" "a" {\n  name = "AWS-RunPatchBaseline"\n}\n'},
        {"a.json": '{"Resources": {"A": {"Type": "AWS::SSM::Association"}}}'},
        {"lib/a.ts": "new ssm.CfnAssociation(this, 'A', { name: 'AWS-ApplyAnsiblePlaybooks' });\n"},
        {"b.tf": 'resource "aws_ssm_patch_baseline" "b" {\n  name = "b"\n}\n'},
    ],
    ids=["inspector", "tf-association", "cfn-association", "cdk-association", "patch-baseline"],
)
def test_automated_protection_passes(tmp_path: Path, extra: dict) -> None:
    files = {"i.tf": _INSTANCE_TF.format(extra=""), **extra}
    assert not _found(_scan(tmp_path, files), "REPO-145")


def test_automated_protection_is_org_level(tmp_path: Path) -> None:
    files = {"i.tf": _INSTANCE_TF.format(extra="")}
    assert not _found(_scan(tmp_path, files, org=False), "REPO-145")


def test_no_compute_does_not_fire(tmp_path: Path) -> None:
    files = {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'}
    assert not _found(_scan(tmp_path, files), "REPO-145")
