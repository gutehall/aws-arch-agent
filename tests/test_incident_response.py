"""SEC 10: forensic capture (REPO-007) and containment controls (REPO-008)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import containment_controls, forensic_controls

SOURCES = ("cdk", "cloudformation", "terraform")
_FILE = {"cdk": "lib/ir.ts", "cloudformation": "ir.template.json", "terraform": "ir.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict[str, tuple[str, dict]]) -> str:
    return json.dumps({"Resources": {
        name: {"Type": rtype, "Properties": props} for name, (rtype, props) in resources.items()
    }})


def _workload(root: Path, source: str) -> None:
    """One app stack with a bucket and a plain security group: no incident response."""
    if source == "cdk":
        _write(root / "package.json", "{}")
        _write(root / "lib" / "stack.ts", (
            "new s3.Bucket(this, 'Data');\n"
            "new ec2.SecurityGroup(this, 'WebSg', { vpc, description: 'web' });\n"
        ))
    elif source == "cloudformation":
        _write(root / "stack.template.json", _cfn({
            "Data": ("AWS::S3::Bucket", {}),
            "WebSg": ("AWS::EC2::SecurityGroup", {"GroupDescription": "web"}),
        }))
    else:
        _write(root / "main.tf", (
            'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n'
            'resource "aws_security_group" "web" {\n  description = "web"\n}\n'
        ))


def _scan(root: Path, **kwargs):
    _report, ctx, findings, _w = analyze_v1(root, use_llm=False, **kwargs)
    return ctx, findings


def _sec10(findings, ran):
    return {a.question.id: a for a in well_architected.answers(findings, ran)}["SEC 10"]


# A GuardDuty finding rule, per source, with no capture action in the file.
FINDING_RULE = {
    "cdk": "new events.Rule(this, 'OnFinding', { eventPattern: { source: ['aws.guardduty'] }, "
           "targets: [new targets.SfnStateMachine(machine)] });\n",
    "cloudformation": _cfn({"OnFinding": ("AWS::Events::Rule", {
        "EventPattern": {"source": ["aws.securityhub"],
                         "detail-type": ["Security Hub Findings - Imported"]},
        "Targets": [{"Arn": "x", "Id": "ir"}]})}),
    "terraform": (
        'resource "aws_cloudwatch_event_rule" "finding" {\n'
        '  event_pattern = jsonencode({ "detail-type" = ["GuardDuty Finding"] })\n}\n'
    ),
}
# A capture action, per source, in its own file.
CAPTURE = {
    "cdk": "new tasks.CallAwsService(this, 'Snap', { service: 'ec2', "
           "action: 'createSnapshots', iamResources: ['*'] });\n",
    "cloudformation": _cfn({"Snap": ("AWS::SSM::Association", {
        "Name": "AWS-CreateSnapshot"})}),
    "terraform": (
        'resource "aws_cloudwatch_event_target" "snap" {\n'
        '  arn = "arn:aws:ssm:eu-west-1::automation-definition/AWSSupport-ContainEC2Instance"\n'
        "}\n"
    ),
}
DETECTIVE = {
    "cdk": "new detective.CfnGraph(this, 'Graph');\n",
    "cloudformation": _cfn({"Graph": ("AWS::Detective::Graph", {})}),
    "terraform": 'resource "aws_detective_graph" "g" {\n}\n',
}
_CAPTURE_FILE = {
    "cdk": "lib/capture.ts", "cloudformation": "capture.template.json",
    "terraform": "capture.tf",
}


@pytest.mark.parametrize("source", SOURCES)
def test_rules_are_off_by_default_so_sec10_is_not_checked(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source)
    ctx, findings = _scan(tmp_path)
    assert ctx.source == source
    ids = {f.id for f in findings}
    assert not ids & {"REPO-007", "REPO-008"}
    assert not {"REPO-007", "REPO-008"} & set(ctx.rules_run)
    sec10 = _sec10(findings, ctx.rules_run)
    assert not sec10.met
    assert {"SEC10-BP03", "SEC10-BP06"} <= set(sec10.not_checked)


@pytest.mark.parametrize("source", SOURCES)
def test_workload_without_controls_fails_both_with_rules_org(
    tmp_path: Path, source: str
) -> None:
    _workload(tmp_path, source)
    ctx, findings = _scan(tmp_path, rules_org=True)
    assert ctx.source == source
    by_id = {f.id: f for f in findings if f.id in {"REPO-007", "REPO-008"}}
    assert set(by_id) == {"REPO-007", "REPO-008"}
    assert by_id["REPO-007"].best_practices == ["SEC10-BP03"]
    assert by_id["REPO-008"].best_practices == ["SEC10-BP06"]
    for f in by_id.values():
        assert f.question == "SEC 10"
        assert f.severity == "Medium"
        assert f.category == "Security"
        assert f.evidence.startswith("Searched the IaC and code for")
    sec10 = _sec10(findings, ctx.rules_run)
    assert not sec10.met
    assert not {"SEC10-BP03", "SEC10-BP06"} & set(sec10.not_checked)


def test_rules_include_runs_them_without_rules_org(tmp_path: Path) -> None:
    _workload(tmp_path, "terraform")
    ctx, findings = _scan(tmp_path, rules_include=["REPO-007", "REPO-008"])
    assert sorted(f.id for f in findings) == ["REPO-007", "REPO-008"]
    assert sorted(ctx.rules_run) == ["REPO-007", "REPO-008"]


@pytest.mark.parametrize("source", SOURCES)
def test_finding_rule_with_capture_passes_repo_007(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source)
    _write(tmp_path / _FILE[source], FINDING_RULE[source])
    _write(tmp_path / _CAPTURE_FILE[source], CAPTURE[source])
    _ctx, findings = _scan(tmp_path, rules_org=True)
    assert "REPO-007" not in {f.id for f in findings}


@pytest.mark.parametrize("source", SOURCES)
def test_detective_passes_repo_007(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source)
    _write(tmp_path / _FILE[source], DETECTIVE[source])
    _ctx, findings = _scan(tmp_path, rules_org=True)
    assert "REPO-007" not in {f.id for f in findings}


@pytest.mark.parametrize("source", SOURCES)
def test_finding_rule_without_capture_fails_repo_007(tmp_path: Path, source: str) -> None:
    _workload(tmp_path, source)
    _write(tmp_path / _FILE[source], FINDING_RULE[source])
    _ctx, findings = _scan(tmp_path, rules_org=True)
    (f,) = [f for f in findings if f.id == "REPO-007"]
    assert f.evidence.endswith(f"found a finding rule ({_FILE[source]}) but no capture action")


def test_capture_without_a_finding_rule_fails_repo_007(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf", 'resource "aws_cloudwatch_event_rule" "nightly" {\n'
                                 '  schedule_expression = "rate(1 day)"\n}\n')
    _write(tmp_path / "backup.py", "ec2.create_snapshot(VolumeId=volume)\n")
    assert set(forensic_controls(tmp_path)) == {"capture"}
    _ctx, findings = _scan(tmp_path, rules_org=True)
    assert "REPO-007" in {f.id for f in findings}


def test_lambda_code_that_snapshots_counts_as_capture(tmp_path: Path) -> None:
    _write(tmp_path / "lib" / "ir.ts", FINDING_RULE["cdk"])
    _write(tmp_path / "lambda" / "isolate.py", "ec2.create_snapshot(VolumeId=volume_id)\n")
    assert forensic_controls(tmp_path) == {
        "finding rule": "lib/ir.ts", "capture": "lambda/isolate.py",
    }


# One containment control of each kind, per source.
CONTAINMENT: dict[str, dict[str, str]] = {
    "quarantine_sg": {
        "cdk": "new ec2.SecurityGroup(this, 'QuarantineSg', { vpc, allowAllOutbound: false });\n",
        "cloudformation": _cfn({"IsolationSecurityGroup": ("AWS::EC2::SecurityGroup", {
            "GroupDescription": "no rules"})}),
        "terraform": 'resource "aws_security_group" "forensic" {\n  description = "x"\n}\n',
    },
    "runbook": {
        "cdk": "new ssm.CfnAssociation(this, 'Contain', "
               "{ name: 'AWSSupport-ContainEC2Instance' });\n",
        "cloudformation": _cfn({"Open": ("AWS::SSM::Association", {
            "Name": "AWS-DisablePublicAccessForSecurityGroup"})}),
        "terraform": (
            'resource "aws_config_remediation_configuration" "r" {\n'
            '  target_id = "AWSConfigRemediation-RevokeUnusedIAMUserCredentials"\n}\n'
        ),
    },
    "revoke": {
        "cdk": "await iam.send(new UpdateAccessKeyCommand({ AccessKeyId, Status: 'Inactive' }));\n",
        "cloudformation": _cfn({"Revoke": ("AWS::IAM::ManagedPolicy", {"PolicyDocument": {
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {
                "DateLessThan": {"aws:TokenIssueTime": "2026-11-10T00:00:00Z"}}}]}})}),
        "terraform": (
            'resource "aws_iam_role_policy_attachment" "revoke" {\n'
            '  policy_arn = "arn:aws:iam::aws:policy/AWSRevokeOlderSessions"\n}\n'
        ),
    },
}


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("kind", sorted(CONTAINMENT))
def test_any_containment_control_passes_repo_008(
    tmp_path: Path, source: str, kind: str
) -> None:
    _workload(tmp_path, source)
    _write(tmp_path / _FILE[source], CONTAINMENT[kind][source])
    _ctx, findings = _scan(tmp_path, rules_org=True)
    assert "REPO-008" not in {f.id for f in findings}


@pytest.mark.parametrize(
    "text",
    [
        # An isolated subnet is not an isolation security group.
        "new ec2.SecurityGroup(this, 'Db', { vpc });\n"
        "vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED }\n",
        # Reactivating a key is not revocation.
        "iam.update_access_key(AccessKeyId=key, Status='Active')\n",
        # The word without a security group is not a control.
        "// quarantine bucket\nnew s3.Bucket(this, 'Quarantine');\n",
    ],
)
def test_near_misses_are_not_containment(tmp_path: Path, text: str) -> None:
    _write(tmp_path / "lib" / "stack.ts", text)
    assert containment_controls(tmp_path) == {}


def test_controls_in_tests_do_not_count(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "test_ir.py", "detective.CfnGraph(self, 'G')\n"
                                              "ec2.SecurityGroup(self, 'QuarantineSg', vpc=vpc)\n")
    assert forensic_controls(tmp_path) == {}
    assert containment_controls(tmp_path) == {}
