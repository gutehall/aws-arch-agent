"""REL 10: a component that runs in one place is rebuilt when it fails (REPO-056)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import SingleLocationRecoveryMissing

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stack(root: Path, source: str, *parts: object) -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = json.dumps({"Resources": merged}, indent=2)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / "prod" / _PATHS[source], body)


INSTANCE = {
    "cdk": "new ec2.Instance(this, 'Box', { vpc, instanceType, machineImage });\n",
    "cloudformation": {"Box": {"Type": "AWS::EC2::Instance", "Properties": {
        "InstanceType": "t3.micro", "ImageId": "ami-1"}}},
    "terraform": 'resource "aws_instance" "box" {\n  instance_type = "t3.micro"\n}\n',
}
RECOVER_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Status', { metric, threshold: 1, evaluationPeriods: 2 })"
           ".addAlarmAction(new actions.Ec2Action(actions.Ec2InstanceAction.RECOVER));\n",
    "cloudformation": {"Status": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "MetricName": "StatusCheckFailed_System", "Namespace": "AWS/EC2", "Threshold": 1,
        "AlarmActions": [{"Fn::Sub": "arn:aws:automate:${AWS::Region}:ec2:recover"}]}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "status" {\n'
                 '  metric_name = "StatusCheckFailed_System"\n'
                 '  alarm_actions = ["arn:aws:automate:eu-west-1:ec2:recover"]\n}\n',
}
ASG = {
    "cdk": "new autoscaling.AutoScalingGroup(this, 'One', { vpc, instanceType, machineImage, "
           "minCapacity: 1, maxCapacity: 1 });\n",
    "cloudformation": {"One": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
        "MinSize": "1", "MaxSize": "1"}}},
    "terraform": 'resource "aws_autoscaling_group" "one" {\n  min_size = 1\n  max_size = 1\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_standalone_instance_fails_repo_056(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, INSTANCE[source])
    (finding,) = SingleLocationRecoveryMissing().run(tmp_path)
    assert finding.id == "REPO-056"
    assert f"prod/{_PATHS[source]}" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("control", [RECOVER_ALARM, ASG], ids=["alarm", "asg"])
def test_instance_with_rebuild_passes(tmp_path: Path, source: str, control: dict) -> None:
    _stack(tmp_path, source, INSTANCE[source], control[source])
    assert SingleLocationRecoveryMissing().run(tmp_path) == []


def test_backup_plan_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", INSTANCE["terraform"],
           'resource "aws_backup_plan" "daily" {\n  name = "daily"\n}\n')
    assert SingleLocationRecoveryMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", ["cloudformation", "terraform"])
def test_auto_recovery_disabled_always_fires(tmp_path: Path, source: str) -> None:
    if source == "cloudformation":
        box = {"Box": {"Type": "AWS::EC2::Instance", "Properties": {
            "MaintenanceOptions": {"AutoRecovery": "disabled"}}}}
        _stack(tmp_path, source, box, ASG[source])
    else:
        _stack(tmp_path, source, 'resource "aws_instance" "box" {\n'
               '  maintenance_options {\n    auto_recovery = "disabled"\n  }\n}\n', ASG[source])
    (finding,) = SingleLocationRecoveryMissing().run(tmp_path)
    assert "Turns off automatic recovery" in finding.evidence


def test_no_instance_gets_no_repo_056(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_lambda_function" "fn" {\n  handler = "h"\n}\n')
    assert SingleLocationRecoveryMissing().run(tmp_path) == []


def test_python_cdk_instance(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "ec2.Instance(self, 'Box', vpc=vpc, instance_type=t, machine_image=ami)\n")
    assert SingleLocationRecoveryMissing().run(tmp_path)


def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", INSTANCE["terraform"])
    (hit,) = SingleLocationRecoveryMissing().run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", f"{hit.title}\n{hit.evidence}\n{hit.recommendation}\n")
    assert len(SingleLocationRecoveryMissing().run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    assert SingleLocationRecoveryMissing().run(empty) == []


def test_repo_056_maps_to_rel10_bp02_and_runs_by_default() -> None:
    assert well_architected.best_practices_of("REPO-056") == ("REL10-BP02",)
    assert "REPO-056" not in ORG_RULE_IDS


def test_rel10_is_fully_checked() -> None:
    (rel10,) = [a for a in well_architected.answers([]) if a.question.id == "REL 10"]
    assert rel10.not_checked == ()
    assert rel10.met
