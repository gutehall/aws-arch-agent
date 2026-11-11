"""REL 9: backups are restored on a schedule to test them (REPO-051)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import RestoreTestMissing, restore_tests

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


PLAN = {
    "cdk": "const plan = backup.BackupPlan.dailyWeeklyMonthly5YearRetention(this, 'Plan');\n",
    "cloudformation": {"Plan": {"Type": "AWS::Backup::BackupPlan", "Properties": {
        "BackupPlan": {"BackupPlanName": "daily", "BackupPlanRule": []}}}},
    "terraform": 'resource "aws_backup_plan" "daily" {\n  name = "daily"\n}\n',
}
RESTORE_TEST = {
    "cdk": "new backup.CfnRestoreTestingPlan(this, 'RestoreTest', { restoreTestingPlanName: "
           "'weekly', scheduleExpression: 'cron(0 3 ? * SUN *)', recoveryPointSelection });\n",
    "cloudformation": {"RestoreTest": {"Type": "AWS::Backup::RestoreTestingPlan", "Properties": {
        "RestoreTestingPlanName": "weekly", "ScheduleExpression": "cron(0 3 ? * SUN *)"}}},
    "terraform": 'resource "aws_backup_restore_testing_plan" "weekly" {\n'
                 '  schedule_expression = "cron(0 3 ? * SUN *)"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_backup_plan_without_restore_test_fails_repo_051(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, PLAN[source])
    (finding,) = RestoreTestMissing().run(tmp_path)
    assert finding.id == "REPO-051"
    assert "AWS Backup plan" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_restore_testing_plan_passes(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, PLAN[source], RESTORE_TEST[source])
    assert RestoreTestMissing().run(tmp_path) == []


def test_rds_database_counts_as_backed_up(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n')
    (finding,) = RestoreTestMissing().run(tmp_path)
    assert "RDS or Aurora backups" in finding.evidence


def test_dynamodb_pitr_counts_as_backed_up(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", {"T": {"Type": "AWS::DynamoDB::Table", "Properties": {
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}}}})
    (finding,) = RestoreTestMissing().run(tmp_path)
    assert "point-in-time recovery" in finding.evidence


def test_scheduled_restore_function_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", PLAN["cdk"],
           "new events.Rule(this, 'Nightly', { schedule: events.Schedule.cron({ hour: '3' }), "
           "targets: [new targets.LambdaFunction(restoreFn)] });\n")
    _write(tmp_path / "prod" / "lambda" / "restore.py",
           "def handler(event, context):\n"
           "    rds.restore_db_instance_to_point_in_time(SourceDBInstanceIdentifier='db')\n")
    assert restore_tests(tmp_path) == {"scheduled restore": "prod/lib/stack.ts"}
    assert RestoreTestMissing().run(tmp_path) == []


def test_restore_call_without_a_schedule_does_not_pass(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", PLAN["cdk"])
    _write(tmp_path / "prod" / "lambda" / "restore.py",
           "rds.restore_db_instance_to_point_in_time(SourceDBInstanceIdentifier='db')\n")
    assert RestoreTestMissing().run(tmp_path)


def test_restore_command_in_a_build_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", PLAN["terraform"])
    _write(tmp_path / ".github" / "workflows" / "restore.yml",
           "on:\n  schedule:\n    - cron: '0 3 * * 0'\njobs:\n  restore:\n    steps:\n"
           "      - run: aws backup start-restore-job --recovery-point-arn $ARN\n")
    assert RestoreTestMissing().run(tmp_path) == []


def test_no_backups_gets_no_repo_051(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_sqs_queue" "q" {\n  name = "q"\n}\n')
    assert RestoreTestMissing().run(tmp_path) == []


def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", PLAN["terraform"])
    (hit,) = RestoreTestMissing().run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", f"{hit.title}\n{hit.evidence}\n{hit.recommendation}\n")
    assert len(RestoreTestMissing().run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    assert RestoreTestMissing().run(empty) == []


def test_repo_051_maps_to_rel09_bp04_and_runs_by_default() -> None:
    assert well_architected.best_practices_of("REPO-051") == ("REL09-BP04",)
    assert "REPO-051" not in ORG_RULE_IDS


def test_rel9_is_fully_checked_and_reads_met_without_findings() -> None:
    (rel9,) = [a for a in well_architected.answers([]) if a.question.id == "REL 9"]
    assert rel9.not_checked == ()
    assert rel9.met
