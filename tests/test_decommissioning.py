"""COST 4: decommissioning. Tracking resources over their lifetime with created-by and
owner tags (REPO-086) and a decommissioning process for temporary environments
(REPO-087)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    DecommissioningMissing,
    ResourceLifetimeUntracked,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stack(root: Path, source: str, *parts: object, env: str = "prod") -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = json.dumps({"Resources": merged}, indent=2)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / env / _PATHS[source], body)


BUCKET = {
    "cdk": "new s3.Bucket(this, 'Data');\n",
    "cloudformation": {"Data": {"Type": "AWS::S3::Bucket", "Properties": {}}},
    "terraform": 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n',
}


def _tags(source: str, *keys: str) -> object:
    """A bucket with tags keyed keys: CloudFormation Tags, Terraform provider default_tags,
    CDK Tags.of(this).add."""
    if source == "cloudformation":
        return {"Data": {"Type": "AWS::S3::Bucket", "Properties": {
            "Tags": [{"Key": k, "Value": "x"} for k in keys]}}}
    if source == "terraform":
        tags = "".join(f'      {k} = "x"\n' for k in keys)
        return ('provider "aws" {\n  default_tags {\n    tags = {\n'
                f'{tags}    }}\n  }}\n}}\n' + BUCKET["terraform"])
    return BUCKET["cdk"] + "".join(f"Tags.of(this).add('{k}', 'x');\n" for k in keys)


# REPO-086: resources carry a created-by and an owner tag.

@pytest.mark.parametrize("source", SOURCES)
def test_untagged_workload_fires_repo_086(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _tags(source))
    (hit,) = ResourceLifetimeUntracked().run(tmp_path)
    assert hit.id == "REPO-086"
    assert "no created-by or owner tag" in hit.evidence and "prod/" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_owner_only_names_created_by_repo_086(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _tags(source, "Owner"))
    (hit,) = ResourceLifetimeUntracked().run(tmp_path)
    assert "no created-by tag" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_created_by_only_names_owner_repo_086(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _tags(source, "CreatedBy"))
    (hit,) = ResourceLifetimeUntracked().run(tmp_path)
    assert "no owner tag" in hit.evidence


@pytest.mark.parametrize("keys", (("CreatedBy", "Owner"), ("managed-by", "team"),
                                  ("Repository", "CostOwner"), ("iac", "owner"),
                                  ("Source", "Team"), ("created_by", "OWNER")))
@pytest.mark.parametrize("source", SOURCES)
def test_created_by_and_owner_pass_repo_086(tmp_path: Path, source: str,
                                            keys: tuple[str, str]) -> None:
    _stack(tmp_path, source, _tags(source, *keys))
    assert ResourceLifetimeUntracked().run(tmp_path) == []


def test_terraform_module_source_is_not_a_tag_repo_086(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", _tags("terraform", "Owner"),
           'module "net" {\n  source = "./modules/net"\n}\n')
    (hit,) = ResourceLifetimeUntracked().run(tmp_path)
    assert "no created-by tag" in hit.evidence


def test_tags_in_another_file_count_repo_086(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    assert ResourceLifetimeUntracked().run(tmp_path)
    _write(tmp_path / "shared" / "providers.tf",
           'provider "aws" {\n  default_tags {\n    tags = {\n      ManagedBy = "terraform"\n'
           '      Owner = "platform"\n    }\n  }\n}\n')
    assert ResourceLifetimeUntracked().run(tmp_path) == []


def test_python_cdk_repo_086(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "s3.Bucket(self, 'Data')\n")
    assert ResourceLifetimeUntracked().run(tmp_path)
    _write(tmp_path / "app.py", "s3.Bucket(self, 'Data')\n"
           "Tags.of(app).add('Creator', 'cdk')\nTags.of(app).add('Team', 'platform')\n")
    assert ResourceLifetimeUntracked().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_workload_is_skipped_repo_086(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"], env=env)
    assert ResourceLifetimeUntracked().run(tmp_path) == []


def test_no_workload_is_silent_repo_086(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", 'variable "region" {}\n')
    assert ResourceLifetimeUntracked().run(tmp_path) == []


# REPO-087: temporary environments are torn down.

PR_DEPLOY = (
    "on:\n  pull_request:\n    branches: [main]\njobs:\n  preview:\n"
    "    runs-on: ubuntu-latest\n    steps:\n      - run: npx cdk deploy --all\n"
)
PR_CLOSED = (
    "on:\n  pull_request:\n    types: [closed]\njobs:\n  cleanup:\n"
    "    runs-on: ubuntu-latest\n    steps:\n      - run: npx cdk destroy --force --all\n"
)
GITLAB_REVIEW = (
    "deploy_review:\n  stage: deploy\n  script:\n    - terraform apply -auto-approve\n"
    "  environment:\n    name: review/$CI_COMMIT_REF_SLUG\n"
)
GITLAB_STOP = (
    "    on_stop: stop_review\n\nstop_review:\n  stage: deploy\n  script:\n"
    "    - terraform destroy -auto-approve\n  when: manual\n  environment:\n"
    "    name: review/$CI_COMMIT_REF_SLUG\n    action: stop\n"
)
SCHEDULED_CLEANUP = {
    "cdk": "new events.Rule(this, 'StackCleanup', "
           "{ schedule: events.Schedule.rate(cdk.Duration.days(1)) });\n",
    "cloudformation": {"Teardown": {"Type": "AWS::Events::Rule", "Properties": {
        "ScheduleExpression": "rate(1 day)",
        "Targets": [{"Id": "fn", "Arn": {"Fn::GetAtt": ["TeardownFunction", "Arn"]}}]}}},
    "terraform": 'resource "aws_cloudwatch_event_rule" "cleanup" {\n'
                 '  schedule_expression = "rate(1 day)"\n}\n',
}
SCHEDULE = {
    "cdk": "new events.Rule(this, 'Nightly', "
           "{ schedule: events.Schedule.rate(cdk.Duration.days(1)) });\n",
    "cloudformation": {"Nightly": {"Type": "AWS::Events::Rule", "Properties": {
        "ScheduleExpression": "rate(1 day)"}}},
    "terraform": 'resource "aws_cloudwatch_event_rule" "nightly" {\n'
                 '  schedule_expression = "rate(1 day)"\n}\n',
}


@pytest.mark.parametrize("env", ("sandbox", "preview", "pr-12"))
@pytest.mark.parametrize("source", SOURCES)
def test_temporary_stack_without_teardown_fires_repo_087(tmp_path: Path, source: str,
                                                         env: str) -> None:
    _stack(tmp_path, source, BUCKET[source], env=env)
    (hit,) = DecommissioningMissing().run(tmp_path)
    assert hit.id == "REPO-087"
    assert env in hit.evidence and "found none" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_no_temporary_environment_is_silent_repo_087(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source])
    _stack(tmp_path, source, BUCKET[source], env="dev")
    assert DecommissioningMissing().run(tmp_path) == []


def test_pull_request_deploy_without_destroy_fires_repo_087(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", BUCKET["cdk"])
    _write(tmp_path / ".github" / "workflows" / "preview.yml", PR_DEPLOY)
    (hit,) = DecommissioningMissing().run(tmp_path)
    assert ".github/workflows/preview.yml (deploys on pull requests)" in hit.evidence
    _write(tmp_path / ".github" / "workflows" / "cleanup.yml", PR_CLOSED)
    assert DecommissioningMissing().run(tmp_path) == []


@pytest.mark.parametrize("trigger", ("on: pull_request\n", "on: [push, pull_request]\n",
                                     "on:\n  - pull_request\n"))
@pytest.mark.parametrize("deploy", ("terraform apply -auto-approve", "sam deploy",
                                    "aws cloudformation deploy --stack-name pr",
                                    "npx serverless deploy --stage pr"))
def test_pull_request_triggers_and_deploys_repo_087(tmp_path: Path, trigger: str,
                                                    deploy: str) -> None:
    _write(tmp_path / ".github" / "workflows" / "pr.yml",
           f"{trigger}jobs:\n  deploy:\n    steps:\n      - run: {deploy}\n")
    assert DecommissioningMissing().run(tmp_path)


@pytest.mark.parametrize("workflow", (
    "on:\n  pull_request:\njobs:\n  plan:\n    steps:\n      - run: npx cdk diff\n",
    "on:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    steps:\n"
    "      - run: npx cdk deploy\n",
    "on: [push, pull_request]\njobs:\n  deploy:\n"
    "    if: github.ref == 'refs/heads/main'\n    steps:\n      - run: terraform apply\n",
))
def test_workflow_that_does_not_deploy_per_pull_request_is_silent_repo_087(
        tmp_path: Path, workflow: str) -> None:
    _write(tmp_path / ".github" / "workflows" / "ci.yml", workflow)
    assert DecommissioningMissing().run(tmp_path) == []


def test_gitlab_review_environment_needs_on_stop_repo_087(tmp_path: Path) -> None:
    _write(tmp_path / ".gitlab-ci.yml", GITLAB_REVIEW)
    (hit,) = DecommissioningMissing().run(tmp_path)
    assert ".gitlab-ci.yml (review/ environment)" in hit.evidence
    _write(tmp_path / ".gitlab-ci.yml", GITLAB_REVIEW + GITLAB_STOP)
    assert DecommissioningMissing().run(tmp_path) == []


@pytest.mark.parametrize("command", ("cdk destroy --force", "terraform destroy",
                                     "terraform apply -destroy -auto-approve",
                                     "sam delete --no-prompts",
                                     "aws cloudformation delete-stack --stack-name x",
                                     "serverless remove"))
def test_teardown_step_in_ci_passes_repo_087(tmp_path: Path, command: str) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"], env="sandbox")
    _write(tmp_path / ".github" / "workflows" / "teardown.yml",
           f"on: workflow_dispatch\njobs:\n  down:\n    steps:\n      - run: {command}\n")
    assert DecommissioningMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_scheduled_cleanup_passes_repo_087(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source], env="sandbox")
    _stack(tmp_path, source, SCHEDULE[source], env="ops")
    assert DecommissioningMissing().run(tmp_path)
    _stack(tmp_path, source, SCHEDULED_CLEANUP[source], env="ops")
    assert DecommissioningMissing().run(tmp_path) == []


def test_schedule_with_cleanup_code_passes_repo_087(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"], env="sandbox")
    _stack(tmp_path, "terraform", SCHEDULE["terraform"], env="ops")
    assert DecommissioningMissing().run(tmp_path)
    _write(tmp_path / "functions" / "handler.py",
           "def handler(event, context):\n    # delete expired sandbox stacks\n"
           "    return cleanup()\n")
    assert DecommissioningMissing().run(tmp_path) == []


def test_aws_nuke_config_passes_repo_087(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"], env="sandbox")
    _write(tmp_path / "ops" / "nuke-config.yml", "regions: [eu-west-1]\n")
    assert DecommissioningMissing().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("DECOMMISSIONING.md", "1. Run `cdk destroy` for the stack.\n2. Delete the log groups.\n"),
    ("docs/teardown.md", "Remove the sandbox with terraform destroy.\n"),
    ("README.md", "# App\n\n## Teardown\n\nRun `npx cdk destroy --all` when done.\n"),
    ("docs/runbook.md", "# Runbook\n\n### Decommissioning a sandbox\n\nDelete the stack.\n"),
))
def test_decommission_note_passes_repo_087(tmp_path: Path, path: str, text: str) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"], env="sandbox")
    _write(tmp_path / path, text)
    assert DecommissioningMissing().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("README.md", "# App\n\n## Cleanup\n\nTBD\n"),
    ("docs/teardown.md", "Ask the platform team.\n"),
    ("README.md", "# App\n\nDeploy with cdk deploy. Delete nothing.\n"),
))
def test_note_that_does_not_describe_the_process_fires_repo_087(tmp_path: Path, path: str,
                                                                text: str) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"], env="sandbox")
    _write(tmp_path / path, text)
    assert DecommissioningMissing().run(tmp_path)


def test_python_cdk_stack_id_repo_087(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "AppStack(app, 'FeatureLoginStack')\n")
    (hit,) = DecommissioningMissing().run(tmp_path)
    assert "FeatureLoginStack" in hit.evidence


# Shared.

RULES = (ResourceLifetimeUntracked(), DecommissioningMissing())


def _firing(rule_id: str, root: Path) -> None:
    env = "sandbox" if rule_id == "REPO-087" else "prod"
    _stack(root, "terraform", BUCKET["terraform"], env=env)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path,
                                                                   rule) -> None:
    _firing(rule.id, tmp_path)
    (hit,) = rule.run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    text = f"{hit.title}\n{hit.evidence}\n{hit.recommendation}\n"
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", text)
    assert len(rule.run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", text)
    assert rule.run(empty) == []


@pytest.mark.parametrize("rule_id,practice", (
    ("REPO-086", "COST04-BP01"), ("REPO-087", "COST04-BP02"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert well_architected.question_of(rule_id) == "COST 4"


def test_rules_run_by_default() -> None:
    assert {r.id for r in RULES} & ORG_RULE_IDS == set()
    assert {r.category for r in RULES} == {"Cost"}
    assert {r.severity for r in RULES} == {"Low"}
    assert {t for r in RULES for t in r.themes} == {"finops"}


def test_cost4_is_fully_checked() -> None:
    (cost4,) = [a for a in well_architected.answers([]) if a.question.id == "COST 4"]
    assert cost4.not_checked == ()


def test_cost4_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    findings = ResourceLifetimeUntracked().run(tmp_path)
    (cost4,) = [a for a in well_architected.answers(findings) if a.question.id == "COST 4"]
    assert not cost4.met
