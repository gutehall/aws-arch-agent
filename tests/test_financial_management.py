"""COST 1: cloud financial management. Budget ownership (REPO-073), proactive cost
monitoring (REPO-074), keeping up with new releases (REPO-075), business value per unit
(REPO-076), and a cost-owner note for finance and technology (REPO-077), organizational
processes (REPO-078) and culture (REPO-079)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    BudgetOwnerMissing,
    BusinessValueUnquantified,
    CostAwareCultureMissing,
    CostAwareProcessMissing,
    FinanceTechPartnershipMissing,
    OldGenerationResources,
    ReactiveCostMonitoring,
)
from aws_arch_agent.rules.sustainability import LatestGenInstances

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


FUNCTION = {
    "cdk": "const fn = new lambda.Function(this, 'Fn', { runtime, handler, code });\n",
    "cloudformation": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": {}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n}\n',
}
BUCKET = {
    "cdk": "new s3.Bucket(this, 'Data');\n",
    "cloudformation": {"Data": {"Type": "AWS::S3::Bucket", "Properties": {}}},
    "terraform": 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n',
}


def _budget(source: str, *, threshold: object = 100, kind: str = "ACTUAL",
            subscriber: bool = False, tag: str | None = None,
            name: str = "monthly") -> object:
    """A budget with one notification, in the given source."""
    if source == "cloudformation":
        entry: dict = {"Notification": {"NotificationType": kind,
                                        "ComparisonOperator": "GREATER_THAN",
                                        "Threshold": threshold}}
        entry["Subscribers"] = (
            [{"SubscriptionType": "EMAIL", "Address": "a@example.com"}] if subscriber else []
        )
        props: dict = {"Budget": {"BudgetName": name, "BudgetType": "COST",
                                  "TimeUnit": "MONTHLY"},
                       "NotificationsWithSubscribers": [entry]}
        if tag:
            props["ResourceTags"] = [{"Key": tag, "Value": "team-a"}]
        return {"Budget": {"Type": "AWS::Budgets::Budget", "Properties": props}}
    if source == "terraform":
        subs = '    subscriber_email_addresses = ["a@example.com"]\n' if subscriber else ""
        tags = f'  tags = {{\n    {tag} = "team-a"\n  }}\n' if tag else ""
        return (f'resource "aws_budgets_budget" "{name}" {{\n  name = "{name}"\n'
                '  budget_type = "COST"\n  time_unit = "MONTHLY"\n'
                f'  notification {{\n    comparison_operator = "GREATER_THAN"\n'
                f'    threshold = {threshold}\n    threshold_type = "PERCENTAGE"\n'
                f'    notification_type = "{kind}"\n{subs}  }}\n{tags}}}\n')
    subs = ("subscribers: [{ subscriptionType: 'EMAIL', address: 'a@example.com' }]"
            if subscriber else "subscribers: []")
    tags = f", resourceTags: [{{ key: '{tag}', value: 'team-a' }}]" if tag else ""
    return (f"const budget = new budgets.CfnBudget(this, '{name}', {{\n"
            f"  budget: {{ budgetName: '{name}', budgetType: 'COST', timeUnit: 'MONTHLY' }},\n"
            f"  notificationsWithSubscribers: [{{ notification: {{ notificationType: '{kind}',"
            f" comparisonOperator: 'GREATER_THAN', threshold: {threshold} }}, {subs} }}]"
            f"{tags},\n}});\n")


# REPO-073: a budget names an owner.

@pytest.mark.parametrize("source", SOURCES)
def test_budget_without_owner_fires_repo_073(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source], _budget(source))
    (hit,) = BudgetOwnerMissing().run(tmp_path)
    assert hit.id == "REPO-073"
    assert "monthly" in hit.evidence and "Owner" in hit.evidence


@pytest.mark.parametrize("owner", ({"tag": "Owner"}, {"tag": "CostOwner"}, {"tag": "team"},
                                   {"subscriber": True}),
                         ids=("owner-tag", "cost-owner-tag", "team-tag", "subscriber"))
@pytest.mark.parametrize("source", SOURCES)
def test_budget_with_owner_passes_repo_073(tmp_path: Path, source: str, owner: dict) -> None:
    _stack(tmp_path, source, BUCKET[source], _budget(source, **owner))
    assert BudgetOwnerMissing().run(tmp_path) == []


def test_cdk_tags_of_budget_passes_repo_073(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", _budget("cdk"), "Tags.of(budget).add('Owner', 'team-a');\n")
    assert BudgetOwnerMissing().run(tmp_path) == []


def test_python_cdk_budget_repo_073(tmp_path: Path) -> None:
    body = ("budgets.CfnBudget(self, 'Monthly', budget=budgets.CfnBudget.BudgetDataProperty("
            "budget_type='COST', time_unit='MONTHLY'){})\n")
    _write(tmp_path / "prod" / "stack.py", body.format(""))
    assert BudgetOwnerMissing().run(tmp_path)
    _write(tmp_path / "prod" / "stack.py", body.format(
        ", resource_tags=[budgets.CfnBudget.ResourceTagProperty(key='Owner', value='a')]"))
    assert BudgetOwnerMissing().run(tmp_path) == []


@pytest.mark.parametrize("rule", (BudgetOwnerMissing(), ReactiveCostMonitoring()),
                         ids=lambda r: r.id)
@pytest.mark.parametrize("source", SOURCES)
def test_no_budget_is_left_to_cost_014(tmp_path: Path, source: str, rule) -> None:
    _stack(tmp_path, source, FUNCTION[source], BUCKET[source])
    assert rule.run(tmp_path) == []


# REPO-074: cost watched before it is spent.

ANOMALY = {
    "cdk": "new ce.CfnAnomalyMonitor(this, 'Anomalies', { monitorName: 'svc', "
           "monitorType: 'DIMENSIONAL', monitorDimension: 'SERVICE' });\n",
    "cloudformation": {"Anomalies": {"Type": "AWS::CE::AnomalyMonitor", "Properties": {
        "MonitorName": "svc", "MonitorType": "DIMENSIONAL"}}},
    "terraform": 'resource "aws_ce_anomaly_monitor" "svc" {\n  name = "svc"\n'
                 '  monitor_type = "DIMENSIONAL"\n}\n',
}


@pytest.mark.parametrize("threshold", (100, 120))
@pytest.mark.parametrize("source", SOURCES)
def test_actual_at_100_fires_repo_074(tmp_path: Path, source: str, threshold: int) -> None:
    _stack(tmp_path, source, _budget(source, threshold=threshold, subscriber=True))
    (hit,) = ReactiveCostMonitoring().run(tmp_path)
    assert hit.id == "REPO-074"
    assert "FORECASTED" in hit.evidence


@pytest.mark.parametrize("early", ({"threshold": 80}, {"kind": "FORECASTED"}),
                         ids=("80-percent", "forecasted"))
@pytest.mark.parametrize("source", SOURCES)
def test_early_notification_passes_repo_074(tmp_path: Path, source: str, early: dict) -> None:
    _stack(tmp_path, source, _budget(source, subscriber=True, **early))
    assert ReactiveCostMonitoring().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_anomaly_monitor_passes_repo_074(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _budget(source, subscriber=True), ANOMALY[source])
    assert ReactiveCostMonitoring().run(tmp_path) == []


def test_cfn_yaml_budget_repo_074(tmp_path: Path) -> None:
    yaml = ("Resources:\n  Monthly:\n    Type: AWS::Budgets::Budget\n    Properties:\n"
            "      Budget:\n        BudgetType: COST\n        TimeUnit: MONTHLY\n"
            "      NotificationsWithSubscribers:\n        - Notification:\n"
            "            NotificationType: ACTUAL\n            ComparisonOperator: GREATER_THAN\n"
            "            Threshold: {}\n          Subscribers:\n"
            "            - SubscriptionType: EMAIL\n              Address: a@example.com\n")
    _write(tmp_path / "prod" / "budget.yaml", yaml.format(100))
    assert ReactiveCostMonitoring().run(tmp_path)
    assert BudgetOwnerMissing().run(tmp_path) == []
    _write(tmp_path / "prod" / "budget.yaml", yaml.format(80))
    assert ReactiveCostMonitoring().run(tmp_path) == []


# REPO-075: previous-generation types and deprecated runtimes.

OLD = {
    "cdk": "new ec2.Instance(this, 'Box', { instanceType: new ec2.InstanceType('m1.small') });\n",
    "cloudformation": {"Box": {"Type": "AWS::EC2::Instance", "Properties": {
        "InstanceType": "x1e.xlarge"}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  runtime = "nodejs14.x"\n}\n',
}
CURRENT = {
    "cdk": "new ec2.Instance(this, 'Box', { instanceType: new ec2.InstanceType('m7g.large') });\n"
           "new lambda.Function(this, 'Fn', { runtime: lambda.Runtime.JAVA_8_CORRETTO });\n",
    "cloudformation": {"Box": {"Type": "AWS::EC2::Instance", "Properties": {
        "InstanceType": "r5.large"}}, "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
            "Runtime": "java8.al2"}}},
    "terraform": 'resource "aws_lambda_function" "fn" {\n  runtime = "python3.12"\n}\n'
                 'resource "aws_ebs_volume" "v" {\n  type = "gp2"\n}\n# we left m1 and c1\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_old_generation_fires_repo_075(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, OLD[source])
    (hit,) = OldGenerationResources().run(tmp_path)
    assert hit.id == "REPO-075"
    assert hit.file == f"prod/{_PATHS[source]}"


@pytest.mark.parametrize("source", SOURCES)
def test_current_generation_passes_repo_075(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, CURRENT[source])
    assert OldGenerationResources().run(tmp_path) == []


@pytest.mark.parametrize("text", (
    "instanceType: 'db.m1.small'", "cache_node_type = \"cache.t1.micro\"",
    "runtime: lambda.Runtime.PYTHON_3_7", "Runtime: go1.x", "runtime='ruby2.7'",
    "ec2.InstanceType.of(ec2.InstanceClass.P2, ec2.InstanceSize.XLARGE)",
))
def test_old_forms_fire_repo_075(tmp_path: Path, text: str) -> None:
    _write(tmp_path / "prod" / "stack.ts", text + "\n")
    assert OldGenerationResources().run(tmp_path)


@pytest.mark.parametrize("text", (
    "InstanceType: t2.micro", "instance_type = \"m4.large\"", "'db.m4.large'",
    "'db.t2.micro'", "cache.m3.medium", "c4.xlarge",
))
def test_sust_007_types_are_left_to_it(tmp_path: Path, text: str) -> None:
    _write(tmp_path / "prod" / "stack.ts", text + "\n")
    assert OldGenerationResources().run(tmp_path) == []
    assert LatestGenInstances().run(tmp_path)


@pytest.mark.parametrize("name,body", (
    ("docs/service-review.md", "Reviewed 2026-10-01: moved to Graviton.\n"),
    ("docs/notes.md", "# Architecture review\n\nHeld in March 2026.\n"),
))
def test_dated_review_note_passes_repo_075(tmp_path: Path, name: str, body: str) -> None:
    _stack(tmp_path, "terraform", OLD["terraform"])
    _write(tmp_path / name, body)
    assert OldGenerationResources().run(tmp_path) == []


def test_undated_review_note_does_not_pass_repo_075(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", OLD["terraform"])
    _write(tmp_path / "docs" / "service-review.md", "# Service review\n\nTo do.\n")
    assert OldGenerationResources().run(tmp_path)


# REPO-076: spend tied to a unit of business value.

@pytest.mark.parametrize("source", SOURCES)
def test_compute_without_unit_fires_repo_076(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, FUNCTION[source], _budget(source, name="monthly"))
    (hit,) = BusinessValueUnquantified().run(tmp_path)
    assert hit.id == "REPO-076"
    assert "Lambda" in hit.evidence


@pytest.mark.parametrize("name", ("cost-per-order", "CostPerTenant", "spend_per_request"))
@pytest.mark.parametrize("source", SOURCES)
def test_unit_budget_passes_repo_076(tmp_path: Path, source: str, name: str) -> None:
    _stack(tmp_path, source, FUNCTION[source], _budget(source, name=name))
    assert BusinessValueUnquantified().run(tmp_path) == []


def test_unit_cost_metric_passes_repo_076(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", FUNCTION["cdk"],
           "new cloudwatch.Metric({ namespace: 'Shop', metricName: 'CostPerOrder' });\n")
    assert BusinessValueUnquantified().run(tmp_path) == []


def test_superuser_is_not_a_unit_repo_076(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", FUNCTION["terraform"],
           _budget("terraform", name="superuser"))
    assert BusinessValueUnquantified().run(tmp_path)


def test_no_compute_passes_repo_076(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    assert BusinessValueUnquantified().run(tmp_path) == []


# REPO-077 to REPO-079: a cost note that names an owner.

NOTE_RULES = (FinanceTechPartnershipMissing(), CostAwareProcessMissing(),
              CostAwareCultureMissing())


@pytest.mark.parametrize("rule", NOTE_RULES, ids=lambda r: r.id)
@pytest.mark.parametrize("source", SOURCES)
def test_workload_without_cost_note_fires(tmp_path: Path, source: str, rule) -> None:
    _stack(tmp_path, source, BUCKET[source])
    (hit,) = rule.run(tmp_path)
    assert hit.id == rule.id
    assert "S3 bucket" in hit.evidence


@pytest.mark.parametrize("name,body", (
    ("COST.md", "# Cost\n\nOwner: Platform team\n"),
    ("FINOPS.md", "Cost owner: @alice\n"),
    ("docs/cost-ownership.md", "| Role | Name |\n| Accountable | jane@example.com |\n"),
    ("README.md", "# App\n\n## Cost ownership\n\n**Owner**: Payments team\n\n## Build\n"),
    ("docs/guide.md", "## FinOps\n\nThe contact is Jane Doe.\n"),
), ids=("cost-md", "finops-md", "docs-cost", "readme-heading", "docs-heading"))
@pytest.mark.parametrize("rule", NOTE_RULES, ids=lambda r: r.id)
def test_cost_note_with_owner_passes(tmp_path: Path, rule, name: str, body: str) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    _write(tmp_path / name, body)
    assert rule.run(tmp_path) == []


@pytest.mark.parametrize("name,body", (
    ("COST.md", "# Cost\n\nWe should keep spend low. Owner: TBD\n"),
    ("README.md", "## Cost\n\nCheck the budget.\n\n## Owner\n\nOwner: Platform team\n"),
    ("README.md", "## Cost Optimization (29 rules)\n\nOwner: Platform team\n"),
    ("notes.md", "Owner: Platform team\n"),
), ids=("placeholder", "owner-outside-section", "not-a-cost-heading", "not-a-cost-note"))
@pytest.mark.parametrize("rule", NOTE_RULES, ids=lambda r: r.id)
def test_cost_note_without_owner_does_not_pass(tmp_path: Path, rule, name: str,
                                               body: str) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    _write(tmp_path / name, body)
    assert rule.run(tmp_path)


@pytest.mark.parametrize("name", (".github/pull_request_template.md",
                                  ".github/PULL_REQUEST_TEMPLATE/infra.md",
                                  ".gitlab/merge_request_templates/Default.md"))
def test_pr_template_cost_checkbox_passes_repo_078_only(tmp_path: Path, name: str) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    _write(tmp_path / name, "## Checklist\n\n- [ ] Tests pass\n- [ ] Cost impact estimated\n")
    assert CostAwareProcessMissing().run(tmp_path) == []
    assert FinanceTechPartnershipMissing().run(tmp_path)
    assert CostAwareCultureMissing().run(tmp_path)


def test_pr_template_without_cost_item_fires_repo_078(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    _write(tmp_path / ".github" / "pull_request_template.md", "- [ ] Tests pass\n")
    assert CostAwareProcessMissing().run(tmp_path)


def test_tool_markdown_report_is_not_a_note(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"], OLD["terraform"])
    _write(tmp_path / "docs" / "cost-review.md",
           "# AWS Architecture Review Report\n\n- Generated: 2026-11-12 10:00\n\n"
           "## Cost\n\nOwner: Platform team\n")
    assert FinanceTechPartnershipMissing().run(tmp_path)
    assert OldGenerationResources().run(tmp_path)


# Shared: dev paths, saved reports, mapping.

RULES = (BudgetOwnerMissing(), ReactiveCostMonitoring(), OldGenerationResources(),
         BusinessValueUnquantified(), *NOTE_RULES)
FIRING = {
    "REPO-073": _budget("terraform"), "REPO-074": _budget("terraform"),
    "REPO-075": OLD["terraform"], "REPO-076": FUNCTION["terraform"],
    "REPO-077": BUCKET["terraform"], "REPO-078": BUCKET["terraform"],
    "REPO-079": BUCKET["terraform"],
}


@pytest.mark.parametrize("env", ("dev", "staging"))
@pytest.mark.parametrize("rule", [r for r in RULES if r.id not in ("REPO-073", "REPO-074")],
                         ids=lambda r: r.id)
def test_dev_paths_are_skipped(tmp_path: Path, rule, env: str) -> None:
    _stack(tmp_path, "terraform", FIRING[rule.id], env=env)
    assert rule.run(tmp_path) == []
    _stack(tmp_path, "terraform", FIRING[rule.id])
    assert rule.run(tmp_path)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path,
                                                                   rule) -> None:
    _stack(tmp_path, "terraform", FIRING[rule.id])
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
    ("REPO-073", "COST01-BP01"), ("REPO-074", "COST01-BP06"), ("REPO-075", "COST01-BP07"),
    ("REPO-076", "COST01-BP09"), ("REPO-077", "COST01-BP02"), ("REPO-078", "COST01-BP04"),
    ("REPO-079", "COST01-BP08"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert well_architected.question_of(rule_id) == "COST 1"


def test_new_rules_run_by_default() -> None:
    assert not {r.id for r in RULES} & ORG_RULE_IDS
    assert {r.category for r in RULES} == {"Cost"}
    assert {r.severity for r in RULES} == {"Low"}


def test_cost1_is_fully_checked() -> None:
    (cost1,) = [a for a in well_architected.answers([]) if a.question.id == "COST 1"]
    assert cost1.not_checked == ()


def test_cost1_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    findings = CostAwareCultureMissing().run(tmp_path)
    (cost1,) = [a for a in well_architected.answers(findings) if a.question.id == "COST 1"]
    assert not cost1.met
