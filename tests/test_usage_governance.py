"""COST 2: usage governance. Cost policies (REPO-080, account-level), cost controls
(REPO-081), goals and targets (REPO-082), account structure (REPO-083), billing access
through groups and roles (REPO-084), and project lifecycle tags (REPO-085)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    BillingAccessOnUser,
    BudgetTargetMissing,
    CostControlMissing,
    CostPolicyMissing,
    ProjectLifecycleUntracked,
    SharedAccountEnvironments,
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
SCP = {
    "cdk": "new organizations.CfnPolicy(this, 'Scp', { name: 'cost', "
           "type: 'SERVICE_CONTROL_POLICY', content });\n",
    "cloudformation": {"Scp": {"Type": "AWS::Organizations::Policy", "Properties": {
        "Name": "cost", "Type": "SERVICE_CONTROL_POLICY", "Content": {}}}},
    "terraform": 'resource "aws_organizations_policy" "cost" {\n  name = "cost"\n'
                 '  type = "SERVICE_CONTROL_POLICY"\n  content = "{}"\n}\n',
}


def _deny(source: str, action: str = "ec2:RunInstances",
          key: str = "ec2:InstanceType", effect: str = "Deny") -> object:
    """A policy statement on an action with a condition key."""
    if source == "cloudformation":
        return {"Guard": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
            "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": effect, "Action": action, "Resource": "*",
                "Condition": {"StringNotLike": {key: ["t3.*"]}}}]}}}}
    if source == "terraform":
        return ('resource "aws_iam_policy" "guard" {\n  policy = jsonencode({\n'
                f'    Statement = [{{\n      Effect = "{effect}"\n'
                f'      Action = "{action}"\n      Resource = "*"\n'
                f'      Condition = {{ StringNotLike = {{ "{key}" = ["t3.*"] }} }}\n'
                '    }]\n  })\n}\n')
    return (f"new iam.ManagedPolicy(this, 'Guard', {{ statements: [new iam.PolicyStatement({{"
            f" effect: iam.Effect.{effect.upper()}, actions: ['{action}'], resources: ['*'],"
            f" conditions: {{ StringNotLike: {{ '{key}': ['t3.*'] }} }} }})] }});\n")


# REPO-080: a policy states what may be spent.

@pytest.mark.parametrize("source", SOURCES)
def test_no_cost_policy_fires_repo_080(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source])
    (hit,) = CostPolicyMissing().run(tmp_path)
    assert hit.id == "REPO-080"
    assert "service control policy" in hit.evidence and "ec2:InstanceType" in hit.evidence


@pytest.mark.parametrize("policy", ("scp", "instance-type", "region", "sagemaker"))
@pytest.mark.parametrize("source", SOURCES)
def test_cost_policy_passes_repo_080(tmp_path: Path, source: str, policy: str) -> None:
    guard = {
        "scp": SCP[source],
        "instance-type": _deny(source),
        "region": _deny(source, action="*", key="aws:RequestedRegion"),
        "sagemaker": _deny(source, action="sagemaker:CreateEndpoint",
                           key="sagemaker:InstanceTypes"),
    }[policy]
    _stack(tmp_path, source, BUCKET[source], guard)
    assert CostPolicyMissing().run(tmp_path) == []


@pytest.mark.parametrize("guard", ({"effect": "Allow"},
                                   {"action": "s3:DeleteBucket", "key": "aws:SecureTransport"}),
                         ids=("allow", "unrelated-deny"))
@pytest.mark.parametrize("source", SOURCES)
def test_other_policies_do_not_pass_repo_080(tmp_path: Path, source: str, guard: dict) -> None:
    _stack(tmp_path, source, BUCKET[source], _deny(source, **guard))
    assert CostPolicyMissing().run(tmp_path)


def test_python_cdk_deny_passes_repo_080(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py", "s3.Bucket(self, 'Data')\n")
    assert CostPolicyMissing().run(tmp_path)
    _write(tmp_path / "prod" / "guard.py",
           "iam.PolicyStatement(effect=iam.Effect.DENY, actions=['rds:CreateDBInstance'], "
           "resources=['*'], conditions={'StringNotEquals': {'rds:DatabaseClass': "
           "['db.t4g.micro']}})\n")
    assert CostPolicyMissing().run(tmp_path) == []


def test_repo_080_is_org_level() -> None:
    assert "REPO-080" in ORG_RULE_IDS


# REPO-081: a cost control applies to the workload.

BOUNDARY = {
    "cdk": "PermissionsBoundary.of(this).apply(boundary);\n",
    "cloudformation": {"Role": {"Type": "AWS::IAM::Role", "Properties": {
        "AssumeRolePolicyDocument": {}, "PermissionsBoundary": "arn:aws:iam::1:policy/b"}}},
    "terraform": 'resource "aws_iam_role" "app" {\n  name = "app"\n'
                 '  permissions_boundary = aws_iam_policy.boundary.arn\n}\n',
}
BUDGET_ACTION = {
    "cdk": "new budgets.CfnBudgetsAction(this, 'Stop', { actionType: 'APPLY_IAM_POLICY', "
           "budgetName: 'monthly' });\n",
    "cloudformation": {"Stop": {"Type": "AWS::Budgets::BudgetsAction", "Properties": {
        "ActionType": "APPLY_IAM_POLICY", "BudgetName": "monthly"}}},
    "terraform": 'resource "aws_budgets_budget_action" "stop" {\n'
                 '  budget_name = "monthly"\n  action_type = "APPLY_IAM_POLICY"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_workload_without_control_fires_repo_081(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source])
    (hit,) = CostControlMissing().run(tmp_path)
    assert hit.id == "REPO-081"
    assert "permissions boundary" in hit.evidence and "Budgets action" in hit.evidence


@pytest.mark.parametrize("control", ("boundary", "budget-action", "deny", "scp"))
@pytest.mark.parametrize("source", SOURCES)
def test_cost_control_passes_repo_081(tmp_path: Path, source: str, control: str) -> None:
    guard = {"boundary": BOUNDARY[source], "budget-action": BUDGET_ACTION[source],
             "deny": _deny(source), "scp": SCP[source]}[control]
    _stack(tmp_path, source, BUCKET[source], guard)
    assert CostControlMissing().run(tmp_path) == []


def test_python_cdk_budget_action_passes_repo_081(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py", "s3.Bucket(self, 'Data')\n")
    assert CostControlMissing().run(tmp_path)
    _write(tmp_path / "prod" / "stack.py", "s3.Bucket(self, 'Data')\n"
           "budgets.CfnBudgetsAction(self, 'Stop', action_type='RUN_SSM_DOCUMENTS')\n")
    assert CostControlMissing().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_workload_is_skipped_repo_081(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"], env=env)
    assert CostControlMissing().run(tmp_path) == []
    assert CostPolicyMissing().run(tmp_path) == []


# REPO-082: a budget sets a target.

def _budget(source: str, limit: str | None = None) -> object:
    """A budget with a limit amount, planned limits, auto adjust only, or no target."""
    if source == "cloudformation":
        data: dict = {"BudgetType": "COST", "TimeUnit": "MONTHLY"}
        if limit == "amount":
            data["BudgetLimit"] = {"Amount": 100, "Unit": "USD"}
        elif limit == "planned":
            data["PlannedBudgetLimits"] = {"1735689600": {"Amount": 100, "Unit": "USD"}}
        elif limit == "auto":
            data["AutoAdjustData"] = {"AutoAdjustType": "HISTORICAL"}
        return {"Budget": {"Type": "AWS::Budgets::Budget", "Properties": {"Budget": data}}}
    if source == "terraform":
        extra = {"amount": '  limit_amount = "100"\n  limit_unit = "USD"\n',
                 "planned": '  planned_limit {\n    start_time = "2026-01-01_00:00"\n'
                            '    amount = "100"\n    unit = "USD"\n  }\n',
                 "auto": '  auto_adjust_data {\n    auto_adjust_type = "HISTORICAL"\n  }\n',
                 }.get(limit or "", "")
        return ('resource "aws_budgets_budget" "monthly" {\n  budget_type = "COST"\n'
                f'  time_unit = "MONTHLY"\n{extra}}}\n')
    extra = {"amount": ", budgetLimit: { amount: 100, unit: 'USD' }",
             "planned": ", plannedBudgetLimits: limits",
             "auto": ", autoAdjustData: { autoAdjustType: 'HISTORICAL' }"}.get(limit or "", "")
    return ("new budgets.CfnBudget(this, 'Monthly', { budget: { budgetType: 'COST', "
            f"timeUnit: 'MONTHLY'{extra} }} }});\n")


@pytest.mark.parametrize("limit", (None, "auto"), ids=("none", "auto-adjust-only"))
@pytest.mark.parametrize("source", SOURCES)
def test_budget_without_target_fires_repo_082(tmp_path: Path, source: str,
                                              limit: str | None) -> None:
    _stack(tmp_path, source, _budget(source, limit))
    (hit,) = BudgetTargetMissing().run(tmp_path)
    assert hit.id == "REPO-082"
    assert "limit amount" in hit.evidence and hit.file


@pytest.mark.parametrize("limit", ("amount", "planned"))
@pytest.mark.parametrize("source", SOURCES)
def test_budget_with_target_passes_repo_082(tmp_path: Path, source: str, limit: str) -> None:
    _stack(tmp_path, source, _budget(source, limit))
    assert BudgetTargetMissing().run(tmp_path) == []


def test_python_cdk_budget_repo_082(tmp_path: Path) -> None:
    body = ("budgets.CfnBudget(self, 'Monthly', budget=budgets.CfnBudget.BudgetDataProperty("
            "budget_type='COST', time_unit='MONTHLY'{}))\n")
    _write(tmp_path / "prod" / "stack.py", body.format(""))
    assert BudgetTargetMissing().run(tmp_path)
    _write(tmp_path / "prod" / "stack.py", body.format(
        ", budget_limit=budgets.CfnBudget.SpendProperty(amount=100, unit='USD')"))
    assert BudgetTargetMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_no_budget_is_left_to_cost_014_repo_082(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source])
    assert BudgetTargetMissing().run(tmp_path) == []


# REPO-083: production and non-production in separate accounts.

def _envs(root: Path, source: str, accounts: tuple[str, str] | None = None) -> None:
    """A production and a dev stack, with a literal account each when given."""
    if source == "cdk":
        prod, dev = (f"'{a}'" for a in accounts) if accounts else ("props.account",) * 2
        _write(root / "lib" / "stack.ts", BUCKET["cdk"])
        _write(root / "bin" / "app.ts",
               f"new AppStack(app, 'ProdStack', {{ env: {{ account: {prod}, region }} }});\n"
               f"new AppStack(app, 'DevStack', {{ env: {{ account: {dev}, region }} }});\n")
        return
    for env, account in zip(("prod", "dev"), accounts or (None, None)):
        if source == "terraform":
            pin = f'  allowed_account_ids = ["{account}"]\n' if account else ""
            _write(root / "envs" / env / "main.tf",
                   f'provider "aws" {{\n  region = "eu-west-1"\n{pin}}}\n'
                   + BUCKET["terraform"])
        else:
            _stack(root, source, BUCKET[source], env=env)


@pytest.mark.parametrize("source", SOURCES)
def test_shared_account_fires_repo_083(tmp_path: Path, source: str) -> None:
    _envs(tmp_path, source)
    (hit,) = SharedAccountEnvironments().run(tmp_path)
    assert hit.id == "REPO-083" and hit.severity == "Medium"
    assert "prod" in hit.evidence and "dev" in hit.evidence


@pytest.mark.parametrize("source", ("cdk", "terraform"))
def test_distinct_accounts_pass_repo_083(tmp_path: Path, source: str) -> None:
    _envs(tmp_path, source, ("111111111111", "222222222222"))
    assert SharedAccountEnvironments().run(tmp_path) == []


@pytest.mark.parametrize("source", ("cdk", "terraform"))
def test_same_account_twice_fires_repo_083(tmp_path: Path, source: str) -> None:
    _envs(tmp_path, source, ("111111111111", "111111111111"))
    assert SharedAccountEnvironments().run(tmp_path)


def test_assume_role_accounts_pass_repo_083(tmp_path: Path) -> None:
    _envs(tmp_path, "terraform")
    for env, account in (("prod", "111111111111"), ("dev", "222222222222")):
        _write(tmp_path / "envs" / env / "provider.tf",
               'provider "aws" {\n  assume_role {\n'
               f'    role_arn = "arn:aws:iam::{account}:role/deploy"\n  }}\n}}\n')
    assert SharedAccountEnvironments().run(tmp_path) == []


def test_tfvars_accounts_pass_repo_083(tmp_path: Path) -> None:
    _envs(tmp_path, "terraform")
    _write(tmp_path / "prod.tfvars", 'account_id = "111111111111"\n')
    _write(tmp_path / "dev.tfvars", 'account_id = "222222222222"\n')
    assert SharedAccountEnvironments().run(tmp_path) == []


@pytest.mark.parametrize("split", ("ou", "stackset"))
def test_cloudformation_account_split_passes_repo_083(tmp_path: Path, split: str) -> None:
    _envs(tmp_path, "cloudformation")
    body = ({"Ou": {"Type": "AWS::Organizations::OrganizationalUnit",
                    "Properties": {"Name": "prod", "ParentId": "r-1"}}}
            if split == "ou" else
            {"Set": {"Type": "AWS::CloudFormation::StackSet", "Properties": {
                "StackSetName": "app", "StackInstancesGroup": [{
                    "DeploymentTargets": {"OrganizationalUnitIds": ["ou-1"]},
                    "Regions": ["eu-west-1"]}]}}})
    _write(tmp_path / "org" / "org.template.json", json.dumps({"Resources": body}))
    assert SharedAccountEnvironments().run(tmp_path) == []


def test_python_cdk_stages_repo_083(tmp_path: Path) -> None:
    body = ("AppStage(app, 'Prod', env=cdk.Environment(account={}))\n"
            "AppStage(app, 'Dev', env=cdk.Environment(account={}))\n")
    _write(tmp_path / "stack.py", "s3.Bucket(self, 'Data')\n")
    _write(tmp_path / "app.py", body.format("acct", "acct"))
    assert SharedAccountEnvironments().run(tmp_path)
    _write(tmp_path / "app.py", body.format("'111111111111'", "'222222222222'"))
    assert SharedAccountEnvironments().run(tmp_path) == []


def test_terraform_workspaces_repo_083(tmp_path: Path) -> None:
    _write(tmp_path / "main.tf",
           'locals {\n  size = terraform.workspace == "prod" ? "large" : "small"\n'
           '  debug = terraform.workspace == "dev"\n}\n' + BUCKET["terraform"])
    assert SharedAccountEnvironments().run(tmp_path)


def test_environments_without_resources_pass_repo_083(tmp_path: Path) -> None:
    _write(tmp_path / "prod.tfvars", 'region = "eu-west-1"\n')
    _write(tmp_path / "dev.tfvars", 'region = "eu-west-1"\n')
    assert SharedAccountEnvironments().run(tmp_path) == []
    _write(tmp_path / "main.tf", BUCKET["terraform"])
    assert SharedAccountEnvironments().run(tmp_path)


@pytest.mark.parametrize("source", SOURCES)
def test_one_environment_passes_repo_083(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source])
    assert SharedAccountEnvironments().run(tmp_path) == []


# REPO-084: billing access through groups and roles.

def _billing(source: str, principal: str = "user") -> object:
    """Billing granted to an IAM user (or a group) through a managed or inline policy."""
    if source == "cloudformation":
        kind = {"user": "User", "group": "Group"}[principal]
        return {"Finance": {"Type": f"AWS::IAM::{kind}", "Properties": {
            "ManagedPolicyArns": ["arn:aws:iam::aws:policy/job-function/Billing"]}}}
    if source == "terraform":
        if principal == "group":
            return ('resource "aws_iam_group_policy_attachment" "finance" {\n'
                    '  group = aws_iam_group.finance.name\n'
                    '  policy_arn = "arn:aws:iam::aws:policy/AWSBillingReadOnlyAccess"\n}\n')
        return ('resource "aws_iam_user_policy_attachment" "finance" {\n'
                '  user = aws_iam_user.finance.name\n'
                '  policy_arn = "arn:aws:iam::aws:policy/AWSBillingReadOnlyAccess"\n}\n')
    kind = {"user": "User", "group": "Group"}[principal]
    return (f"const finance = new iam.{kind}(this, 'Finance');\n"
            "finance.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName("
            "'job-function/Billing'));\n")


@pytest.mark.parametrize("source", SOURCES)
def test_billing_on_user_fires_repo_084(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _billing(source))
    (hit,) = BillingAccessOnUser().run(tmp_path)
    assert hit.id == "REPO-084" and hit.file and hit.line
    assert "finance" in hit.evidence.lower()


@pytest.mark.parametrize("source", SOURCES)
def test_billing_on_group_passes_repo_084(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _billing(source, "group"))
    assert BillingAccessOnUser().run(tmp_path) == []


def test_inline_billing_policies_fire_repo_084(tmp_path: Path) -> None:
    cfn = {"Finance": {"Type": "AWS::IAM::User", "Properties": {"Policies": [{
        "PolicyName": "cost", "PolicyDocument": {"Statement": [{
            "Effect": "Allow", "Action": ["ce:GetCostAndUsage"], "Resource": "*"}]}}]}},
        "Attached": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
            "Users": [{"Ref": "Finance"}], "PolicyDocument": {"Statement": [{
                "Effect": "Allow", "Action": "aws-portal:ViewBilling", "Resource": "*"}]}}}}
    _stack(tmp_path / "cf", "cloudformation", cfn)
    assert len(BillingAccessOnUser().run(tmp_path / "cf")[0].evidence.split(" in ")) == 3
    _stack(tmp_path / "tf", "terraform",
           'data "aws_iam_policy_document" "cost" {\n  statement {\n'
           '    actions = ["budgets:ViewBudget"]\n    resources = ["*"]\n  }\n}\n'
           'resource "aws_iam_user_policy" "cost" {\n  user = aws_iam_user.finance.name\n'
           '  policy = data.aws_iam_policy_document.cost.json\n}\n')
    assert BillingAccessOnUser().run(tmp_path / "tf")
    _stack(tmp_path / "cdk", "cdk",
           "const user = new iam.User(this, 'Finance');\n"
           "const cost = new iam.Policy(this, 'Cost', { statements: [new iam.PolicyStatement("
           "{ actions: ['cur:DescribeReportDefinitions'], resources: ['*'] })] });\n"
           "user.attachInlinePolicy(cost);\n")
    assert BillingAccessOnUser().run(tmp_path / "cdk")


def test_python_cdk_billing_on_user_repo_084(tmp_path: Path) -> None:
    body = ("finance = iam.User(self, 'Finance')\nfinance.add_to_policy(iam.PolicyStatement("
            "actions=['{}'], resources=['*']))\n")
    _write(tmp_path / "prod" / "stack.py", body.format("billing:GetBillingData"))
    assert BillingAccessOnUser().run(tmp_path)
    _write(tmp_path / "prod" / "stack.py", body.format("s3:GetObject"))
    assert BillingAccessOnUser().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_no_billing_grant_passes_repo_084(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source], _deny(source, effect="Allow"))
    assert BillingAccessOnUser().run(tmp_path) == []


def test_repo_084_is_identity() -> None:
    assert BillingAccessOnUser.themes == ("identity",)


# REPO-085: temporary stacks carry an end date and an environment.

def _tags(source: str, *keys: str) -> object:
    if source == "cloudformation":
        return {"Data": {"Type": "AWS::S3::Bucket", "Properties": {
            "Tags": [{"Key": k, "Value": "x"} for k in keys]}}}
    if source == "terraform":
        tags = "".join(f'      {k} = "x"\n' for k in keys)
        return ('provider "aws" {\n  default_tags {\n    tags = {\n'
                f'{tags}    }}\n  }}\n}}\n' + BUCKET["terraform"])
    return BUCKET["cdk"] + "".join(f"Tags.of(this).add('{k}', 'x');\n" for k in keys)


@pytest.mark.parametrize("env", ("sandbox", "scratch", "preview", "pr-12"))
@pytest.mark.parametrize("source", SOURCES)
def test_temporary_stack_without_end_date_fires_repo_085(tmp_path: Path, source: str,
                                                         env: str) -> None:
    _stack(tmp_path, source, _tags(source, "Environment"), env=env)
    (hit,) = ProjectLifecycleUntracked().run(tmp_path)
    assert hit.id == "REPO-085"
    assert "no end-date tag" in hit.evidence and env in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_temporary_stack_without_any_tag_names_both_repo_085(tmp_path: Path,
                                                             source: str) -> None:
    _stack(tmp_path, source, _tags(source), env="sandbox")
    (hit,) = ProjectLifecycleUntracked().run(tmp_path)
    assert "no end-date or environment tag" in hit.evidence


@pytest.mark.parametrize("keys", (("ExpiryDate", "Environment"), ("delete-after", "env"),
                                  ("TTL", "Stage")))
@pytest.mark.parametrize("source", SOURCES)
def test_tagged_temporary_stack_passes_repo_085(tmp_path: Path, source: str,
                                                keys: tuple[str, str]) -> None:
    _stack(tmp_path, source, _tags(source, *keys), env="sandbox")
    assert ProjectLifecycleUntracked().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_production_stack_passes_repo_085(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _tags(source))
    assert ProjectLifecycleUntracked().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_long_lived_environments_are_not_temporary_repo_085(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", _tags("terraform"), env=env)
    assert ProjectLifecycleUntracked().run(tmp_path) == []


def test_terraform_tags_in_sibling_file_pass_repo_085(tmp_path: Path) -> None:
    _write(tmp_path / "sandbox" / "main.tf", BUCKET["terraform"])
    assert ProjectLifecycleUntracked().run(tmp_path)
    _write(tmp_path / "sandbox" / "providers.tf",
           'provider "aws" {\n  default_tags {\n    tags = {\n      Environment = "dev"\n'
           '      ExpiryDate = "2026-12-31"\n    }\n  }\n}\n')
    assert ProjectLifecycleUntracked().run(tmp_path) == []


def test_cdk_stack_ids_repo_085(tmp_path: Path) -> None:
    body = ("new AppStack(app, 'ProdStack');\nnew AppStack(app, 'Pr42Stack');\n"
            "new AppStack(app, 'FeatureLoginStack');\n")
    _write(tmp_path / "bin" / "app.ts", body)
    (hit,) = ProjectLifecycleUntracked().run(tmp_path)
    assert "Pr42Stack" in hit.evidence and "FeatureLoginStack" in hit.evidence
    assert "ProdStack" not in hit.evidence
    _write(tmp_path / "bin" / "app.ts", body + "Tags.of(app).add('Environment', 'dev');\n"
           "Tags.of(app).add('Expires', '2026-12-31');\n")
    assert ProjectLifecycleUntracked().run(tmp_path) == []


def test_python_cdk_stack_ids_repo_085(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "AppStack(app, 'SandboxStack')\n")
    assert ProjectLifecycleUntracked().run(tmp_path)
    _write(tmp_path / "app.py", "AppStack(app, 'SandboxStack')\n"
           "Tags.of(app).add('EndDate', '2026-12-31')\nTags.of(app).add('Environment', 'dev')\n")
    assert ProjectLifecycleUntracked().run(tmp_path) == []


def test_code_without_resources_is_not_a_stack_repo_085(tmp_path: Path) -> None:
    _write(tmp_path / "sandbox" / "handler.py", "def handler(event, context):\n    return 1\n")
    assert ProjectLifecycleUntracked().run(tmp_path) == []


# Shared.

RULES = (CostPolicyMissing(), CostControlMissing(), BudgetTargetMissing(),
         SharedAccountEnvironments(), BillingAccessOnUser(), ProjectLifecycleUntracked())


def _firing(rule_id: str, root: Path) -> None:
    if rule_id == "REPO-082":
        _stack(root, "terraform", _budget("terraform"))
    elif rule_id == "REPO-083":
        _envs(root, "terraform")
    elif rule_id == "REPO-084":
        _stack(root, "terraform", _billing("terraform"))
    elif rule_id == "REPO-085":
        _stack(root, "terraform", BUCKET["terraform"], env="sandbox")
    else:
        _stack(root, "terraform", BUCKET["terraform"])


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
    ("REPO-080", "COST02-BP01"), ("REPO-081", "COST02-BP05"), ("REPO-082", "COST02-BP02"),
    ("REPO-083", "COST02-BP03"), ("REPO-084", "COST02-BP04"), ("REPO-085", "COST02-BP06"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert well_architected.question_of(rule_id) == "COST 2"


def test_only_repo_080_is_org_level() -> None:
    assert {r.id for r in RULES} & ORG_RULE_IDS == {"REPO-080"}
    assert {r.category for r in RULES} == {"Cost"}
    assert {r.id: r.severity for r in RULES if r.severity != "Low"} == {"REPO-083": "Medium"}


def test_cost2_is_fully_checked() -> None:
    (cost2,) = [a for a in well_architected.answers([]) if a.question.id == "COST 2"]
    assert cost2.not_checked == ()


def test_cost2_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    findings = CostControlMissing().run(tmp_path)
    (cost2,) = [a for a in well_architected.answers(findings) if a.question.id == "COST 2"]
    assert not cost2.met
