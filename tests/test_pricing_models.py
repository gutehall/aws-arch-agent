"""COST 7: pricing models. Pricing model analysis for fleets (REPO-090), Region by cost
(REPO-091), third-party agreement terms (REPO-092) and pricing at the management account
level (REPO-093)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    HIGHER_PRICED_REGIONS,
    ManagementPricingMissing,
    PricingModelUnanalysed,
    RegionNotChosenByCost,
    ThirdPartyTermsMissing,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}
RULES = (PricingModelUnanalysed(), RegionNotChosenByCost(), ThirdPartyTermsMissing(),
         ManagementPricingMissing())


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


# REPO-090: pricing model analysis.

ASG = {
    "cdk": "new autoscaling.AutoScalingGroup(this, 'Web', { vpc, minCapacity: 2, "
           "maxCapacity: 6 });\n",
    "cloudformation": {"Web": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
        "MinSize": "2", "MaxSize": "6"}}},
    "terraform": 'resource "aws_autoscaling_group" "web" {\n  min_size = 2\n'
                 '  max_size = 6\n}\n',
}
ECS = {
    "cdk": "new ecs.FargateService(this, 'Api', { cluster, taskDefinition });\n",
    "cloudformation": {"Api": {"Type": "AWS::ECS::Service", "Properties": {}}},
    "terraform": 'resource "aws_ecs_service" "api" {\n  name = "api"\n}\n',
}
NODEGROUP = {
    "cdk": "cluster.addNodegroupCapacity('Workers', { minSize: 2 });\n",
    "cloudformation": {"Workers": {"Type": "AWS::EKS::Nodegroup", "Properties": {}}},
    "terraform": 'resource "aws_eks_node_group" "workers" {\n  cluster_name = "main"\n}\n',
}
BATCH = {
    "cdk": "new batch.ManagedEc2EcsComputeEnvironment(this, 'Jobs', { vpc });\n",
    "cloudformation": {"Jobs": {"Type": "AWS::Batch::ComputeEnvironment", "Properties": {
        "Type": "MANAGED", "ComputeResources": {"Type": "EC2"}}}},
    "terraform": 'resource "aws_batch_compute_environment" "jobs" {\n'
                 '  compute_resources {\n    type = "EC2"\n  }\n}\n',
}
DATABASE = {
    "cdk": "new rds.DatabaseInstance(this, 'Db', { engine });\n",
    "cloudformation": {"Db": {"Type": "AWS::RDS::DBInstance", "Properties": {}}},
    "terraform": 'resource "aws_db_instance" "db" {\n  engine = "postgres"\n}\n',
}
COMMITMENT_TAG = {
    "cdk": "Tags.of(this).add('PricingModel', 'compute-savings-plan');\n",
    "cloudformation": {"Tagged": {"Type": "AWS::S3::Bucket", "Properties": {
        "Tags": [{"Key": "Commitment", "Value": "ri-3y"}]}}},
    "terraform": 'provider "aws" {\n  default_tags {\n    tags = {\n'
                 '      SavingsPlan = "compute"\n    }\n  }\n}\n',
}
SPOT = {
    "cdk": (
        "new autoscaling.AutoScalingGroup(this, 'Spot', { vpc, spotPrice: '0.05' });\n",
        "new autoscaling.AutoScalingGroup(this, 'Mixed', { mixedInstancesPolicy: { "
        "instancesDistribution: { onDemandPercentageAboveBaseCapacity: 20 } } });\n",
        "new autoscaling.AutoScalingGroup(this, 'Mixed', { mixedInstancesPolicy: { "
        "instancesDistribution: { spotAllocationStrategy: SpotAllocationStrategy."
        "PRICE_CAPACITY_OPTIMIZED } } });\n",
        "capacityProviderStrategies: [{ capacityProvider: 'FARGATE_SPOT', weight: 2 }],\n",
        "cluster.addNodegroupCapacity('Spot', { capacityType: eks.CapacityType.SPOT });\n",
        "new batch.ManagedEc2EcsComputeEnvironment(this, 'Spot', { vpc, spot: true });\n",
        "cluster.addCapacity('Asg', { spotInstanceDraining: true });\n",
    ),
    "cloudformation": (
        {"Lt": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {"LaunchTemplateData": {
            "InstanceMarketOptions": {"MarketType": "spot"}}}}},
        {"Mixed": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
            "MixedInstancesPolicy": {"InstancesDistribution": {
                "OnDemandPercentageAboveBaseCapacity": 0}}}}},
        {"Cp": {"Type": "AWS::ECS::ClusterCapacityProviderAssociations", "Properties": {
            "CapacityProviders": ["FARGATE", "FARGATE_SPOT"]}}},
        {"Ng": {"Type": "AWS::EKS::Nodegroup", "Properties": {"CapacityType": "SPOT"}}},
        {"Ce": {"Type": "AWS::Batch::ComputeEnvironment", "Properties": {
            "ComputeResources": {"Type": "SPOT"}}}},
    ),
    "terraform": (
        'resource "aws_launch_template" "lt" {\n  instance_market_options {\n'
        '    market_type = "spot"\n  }\n}\n',
        'resource "aws_eks_node_group" "spot" {\n  capacity_type = "SPOT"\n}\n',
        'resource "aws_batch_compute_environment" "spot" {\n  compute_resources {\n'
        '    type = "SPOT"\n  }\n}\n',
        'resource "aws_batch_compute_environment" "fspot" {\n  compute_resources {\n'
        '    type = "FARGATE_SPOT"\n  }\n}\n',
        'resource "aws_launch_configuration" "lc" {\n  spot_price = "0.05"\n}\n',
    ),
}
SPOT_CASES = [(s, i) for s in SOURCES for i in range(len(SPOT[s]))]


@pytest.mark.parametrize("fleet", (ASG, ECS, NODEGROUP, BATCH),
                         ids=("asg", "ecs", "nodegroup", "batch"))
@pytest.mark.parametrize("source", SOURCES)
def test_on_demand_fleet_fires_repo_090(tmp_path: Path, source: str, fleet: dict) -> None:
    _stack(tmp_path, source, fleet[source])
    (hit,) = PricingModelUnanalysed().run(tmp_path)
    assert hit.id == "REPO-090"
    assert f"in prod/{_PATHS[source]}" in hit.evidence and "Spot" in hit.evidence


@pytest.mark.parametrize("source,index", SPOT_CASES)
def test_spot_setting_passes_repo_090(tmp_path: Path, source: str, index: int) -> None:
    _stack(tmp_path, source, ASG[source], SPOT[source][index])
    assert PricingModelUnanalysed().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_commitment_tag_passes_repo_090(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ECS[source], COMMITMENT_TAG[source])
    assert PricingModelUnanalysed().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("docs/pricing-model.md", "Baseline on a Compute Savings Plan.\n"),
    ("SAVINGS_PLANS.md", "Bought in March.\n"),
    ("README.md", "# App\n\n## Reserved Instances\n\nThree-year for the baseline.\n"),
    ("docs/cost.md", "# Cost\n\n## Commitments\n\nNone yet: usage is not steady.\n"),
))
def test_pricing_note_passes_repo_090(tmp_path: Path, path: str, text: str) -> None:
    _stack(tmp_path, "terraform", ASG["terraform"])
    _write(tmp_path / path, text)
    assert PricingModelUnanalysed().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_on_demand_database_alone_is_silent_repo_090(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, DATABASE[source])
    assert PricingModelUnanalysed().run(tmp_path) == []


def test_spot_in_dev_does_not_pass_production_repo_090(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", ASG["terraform"])
    _stack(tmp_path, "terraform", SPOT["terraform"][0], env="dev")
    assert PricingModelUnanalysed().run(tmp_path)


def test_full_on_demand_mixed_instances_fires_repo_090(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_autoscaling_group" "web" {\n'
           '  mixed_instances_policy {\n    instances_distribution {\n'
           '      on_demand_percentage_above_base_capacity = 100\n    }\n  }\n}\n')
    assert PricingModelUnanalysed().run(tmp_path)


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_fleet_is_skipped_repo_090(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", ASG["terraform"], env=env)
    assert PricingModelUnanalysed().run(tmp_path) == []


def test_python_cdk_repo_090(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "eks.Nodegroup(self, 'Workers', cluster=cluster)\n")
    (hit,) = PricingModelUnanalysed().run(tmp_path)
    assert "EKS node group Workers in app.py:1" in hit.evidence
    _write(tmp_path / "app.py", "eks.Nodegroup(self, 'Workers', cluster=cluster, "
           "capacity_type=eks.CapacityType.SPOT)\n")
    assert PricingModelUnanalysed().run(tmp_path) == []


# REPO-091: Region by cost.

REGION = {
    "cdk": "new AppStack(app, 'App', {{ env: {{ region: '{region}' }} }});\n",
    "terraform": 'provider "aws" {{\n  region = "{region}"\n}}\n',
}


@pytest.mark.parametrize("source", ("cdk", "terraform"))
def test_higher_priced_region_fires_repo_091(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, REGION[source].format(region="sa-east-1"))
    (hit,) = RegionNotChosenByCost().run(tmp_path)
    assert hit.id == "REPO-091"
    assert f"sa-east-1 at prod/{_PATHS[source]}:" in hit.evidence


def test_every_listed_region_fires_repo_091(tmp_path: Path) -> None:
    for i, region in enumerate(HIGHER_PRICED_REGIONS):
        _write(tmp_path / "prod" / f"r{i}.tf", REGION["terraform"].format(region=region))
    (hit,) = RegionNotChosenByCost().run(tmp_path)
    assert f"and {len(HIGHER_PRICED_REGIONS) - 3} more" in hit.evidence


@pytest.mark.parametrize("region", ("us-east-1", "us-west-2", "eu-west-1"))
@pytest.mark.parametrize("source", ("cdk", "terraform"))
def test_lower_priced_region_passes_repo_091(tmp_path: Path, source: str,
                                             region: str) -> None:
    _stack(tmp_path, source, REGION[source].format(region=region))
    assert RegionNotChosenByCost().run(tmp_path) == []


@pytest.mark.parametrize("source,text", (
    ("cdk", "new AppStack(app, 'App', { env: { region: process.env.CDK_DEFAULT_REGION } });\n"),
    ("cdk", "new AppStack(app, 'App', { env: { region: app.node.tryGetContext('region') } });\n"),
    ("terraform", 'provider "aws" {\n  region = var.region\n}\n'),
    ("terraform", 'variable "region" {\n  type = string\n}\n'),
))
def test_region_from_parameter_passes_repo_091(tmp_path: Path, source: str,
                                               text: str) -> None:
    _stack(tmp_path, source, text)
    assert RegionNotChosenByCost().run(tmp_path) == []


def test_terraform_variable_default_fires_repo_091(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'variable "region" {\n  default = "ap-southeast-2"\n}\n')
    (hit,) = RegionNotChosenByCost().run(tmp_path)
    assert "ap-southeast-2 at prod/main.tf:2" in hit.evidence


def test_cloudformation_is_region_agnostic_repo_091(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", {"Rec": {"Type": "AWS::Route53::RecordSet",
                                                "Properties": {"Region": "sa-east-1"}}})
    assert RegionNotChosenByCost().run(tmp_path) == []


def test_cloudformation_stackset_region_fires_repo_091(tmp_path: Path) -> None:
    stackset = {"Set": {"Type": "AWS::CloudFormation::StackSet", "Properties": {
        "StackInstancesGroup": [{"Regions": ["us-east-1", "ap-northeast-1"]}]}}}
    _stack(tmp_path, "cloudformation", stackset)
    (hit,) = RegionNotChosenByCost().run(tmp_path)
    assert "ap-northeast-1 at prod/stack.template.json" in hit.evidence
    assert "us-east-1" not in hit.evidence.split(", priced")[0]


@pytest.mark.parametrize("source,text", (
    ("cdk", "new AppStack(app, 'App', { env: { region: 'sa-east-1' } }); // latency\n"),
    ("cdk", "// data residency: Brazilian customer data stays in Brazil\n"
            "new AppStack(app, 'App', { env: { region: 'sa-east-1' } });\n"),
    ("terraform", 'provider "aws" {\n  # compliance: LGPD\n  region = "sa-east-1"\n}\n'),
))
def test_region_comment_passes_repo_091(tmp_path: Path, source: str, text: str) -> None:
    _stack(tmp_path, source, text)
    assert RegionNotChosenByCost().run(tmp_path) == []


def test_unrelated_comment_does_not_pass_repo_091(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'provider "aws" {\n  # main provider\n'
           '  region = "sa-east-1"\n}\n')
    assert RegionNotChosenByCost().run(tmp_path)


@pytest.mark.parametrize("path,text", (
    ("docs/region.md", "We run in sa-east-1 for latency to users in Brazil.\n"),
    ("README.md", "# App\n\n## Region choice\n\nsa-east-1 for data residency.\n\n## Use\n"),
    ("docs/arch.md", "# Arch\n\n## Region\n\nsa-east-1 costs more; latency wins.\n"),
))
def test_region_note_passes_repo_091(tmp_path: Path, path: str, text: str) -> None:
    _stack(tmp_path, "terraform", REGION["terraform"].format(region="sa-east-1"))
    _write(tmp_path / path, text)
    assert RegionNotChosenByCost().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("docs/region.md", "We run in sa-east-1.\n"),
    ("README.md", "# App\n\n## Price region\n\nEach stack is priced in one region.\n"),
    ("README.md", "# App\n\n## Usage\n\nsa-east-1 for latency.\n"),
))
def test_region_note_without_reason_or_region_fires_repo_091(tmp_path: Path, path: str,
                                                             text: str) -> None:
    _stack(tmp_path, "terraform", REGION["terraform"].format(region="sa-east-1"))
    _write(tmp_path / path, text)
    assert RegionNotChosenByCost().run(tmp_path)


def test_python_cdk_repo_091(tmp_path: Path) -> None:
    _write(tmp_path / "app.py",
           "AppStack(app, 'App', env=cdk.Environment(region='eu-central-2'))\n")
    (hit,) = RegionNotChosenByCost().run(tmp_path)
    assert "eu-central-2 at app.py:1" in hit.evidence
    _write(tmp_path / "app.py",
           "AppStack(app, 'App', env=cdk.Environment(region='eu-central-2'))  # sovereignty\n")
    assert RegionNotChosenByCost().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_region_is_skipped_repo_091(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", REGION["terraform"].format(region="sa-east-1"), env=env)
    assert RegionNotChosenByCost().run(tmp_path) == []


# REPO-092: third-party agreement terms.

MARKETPLACE = {
    "cdk": "const ami = ec2.MachineImage.lookup({ name: 'fw-*', owners: ['aws-marketplace'] "
           "});\n",
    "cloudformation": {"Fw": {"Type": "AWS::EC2::Instance", "Metadata": {
        "ProductCode": "abc123"}, "Properties": {}}},
    "terraform": 'data "aws_ami" "fw" {\n  most_recent = true\n'
                 '  owners      = ["aws-marketplace"]\n}\n',
}
TERM_TAG = {
    "cdk": "Tags.of(this).add('ContractEnd', '2027-06-30');\n",
    "cloudformation": {"Tagged": {"Type": "AWS::S3::Bucket", "Properties": {
        "Tags": [{"Key": "MarketplaceTerm", "Value": "12-month"}]}}},
    "terraform": 'provider "aws" {\n  default_tags {\n    tags = {\n'
                 '      LicenseTerm = "annual"\n    }\n  }\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_marketplace_without_term_fires_repo_092(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, MARKETPLACE[source])
    (hit,) = ThirdPartyTermsMissing().run(tmp_path)
    assert hit.id == "REPO-092"
    assert f"in prod/{_PATHS[source]}:" in hit.evidence and "ContractEnd" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_marketplace_with_term_tag_passes_repo_092(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, MARKETPLACE[source], TERM_TAG[source])
    assert ThirdPartyTermsMissing().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("docs/vendors.md", "Firewall: annual private offer.\n"),
    ("MARKETPLACE.md", "Renews 2027-06-30.\n"),
    ("README.md", "# App\n\n## Third-party licences\n\n36-month contract for the WAF.\n"),
))
def test_vendor_note_with_term_passes_repo_092(tmp_path: Path, path: str, text: str) -> None:
    _stack(tmp_path, "terraform", MARKETPLACE["terraform"])
    _write(tmp_path / path, text)
    assert ThirdPartyTermsMissing().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("docs/vendors.md", "Firewall from the Marketplace.\n"),
    ("README.md", "# App\n\n## License\n\nMIT.\n"),
    ("README.md", "# App\n\n## Usage\n\nAnnual contract for the firewall.\n"),
))
def test_vendor_note_without_term_fires_repo_092(tmp_path: Path, path: str,
                                                 text: str) -> None:
    _stack(tmp_path, "terraform", MARKETPLACE["terraform"])
    _write(tmp_path / path, text)
    assert ThirdPartyTermsMissing().run(tmp_path)


@pytest.mark.parametrize("text", (
    'data "aws_ami" "fw" {\n  filter {\n    name   = "product-code"\n'
    '    values = ["abc123"]\n  }\n}\n',
    'resource "aws_instance" "fw" {\n  ami = "ami-1"\n}\n'
    'data "aws_ami" "fw" {\n  owners = ["self", "aws-marketplace"]\n}\n',
))
def test_terraform_marketplace_forms_fire_repo_092(tmp_path: Path, text: str) -> None:
    _stack(tmp_path, "terraform", text)
    assert ThirdPartyTermsMissing().run(tmp_path)


def test_service_catalog_marketplace_product_fires_repo_092(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.yaml",
           "Resources:\n  Fw:\n    Type: AWS::ServiceCatalog::CloudFormationProvisionedProduct\n"
           "    Properties:\n      ProductId: prod-abc123\n")
    (hit,) = ThirdPartyTermsMissing().run(tmp_path)
    assert "Marketplace product in prod/stack.yaml:5" in hit.evidence


@pytest.mark.parametrize("source,text", (
    ("terraform", 'data "aws_ami" "al" {\n  owners = ["amazon"]\n}\n'),
    ("cdk", "const ami = ec2.MachineImage.lookup({ name: 'al-*', owners: ['amazon'] });\n"),
    ("cdk", "const ami = ec2.MachineImage.latestAmazonLinux2023();\n"),
))
def test_no_marketplace_is_silent_repo_092(tmp_path: Path, source: str, text: str) -> None:
    _stack(tmp_path, source, text)
    assert ThirdPartyTermsMissing().run(tmp_path) == []


def test_python_cdk_repo_092(tmp_path: Path) -> None:
    _write(tmp_path / "app.py",
           "ami = ec2.MachineImage.lookup(name='fw-*', owners=['aws-marketplace'])\n")
    (hit,) = ThirdPartyTermsMissing().run(tmp_path)
    assert "Marketplace AMI lookup in app.py:1" in hit.evidence
    _write(tmp_path / "docs" / "third-party.md", "Firewall: renewal 2027-01-31.\n")
    assert ThirdPartyTermsMissing().run(tmp_path) == []


# REPO-093: pricing at the management account level.

ORG = {
    "cdk": "new organizations.CfnAccount(this, 'Prod', { accountName: 'prod', "
           "email: 'a@example.com' });\n",
    "cloudformation": {"Ou": {"Type": "AWS::Organizations::OrganizationalUnit",
                              "Properties": {"Name": "workloads"}}},
    "terraform": 'resource "aws_organizations_policy" "deny" {\n'
                 '  type = "SERVICE_CONTROL_POLICY"\n}\n',
}
SP_BUDGET = {
    "cdk": "new budgets.CfnBudget(this, 'Sp', { budget: { budgetType: "
           "'SAVINGS_PLANS_UTILIZATION', timeUnit: 'MONTHLY' } });\n",
    "cloudformation": {"Ri": {"Type": "AWS::Budgets::Budget", "Properties": {"Budget": {
        "BudgetType": "RI_COVERAGE", "TimeUnit": "MONTHLY"}}}},
    "terraform": 'resource "aws_budgets_budget" "sp" {\n'
                 '  budget_type = "SAVINGS_PLANS_COVERAGE"\n  time_unit = "MONTHLY"\n}\n',
}
COST_BUDGET = {
    "cdk": "new budgets.CfnBudget(this, 'Cost', { budget: { budgetType: 'COST', "
           "timeUnit: 'MONTHLY' } });\n",
    "cloudformation": {"Cost": {"Type": "AWS::Budgets::Budget", "Properties": {"Budget": {
        "BudgetType": "COST", "TimeUnit": "MONTHLY"}}}},
    "terraform": 'resource "aws_budgets_budget" "cost" {\n  budget_type = "COST"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_org_stack_without_commitment_tracking_fires_repo_093(tmp_path: Path,
                                                              source: str) -> None:
    _stack(tmp_path, source, ORG[source], COST_BUDGET[source])
    (hit,) = ManagementPricingMissing().run(tmp_path)
    assert hit.id == "REPO-093"
    assert f"in prod/{_PATHS[source]}" in hit.evidence
    assert "SAVINGS_PLANS_UTILIZATION" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_org_stack_with_commitment_budget_passes_repo_093(tmp_path: Path,
                                                          source: str) -> None:
    _stack(tmp_path, source, ORG[source], SP_BUDGET[source])
    assert ManagementPricingMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_app_stack_is_silent_repo_093(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, ASG[source], COST_BUDGET[source])
    assert ManagementPricingMissing().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("docs/savings-plans.md", "Bought in the management account.\n"),
    ("README.md", "# Org\n\n## Commitments\n\nCompute Savings Plan, shared.\n"),
))
def test_commitment_note_passes_repo_093(tmp_path: Path, path: str, text: str) -> None:
    _stack(tmp_path, "terraform", ORG["terraform"])
    _write(tmp_path / path, text)
    assert ManagementPricingMissing().run(tmp_path) == []


def test_discount_sharing_setting_passes_repo_093(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", ORG["cdk"], "const settings = { riSharing: true };\n")
    assert ManagementPricingMissing().run(tmp_path) == []


def test_tag_policy_alone_is_not_an_org_stack_repo_093(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_organizations_policy" "tags" {\n'
           '  type = "TAG_POLICY"\n}\n')
    assert ManagementPricingMissing().run(tmp_path) == []


def test_file_that_only_names_the_type_is_not_an_org_stack_repo_093(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "rules.py", 'TYPES = "AWS::Organizations::Account"\n')
    assert ManagementPricingMissing().run(tmp_path) == []


def test_python_cdk_repo_093(tmp_path: Path) -> None:
    org = "organizations.CfnAccount(self, 'Prod', account_name='prod', email='a@example.com')\n"
    _write(tmp_path / "app.py", org)
    assert ManagementPricingMissing().run(tmp_path)
    _write(tmp_path / "app.py", org + "budgets.CfnBudget(self, 'Ri', budget=budgets.CfnBudget"
           ".BudgetDataProperty(budget_type='RI_UTILIZATION', time_unit='MONTHLY'))\n")
    assert ManagementPricingMissing().run(tmp_path) == []


# All four rules.

def _firing(rule_id: str, root: Path) -> None:
    text = {
        "REPO-090": ASG["terraform"],
        "REPO-091": REGION["terraform"].format(region="sa-east-1"),
        "REPO-092": MARKETPLACE["terraform"],
        "REPO-093": ORG["terraform"],
    }[rule_id]
    _stack(root, "terraform", text)


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
    ("REPO-090", "COST07-BP01"), ("REPO-091", "COST07-BP02"),
    ("REPO-092", "COST07-BP03"), ("REPO-093", "COST07-BP05"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert well_architected.question_of(rule_id) == "COST 7"


def test_rules_run_by_default() -> None:
    assert {r.id for r in RULES} & ORG_RULE_IDS == set()
    assert {r.category for r in RULES} == {"Cost"}
    assert {r.severity for r in RULES} == {"Low"}
    assert {t for r in RULES for t in r.themes} == {"finops"}


def test_cost7_is_fully_checked() -> None:
    (cost7,) = [a for a in well_architected.answers([]) if a.question.id == "COST 7"]
    assert cost7.not_checked == ()


def test_cost7_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _firing("REPO-091", tmp_path)
    findings = RegionNotChosenByCost().run(tmp_path)
    (cost7,) = [a for a in well_architected.answers(findings) if a.question.id == "COST 7"]
    assert not cost7.met
