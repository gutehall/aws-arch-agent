"""COST 6: resource type, size and number. A cost estimate for the workload (REPO-088)
and shared resources instead of a VPC or cluster per workload (REPO-089)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import CostModelMissing, SharedResourcesUnused

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}
RULES = (CostModelMissing(), SharedResourcesUnused())


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
VPC = {
    "cdk": "const vpc = new ec2.Vpc(this, 'Vpc', { maxAzs: 2 });\n",
    "cloudformation": {"Vpc": {"Type": "AWS::EC2::VPC",
                               "Properties": {"CidrBlock": "10.0.0.0/16"}}},
    "terraform": 'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n',
}
CLUSTER = {
    "cdk": "new ecs.Cluster(this, 'Cluster', { vpc });\n",
    "cloudformation": {"Cluster": {"Type": "AWS::EKS::Cluster", "Properties": {}}},
    "terraform": 'resource "aws_ecs_cluster" "main" {\n  name = "main"\n}\n',
}
LOOKUP = {
    "cdk": "const vpc = ec2.Vpc.fromLookup(this, 'Shared', { vpcName: 'shared' });\n",
    "cloudformation": {"Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
        "VpcId": {"Fn::ImportValue": "shared-vpc-id"}}}},
    "terraform": 'data "aws_vpc" "shared" {\n  tags = { Name = "shared" }\n}\n',
}
RAM = {
    "cdk": "new ram.CfnResourceShare(this, 'Share', { name: 'subnets' });\n",
    "cloudformation": {"Share": {"Type": "AWS::RAM::ResourceShare",
                                 "Properties": {"Name": "subnets"}}},
    "terraform": 'resource "aws_ram_resource_share" "subnets" {\n  name = "subnets"\n}\n',
}
TENANCY = {
    "cdk": "Tags.of(this).add('Tenancy', 'single');\n",
    "cloudformation": {"Vpc2": {"Type": "AWS::EC2::VPC", "Properties": {
        "Tags": [{"Key": "Tenancy", "Value": "dedicated"}]}}},
    "terraform": 'provider "aws" {\n  default_tags {\n    tags = {\n'
                 '      tenant-model = "single"\n    }\n  }\n}\n',
}
WORKFLOW = (
    "on: pull_request\njobs:\n  cost:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - run: infracost {cmd} --path .\n"
)


# REPO-088: a cost estimate for the workload.

@pytest.mark.parametrize("source", SOURCES)
def test_workload_without_estimate_fires_repo_088(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source])
    (hit,) = CostModelMissing().run(tmp_path)
    assert hit.id == "REPO-088"
    assert "S3 bucket in prod/" in hit.evidence and "infracost" in hit.evidence


@pytest.mark.parametrize("cmd", ("breakdown", "diff", "comment github"))
@pytest.mark.parametrize("source", SOURCES)
def test_infracost_ci_step_passes_repo_088(tmp_path: Path, source: str, cmd: str) -> None:
    _stack(tmp_path, source, BUCKET[source])
    _write(tmp_path / ".github" / "workflows" / "cost.yml", WORKFLOW.format(cmd=cmd))
    assert CostModelMissing().run(tmp_path) == []


def test_infracost_auth_step_does_not_pass_repo_088(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    _write(tmp_path / ".github" / "workflows" / "cost.yml",
           WORKFLOW.format(cmd="auth login"))
    assert CostModelMissing().run(tmp_path)


@pytest.mark.parametrize("path", ("infracost.yml", "infracost.yaml", "infracost-usage.yml",
                                  ".infracost/pricing.gitignore", "cdk-cost-report.json",
                                  ".cost-estimate.json"))
def test_cost_estimate_config_passes_repo_088(tmp_path: Path, path: str) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"])
    _write(tmp_path / path, "version: 0.1\n")
    assert CostModelMissing().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("docs/cost-estimate.md", "Monthly: $1,200 at 50 requests per second.\n"),
    ("COST_MODEL.md", "Expected spend is USD 300 a month.\n"),
    ("docs/pricing.txt", "Roughly 300 USD per month.\n"),
    ("estimate.md", "Storage: €40 a month.\n"),
    ("docs/cost-model.md", "See https://calculator.aws/#/estimate?id=abc\n"),
    ("README.md", "# App\n\n## Estimated cost\n\nAbout $85 a month.\n\n## Usage\n"),
    ("docs/arch.md", "# Arch\n\n## Cost estimate\n\nhttps://calculator.aws/#/estimate\n"),
))
def test_estimate_note_with_amount_passes_repo_088(tmp_path: Path, path: str,
                                                   text: str) -> None:
    _stack(tmp_path, "cdk", BUCKET["cdk"])
    _write(tmp_path / path, text)
    assert CostModelMissing().run(tmp_path) == []


@pytest.mark.parametrize("path,text", (
    ("docs/cost-estimate.md", "We will estimate the cost later.\n"),
    ("README.md", "# App\n\n## Pricing\n\nREPO-088 checks for a cost estimate.\n"),
    ("README.md", "# App\n\nCosts about $85 a month.\n"),
))
def test_estimate_note_without_amount_fires_repo_088(tmp_path: Path, path: str,
                                                     text: str) -> None:
    _stack(tmp_path, "cdk", BUCKET["cdk"])
    _write(tmp_path / path, text)
    assert CostModelMissing().run(tmp_path)


def test_python_cdk_repo_088(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "s3.Bucket(self, 'Data')\n")
    assert CostModelMissing().run(tmp_path)
    _write(tmp_path / "docs" / "estimate.md", "Total: $120 per month\n")
    assert CostModelMissing().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_workload_is_skipped_repo_088(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", BUCKET["terraform"], env=env)
    assert CostModelMissing().run(tmp_path) == []


def test_no_workload_is_silent_repo_088(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "main.tf", 'variable "region" {}\n')
    assert CostModelMissing().run(tmp_path) == []


# REPO-089: shared resources.

@pytest.mark.parametrize("own", (VPC, CLUSTER), ids=("vpc", "cluster"))
@pytest.mark.parametrize("source", SOURCES)
def test_own_vpc_or_cluster_fires_repo_089(tmp_path: Path, source: str, own: dict) -> None:
    _stack(tmp_path, source, own[source])
    (hit,) = SharedResourcesUnused().run(tmp_path)
    assert hit.id == "REPO-089"
    assert "Creates its own" in hit.evidence and "prod/" in hit.evidence
    assert "AWS RAM" in hit.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_no_own_vpc_or_cluster_is_silent_repo_089(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, BUCKET[source])
    assert SharedResourcesUnused().run(tmp_path) == []


@pytest.mark.parametrize("shared", (LOOKUP, RAM, TENANCY), ids=("lookup", "ram", "tenancy"))
@pytest.mark.parametrize("source", SOURCES)
def test_shared_or_single_tenant_passes_repo_089(tmp_path: Path, source: str,
                                                 shared: dict) -> None:
    _stack(tmp_path, source, CLUSTER[source], shared[source])
    assert SharedResourcesUnused().run(tmp_path) == []


@pytest.mark.parametrize("text", (
    "Bucket.fromBucketName(this, 'Logs', 'shared-logs');",
    "ecs.Cluster.fromClusterAttributes(this, 'C', attrs);",
    "ec2.Subnet.fromSubnetId(this, 'S', 'subnet-1');",
    "// single-tenant: one VPC per customer",
    "/* dedicated by design */",
))
def test_cdk_shared_lookups_and_comments_pass_repo_089(tmp_path: Path, text: str) -> None:
    _stack(tmp_path, "cdk", VPC["cdk"], text + "\n")
    assert SharedResourcesUnused().run(tmp_path) == []


@pytest.mark.parametrize("text", (
    'data "terraform_remote_state" "network" {\n  backend = "s3"\n}\n',
    'data "aws_subnets" "shared" {}\n',
    'resource "aws_ram_resource_association" "a" {}\n',
    "# single tenant for compliance\n",
))
def test_terraform_shared_passes_repo_089(tmp_path: Path, text: str) -> None:
    _stack(tmp_path, "terraform", VPC["terraform"], text)
    assert SharedResourcesUnused().run(tmp_path) == []


def test_cloudformation_yaml_import_and_ssm_vpc_pass_repo_089(tmp_path: Path) -> None:
    own = "Resources:\n  Cluster:\n    Type: AWS::ECS::Cluster\n"
    _write(tmp_path / "prod" / "stack.yaml", own)
    assert SharedResourcesUnused().run(tmp_path)
    _write(tmp_path / "prod" / "stack.yaml",
           own + "  Sg:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n"
           "      VpcId: !ImportValue shared-vpc\n")
    assert SharedResourcesUnused().run(tmp_path) == []
    _write(tmp_path / "prod" / "stack.yaml",
           "Parameters:\n  VpcId:\n    Type: AWS::SSM::Parameter::Value<AWS::EC2::VPC::Id>\n"
           + own)
    assert SharedResourcesUnused().run(tmp_path) == []


def test_tenancy_tag_of_another_value_fires_repo_089(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", VPC["cdk"], "Tags.of(this).add('Tenancy', 'multi');\n")
    assert SharedResourcesUnused().run(tmp_path)


def test_python_cdk_repo_089(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "vpc = ec2.Vpc(self, 'Vpc')\n")
    assert SharedResourcesUnused().run(tmp_path)
    _write(tmp_path / "app.py", "vpc = ec2.Vpc.from_lookup(self, 'Vpc', vpc_name='shared')\n"
           "eks.Cluster(self, 'Cluster', vpc=vpc)\n")
    assert SharedResourcesUnused().run(tmp_path) == []


@pytest.mark.parametrize("env", ("dev", "staging"))
def test_non_production_vpc_is_skipped_repo_089(tmp_path: Path, env: str) -> None:
    _stack(tmp_path, "terraform", VPC["terraform"], env=env)
    assert SharedResourcesUnused().run(tmp_path) == []


# Both rules.

def _firing(rule_id: str, root: Path) -> None:
    own = BUCKET if rule_id == "REPO-088" else VPC
    _stack(root, "terraform", own["terraform"])


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
    ("REPO-088", "COST06-BP01"), ("REPO-089", "COST06-BP04"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert well_architected.question_of(rule_id) == "COST 6"


def test_rules_run_by_default() -> None:
    assert {r.id for r in RULES} & ORG_RULE_IDS == set()
    assert {r.category for r in RULES} == {"Cost"}
    assert {r.severity for r in RULES} == {"Low"}
    assert {t for r in RULES for t in r.themes} == {"finops"}


def test_cost6_is_fully_checked() -> None:
    (cost6,) = [a for a in well_architected.answers([]) if a.question.id == "COST 6"]
    assert cost6.not_checked == ()


def test_cost6_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", VPC["terraform"])
    findings = SharedResourcesUnused().run(tmp_path)
    (cost6,) = [a for a in well_architected.answers(findings) if a.question.id == "COST 6"]
    assert not cost6.met
