"""Estimated monthly cost per stack in the report (DM3-542)."""
import json
from pathlib import Path

from typer.testing import CliRunner

from aws_arch_agent import pricing
from aws_arch_agent.cli import app
from aws_arch_agent.rules import estimates, stack_cost
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform

H = 730


def _p(key: str, region: str = "us-east-1") -> float:
    found = pricing.price(key, region)
    assert found is not None, key
    return found.usd


STACK = {
    "Web": {"Type": "AWS::EC2::Instance", "Properties": {
        "InstanceType": "m5.large", "MetadataOptions": {"HttpTokens": "required"}}},
    "Db": {"Type": "AWS::RDS::DBInstance", "Properties": {
        "DBInstanceClass": "db.m5.large", "Engine": "postgres", "MultiAZ": True, "StorageEncrypted": True}},
    "Nat": {"Type": "AWS::EC2::NatGateway", "Properties": {"SubnetId": "subnet-1",
                                                           "AllocationId": {"Fn::GetAtt": ["Ip", "AllocationId"]}}},
    "Ip": {"Type": "AWS::EC2::EIP", "Properties": {"Domain": "vpc"}},
    "Data": {"Type": "AWS::EC2::Volume", "Properties": {
        "AvailabilityZone": "us-east-1a", "Size": 100, "VolumeType": "gp3", "Encrypted": True}},
    "Table": {"Type": "AWS::DynamoDB::Table", "Properties": {
        "BillingMode": "PROVISIONED", "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        "KeySchema": [], "AttributeDefinitions": []}},
    # Usage-based or not in the snapshot: listed as not priced.
    "Fn": {"Type": "AWS::Lambda::Function", "Properties": {"Runtime": "python3.13", "Handler": "a", "Role": "r"}},
    "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
    "OnDemand": {"Type": "AWS::DynamoDB::Table", "Properties": {"BillingMode": "PAY_PER_REQUEST"}},
    "ParamInstance": {"Type": "AWS::EC2::Instance", "Properties": {
        "InstanceType": {"Ref": "Type"}, "MetadataOptions": {"HttpTokens": "required"}}},
    # Free in themselves: not listed.
    "Role": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {}}},
    "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"GroupDescription": "x"}},
}


def _expected() -> dict[str, float]:
    return {
        "Db": round(H * _p("rds:postgres:multi-az:db.m5.large"), 2),
        "Web": round(H * _p("ec2:m5.large"), 2),
        "Nat": round(H * _p("nat:hour"), 2),
        "Table": round(H * (5 * _p("dynamodb:rcu-hour") + 5 * _p("dynamodb:wcu-hour")), 2),
        "Data": round(100 * _p("ebs:gp3"), 2),
        "Ip": round(H * _p("eip:in-use-hour"), 2),
    }


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "stack.json").write_text(
        json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": STACK}), encoding="utf-8")
    return tmp_path


def test_summary_prices_every_covered_resource(tmp_path: Path) -> None:
    _repo(tmp_path)
    with stack_cost.collect():
        findings = run_cf_rules_from_paths([tmp_path / "stack.json"], repo_path=tmp_path)
        cost = stack_cost.summary(findings, tmp_path)
    assert cost is not None
    expected = _expected()
    total = round(sum(expected.values()), 2)
    assert cost["stacks"] == [{"name": "stack.json", "resources_priced": 6, "monthly_usd": total}]
    assert cost["total_monthly_usd"] == total
    top = [r["name"] for r in cost["top_resources"]]
    assert top == sorted(expected, key=lambda k: -expected[k])[:5]
    assert all(r["file"] == "stack.json" for r in cost["top_resources"])
    assert "Saving if" not in "".join(r["basis"] for r in cost["top_resources"])
    assert cost["not_priced"] == {
        "AWS::DynamoDB::Table": 1, "AWS::EC2::Instance": 1, "AWS::Lambda::Function": 1, "AWS::S3::Bucket": 1}
    assert cost["region"] == "us-east-1" and cost["snapshot_date"] == pricing.snapshot_date("us-east-1")


def test_savings_are_summed_from_findings_and_kept_apart(tmp_path: Path) -> None:
    resources = {"Gp2": {"Type": "AWS::EC2::Volume", "Properties": {
        "AvailabilityZone": "us-east-1a", "Size": 100, "VolumeType": "gp2", "Encrypted": True}}}
    (tmp_path / "t.json").write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    with stack_cost.collect():
        findings = run_cf_rules_from_paths([tmp_path / "t.json"], repo_path=tmp_path)
        cost = stack_cost.summary(findings, tmp_path)
    assert cost is not None
    gp2 = next(f for f in findings if f.id == "CF-EBS-002")
    assert cost["savings_findings"] == 1 and cost["savings_monthly_usd"] == gp2.monthly_savings_usd
    assert cost["total_monthly_usd"] == round(100 * _p("ebs:gp2"), 2)  # the full cost, nothing subtracted


def test_no_summary_without_templates() -> None:
    with stack_cost.collect():
        assert stack_cost.summary([]) is None
    stack_cost.record(Path("t.json"), [])  # outside collect(): a no-op
    assert stack_cost.summary([]) is None


TF = """\
resource "aws_instance" "web" {
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = true
}

resource "aws_dynamodb_table" "orders" {
  name           = "orders"
  hash_key       = "id"
  read_capacity  = 10
  write_capacity = 2
}

resource "aws_dynamodb_table" "events" {
  name         = "events"
  hash_key     = "id"
  billing_mode = "PAY_PER_REQUEST"
}

resource "aws_lambda_function" "fn" {
  function_name = "fn"
  role          = "r"
}

resource "aws_iam_role" "r" {
  assume_role_policy = "{}"
}
"""


def test_terraform_module_total(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(TF, encoding="utf-8")
    with stack_cost.collect():
        findings = run_resource_checks(resources_from_terraform(tmp_path), tmp_path)
        cost = stack_cost.summary(findings, tmp_path.parent)
    assert cost is not None
    expected = round(
        H * _p("ec2:t3.micro") + 50 * _p("ebs:gp2")
        + H * (10 * _p("dynamodb:rcu-hour") + 2 * _p("dynamodb:wcu-hour")), 2)
    assert cost["stacks"] == [{"name": tmp_path.name, "resources_priced": 3, "monthly_usd": expected}]
    assert cost["not_priced"] == {"aws_dynamodb_table": 1, "aws_lambda_function": 1}
    web = next(r for r in cost["top_resources"] if r["name"] == "aws_instance.web")
    assert web["line"] == 1 and web["file"].endswith("main.tf")


def test_reports_show_the_cost_section(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    total = round(sum(_expected().values()), 2)
    runner = CliRunner()

    out_md = tmp_path / "r.md"
    result = runner.invoke(app, ["--repo", str(repo), "--no-llm", "--out", str(out_md)])
    assert result.exit_code == 0, result.output
    md = out_md.read_text()
    assert "## Estimated Monthly Cost (estimate)" in md
    assert f"| **Total** | 6 | **${total:,.2f}** |" in md
    assert "Top 5 resources by estimated cost:" in md
    assert "Not priced (usage-based, or not in the price snapshot): AWS::DynamoDB::Table ×1" in md
    assert f"Region us-east-1, AWS prices of {pricing.snapshot_date('us-east-1')}." in md

    out_json = tmp_path / "r.json"
    result = runner.invoke(app, ["--repo", str(repo), "--no-llm", "--format", "json", "--out", str(out_json)])
    assert result.exit_code == 0, result.output
    cost = json.loads(out_json.read_text())["context"]["notes"]["cost"]
    assert cost["total_monthly_usd"] == total and cost["not_priced"]["AWS::S3::Bucket"] == 1

    out_html = tmp_path / "r.html"
    result = runner.invoke(app, ["--repo", str(repo), "--no-llm", "--format", "html", "--out", str(out_html)])
    assert result.exit_code == 0, result.output
    html = out_html.read_text()
    assert "Estimated monthly cost (estimate)" in html and f"${total:,.2f}" in html
    assert "AWS::Lambda::Function ×1" in html


def test_region_changes_the_total(tmp_path: Path) -> None:
    _repo(tmp_path)
    with pricing.use_region("eu-north-1"), stack_cost.collect():
        findings = run_cf_rules_from_paths([tmp_path / "stack.json"], repo_path=tmp_path)
        north = stack_cost.summary(findings, tmp_path)
    assert north is not None and north["region"] == "eu-north-1"
    assert north["total_monthly_usd"] != round(sum(_expected().values()), 2)


def test_resource_cost_drops_the_saving() -> None:
    class R:
        type, properties = "instance", {"InstanceType": "m5.4xlarge"}

    cost = estimates.resource_cost(R())
    assert cost is not None and cost.monthly_savings_usd is None and "Saving if" not in cost.basis
