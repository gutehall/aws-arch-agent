"""Production-grade spend in non-production stacks."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent import pricing
from aws_arch_agent.cli import app
from aws_arch_agent.config import ConfigError, load_config
from aws_arch_agent.models import Finding
from aws_arch_agent.rules import environments
from aws_arch_agent.rules.cf_template import drop_static_covered_by_cf, run_resource_checks
from aws_arch_agent.rules.resource_model import Resource
from aws_arch_agent.rules.terraform_model import resources_from_terraform

H = 730
ENV_IDS = {f"CF-ENV-00{i}" for i in range(1, 7)}
# Advice that would contradict CF-ENV-001 (Multi-AZ) or the retention check.
OPPOSITES = {"CF-RDS-003", "CF-DEL-001"}


def _p(key: str) -> float:
    found = pricing.price(key, "us-east-1")
    assert found is not None, key
    return found.usd


STACK = {
    "Db": {"Type": "AWS::RDS::DBInstance", "Properties": {
        "DBInstanceClass": "db.m5.2xlarge", "Engine": "postgres", "MultiAZ": True, "StorageEncrypted": True,
        "BackupRetentionPeriod": 7, "DeletionProtection": True}},
    "SingleDb": {"Type": "AWS::RDS::DBInstance", "Properties": {
        "DBInstanceClass": "db.t3.micro", "Engine": "postgres", "StorageEncrypted": True,
        "BackupRetentionPeriod": 7, "DeletionProtection": True}},
    "Cache": {"Type": "AWS::ElastiCache::ReplicationGroup", "Properties": {
        "ReplicationGroupDescription": "c", "MultiAZEnabled": True, "AtRestEncryptionEnabled": True,
        "TransitEncryptionEnabled": True}},
    "Web": {"Type": "AWS::EC2::Instance", "Properties": {
        "InstanceType": "m5.4xlarge", "MetadataOptions": {"HttpTokens": "required"}}},
    "Small": {"Type": "AWS::EC2::Instance", "Properties": {
        "InstanceType": "t3.large", "MetadataOptions": {"HttpTokens": "required"}}},
    "NatA": {"Type": "AWS::EC2::NatGateway", "Properties": {"SubnetId": "a", "AllocationId": "eipalloc-1"}},
    "NatB": {"Type": "AWS::EC2::NatGateway", "Properties": {"SubnetId": "b", "AllocationId": "eipalloc-2"}},
    "Logs": {"Type": "AWS::Logs::LogGroup", "Properties": {"RetentionInDays": 365, "KmsKeyId": "k"}},
    "ShortLogs": {"Type": "AWS::Logs::LogGroup", "Properties": {"RetentionInDays": 14, "KmsKeyId": "k"}},
    "Forever": {"Type": "AWS::Logs::LogGroup", "Properties": {"KmsKeyId": "k"}},
    "Table": {"Type": "AWS::DynamoDB::Table", "Properties": {
        "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
        "SSESpecification": {"SSEEnabled": True}}},
    "OnDemand": {"Type": "AWS::DynamoDB::Table", "Properties": {
        "BillingMode": "PAY_PER_REQUEST",
        "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True},
        "SSESpecification": {"SSEEnabled": True}}},
    "Alias": {"Type": "AWS::Lambda::Alias", "Properties": {
        "FunctionName": "f", "FunctionVersion": "1", "Name": "live",
        "ProvisionedConcurrencyConfig": {"ProvisionedConcurrentExecutions": 10}}},
}


def _repo(root: Path) -> Path:
    for env in ("dev", "prod"):
        d = root / "infra" / env
        d.mkdir(parents=True)
        (d / "stack.json").write_text(json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": STACK}),
                                      encoding="utf-8")
    return root


def _scan(repo: Path) -> list[dict]:
    out = repo / "r.json"
    result = CliRunner().invoke(app, ["--repo", str(repo), "--no-llm", "--format", "json", "--out", str(out)])
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text(encoding="utf-8"))["findings"]



def test_same_template_in_dev_and_prod_scan(tmp_path: Path) -> None:
    """Done when: cost findings in dev, reliability findings in prod, no contradictory pair."""
    findings = _scan(_repo(tmp_path))
    dev = {(f["id"], f["evidence"].split(" ")[0] if f["evidence"] else "") for f in findings
           if f["file"] == "infra/dev/stack.json"}
    prod = {(f["id"], f["evidence"].split(" ")[0] if f["evidence"] else "") for f in findings
            if f["file"] == "infra/prod/stack.json"}
    dev_ids, prod_ids = {i for i, _ in dev}, {i for i, _ in prod}
    assert ENV_IDS <= dev_ids                 # every non-prod cost check fires in dev
    assert not (ENV_IDS & prod_ids)           # and none in prod
    assert "CF-RDS-003" in prod_ids           # prod still gets the reliability advice
    assert not (OPPOSITES & dev_ids)          # dev never gets both pieces of advice
    assert ("CF-ENV-001", "Db") in dev and ("CF-ENV-001", "Cache") in dev
    assert ("CF-ENV-001", "SingleDb") not in dev
    assert ("CF-ENV-003", "Web") in dev and ("CF-ENV-003", "Small") not in dev
    assert ("CF-ENV-005", "ShortLogs") not in dev and ("CF-ENV-006", "OnDemand") not in dev
    assert ("CF-ENV-005", "Forever") in dev and "CF-CW-001" not in dev_ids  # one piece of log advice
    assert "CF-CW-001" in prod_ids


def test_savings(tmp_path: Path) -> None:
    by = {(f["id"], (f["evidence"] or "").split(" ")[0]): f for f in _scan(_repo(tmp_path))
          if f["file"] == "infra/dev/stack.json"}
    db = by[("CF-ENV-001", "Db")]
    assert db["monthly_savings_usd"] == round(
        H * _p("rds:postgres:multi-az:db.m5.2xlarge") - H * _p("rds:postgres:single-az:db.m5.2xlarge"), 2)
    web = by[("CF-ENV-003", "Web")]
    assert web["monthly_savings_usd"] == round(H * _p("ec2:m5.4xlarge") - H * _p("ec2:m5.large"), 2)
    nat = next(f for (i, _), f in by.items() if i == "CF-ENV-004")
    assert nat["monthly_savings_usd"] == round(H * _p("nat:hour"), 2)
    assert by[("CF-ENV-001", "Cache")]["monthly_savings_usd"] is None  # ElastiCache is not priced
    assert all(f["recommendation"].startswith("This is a dev stack.") for (i, _), f in by.items() if i in ENV_IDS)


def test_staging_gets_the_cost_checks_and_no_multi_az_advice(tmp_path: Path) -> None:
    d = tmp_path / "staging"
    d.mkdir()
    (d / "stack.json").write_text(json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": {
        "Db": STACK["Db"], "Plain": STACK["SingleDb"]}}), encoding="utf-8")
    ids = {f["id"] for f in _scan(tmp_path)}
    assert "CF-ENV-001" in ids and "CF-RDS-003" not in ids and "CF-DEL-001" not in ids


def test_max_instance_size_config(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".aws-arch-agent.yaml").write_text("nonprod:\n  max_instance_size: 4xlarge\n", encoding="utf-8")
    ids = {f["id"] for f in _scan(repo) if f["file"] == "infra/dev/stack.json"}
    assert "CF-ENV-003" not in ids
    (repo / ".aws-arch-agent.yaml").write_text("nonprod:\n  max_instance_size: huge\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="max_instance_size"):
        load_config(repo)


TF = """\
resource "aws_lambda_provisioned_concurrency_config" "pc" {
  function_name                     = "f"
  qualifier                         = "live"
  provisioned_concurrent_executions = 5
}

resource "aws_elasticache_replication_group" "cache" {
  replication_group_id       = "c"
  description                = "c"
  multi_az_enabled           = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
}

resource "aws_dynamodb_table" "from_var" {
  name         = "t"
  hash_key     = "id"
  billing_mode = var.mode
}

resource "aws_cloudwatch_log_group" "from_var" {
  name              = "l"
  retention_in_days = var.days
}

resource "aws_lambda_provisioned_concurrency_config" "from_var" {
  function_name                     = "f"
  qualifier                         = "live"
  provisioned_concurrent_executions = var.count
}

resource "aws_elasticache_replication_group" "maybe" {
  replication_group_id = "m"
  description          = "m"
  multi_az_enabled     = var.multi_az
}
"""


def test_terraform_dev_module(tmp_path: Path) -> None:
    module = tmp_path / "envs" / "dev"
    module.mkdir(parents=True)
    (module / "main.tf").write_text(TF, encoding="utf-8")
    with environments.use_environments(None, tmp_path):
        found = {(f.id, f.evidence.split(" ")[0]) for f in run_resource_checks(resources_from_terraform(module), module)
                 if f.id in ENV_IDS}
    assert found == {("CF-ENV-002", "aws_lambda_provisioned_concurrency_config.pc"),
                     ("CF-ENV-001", "aws_elasticache_replication_group.cache")}  # billing_mode from a var: not judged


def test_cdk_source_multi_az_advice_is_prod_only() -> None:
    static = [Finding(id=i, title="t", recommendation="r") for i in ("REL-001", "REL-016", "SEC-005")]
    with environments.use_environments(None, None):
        assert [f.id for f in drop_static_covered_by_cf(list(static))] == ["REL-001", "REL-016", "SEC-005"]
        environments.apply([], Path("cdk.out") / "dev-stack.template.json", [Resource(type=None, name="x")])
        assert [f.id for f in drop_static_covered_by_cf(list(static))] == ["SEC-005"]
        environments.apply([], Path("cdk.out") / "prod-stack.template.json", [Resource(type=None, name="y")])
        assert [f.id for f in drop_static_covered_by_cf(list(static))] == ["REL-001", "REL-016", "SEC-005"]
    cost = [Finding(id="COST-003", title="t", recommendation="r")]
    with environments.use_environments(None, None):
        environments.apply([], Path("cdk.out") / "dev-stack.template.json", [Resource(type=None, name="x")])
        assert drop_static_covered_by_cf(list(cost)) == []  # autoscaling advice vs on-demand
    with environments.use_environments(None, None):
        # --templates may hold only some stacks of the app: the CDK source advice stays.
        environments.apply([], Path("templates") / "dev-stack.template.json", [Resource(type=None, name="x")])
        assert [f.id for f in drop_static_covered_by_cf(list(static))] == ["REL-001", "REL-016", "SEC-005"]


def test_family_without_the_cap_size_keeps_the_finding() -> None:
    from aws_arch_agent.rules.estimates import downsize

    # m5 has no 48xlarge: no price, so no saving (the CF-ENV-003 finding itself still fires).
    assert downsize("ec2", "m5.48xlarge", "large") is None


def test_config_accepts_every_known_size(tmp_path: Path) -> None:
    (tmp_path / ".aws-arch-agent.yaml").write_text("nonprod:\n  max_instance_size: 6xlarge\n", encoding="utf-8")
    assert load_config(tmp_path).nonprod_max_size == "6xlarge"
