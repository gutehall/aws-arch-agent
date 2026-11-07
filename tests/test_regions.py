"""Price region per stack: --region, the stack's own code, AWS_REGION, then us-east-1."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent import pricing
from aws_arch_agent.cli import app
from aws_arch_agent.rules import regions, stack_cost
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths

GP2 = {"Type": "AWS::EC2::Volume", "Properties": {"VolumeType": "gp2", "Size": 100, "Encrypted": True}}


def _gp2_cost(region: str) -> float:
    found = pricing.price("ebs:gp2", region)
    assert found is not None
    return round(100 * found.usd, 2)


def _template(path: Path, resources: dict | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"Resources": resources or {"Vol": GP2}}), encoding="utf-8")
    return path


def _cdk_out(root: Path, stacks: dict[str, str]) -> list[Path]:
    """cdk.out with one gp2 volume per stack; stacks maps name -> environment."""
    out = root / "cdk.out"
    artifacts = {
        name: {"type": "aws:cloudformation:stack", "environment": env,
               "properties": {"templateFile": f"{name}.template.json"}}
        for name, env in stacks.items()
    }
    out.mkdir(parents=True)
    (out / "manifest.json").write_text(json.dumps({"version": "36.0.0", "artifacts": artifacts}))
    return [_template(out / f"{name}.template.json") for name in stacks]


def _gp2_finding_cost(findings: list) -> dict[str, float | None]:
    return {Path(f.file).name: f.monthly_cost_usd for f in findings if f.id == "CF-EBS-002"}


def test_cdk_stack_env_sets_each_stacks_region(tmp_path: Path) -> None:
    paths = _cdk_out(tmp_path, {"North": "aws://111122223333/eu-north-1",
                                "Agnostic": "aws://unknown-account/unknown-region"})
    with regions.use_regions(None, env={}), stack_cost.collect():
        findings = run_cf_rules_from_paths(paths, repo_path=tmp_path)
        note, cost = regions.note(), stack_cost.summary(findings, tmp_path)
    assert _gp2_finding_cost(findings) == {
        "North.template.json": _gp2_cost("eu-north-1"),
        "Agnostic.template.json": _gp2_cost("us-east-1"),  # env-agnostic: the fallback
    }
    assert [(e["region"], e["source"]) for e in note["regions"]] == [
        ("eu-north-1", "CDK stack env"), ("us-east-1", "default")]
    assert note["region"] == "eu-north-1, us-east-1"
    assert cost is not None and cost["region"] == "eu-north-1, us-east-1"
    assert {s["name"]: s["region"] for s in cost["stacks"]} == {
        "cdk.out/Agnostic.template.json": "us-east-1", "cdk.out/North.template.json": "eu-north-1"}


def test_region_flag_wins_over_the_stack(tmp_path: Path) -> None:
    paths = _cdk_out(tmp_path, {"North": "aws://111122223333/eu-north-1"})
    with regions.use_regions("eu-west-1", env={"AWS_REGION": "us-west-2"}):
        findings = run_cf_rules_from_paths(paths, repo_path=tmp_path)
        note = regions.note()
    assert _gp2_finding_cost(findings) == {"North.template.json": _gp2_cost("eu-west-1")}
    assert note["regions"][0]["source"] == "--region / config"


def test_availability_zones_name_the_region_when_they_agree(tmp_path: Path) -> None:
    one = _template(tmp_path / "one.json", {"Vol": {**GP2, "Properties": {
        **GP2["Properties"], "AvailabilityZone": "eu-west-1b"}}})
    two = _template(tmp_path / "two.json", {
        "A": {**GP2, "Properties": {**GP2["Properties"], "AvailabilityZone": "eu-west-1a"}},
        "B": {**GP2, "Properties": {**GP2["Properties"], "AvailabilityZone": "us-west-2a"}},
    })
    with regions.use_regions(None, env={}):
        assert regions.resolve(one, []).region == "us-east-1"  # resources decide, not the path
        findings = run_cf_rules_from_paths([one, two], repo_path=tmp_path)
        used = {Path(k).name: v for k, v in regions.used().items()}
    assert used["one.json"] == regions.Resolved("eu-west-1", "availability zones")
    assert used["two.json"] == regions.Resolved("us-east-1", "default")  # two regions: no guess
    assert len([f for f in findings if f.id == "CF-EBS-002"]) == 3


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"AWS_REGION": "eu-central-1", "AWS_DEFAULT_REGION": "us-west-2"}, ("eu-central-1", "AWS_REGION")),
        ({"AWS_DEFAULT_REGION": "us-west-2"}, ("us-west-2", "AWS_DEFAULT_REGION")),
        ({"AWS_REGION": "not a region"}, ("us-east-1", "default")),
        ({}, ("us-east-1", "default")),
    ],
)
def test_shell_region_is_the_fallback(tmp_path: Path, env: dict, expected: tuple) -> None:
    path = _template(tmp_path / "stack.json")
    with regions.use_regions(None, env=env):
        findings = run_cf_rules_from_paths([path], repo_path=tmp_path)
        resolved = regions.used()[str(path.resolve())]
    assert (resolved.region, resolved.source) == expected
    assert _gp2_finding_cost(findings) == {"stack.json": _gp2_cost(expected[0])}


def _tf(module: Path, provider: str) -> Path:
    module.mkdir(parents=True, exist_ok=True)
    (module / "main.tf").write_text(
        'variable "aws_region" {\n  default = "eu-north-1"\n}\n'
        + provider
        + 'resource "aws_ebs_volume" "data" {\n'
        '  size = 100\n  type = "gp2"\n  encrypted = true\n}\n',
        encoding="utf-8",
    )
    return module


@pytest.mark.parametrize(
    ("provider", "expected"),
    [
        ('provider "aws" {\n  region = "eu-west-1"\n}\n', "eu-west-1"),
        ('provider "aws" {\n  region = var.aws_region\n}\n', "eu-north-1"),
        ('provider "aws" {\n  region = "${var.aws_region}"\n}\n', "eu-north-1"),
        # An aliased provider is not the default one: the fallback decides.
        ('provider "aws" {\n  alias = "east"\n  region = "eu-central-1"\n}\n', "us-east-1"),
    ],
)
def test_terraform_provider_region(tmp_path: Path, provider: str, expected: str) -> None:
    module = _tf(tmp_path / "infra", provider)
    assert regions.terraform_provider_region(module) == (None if "alias" in provider else expected)
    out = tmp_path / "report.json"
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--iac", "terraform", "--no-llm",
                                      "--format", "json", "--out", str(out)])
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["context"]["notes"]["prices"]["region"] == expected
    gp2 = next(f for f in data["findings"] if f["id"] == "CF-EBS-002")
    assert gp2["monthly_cost_usd"] == _gp2_cost(expected)


def test_terraform_plan_region(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({
        "configuration": {"provider_config": {"aws": {"expressions": {"region": {"references": ["var.r"]}}}}},
        "variables": {"r": {"value": "eu-central-1"}},
    }))
    assert regions.terraform_plan_region(plan) == "eu-central-1"
    plan.write_text(json.dumps({
        "configuration": {"provider_config": {"aws": {"expressions": {"region": {"constant_value": "us-west-2"}}}}},
    }))
    assert regions.terraform_plan_region(plan) == "us-west-2"
    plan.write_text("not json")
    assert regions.terraform_plan_region(plan) is None


def test_detected_region_without_prices_warns_and_skips_its_estimates(tmp_path: Path) -> None:
    _cdk_out(tmp_path, {"Sydney": "aws://111122223333/ap-southeast-2"})
    out = tmp_path / "report.md"
    result = CliRunner().invoke(app, ["--repo", str(tmp_path), "--mode", "v2", "--no-llm",
                                      "--templates", str(tmp_path / "cdk.out"), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "No prices for region ap-southeast-2" in result.output
    assert "ap-southeast-2 (CDK stack env; not in the price snapshot" in out.read_text(encoding="utf-8")


def test_outside_a_scan_use_region_decides(tmp_path: Path) -> None:
    path = _template(tmp_path / "stack.json", {"Vol": {**GP2, "Properties": {
        **GP2["Properties"], "AvailabilityZone": "eu-west-1a"}}})
    with pricing.use_region("eu-north-1"):
        findings = run_cf_rules_from_paths([path])
    assert _gp2_finding_cost(findings) == {"stack.json": _gp2_cost("eu-north-1")}


def test_terraform_json_provider_region(tmp_path: Path) -> None:
    (tmp_path / "main.tf.json").write_text(json.dumps({
        "variable": {"r": {"default": "eu-west-1"}}, "provider": {"aws": {"region": "${var.r}"}},
    }))
    assert regions.terraform_provider_region(tmp_path) == "eu-west-1"


def test_only_availability_zone_keys_name_the_region(tmp_path: Path) -> None:
    tagged = _template(tmp_path / "tagged.json", {"Vol": {**GP2, "Properties": {
        **GP2["Properties"], "Tags": [{"Key": "Name", "Value": "eu-west-1a"}]}}})
    zoned = _template(tmp_path / "zoned.json", {"Db": {"Type": "AWS::RDS::DBCluster", "Properties": {
        "AvailabilityZones": ["eu-central-1a", "eu-central-1b"]}}})
    with regions.use_regions(None, env={}):
        run_cf_rules_from_paths([tagged, zoned], repo_path=tmp_path)
        used = {Path(k).name: v.region for k, v in regions.used().items()}
    assert used == {"tagged.json": "us-east-1", "zoned.json": "eu-central-1"}


def test_cost_section_dates_each_region_when_there_are_several(tmp_path: Path) -> None:
    paths = _cdk_out(tmp_path, {"North": "aws://111122223333/eu-north-1",
                                "West": "aws://111122223333/eu-west-1"})
    with regions.use_regions(None, env={}), stack_cost.collect():
        findings = run_cf_rules_from_paths(paths, repo_path=tmp_path)
        cost = stack_cost.summary(findings, tmp_path)
    assert cost is not None and cost["snapshot_date"] is None
    assert {s["region"]: s["snapshot_date"] for s in cost["stacks"]} == {
        "eu-north-1": pricing.snapshot_date("eu-north-1"), "eu-west-1": pricing.snapshot_date("eu-west-1")}
