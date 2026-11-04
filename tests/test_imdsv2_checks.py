"""CF-EC2-001 (templates) and SEC-066 (CDK source): IMDSv2 not required."""
import json
from pathlib import Path

from aws_arch_agent.rules.cf_template import (
    drop_static_covered_by_cf,
    run_cf_rules_from_paths,
    run_resource_checks,
)
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.security_compute import Ec2Imdsv2NotRequired
from aws_arch_agent.rules.terraform_model import resources_from_terraform


def _cf(tmp_path: Path, resources: dict) -> dict[str, str]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    findings = run_cf_rules_from_paths([path], repo_path=tmp_path)
    return {f.evidence.split(" ")[0]: f.severity for f in findings if f.id == "CF-EC2-001"}


def _instance(**props) -> dict:
    return {"Type": "AWS::EC2::Instance", "Properties": {"InstanceType": "t3.micro", **props}}


def _lt(metadata=None) -> dict:
    data = {"MetadataOptions": metadata} if metadata is not None else {}
    return {"Type": "AWS::EC2::LaunchTemplate", "Properties": {"LaunchTemplateData": data}}


def test_cloudformation_instances_and_launch_templates(tmp_path: Path) -> None:
    assert _cf(tmp_path, {
        "Optional": _instance(MetadataOptions={"HttpTokens": "optional"}),
        "Unset": _instance(),
        "Required": _instance(MetadataOptions={"HttpTokens": "required"}),
        "Disabled": _instance(MetadataOptions={"HttpEndpoint": "disabled"}),
        "FromParam": _instance(MetadataOptions={"HttpTokens": {"Ref": "Tokens"}}),
        "UsesLt": _instance(LaunchTemplate={"LaunchTemplateId": {"Ref": "LtUnset"}, "Version": "1"}),
        "Overrides": _instance(
            LaunchTemplate={"LaunchTemplateId": {"Ref": "LtRequired"}, "Version": "1"},
            MetadataOptions={"HttpTokens": "optional"},
        ),
        "LtUnset": _lt(),
        "LtOptional": _lt({"HttpTokens": "optional"}),
        "LtRequired": _lt({"HttpTokens": "required"}),
    }) == {
        "Optional": "High",
        "Unset": "Medium",
        "Overrides": "High",
        "LtUnset": "Medium",
        "LtOptional": "High",
    }


def test_cloudformation_fix_matches_the_resource_shape(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"I": _instance(), "Lt": _lt()}}), encoding="utf-8")
    findings = attach_fixes(
        [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id == "CF-EC2-001"],
        "cloudformation",
    )
    by_name = {f.evidence.split(" ")[0]: f for f in findings}
    assert "MetadataOptions:\n      HttpTokens: required" in by_name["I"].suggested_code
    assert "LaunchTemplateData:\n      MetadataOptions:" in by_name["Lt"].suggested_code
    assert all("In CDK" not in f.recommendation for f in findings)


TF = """\
resource "aws_instance" "unset" {
  ami           = "ami-123"
  instance_type = "t3.micro"
}

resource "aws_instance" "optional" {
  ami           = "ami-123"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_instance" "required" {
  ami           = "ami-123"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_instance" "from_var" {
  ami           = "ami-123"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = var.tokens
  }
}

resource "aws_instance" "dynamic" {
  ami           = "ami-123"
  instance_type = "t3.micro"
  dynamic "metadata_options" {
    for_each = var.metadata
    content {
      http_tokens = metadata_options.value
    }
  }
}

resource "aws_instance" "uses_lt" {
  launch_template {
    id = aws_launch_template.unset.id
  }
}

resource "aws_launch_template" "unset" {
  image_id = "ami-123"
}

resource "aws_launch_template" "var_tokens" {
  image_id = "ami-123"
  metadata_options {
    http_tokens = var.tokens
  }
}
"""


def _tf(tmp_path: Path) -> list[Finding]:
    (tmp_path / "main.tf").write_text(TF, encoding="utf-8")
    return run_resource_checks(resources_from_terraform(tmp_path), tmp_path / "main.tf")


def test_terraform_instances_and_launch_templates(tmp_path: Path) -> None:
    got = {f.evidence.split(" ")[0]: f.severity for f in _tf(tmp_path) if f.id == "CF-EC2-001"}
    assert got == {
        "aws_instance.unset": "Medium",
        "aws_instance.optional": "High",
        "aws_launch_template.unset": "Medium",
    }


def test_terraform_unknown_tokens_do_not_hide_the_spot_check(tmp_path: Path) -> None:
    """A var in metadata_options must not mark the whole LaunchTemplateData unresolved."""
    spot = [f for f in _tf(tmp_path) if f.id == "CF-SUST-003"]
    assert spot and "2 LaunchTemplate(s)" in (spot[0].evidence or "")


def test_terraform_fix_matches_the_resource_shape(tmp_path: Path) -> None:
    findings = attach_fixes([f for f in _tf(tmp_path) if f.id == "CF-EC2-001"], "terraform")
    by_name = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert by_name["aws_instance.optional"].startswith('resource "aws_instance" "optional" {')
    assert by_name["aws_launch_template.unset"].startswith('resource "aws_launch_template" "unset" {')
    assert 'http_tokens   = "required"' in by_name["aws_instance.unset"]


def test_static_rule_is_dropped_when_cf_reports_it() -> None:
    findings = [Finding(id=i, title="t", recommendation="r") for i in ("SEC-066", "CF-EC2-001")]
    assert [f.id for f in drop_static_covered_by_cf(findings)] == ["CF-EC2-001"]


def _cdk_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def test_cdk_aspect_on_the_app_clears_every_stack(tmp_path: Path) -> None:
    repo = _cdk_repo(tmp_path, {
        "lib/stack.ts": "new ec2.Instance(this, 'I', { vpc, instanceType, machineImage });",
        "bin/app.ts": "Aspects.of(app).add(new ec2.InstanceRequireImdsv2Aspect());",
    })
    assert Ec2Imdsv2NotRequired().run(repo, "typescript") == []


def test_cdk_setting_in_another_file_does_not_clear_an_instance(tmp_path: Path) -> None:
    repo = _cdk_repo(tmp_path, {
        "lib/a.ts": "new ec2.Instance(this, 'A', { vpc, instanceType, machineImage });",
        "lib/b.ts": "new ec2.Instance(this, 'B', { vpc, instanceType, machineImage, requireImdsv2: true });",
    })
    findings = Ec2Imdsv2NotRequired().run(repo, "typescript")
    assert [Path(f.file or "").name for f in findings] == ["a.ts"]
