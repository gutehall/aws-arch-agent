"""SEC 8: a control that stops unencrypted storage from being created (REPO-041)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import EncryptionGuardrailMissing, encryption_guards

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"Resources": resources}, indent=2)


STORE = {
    "cdk": "const data = new s3.Bucket(this, 'Data', { encryption: s3.BucketEncryption.S3_MANAGED });\n",
    "cloudformation": {"Data": {"Type": "AWS::S3::Bucket", "Properties": {}}},
    "terraform": 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n}\n',
}
DENY_POLICY = {
    "cdk": "data.addToResourcePolicy(new iam.PolicyStatement({ effect: iam.Effect.DENY, "
           "actions: ['s3:PutObject'], principals: [new iam.AnyPrincipal()], resources, "
           "conditions: { Null: { 's3:x-amz-server-side-encryption': 'true' } } }));\n",
    "cloudformation": {"Policy": {"Type": "AWS::S3::BucketPolicy", "Properties": {
        "PolicyDocument": {"Statement": [{"Effect": "Deny", "Action": "s3:PutObject",
                                          "Condition": {"Null": {
                                              "s3:x-amz-server-side-encryption": "true"}}}]}}}},
    "terraform": 'resource "aws_ebs_encryption_by_default" "on" {\n  enabled = true\n}\n',
}
CONFIG_RULE = {
    "cdk": "new config.ManagedRule(this, 'Sse', { identifier: "
           "config.ManagedRuleIdentifiers.S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED });\n",
    "cloudformation": {"Sse": {"Type": "AWS::Config::ConfigRule", "Properties": {
        "Source": {"Owner": "AWS",
                   "SourceIdentifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"}}}},
    "terraform": 'resource "aws_config_config_rule" "ebs" {\n  source {\n    owner = "AWS"\n'
                 '    source_identifier = "ENCRYPTED_VOLUMES"\n  }\n}\n',
}


def _stack(root: Path, source: str, *parts: object) -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = _cfn(merged)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / "prod" / _PATHS[source], body)


@pytest.mark.parametrize("source", SOURCES)
def test_store_without_guardrail_fails_repo_041(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, STORE[source])
    (finding,) = EncryptionGuardrailMissing().run(tmp_path)
    assert finding.id == "REPO-041"
    assert "S3 bucket" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("guard", [DENY_POLICY, CONFIG_RULE], ids=["deny", "config"])
def test_store_with_guardrail_passes(tmp_path: Path, source: str, guard: dict) -> None:
    _stack(tmp_path, source, STORE[source], guard[source])
    assert EncryptionGuardrailMissing().run(tmp_path) == []


def test_scp_on_ec2_encrypted_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_ebs_volume" "v" {\n  size = 10\n}\n'
           'resource "aws_organizations_policy" "deny" {\n  content = jsonencode({\n'
           '    Statement = [{ Effect = "Deny", Action = "ec2:CreateVolume",\n'
           '      Condition = { Bool = { "ec2:Encrypted" = "false" } } }]\n  })\n}\n')
    assert encryption_guards(tmp_path) == {"deny on an encryption condition key": "prod/main.tf"}


def test_cdk_nag_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", STORE["cdk"])
    _write(tmp_path / "bin" / "app.ts",
           "import { AwsSolutionsChecks } from 'cdk-nag';\n"
           "Aspects.of(app).add(new AwsSolutionsChecks());\n")
    assert EncryptionGuardrailMissing().run(tmp_path) == []


@pytest.mark.parametrize("command", [
    "checkov -d .", "tfsec .", "trivy config --exit-code 1 .",
    "cfn-guard validate -d stack.yaml -r rules.guard",
])
def test_policy_scan_in_a_build_passes(tmp_path: Path, command: str) -> None:
    _stack(tmp_path, "terraform", STORE["terraform"])
    _write(tmp_path / ".github" / "workflows" / "ci.yml",
           f"jobs:\n  scan:\n    steps:\n      - run: {command}\n")
    assert EncryptionGuardrailMissing().run(tmp_path) == []


def test_installing_a_scanner_is_not_running_it(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", STORE["terraform"])
    _write(tmp_path / ".github" / "workflows" / "ci.yml",
           "jobs:\n  scan:\n    steps:\n      - run: pip install checkov\n")
    assert EncryptionGuardrailMissing().run(tmp_path)


def test_ebs_volume_counts_as_storage(tmp_path: Path) -> None:
    _stack(tmp_path, "cloudformation", {"Vol": {"Type": "AWS::EC2::Volume",
                                                "Properties": {"Size": 10}}})
    (finding,) = EncryptionGuardrailMissing().run(tmp_path)
    assert "EBS volume" in finding.evidence


def test_no_storage_gets_no_repo_041(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_sqs_queue" "q" {\n  name = "q"\n}\n')
    assert EncryptionGuardrailMissing().run(tmp_path) == []


def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", STORE["terraform"])
    (hit,) = EncryptionGuardrailMissing().run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    _write(tmp_path / "reports" / "report.json", report)
    assert len(EncryptionGuardrailMissing().run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    assert EncryptionGuardrailMissing().run(empty) == []


def test_repo_041_maps_to_sec08_bp03_and_runs_by_default() -> None:
    assert well_architected.best_practices_of("REPO-041") == ("SEC08-BP03",)
    assert "REPO-041" not in ORG_RULE_IDS


def test_sec8_is_fully_checked_and_reads_met_without_findings() -> None:
    (sec8,) = [a for a in well_architected.answers([]) if a.question.id == "SEC 8"]
    assert sec8.not_checked == ()
    assert sec8.met
