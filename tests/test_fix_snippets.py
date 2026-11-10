"""Suggested fixes come in the language of the source the finding points at."""
import json
import shutil
from pathlib import Path

import hcl2
import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import CHECK_PROPERTIES, run_cf_rules_from_paths
from aws_arch_agent.rules.fix_snippets import SNIPPETS, attach_fixes, strip_cdk_hint
from aws_arch_agent.tools.cfn_yaml import load_cfn_yaml

FIXTURES = Path(__file__).parent / "fixtures"
TEMPLATE_LEVEL = {"CF-VPC-001", "CF-FL-001", "CF-SUST-003", "CF-PATCH-001"}


def _materialize(name: str, dest: Path) -> Path:
    src = FIXTURES / name
    for path in src.rglob("*.fixture"):
        target = dest / path.relative_to(src).with_suffix("")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    return dest


def _finding(check_id: str, evidence: str) -> Finding:
    return Finding(id=check_id, title="t", recommendation="Do it. In CDK: thing.method().", evidence=evidence)


def _ids(language: str) -> set[str]:
    return {key.split(":", 1)[0] for key in SNIPPETS[language]}


def test_both_languages_cover_the_same_controls() -> None:
    assert _ids("cloudformation") == _ids("terraform")
    # Every per-resource check with a fix to write has one (V2 stage tracing has none: HTTP APIs lack X-Ray).
    assert set(CHECK_PROPERTIES) - {"CF-APIGW-V2-002"} <= _ids("terraform")
    assert TEMPLATE_LEVEL <= _ids("terraform")


@pytest.mark.parametrize("key", sorted(SNIPPETS["cloudformation"]))
def test_cloudformation_snippets_are_valid_yaml(key: str) -> None:
    check_id, _, rtype = key.partition(":")
    evidence = f"MyThing ({rtype or 'AWS::S3::Bucket'})"
    finding = attach_fixes([_finding(check_id, evidence)], "cloudformation")[0]
    doc = load_cfn_yaml(finding.suggested_code or "")
    assert isinstance(doc, dict) and len(doc) == 1
    body = next(iter(doc.values()))
    assert body["Type"].startswith("AWS::") and isinstance(body["Properties"], dict)


@pytest.mark.parametrize("key", sorted(SNIPPETS["terraform"]))
def test_terraform_snippets_are_valid_hcl(key: str) -> None:
    check_id, _, rtype = key.partition(":")
    rtype = rtype or "aws_s3_bucket"
    finding = attach_fixes([_finding(check_id, f"{rtype}.data ({rtype})")], "terraform")[0]
    doc = hcl2.loads(finding.suggested_code or "")
    assert doc.get("variable" if rtype == "variable" else "resource")


def test_snippets_name_the_resource() -> None:
    cf = attach_fixes([_finding("CF-S3-003", "DataBucket (AWS::S3::Bucket)")], "cloudformation")[0]
    assert cf.suggested_code.startswith("DataBucket:\n")
    tf = attach_fixes([_finding("CF-RDS-001", "aws_rds_cluster.main (aws_rds_cluster)")], "terraform")[0]
    assert tf.suggested_code.startswith('resource "aws_rds_cluster" "main" {')
    vpc = attach_fixes(
        [_finding("CF-FL-001", "Template has 1 VPC(s) and 0 FlowLog(s) (aws_vpc.network)")], "terraform"
    )[0]
    assert "aws_vpc.network.id" in (vpc.suggested_code or "")


def test_cdk_hint_is_dropped() -> None:
    assert strip_cdk_hint(
        "Set PublicAccessBlockConfiguration. In CDK: blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL."
    ) == "Set PublicAccessBlockConfiguration."
    assert strip_cdk_hint("Consider arm64. In CDK: architecture: lambda.Architecture.ARM_64.") == "Consider arm64."
    assert strip_cdk_hint("No hint here.") == "No hint here."


def test_cloudformation_repo_gets_cloudformation_fixes(tmp_path: Path) -> None:
    _r, _c, findings, _w = analyze_v1(_materialize("cloudformation", tmp_path / "cf"), use_llm=False)
    with_code = [f for f in findings if f.suggested_code]
    assert {f.id for f in with_code} >= {"CF-S3-001", "CF-RDS-003", "CF-SQS-002", "CF-FL-001"}
    for f in with_code:
        assert isinstance(load_cfn_yaml(f.suggested_code), dict)
        assert "resource \"" not in f.suggested_code
    assert not any("In CDK" in f.recommendation for f in findings)


def test_terraform_repo_gets_terraform_fixes(tmp_path: Path) -> None:
    _r, _c, findings, _w = analyze_v1(_materialize("terraform", tmp_path / "tf"), use_llm=False)
    by_id = {f.id: f for f in findings}
    assert by_id["CF-S3-001"].suggested_code.startswith(
        'resource "aws_s3_bucket_public_access_block" "data" {'
    )
    assert 'resource "aws_db_instance" "database"' in by_id["CF-RDS-003"].suggested_code
    for f in findings:
        if f.suggested_code:
            assert hcl2.loads(f.suggested_code)
    assert not any("In CDK" in f.recommendation for f in findings)


def test_synth_output_keeps_cdk_guidance(tmp_path: Path) -> None:
    """Findings on cdk synth output still point at the CDK app."""
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "Stack.template.json").write_text(
        json.dumps({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}), encoding="utf-8"
    )
    findings = run_cf_rules_from_paths([cdk_out / "Stack.template.json"], repo_path=tmp_path)
    s3 = next(f for f in findings if f.id == "CF-S3-001")
    assert s3.suggested_code is None
    assert "In CDK" in s3.recommendation


def test_security_group_fix_matches_the_resource_shape() -> None:
    sg = attach_fixes([_finding("CF-SG-001", "Web (AWS::EC2::SecurityGroup)")], "cloudformation")[0]
    assert "SecurityGroupIngress:" in sg.suggested_code
    rule = attach_fixes([_finding("CF-SG-001", "Ssh (AWS::EC2::SecurityGroupIngress)")], "cloudformation")[0]
    assert "Type: AWS::EC2::SecurityGroupIngress" in rule.suggested_code
    tf = attach_fixes(
        [_finding("CF-SG-001", "aws_security_group_rule.rdp (aws_security_group_rule)")], "terraform"
    )[0]
    assert tf.suggested_code.startswith('resource "aws_security_group_rule" "rdp" {')
