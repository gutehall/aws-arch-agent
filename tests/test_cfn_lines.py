"""CloudFormation resources carry the line of their logical ID."""
import json
from pathlib import Path

from aws_arch_agent.baseline import finding_fingerprint
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths
from aws_arch_agent.rules.resource_model import resources_from_cf_template
from aws_arch_agent.tools.cfn_yaml import parse_template_text, parse_template_with_lines

YAML = """AWSTemplateFormatVersion: "2010-09-09"
# a comment
Shared: &tags
  - Key: team
    Value: core
Resources:
  # the bucket
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AWS::StackName}-data"
      Tags: *tags
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: !Ref AWS::StackName
  Queue: {Type: AWS::SQS::Queue, Properties: {QueueName: !GetAtt Topic.TopicName}}
"""


def test_yaml_logical_id_lines(tmp_path: Path) -> None:
    doc, lines = parse_template_with_lines(Path("t.yaml"), YAML)
    assert doc == parse_template_text(Path("t.yaml"), YAML)
    assert lines == {"Bucket": 8, "Topic": 13, "Queue": 17}


def test_json_logical_id_lines() -> None:
    text = json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Outputs": {"Resources": {"X": 1}},
         "Resources": {"A": {"Type": "AWS::S3::Bucket", "Properties": {"Note": "}\"Resources\""}},
                       "B": {"Type": "AWS::SNS::Topic"}}},
        indent=1,
    )
    doc, lines = parse_template_with_lines(Path("t.json"), text)
    assert doc == json.loads(text)
    rows = text.splitlines()
    assert rows[lines["A"] - 1].strip().startswith('"A"')
    assert rows[lines["B"] - 1].strip().startswith('"B"')
    assert "X" not in lines


def test_json_in_template_suffix_and_odd_shapes() -> None:
    _, lines = parse_template_with_lines(Path("t.template"), '{"Resources":\n{"A": {"Type": "AWS::S3::Bucket"}}}')
    assert lines == {"A": 2}
    assert parse_template_with_lines(Path("t.json"), '{"Resources": []}')[1] == {}
    assert parse_template_with_lines(Path("t.json"), "[]")[1] == {}
    assert parse_template_with_lines(Path("t.yaml"), "- a\n- b\n")[1] == {}


def test_malformed_resource_keeps_lines_for_the_rest(tmp_path: Path) -> None:
    text = "Resources:\n  Bad: 3\n  Good:\n    Type: AWS::S3::Bucket\n"
    doc, lines = parse_template_with_lines(Path("t.yaml"), text)
    warnings: list[str] = []
    resources = resources_from_cf_template(Path("t.yaml"), doc, warnings, lines)
    assert [(r.name, r.line) for r in resources] == [("Good", 3)]
    assert warnings and "Bad" in warnings[0]
    assert resources_from_cf_template(Path("t.yaml"), doc)[0].line is None


def test_findings_carry_lines_and_fingerprints_ignore_them(tmp_path: Path) -> None:
    for name, text in {
        "stack.yaml": YAML,
        "stack.template.json": json.dumps(parse_template_text(Path("t.yaml"), YAML), indent=2),
    }.items():
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        findings = run_cf_rules_from_paths([path], repo_path=tmp_path)
        anchored = [f for f in findings if f.evidence and f.evidence.startswith("Bucket")]
        assert anchored and all(f.line for f in anchored)
        for f in anchored:
            before = finding_fingerprint(f)
            f.line = None
            assert finding_fingerprint(f) == before
