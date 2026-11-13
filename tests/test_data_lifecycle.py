"""SEC 7: classified data with no lifecycle or retention rule (REPO-146)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_TAGGED_BUCKET = (
    'resource "aws_s3_bucket" "b" {\n  tags = {\n    DataClassification = "internal"\n  }\n'
    "{extra}}\n"
)


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _hits(findings: list) -> list:
    return [f for f in findings if f.id == "REPO-146"]


def test_rule_answers_sec7() -> None:
    assert RULE_BEST_PRACTICES["REPO-146"] == ("SEC07-BP04",)
    assert "SEC07-BP04" not in NOT_CHECKED


def test_classified_bucket_without_retention_fires(tmp_path: Path) -> None:
    (hit,) = _hits(_scan(tmp_path, {"b.tf": _TAGGED_BUCKET.replace("{extra}", "")}))
    assert hit.question == "SEC 7" and hit.severity == "Low" and hit.file == "prod/b.tf"
    assert "S3 bucket in prod/b.tf" in hit.evidence


@pytest.mark.parametrize(
    "extra",
    [
        '  lifecycle_rule {\n    enabled = true\n  }\n',
        '  time_to_live_attribute = "x"\n',
    ],
    ids=["lifecycle-rule", "ttl"],
)
def test_retention_in_the_file_passes(tmp_path: Path, extra: str) -> None:
    files = {"b.tf": _TAGGED_BUCKET.replace("{extra}", extra)}
    assert not _hits(_scan(tmp_path, files))


def test_cloudformation_lifecycle_passes(tmp_path: Path) -> None:
    text = ('{"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {"Tags": '
            '[{"Key": "DataClassification", "Value": "internal"}], '
            '"LifecycleConfiguration": {"Rules": []}}}}}')
    assert not _hits(_scan(tmp_path, {"t.json": text}))


def test_cloudformation_bucket_without_lifecycle_fires(tmp_path: Path) -> None:
    text = ('{"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {"Tags": '
            '[{"Key": "DataClassification", "Value": "internal"}]}}}}')
    assert len(_hits(_scan(tmp_path, {"t.json": text}))) == 1


def test_cdk_app_tag_with_unlifecycled_bucket_fires(tmp_path: Path) -> None:
    files = {"lib/s.ts": "Tags.of(app).add('DataClassification', 'internal');\n"
                         "new s3.Bucket(this, 'B');\n"}
    assert len(_hits(_scan(tmp_path, files))) == 1


def test_cdk_lifecycle_rules_pass(tmp_path: Path) -> None:
    files = {"lib/s.ts": "Tags.of(app).add('DataClassification', 'internal');\n"
                         "new s3.Bucket(this, 'B', { lifecycleRules: [{ expiration }] });\n"}
    assert not _hits(_scan(tmp_path, files))


def test_unclassified_bucket_is_left_to_the_classification_rule(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"b.tf": 'resource "aws_s3_bucket" "b" {}\n'})
    assert not _hits(findings)
