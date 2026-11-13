"""SEC 7: classification tags (REPO-039) and controls by sensitivity (REPO-040)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    DataClassificationMissing,
    SensitiveDataWithoutCmk,
    unclassified_stores,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _bucket(source: str, tag: str | None = None, cmk: bool = False) -> str:
    if source == "cdk":
        out = "const data = new s3.Bucket(this, 'Data'"
        out += ", { encryption: s3.BucketEncryption.KMS, encryptionKey: key });\n" if cmk else ");\n"
        if tag:
            out += f"Tags.of(data).add('DataClassification', '{tag}');\n"
        return out
    if source == "cloudformation":
        props: dict = {}
        if tag:
            props["Tags"] = [{"Key": "DataClassification", "Value": tag}]
        if cmk:
            props["BucketEncryption"] = {"ServerSideEncryptionConfiguration": [{
                "ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms",
                                                  "KMSMasterKeyID": {"Ref": "Key"}}}]}
        return json.dumps({"Resources": {"Data": {"Type": "AWS::S3::Bucket",
                                                  "Properties": props}}}, indent=2)
    out = 'resource "aws_s3_bucket" "data" {\n  bucket = "data"\n'
    if tag:
        out += f'  tags = {{\n    DataClassification = "{tag}"\n  }}\n'
    out += "}\n"
    if cmk:
        out += ('resource "aws_s3_bucket_server_side_encryption_configuration" "data" {\n'
                "  rule {\n    apply_server_side_encryption_by_default {\n"
                '      sse_algorithm = "aws:kms"\n      kms_master_key_id = aws_kms_key.k.arn\n'
                "    }\n  }\n}\n")
    return out


def _stack(root: Path, source: str, body: str) -> None:
    _write(root / "prod" / _PATHS[source], body)


# REPO-039: classification tag


@pytest.mark.parametrize("source", SOURCES)
def test_untagged_store_fails_repo_039(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _bucket(source))
    (finding,) = DataClassificationMissing().run(tmp_path)
    assert finding.id == "REPO-039"
    assert f"S3 bucket in prod/{_PATHS[source]}" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_tagged_store_passes_repo_039(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _bucket(source, tag="internal"))
    assert DataClassificationMissing().run(tmp_path) == []


def test_app_wide_cdk_tag_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk", _bucket("cdk"))
    _write(tmp_path / "bin" / "app.ts",
           "const app = new cdk.App();\ncdk.Tags.of(app).add('data-classification', 'internal');\n")
    assert DataClassificationMissing().run(tmp_path) == []


def test_terraform_default_tags_pass(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", _bucket("terraform"))
    _write(tmp_path / "prod" / "provider.tf",
           'provider "aws" {\n  default_tags {\n    tags = {\n'
           '      Classification = "internal"\n    }\n  }\n}\n')
    assert DataClassificationMissing().run(tmp_path) == []


def test_default_tags_without_the_key_do_not_pass(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", _bucket("terraform"))
    _write(tmp_path / "prod" / "provider.tf",
           'provider "aws" {\n  default_tags {\n    tags = {\n      Owner = "team"\n'
           "    }\n  }\n}\n")
    assert DataClassificationMissing().run(tmp_path)


def test_only_unclassified_files_are_named(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "a.tf", _bucket("terraform", tag="internal"))
    _write(tmp_path / "prod" / "b.tf", 'resource "aws_dynamodb_table" "t" {\n  name = "t"\n}\n')
    assert unclassified_stores(tmp_path) == {"prod/b.tf": "DynamoDB table"}


def test_no_store_gets_no_repo_039(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", 'resource "aws_sqs_queue" "q" {\n  name = "q"\n}\n')
    assert DataClassificationMissing().run(tmp_path) == []


# REPO-040: sensitive data needs a customer managed key


@pytest.mark.parametrize("source", SOURCES)
def test_confidential_store_without_cmk_fails_repo_040(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _bucket(source, tag="confidential"))
    (finding,) = SensitiveDataWithoutCmk().run(tmp_path)
    assert finding.id == "REPO-040"
    assert f"prod/{_PATHS[source]}" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_confidential_store_with_cmk_passes(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _bucket(source, tag="confidential", cmk=True))
    assert SensitiveDataWithoutCmk().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_internal_store_needs_no_cmk(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, _bucket(source, tag="internal"))
    assert SensitiveDataWithoutCmk().run(tmp_path) == []


@pytest.mark.parametrize("value", ["restricted", "PII", "pci", "Sensitive"])
def test_high_values(tmp_path: Path, value: str) -> None:
    _stack(tmp_path, "terraform", _bucket("terraform", tag=value))
    assert SensitiveDataWithoutCmk().run(tmp_path)


def test_cdk_table_customer_managed_key_passes(tmp_path: Path) -> None:
    _stack(tmp_path, "cdk",
           "const t = new dynamodb.Table(this, 'T', { partitionKey, "
           "encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED });\n"
           "Tags.of(t).add('Classification', 'restricted');\n")
    assert SensitiveDataWithoutCmk().run(tmp_path) == []
    assert DataClassificationMissing().run(tmp_path) == []


# Reports and the answer


def test_saved_report_quoting_findings_neither_passes_nor_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", _bucket("terraform"))
    hits = DataClassificationMissing().run(tmp_path)
    report = json.dumps({"findings": [f.model_dump() for f in hits]})
    _write(tmp_path / "reports" / "report.json", report)
    assert len(DataClassificationMissing().run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    assert DataClassificationMissing().run(empty) == []
    assert SensitiveDataWithoutCmk().run(empty) == []


def test_sec7_rules_map_and_run_by_default() -> None:
    assert well_architected.best_practices_of("REPO-039") == ("SEC07-BP01",)
    assert well_architected.best_practices_of("REPO-040") == ("SEC07-BP02",)
    assert not {"REPO-039", "REPO-040"} & ORG_RULE_IDS


def test_sec7_checks_every_best_practice() -> None:
    (sec7,) = [a for a in well_architected.answers([]) if a.question.id == "SEC 7"]
    assert sec7.not_checked == () and sec7.met
