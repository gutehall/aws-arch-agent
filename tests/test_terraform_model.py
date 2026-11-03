"""Root-module Terraform parses into Resource records the CF-* checks can run on."""
import json
from pathlib import Path

from aws_arch_agent.rules.cf_template import run_resource_checks
from aws_arch_agent.rules.resource_model import CANONICAL_TYPES
from aws_arch_agent.rules.terraform_model import (
    TF_TYPE_TO_CANONICAL,
    find_root_modules,
    resources_from_terraform,
)
from aws_arch_agent.tools.files import iter_files

MAIN_TF = """\
variable "encrypt" {
  type = bool
}

locals {
  retention = 14
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "db" {
  storage_encrypted       = var.encrypt
  multi_az                = false
  backup_retention_period = local.retention
  deletion_protection     = true
  instance_class          = "db.t3.micro"
}
"""


def _checks(tmp_path: Path) -> dict[str, set[str]]:
    resources = resources_from_terraform(tmp_path)
    findings = run_resource_checks(resources, tmp_path / "main.tf")
    out: dict[str, set[str]] = {}
    for f in findings:
        out.setdefault(f.id, set()).add(f.evidence or "")
    return out


def test_types_map_onto_canonical_types() -> None:
    assert set(TF_TYPE_TO_CANONICAL.values()) <= CANONICAL_TYPES


def test_hcl_resources_parse_with_address_file_and_line(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(MAIN_TF, encoding="utf-8")
    resources = {r.name: r for r in resources_from_terraform(tmp_path)}
    bucket = resources["aws_s3_bucket.data"]
    assert bucket.type == "s3_bucket"
    assert bucket.source_type == "aws_s3_bucket"
    assert bucket.file == str(tmp_path / "main.tf")
    assert bucket.line == 9
    assert resources["aws_db_instance.db"].line == 28
    # Split S3 settings resources attach to their bucket.
    assert bucket.properties["VersioningConfiguration"] == {"Status": "Enabled"}
    assert bucket.properties["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True


def test_unresolved_var_and_local_produce_no_finding(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(MAIN_TF, encoding="utf-8")
    db = next(r for r in resources_from_terraform(tmp_path) if r.name == "aws_db_instance.db")
    assert db.unresolved == {"StorageEncrypted", "BackupRetentionPeriod"}
    assert "StorageEncrypted" not in db.properties
    ids = _checks(tmp_path)
    assert "CF-RDS-001" not in ids  # storage_encrypted = var.encrypt
    assert "CF-RDS-002" not in ids  # backup_retention_period = local.retention
    assert "CF-RDS-003" in ids  # multi_az = false is a literal
    assert "CF-RDS-005" not in ids
    assert "CF-S3-001" not in ids and "CF-S3-003" not in ids
    assert ids["CF-S3-004"] == {"aws_s3_bucket.data (aws_s3_bucket)"}


def test_legacy_inline_bucket_arguments(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """resource "aws_s3_bucket" "old" {
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "logs"
  }
}
""",
        encoding="utf-8",
    )
    ids = _checks(tmp_path)
    assert "CF-S3-003" not in ids and "CF-S3-004" not in ids
    assert "CF-S3-001" in ids


def test_bucket_part_that_cannot_be_linked_is_unresolved(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket_public_access_block" "pab" {
  bucket            = var.bucket_name
  block_public_acls = true
}
""",
        encoding="utf-8",
    )
    assert "CF-S3-001" not in _checks(tmp_path)


def test_security_group_ingress_shapes(tmp_path: Path) -> None:
    (tmp_path / "sg.tf").write_text(
        """resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "closed" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
resource "aws_security_group" "dyn" {
  dynamic "ingress" {
    for_each = var.rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
resource "aws_security_group_rule" "rdp" {
  type        = "ingress"
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
}
resource "aws_security_group_rule" "out" {
  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_vpc_security_group_ingress_rule" "all" {
  ip_protocol = "-1"
  cidr_ipv6   = "::/0"
}
""",
        encoding="utf-8",
    )
    assert _checks(tmp_path)["CF-SG-001"] == {
        "aws_security_group.open (aws_security_group)",
        "aws_security_group_rule.rdp (aws_security_group_rule)",
        "aws_vpc_security_group_ingress_rule.all (aws_vpc_security_group_ingress_rule)",
    }


def test_log_group_retention_zero_means_never_expire(tmp_path: Path) -> None:
    (tmp_path / "logs.tf").write_text(
        'resource "aws_cloudwatch_log_group" "a" {\n  retention_in_days = 0\n}\n'
        'resource "aws_cloudwatch_log_group" "b" {\n  retention_in_days = 30\n}\n',
        encoding="utf-8",
    )
    assert _checks(tmp_path)["CF-CW-001"] == {"aws_cloudwatch_log_group.a (aws_cloudwatch_log_group)"}


def test_tf_json_with_unresolved_values(tmp_path: Path) -> None:
    doc = {
        "resource": {
            "aws_db_instance": {
                "db": {"storage_encrypted": "${var.enc}", "multi_az": True, "deletion_protection": True,
                       "backup_retention_period": 7, "publicly_accessible": True}
            }
        }
    }
    (tmp_path / "main.tf.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    resources = resources_from_terraform(tmp_path)
    assert resources[0].name == "aws_db_instance.db"
    assert resources[0].line == 4
    ids = _checks(tmp_path)
    assert "CF-RDS-001" not in ids
    assert "CF-RDS-004" in ids


def test_override_files_and_child_dirs_are_not_read(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_sqs_queue" "q" {}\n', encoding="utf-8")
    (tmp_path / "main_override.tf").write_text('resource "aws_sqs_queue" "q" {}\n', encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "x.tf").write_text('resource "aws_vpc" "v" {}\n', encoding="utf-8")
    names = [r.name for r in resources_from_terraform(tmp_path)]
    assert names == ["aws_sqs_queue.q"]


def test_root_modules_exclude_local_child_modules(tmp_path: Path) -> None:
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "main.tf").write_text(
        'module "net" {\n  source = "../modules/net"\n}\n'
        'module "reg" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "modules" / "net").mkdir(parents=True)
    (tmp_path / "modules" / "net" / "main.tf").write_text('resource "aws_vpc" "v" {}\n', encoding="utf-8")
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "main.tf.json").write_text("{}", encoding="utf-8")
    roots = find_root_modules(iter_files(tmp_path))
    assert roots == [(tmp_path / "infra").resolve(), (tmp_path / "other").resolve()]


def test_bad_file_is_a_warning(tmp_path: Path) -> None:
    (tmp_path / "bad.tf").write_text('resource "aws_vpc" "v" {\n', encoding="utf-8")
    (tmp_path / "ok.tf").write_text('resource "aws_vpc" "v2" {}\n', encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert [r.name for r in resources] == ["aws_vpc.v2"]
    assert any("bad.tf" in w for w in warnings)


def test_unknown_and_non_aws_types_have_no_canonical_type(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        'resource "aws_sns_topic" "t" {}\nresource "random_id" "r" {\n  byte_length = 4\n}\n',
        encoding="utf-8",
    )
    resources = resources_from_terraform(tmp_path)
    assert {r.type for r in resources} == {None}
    assert run_resource_checks(resources, tmp_path / "main.tf") == []
