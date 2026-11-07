"""Root-module Terraform parses into Resource records the CF-* checks can run on."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.rules.cf_template import run_resource_checks
from aws_arch_agent.rules.resource_model import CANONICAL_TYPES
from aws_arch_agent.rules.terraform_model import (
    TF_TYPE_TO_CANONICAL,
    TerraformError,
    find_root_modules,
    load_plan_values,
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
    checks = _checks(tmp_path)
    assert checks["CF-SG-001"] == {
        "aws_security_group.open (aws_security_group)",
        "aws_security_group_rule.rdp (aws_security_group_rule)",
    }
    # Every port open is reported as CF-SG-002 instead.
    assert checks["CF-SG-002"] == {
        "aws_vpc_security_group_ingress_rule.all (aws_vpc_security_group_ingress_rule)",
    }
    assert checks["CF-SG-003"] == {"aws_security_group_rule.out (aws_security_group_rule)"}


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
        'resource "aws_sns_topic_subscription" "t" {}\nresource "random_id" "r" {\n  byte_length = 4\n}\n',
        encoding="utf-8",
    )
    resources = resources_from_terraform(tmp_path)
    assert {r.type for r in resources} == {None}
    assert run_resource_checks(resources, tmp_path / "main.tf") == []


def test_per_instance_refs_and_quoted_bools(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """resource "aws_db_instance" "each" {
  for_each            = var.dbs
  storage_encrypted   = each.value.enc
  multi_az            = "true"
  deletion_protection = true
  backup_retention_period = 7
}
resource "aws_cloudtrail" "t" {
  enable_log_file_validation = count.index == 0
  is_multi_region_trail      = true
  kms_key_id                 = data.aws_kms_key.k.arn
}
""",
        encoding="utf-8",
    )
    ids = _checks(tmp_path)
    assert "CF-RDS-001" not in ids  # each.value.enc
    assert "CF-RDS-003" not in ids  # "true" coerces to true
    assert "CF-CT-001" not in ids  # count.index expression
    assert "CF-CT-003" not in ids  # a data source reference counts as set


def test_expressions_in_compared_arguments_are_unresolved(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """resource "aws_s3_bucket" "b" {
  versioning {
    enabled = data.aws_ssm_parameter.v.value
  }
  dynamic "logging" {
    for_each = var.log_bucket == null ? [] : [1]
    content {
      target_bucket = var.log_bucket
    }
  }
}
resource "aws_lb" "lb" {
  access_logs {
    bucket  = "logs"
    enabled = "true"
  }
}
resource "aws_security_group" "sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = concat(["0.0.0.0/0"], [])
  }
}
resource "aws_vpc_security_group_ingress_rule" "port" {
  cidr_ipv4   = "0.0.0.0/0"
  ip_protocol = "tcp"
  from_port   = data.aws_ssm_parameter.port.value
  to_port     = data.aws_ssm_parameter.port.value
}
resource "aws_eks_cluster" "c" {
  enabled_cluster_log_types = toset(["api"])
}
resource "aws_lambda_function" "f" {
  architectures = [data.aws_ssm_parameter.arch.value]
}
""",
        encoding="utf-8",
    )
    ids = _checks(tmp_path)
    assert "CF-S3-003" not in ids  # enabled = data.* reference
    assert "CF-S3-004" not in ids  # dynamic "logging"
    assert "CF-ALB-001" not in ids  # enabled = "true"
    assert "CF-SG-001" not in ids  # concat(...) and data-source ports
    assert "CF-EKS-001" not in ids  # toset([...])
    assert "CF-S3-001" in ids  # no public access block at all


def test_sqs_redrive_policy_shapes(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """resource "aws_sqs_queue" "literal" {
  sqs_managed_sse_enabled = true
  redrive_policy = "{\\"deadLetterTargetArn\\":\\"arn:aws:sqs:eu-north-1:1:dlq\\",\\"maxReceiveCount\\":3}"
}
resource "aws_sqs_queue" "encoded" {
  sqs_managed_sse_enabled = true
  redrive_policy = jsonencode({ deadLetterTargetArn = aws_sqs_queue.dlq.arn, maxReceiveCount = 3 })
}
resource "aws_sqs_queue" "none" {
  sqs_managed_sse_enabled = true
}
""",
        encoding="utf-8",
    )
    assert _checks(tmp_path)["CF-SQS-002"] == {"aws_sqs_queue.none (aws_sqs_queue)"}


# --- terraform show -json ------------------------------------------------------

def _plan(tmp_path: Path, resources: list[dict], key: str = "planned_values") -> Path:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({key: {"root_module": {"resources": resources}}}), encoding="utf-8")
    return path


def _res(address: str, values: dict, **extra: object) -> dict:
    rtype, name = address.split(".", 1)
    return {"address": address, "mode": "managed", "type": rtype, "name": name, "values": values, **extra}


def test_plan_fills_var_and_local_values(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(MAIN_TF, encoding="utf-8")
    plan = _plan(tmp_path, [
        _res("aws_db_instance.db", {"storage_encrypted": False, "backup_retention_period": 0}),
    ])
    resources = resources_from_terraform(tmp_path, plan_values=load_plan_values(plan))
    db = next(r for r in resources if r.name == "aws_db_instance.db")
    assert db.unresolved == frozenset()
    assert db.properties["StorageEncrypted"] is False
    findings = run_resource_checks(resources, tmp_path / "main.tf")
    ids = {f.id for f in findings}
    assert {"CF-RDS-001", "CF-RDS-002"} <= ids


def test_plan_value_that_is_unknown_stays_unresolved(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(MAIN_TF, encoding="utf-8")
    # backup_retention_period is unknown until apply: terraform leaves it out of values.
    plan = _plan(tmp_path, [_res("aws_db_instance.db", {"storage_encrypted": True})])
    resources = resources_from_terraform(tmp_path, plan_values=load_plan_values(plan))
    db = next(r for r in resources if r.name == "aws_db_instance.db")
    assert db.unresolved == {"BackupRetentionPeriod"}
    assert db.properties["StorageEncrypted"] is True


def test_plan_expands_dynamic_ingress(tmp_path: Path) -> None:
    (tmp_path / "sg.tf").write_text(
        """resource "aws_security_group" "web" {
  dynamic "ingress" {
    for_each = var.rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ingress.value.cidrs
    }
  }
}
""",
        encoding="utf-8",
    )
    assert "CF-SG-001" not in _checks(tmp_path)
    plan = _plan(tmp_path, [_res("aws_security_group.web", {"ingress": [
        {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]},
    ]})])
    resources = resources_from_terraform(tmp_path, plan_values=load_plan_values(plan))
    sg = resources[0]
    assert sg.unresolved == frozenset()
    assert sg.properties["SecurityGroupIngress"] == [
        {"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22}
    ]


def test_plan_keeps_split_bucket_link(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """resource "aws_s3_bucket" "data" {
  bucket = var.name
}
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = var.status
  }
}
""",
        encoding="utf-8",
    )
    plan = _plan(tmp_path, [
        _res("aws_s3_bucket.data", {"bucket": "my-data"}),
        _res("aws_s3_bucket_versioning.data", {
            "bucket": "my-data", "versioning_configuration": [{"status": "Suspended"}],
        }),
    ])
    resources = resources_from_terraform(tmp_path, plan_values=load_plan_values(plan))
    bucket = next(r for r in resources if r.name == "aws_s3_bucket.data")
    assert bucket.properties["VersioningConfiguration"] == {"Status": "Suspended"}
    assert "VersioningConfiguration" not in bucket.unresolved


def test_plan_skips_data_sources_and_indexed_instances(tmp_path: Path) -> None:
    plan = _plan(tmp_path, [
        _res("aws_s3_bucket.one", {"bucket": "a"}),
        _res("aws_s3_bucket.many", {"bucket": "b"}, index=0),
        {**_res("aws_s3_bucket.d", {"bucket": "c"}), "mode": "data"},
    ])
    assert load_plan_values(plan) == {"aws_s3_bucket.one": {"bucket": "a"}}


def test_state_document_is_read_too(tmp_path: Path) -> None:
    plan = _plan(tmp_path, [_res("aws_s3_bucket.one", {"bucket": "a"})], key="values")
    assert load_plan_values(plan) == {"aws_s3_bucket.one": {"bucket": "a"}}


@pytest.mark.parametrize("content", ["not json", "[]", '{"format_version": "1.2"}'])
def test_bad_plan_raises_terraform_error(tmp_path: Path, content: str) -> None:
    path = tmp_path / "plan.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(TerraformError):
        load_plan_values(path)


def test_missing_plan_raises_terraform_error(tmp_path: Path) -> None:
    with pytest.raises(TerraformError):
        load_plan_values(tmp_path / "nope.json")


def test_plan_does_not_pair_set_blocks_by_position(tmp_path: Path) -> None:
    (tmp_path / "sg.tf").write_text(
        """resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = var.ssh_port
    to_port     = var.ssh_port
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }
}
""",
        encoding="utf-8",
    )
    # The plan lists the set in its own order, not config order.
    plan = _plan(tmp_path, [_res("aws_security_group.web", {"ingress": [
        {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]},
        {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]},
    ]})])
    sg = resources_from_terraform(tmp_path, plan_values=load_plan_values(plan))[0]
    assert sorted(sg.properties["SecurityGroupIngress"], key=lambda e: e["FromPort"]) == [
        {"CidrIp": "10.0.0.0/8", "FromPort": 22, "ToPort": 22},
        {"CidrIp": "0.0.0.0/0", "FromPort": 443, "ToPort": 443},
    ]


def test_plan_links_split_bucket_set_from_a_variable(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(
        """resource "aws_s3_bucket" "data" {
  bucket = var.name
}
resource "aws_s3_bucket_versioning" "data" {
  bucket = var.name
  versioning_configuration {
    status = "Enabled"
  }
}
""",
        encoding="utf-8",
    )
    without = resources_from_terraform(tmp_path)
    assert "VersioningConfiguration" in without[0].unresolved
    plan = _plan(tmp_path, [
        _res("aws_s3_bucket.data", {"bucket": "my-data"}),
        _res("aws_s3_bucket_versioning.data", {"bucket": "my-data"}),
    ])
    resources = resources_from_terraform(tmp_path, plan_values=load_plan_values(plan))
    bucket = next(r for r in resources if r.name == "aws_s3_bucket.data")
    assert bucket.properties["VersioningConfiguration"] == {"Status": "Enabled"}
    assert "VersioningConfiguration" not in bucket.unresolved
