"""SageMaker notebooks and endpoint configs, and FSx file systems: CF-SAGE-001..005, CF-FSX-001..003."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.environments import RULE_POLICY
from aws_arch_agent.rules.terraform_model import resources_from_terraform

SAGE = ("CF-SAGE-001", "CF-SAGE-002", "CF-SAGE-003", "CF-SAGE-004", "CF-SAGE-005")
FSX = ("CF-FSX-001", "CF-FSX-002", "CF-FSX-003")
IDS = SAGE + FSX
_PARAM = {"Ref": "Param"}
_KEY = "arn:aws:kms:us-east-1:111122223333:key/k"
_NOTEBOOK = "AWS::SageMaker::NotebookInstance"
_CONFIG = "AWS::SageMaker::EndpointConfig"
_FS = "AWS::FSx::FileSystem"
_BLOCK = {"LUSTRE": "LustreConfiguration", "WINDOWS": "WindowsConfiguration",
          "ONTAP": "OntapConfiguration", "OPENZFS": "OpenZFSConfiguration"}


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf(tmp_path: Path, resources: dict) -> dict[str, set[str]]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    warnings: list[str] = []
    found = run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=warnings)
    assert warnings == []
    return _by_id(found)


def _tf(tmp_path: Path, text: str) -> dict[str, set[str]]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    warnings: list[str] = []
    resources = resources_from_terraform(tmp_path, warnings)
    assert warnings == []
    return _by_id(run_resource_checks(resources, tmp_path / "main.tf"))


def _notebook(**props: Any) -> dict:
    base = {"DirectInternetAccess": "Disabled", "SubnetId": "subnet-1", "RootAccess": "Disabled", "KmsKeyId": _KEY}
    merged = {k: v for k, v in {**base, **props}.items() if v is not None}
    return {"Type": _NOTEBOOK, "Properties": merged}


def _variant(**props: Any) -> dict:
    return {"VariantName": "main", "ModelName": "m", "InstanceType": "ml.m5.large", "InitialInstanceCount": 2, **props}


def _config(*variants: Any, **props: Any) -> dict:
    base = {"ProductionVariants": list(variants), "KmsKeyId": _KEY}
    return {"Type": _CONFIG, "Properties": {k: v for k, v in {**base, **props}.items() if v is not None}}


def _fsx(kind: Any, block: Any = None, **props: Any) -> dict:
    """A file system with every check satisfied, unless a test passes other values."""
    body = {"FileSystemType": kind, "KmsKeyId": _KEY, **props}
    if block is not None and type(kind) is str:
        body[_BLOCK[kind]] = block
    return {"Type": _FS, "Properties": {k: v for k, v in body.items() if v is not None}}


def _persistent(**block: Any) -> dict:
    base = {"DeploymentType": "PERSISTENT_2", "CopyTagsToBackups": True, "AutomaticBackupRetentionDays": 7}
    return {k: v for k, v in {**base, **block}.items() if v is not None}


# --- notebooks ---------------------------------------------------------------


def test_good_notebook_is_clean(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"N": _notebook()}) == {}


@pytest.mark.parametrize("check, key", [("CF-SAGE-001", "DirectInternetAccess"), ("CF-SAGE-003", "RootAccess")])
@pytest.mark.parametrize("value, fires", [
    (None, True), ("Enabled", True), ("Disabled", False), (_PARAM, False),
    ({"Fn::If": ["C", "Enabled", "Disabled"]}, False),
])
def test_notebook_settings_that_default_to_enabled(
    tmp_path: Path, check: str, key: str, value: Any, fires: bool,
) -> None:
    assert _cf(tmp_path, {"N": _notebook(**{key: value})}) == ({check: {"N"}} if fires else {})


@pytest.mark.parametrize("check, key", [("CF-SAGE-002", "SubnetId"), ("CF-SAGE-004", "KmsKeyId")])
@pytest.mark.parametrize("value, fires", [(None, True), (_PARAM, False), ({"Fn::GetAtt": ["X", "Arn"]}, False)])
def test_notebook_settings_that_only_need_a_value(
    tmp_path: Path, check: str, key: str, value: Any, fires: bool,
) -> None:
    assert _cf(tmp_path, {"N": _notebook(**{key: value})}) == ({check: {"N"}} if fires else {})


def test_bare_notebook_gets_every_check_once(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"N": {"Type": _NOTEBOOK, "Properties": {}}})
    assert found == {c: {"N"} for c in ("CF-SAGE-001", "CF-SAGE-002", "CF-SAGE-003", "CF-SAGE-004")}


def test_terraform_notebook(tmp_path: Path) -> None:
    found = _tf(tmp_path, '''
resource "aws_sagemaker_notebook_instance" "bad" {
  name = "n"
}
resource "aws_sagemaker_notebook_instance" "good" {
  name                   = "n"
  direct_internet_access = "Disabled"
  root_access            = "Disabled"
  subnet_id              = aws_subnet.a.id
  kms_key_id             = aws_kms_key.k.arn
}
resource "aws_sagemaker_notebook_instance" "literal" {
  name                   = "n"
  direct_internet_access = "Enabled"
  root_access            = "Enabled"
  subnet_id              = "subnet-1"
  kms_key_id             = "k"
}
''')
    assert found == {
        "CF-SAGE-001": {"aws_sagemaker_notebook_instance.bad", "aws_sagemaker_notebook_instance.literal"},
        "CF-SAGE-002": {"aws_sagemaker_notebook_instance.bad"},
        "CF-SAGE-003": {"aws_sagemaker_notebook_instance.bad", "aws_sagemaker_notebook_instance.literal"},
        "CF-SAGE-004": {"aws_sagemaker_notebook_instance.bad"},
    }


def test_terraform_notebook_variables_are_not_judged(tmp_path: Path) -> None:
    assert _tf(tmp_path, '''
variable "x" {}
resource "aws_sagemaker_notebook_instance" "n" {
  name                   = "n"
  direct_internet_access = var.x
  root_access            = var.x
  subnet_id              = var.x
  kms_key_id             = var.x
}
''') == {}


# --- endpoint configs --------------------------------------------------------


def test_good_endpoint_config_is_clean(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"E": _config(_variant())}) == {}


def test_key_on_instance_variant(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"E": _config(_variant(), KmsKeyId=None)}) == {"CF-SAGE-004": {"E"}}
    assert _cf(tmp_path, {"E": _config(_variant(), KmsKeyId=_PARAM)}) == {}


def test_key_is_not_judged_on_serverless_only(tmp_path: Path) -> None:
    serverless = {"VariantName": "s", "ModelName": "m", "ServerlessConfig": {"MaxConcurrency": 1, "MemorySizeInMB": 1024}}
    assert _cf(tmp_path, {"E": _config(serverless, KmsKeyId=None)}) == {}
    assert _cf(tmp_path, {"E": _config(serverless, _variant(), KmsKeyId=None)}) == {"CF-SAGE-004": {"E"}}


def test_key_counts_a_shadow_instance_variant(tmp_path: Path) -> None:
    serverless = {"VariantName": "s", "ServerlessConfig": {"MaxConcurrency": 1}}
    config = _config(serverless, KmsKeyId=None, ShadowProductionVariants=[_variant()])
    assert _cf(tmp_path, {"E": config}) == {"CF-SAGE-004": {"E"}}


def test_key_is_not_judged_when_variants_are_unknown(tmp_path: Path) -> None:
    config = {"Type": _CONFIG, "Properties": {"ProductionVariants": _PARAM}}
    assert _cf(tmp_path, {"E": config}) == {}
    assert _cf(tmp_path, {"E": _config(_PARAM, KmsKeyId=None)}) == {}


@pytest.mark.parametrize("count, fires", [(1, True), ("1", True), (2, False), (_PARAM, False), (True, False)])
def test_single_instance_variant(tmp_path: Path, count: Any, fires: bool) -> None:
    found = _cf(tmp_path, {"E": _config(_variant(InitialInstanceCount=count))})
    assert found == ({"CF-SAGE-005": {"E"}} if fires else {})


def test_single_instance_ignores_unset_count_and_serverless_and_shadow(tmp_path: Path) -> None:
    unset = {"VariantName": "a", "InstanceType": "ml.m5.large"}
    serverless = {"VariantName": "s", "InitialInstanceCount": 1, "ServerlessConfig": {"MaxConcurrency": 1}}
    assert _cf(tmp_path, {"E": _config(unset, serverless)}) == {}
    shadow = _config(_variant(), ShadowProductionVariants=[_variant(InitialInstanceCount=1)])
    assert _cf(tmp_path, {"E": shadow}) == {}


def test_single_instance_finding_names_the_variant(tmp_path: Path) -> None:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"E": _config(
        _variant(InitialInstanceCount=1, VariantName="blue"), _variant(VariantName="green"))}}), encoding="utf-8")
    found = [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=[]) if f.id == "CF-SAGE-005"]
    assert len(found) == 1 and "blue" in found[0].recommendation and "green" not in found[0].recommendation


def test_single_instance_is_prod_advice() -> None:
    assert RULE_POLICY["CF-SAGE-005"] == {"dev": None, "staging": None}


def test_terraform_endpoint_config(tmp_path: Path) -> None:
    found = _tf(tmp_path, '''
variable "x" {}
resource "aws_sagemaker_endpoint_configuration" "bad" {
  production_variants {
    model_name             = "m"
    instance_type          = "ml.m5.large"
    initial_instance_count = 1
  }
}
resource "aws_sagemaker_endpoint_configuration" "keyed" {
  kms_key_arn = aws_kms_key.k.arn
  production_variants {
    model_name             = "m"
    instance_type          = var.x
    initial_instance_count = 2
  }
}
resource "aws_sagemaker_endpoint_configuration" "unknown" {
  kms_key_arn = var.x
  production_variants {
    model_name             = "m"
    instance_type          = "ml.m5.large"
    initial_instance_count = var.x
  }
}
resource "aws_sagemaker_endpoint_configuration" "serverless" {
  production_variants {
    model_name = "m"
    serverless_config {
      max_concurrency   = 1
      memory_size_in_mb = 1024
    }
  }
}
resource "aws_sagemaker_endpoint_configuration" "dynamic_variants" {
  dynamic "production_variants" {
    for_each = var.x
    content {
      model_name             = "m"
      instance_type          = "ml.m5.large"
      initial_instance_count = 1
    }
  }
}
resource "aws_sagemaker_endpoint_configuration" "dynamic_serverless" {
  production_variants {
    model_name             = "m"
    instance_type          = "ml.m5.large"
    initial_instance_count = 1
    dynamic "serverless_config" {
      for_each = var.x
      content {
        max_concurrency = 1
      }
    }
  }
}
''')
    assert found == {
        "CF-SAGE-004": {"aws_sagemaker_endpoint_configuration.bad"},
        "CF-SAGE-005": {"aws_sagemaker_endpoint_configuration.bad"},
    }


# --- FSx: key ----------------------------------------------------------------


@pytest.mark.parametrize("kind", ["WINDOWS", "ONTAP", "OPENZFS"])
def test_key_on_types_that_always_take_one(tmp_path: Path, kind: str) -> None:
    block = {"CopyTagsToBackups": True} if kind != "ONTAP" else {}
    assert _cf(tmp_path, {"F": _fsx(kind, block, KmsKeyId=None)}) == {"CF-FSX-001": {"F"}}
    assert _cf(tmp_path, {"F": _fsx(kind, block, KmsKeyId=_PARAM)}) == {}
    assert _cf(tmp_path, {"F": _fsx(kind, block, KmsKeyId=None, BackupId="backup-1")}) == {}


def test_key_is_judged_when_only_the_block_is_unknown(tmp_path: Path) -> None:
    fs = _fsx("WINDOWS", _PARAM, KmsKeyId=None)
    assert _cf(tmp_path, {"F": fs}) == {"CF-FSX-001": {"F"}}


@pytest.mark.parametrize("deployment, fires", [
    ("PERSISTENT_1", True), ("PERSISTENT_2", True), ("SCRATCH_1", False), ("SCRATCH_2", False),
    (None, False), (_PARAM, False),
])
def test_key_on_lustre_only_when_persistent(tmp_path: Path, deployment: Any, fires: bool) -> None:
    fs = _fsx("LUSTRE", _persistent(DeploymentType=deployment), KmsKeyId=None)
    found = _cf(tmp_path, {"F": fs})
    assert ("CF-FSX-001" in found) is fires


def test_type_from_a_parameter_is_not_judged(tmp_path: Path) -> None:
    fs = {"Type": _FS, "Properties": {"FileSystemType": _PARAM, "LustreConfiguration": {
        "DeploymentType": "PERSISTENT_2", "AutomaticBackupRetentionDays": 0}}}
    assert _cf(tmp_path, {"F": fs}) == {}


def test_unknown_block_hides_block_settings(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"F": _fsx("OPENZFS", _PARAM)}) == {}
    assert _cf(tmp_path, {"F": _fsx("OPENZFS", {"Fn::If": ["C", {}, {}]})}) == {}


# --- FSx: copy tags ----------------------------------------------------------


@pytest.mark.parametrize("kind, block", [
    ("WINDOWS", {"AutomaticBackupRetentionDays": 7}),
    ("OPENZFS", {"AutomaticBackupRetentionDays": 7}),
    ("LUSTRE", _persistent(CopyTagsToBackups=None)),
])
@pytest.mark.parametrize("value, fires", [(None, True), (False, True), ("false", True), (True, False), (_PARAM, False)])
def test_copy_tags(tmp_path: Path, kind: str, block: dict, value: Any, fires: bool) -> None:
    body = dict(block) if value is None else {**block, "CopyTagsToBackups": value}
    assert _cf(tmp_path, {"F": _fsx(kind, body)}) == ({"CF-FSX-002": {"F"}} if fires else {})


def test_copy_tags_does_not_apply_to_ontap(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"F": _fsx("ONTAP", {})}) == {}


@pytest.mark.parametrize("kind, cited, not_cited", [
    ("LUSTRE", "Security Hub FSx.2", "FSx.1"),
    ("OPENZFS", "Security Hub FSx.1", "FSx.2"),
    ("WINDOWS", None, "Security Hub"),
])
def test_copy_tags_cites_the_right_control(tmp_path: Path, kind: str, cited: str | None, not_cited: str) -> None:
    block = _persistent(CopyTagsToBackups=None) if kind == "LUSTRE" else {}
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"F": _fsx(kind, block)}}), encoding="utf-8")
    found = [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path, warnings=[]) if f.id == "CF-FSX-002"]
    assert len(found) == 1
    assert cited is None or cited in found[0].recommendation
    assert not_cited not in found[0].recommendation


def test_restored_file_system_is_judged_only_on_written_values(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"F": _fsx("OPENZFS", {}, BackupId="backup-1")}) == {}
    written = _fsx("OPENZFS", {"CopyTagsToBackups": False, "AutomaticBackupRetentionDays": 0}, BackupId="backup-1")
    assert _cf(tmp_path, {"F": written}) == {"CF-FSX-002": {"F"}, "CF-FSX-003": {"F"}}
    lustre = _persistent(CopyTagsToBackups=None, AutomaticBackupRetentionDays=None)
    assert _cf(tmp_path, {"F": _fsx("LUSTRE", lustre, BackupId=_PARAM)}) == {}


# --- FSx: backup retention ---------------------------------------------------


@pytest.mark.parametrize("kind", ["WINDOWS", "ONTAP", "OPENZFS"])
@pytest.mark.parametrize("days, fires", [(0, True), ("0", True), (None, False), (7, False), (_PARAM, False)])
def test_retention_with_a_default_above_zero(tmp_path: Path, kind: str, days: Any, fires: bool) -> None:
    block = {"AutomaticBackupRetentionDays": days} if days is not None else {}
    if kind != "ONTAP":
        block["CopyTagsToBackups"] = True
    assert _cf(tmp_path, {"F": _fsx(kind, block)}) == ({"CF-FSX-003": {"F"}} if fires else {})


@pytest.mark.parametrize("days, fires", [(0, True), (None, True), (7, False), (_PARAM, False)])
def test_retention_on_persistent_lustre_defaults_to_zero(tmp_path: Path, days: Any, fires: bool) -> None:
    fs = _fsx("LUSTRE", _persistent(AutomaticBackupRetentionDays=days))
    assert _cf(tmp_path, {"F": fs}) == ({"CF-FSX-003": {"F"}} if fires else {})


@pytest.mark.parametrize("deployment", ["SCRATCH_1", "SCRATCH_2", None, _PARAM])
def test_scratch_or_unknown_lustre_is_not_judged(tmp_path: Path, deployment: Any) -> None:
    block = {"CopyTagsToBackups": False, "AutomaticBackupRetentionDays": 0}
    if deployment is not None:
        block["DeploymentType"] = deployment
    assert _cf(tmp_path, {"F": _fsx("LUSTRE", block, KmsKeyId=None)}) == {}


@pytest.mark.parametrize("linked", [{"ImportPath": "s3://b"}, {"ExportPath": "s3://b/x"}, {"ImportPath": _PARAM}])
def test_lustre_linked_to_s3_has_no_backups(tmp_path: Path, linked: dict) -> None:
    block = {"DeploymentType": "PERSISTENT_2", "AutomaticBackupRetentionDays": 0, **linked}
    assert _cf(tmp_path, {"F": _fsx("LUSTRE", block)}) == {}


def _association(file_system: Any) -> dict:
    return {"Type": "AWS::FSx::DataRepositoryAssociation", "Properties": {
        "FileSystemId": file_system, "FileSystemPath": "/d", "DataRepositoryPath": "s3://b"}}


def test_lustre_with_a_data_repository_association(tmp_path: Path) -> None:
    bare = _persistent(CopyTagsToBackups=None, AutomaticBackupRetentionDays=None)
    both = {"CF-FSX-002": {"G"}, "CF-FSX-003": {"G"}}
    tied = {"F": _fsx("LUSTRE", bare), "G": _fsx("LUSTRE", bare), "A": _association({"Ref": "F"})}
    assert _cf(tmp_path, tied) == both
    unknown = {"F": _fsx("LUSTRE", bare), "G": _fsx("LUSTRE", bare), "A": _association(_PARAM)}
    assert _cf(tmp_path, unknown) == {}


def test_association_does_not_silence_other_types(tmp_path: Path) -> None:
    found = _cf(tmp_path, {"F": _fsx("OPENZFS", {}), "A": _association(_PARAM)})
    assert found == {"CF-FSX-002": {"F"}}


# --- FSx: Terraform ----------------------------------------------------------


def test_terraform_fsx_positive(tmp_path: Path) -> None:
    found = _tf(tmp_path, '''
resource "aws_fsx_lustre_file_system" "l" {
  deployment_type = "PERSISTENT_2"
}
resource "aws_fsx_windows_file_system" "w" {
  automatic_backup_retention_days = 0
}
resource "aws_fsx_ontap_file_system" "o" {
  deployment_type                 = "MULTI_AZ_1"
  automatic_backup_retention_days = 0
}
resource "aws_fsx_openzfs_file_system" "z" {
  deployment_type = "SINGLE_AZ_1"
}
''')
    assert found == {
        "CF-FSX-001": {"aws_fsx_lustre_file_system.l", "aws_fsx_windows_file_system.w",
                       "aws_fsx_ontap_file_system.o", "aws_fsx_openzfs_file_system.z"},
        "CF-FSX-002": {"aws_fsx_lustre_file_system.l", "aws_fsx_windows_file_system.w",
                       "aws_fsx_openzfs_file_system.z"},
        "CF-FSX-003": {"aws_fsx_lustre_file_system.l", "aws_fsx_windows_file_system.w",
                       "aws_fsx_ontap_file_system.o"},
    }


def test_terraform_fsx_negative_and_variables(tmp_path: Path) -> None:
    assert _tf(tmp_path, '''
variable "x" {}
resource "aws_fsx_lustre_file_system" "scratch_default" {
  automatic_backup_retention_days = 0
}
resource "aws_fsx_lustre_file_system" "scratch" {
  deployment_type = "SCRATCH_2"
}
resource "aws_fsx_lustre_file_system" "unknown_type" {
  deployment_type = var.x
}
resource "aws_fsx_lustre_file_system" "linked" {
  deployment_type = "PERSISTENT_1"
  kms_key_id      = aws_kms_key.k.arn
  import_path     = "s3://b"
}
resource "aws_fsx_lustre_file_system" "linked_by_var" {
  deployment_type = "PERSISTENT_1"
  kms_key_id      = aws_kms_key.k.arn
  export_path     = var.x
}
resource "aws_fsx_lustre_file_system" "good" {
  deployment_type                 = "PERSISTENT_2"
  kms_key_id                      = var.x
  copy_tags_to_backups            = true
  automatic_backup_retention_days = 7
}
resource "aws_fsx_windows_file_system" "vars" {
  kms_key_id                      = var.x
  copy_tags_to_backups            = var.x
  automatic_backup_retention_days = var.x
}
resource "aws_fsx_ontap_file_system" "default_retention" {
  kms_key_id = aws_kms_key.k.arn
}
resource "aws_fsx_openzfs_file_system" "restored" {
  backup_id = "backup-1"
}
''') == {}


def test_terraform_data_repository_association(tmp_path: Path) -> None:
    found = _tf(tmp_path, '''
resource "aws_fsx_lustre_file_system" "a" {
  deployment_type = "PERSISTENT_2"
  kms_key_id      = aws_kms_key.k.arn
}
resource "aws_fsx_lustre_file_system" "b" {
  deployment_type = "PERSISTENT_2"
  kms_key_id      = aws_kms_key.k.arn
}
resource "aws_fsx_data_repository_association" "d" {
  file_system_id       = aws_fsx_lustre_file_system.a.id
  data_repository_path = "s3://b"
  file_system_path     = "/d"
}
''')
    assert found == {"CF-FSX-002": {"aws_fsx_lustre_file_system.b"}, "CF-FSX-003": {"aws_fsx_lustre_file_system.b"}}


def test_terraform_adapter_keeps_type_and_tags(tmp_path: Path) -> None:
    resources = resources_from_terraform(_write(tmp_path), [])
    fs = next(r for r in resources if r.name == "aws_fsx_openzfs_file_system.t")
    assert fs.type == "fsx_file_system"
    assert fs.properties["Tags"] and fs.properties["FileSystemType"] == "OPENZFS"


def _write(tmp_path: Path) -> Path:
    (tmp_path / "main.tf").write_text('''
resource "aws_fsx_openzfs_file_system" "t" {
  deployment_type = "SINGLE_AZ_1"
  tags = { backup = "yes" }
}
''', encoding="utf-8")
    return tmp_path


def test_fix_snippets_and_topics_exist() -> None:
    from aws_arch_agent.report.doc_topics import RULE_TOPICS, TOPICS
    from aws_arch_agent.rules.fix_snippets import _CLOUDFORMATION, _TERRAFORM
    for check in IDS:
        assert check in _CLOUDFORMATION and check in _TERRAFORM
        assert RULE_TOPICS[check] in TOPICS
