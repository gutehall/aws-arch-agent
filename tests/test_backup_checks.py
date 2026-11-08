"""AWS Backup vaults, plans and coverage: CF-BAK-001..005."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import SNIPPETS
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = tuple(f"CF-BAK-00{n}" for n in range(1, 6))
_PARAM = {"Ref": "Param"}
_DR_ARN = "arn:aws:backup:eu-north-1:111122223333:backup-vault:dr"
_LOCAL_ARN = "arn:aws:backup:eu-west-1:111122223333:backup-vault:local"
_TF_RULE = 'rule_name = "daily"\n target_vault_name = "v"\n'


def _by_id(found: list[Finding]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in found:
        if f.id in IDS:
            out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _cf(tmp_path: Path, resources: dict, name: str = "t.json") -> dict[str, set[str]]:
    path = tmp_path / name
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


def _vault(**props: Any) -> dict:
    return {"Type": "AWS::Backup::BackupVault",
            "Properties": {"BackupVaultName": "v", "EncryptionKeyArn": "arn:key", **props}}


def _plan(**rule: Any) -> dict:
    base = {"RuleName": "daily", "TargetBackupVault": "v",
            "CopyActions": [{"DestinationBackupVaultArn": _DR_ARN}]}
    return {"Type": "AWS::Backup::BackupPlan", "Properties": {"BackupPlan": {
        "BackupPlanName": "p", "BackupPlanRule": [{**base, **rule}]}}}


def _selection(**body: Any) -> dict:
    return {"Type": "AWS::Backup::BackupSelection", "Properties": {
        "BackupPlanId": {"Ref": "P"},
        "BackupSelection": {"SelectionName": "s", "IamRoleArn": "arn:role", **body}}}


def _table(**props: Any) -> dict:
    return {"Type": "AWS::DynamoDB::Table", "Properties": props}


def test_a_hardened_stack_has_no_findings(tmp_path: Path) -> None:
    template = {
        "V": _vault(LockConfiguration={"MinRetentionDays": 7}),
        "P": _plan(Lifecycle={"DeleteAfterDays": 35}),
        "S": _selection(Resources=[{"Fn::GetAtt": ["T", "Arn"]}]),
        "T": _table(),
    }
    assert _cf(tmp_path, template, "prod-stack.json") == {}


def test_nothing_to_back_up_has_no_findings(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"Q": {"Type": "AWS::SQS::Queue", "Properties": {}}}) == {}


@pytest.mark.parametrize(("props", "fires"), [
    ({"EncryptionKeyArn": None}, True),
    ({"EncryptionKeyArn": "arn:key"}, False),
    ({"EncryptionKeyArn": _PARAM}, False),
])
def test_vault_key(tmp_path: Path, props: dict, fires: bool) -> None:
    assert _cf(tmp_path, {"V": _vault(**props)}) == ({"CF-BAK-001": {"V"}} if fires else {})


@pytest.mark.parametrize(("name", "props", "fires"), [
    ("prod-stack.json", {}, True),
    ("prod-stack.json", {"LockConfiguration": {"MinRetentionDays": 7}}, False),
    ("prod-stack.json", {"LockConfiguration": _PARAM}, False),
    ("dev-stack.json", {}, False),
    ("staging-stack.json", {}, False),
    ("backups.json", {}, False),
])
def test_vault_lock_only_in_prod(tmp_path: Path, name: str, props: dict, fires: bool) -> None:
    assert _cf(tmp_path, {"V": _vault(**props)}, name) == ({"CF-BAK-004": {"V"}} if fires else {})


def test_vault_lock_reads_an_environment_tag(tmp_path: Path) -> None:
    tagged = {"Type": "AWS::SQS::Queue", "Properties": {"Tags": [{"Key": "Environment", "Value": "prod"}]}}
    assert _cf(tmp_path, {"V": _vault(), "Q": tagged}) == {"CF-BAK-004": {"V"}}


@pytest.mark.parametrize(("rule", "fires"), [
    ({"CopyActions": []}, True),
    ({"CopyActions": None}, True),
    ({"CopyActions": [{"DestinationBackupVaultArn": {"Fn::GetAtt": ["V", "BackupVaultArn"]}}]}, True),
    ({"CopyActions": [{"DestinationBackupVaultArn": {"Fn::Sub": "${V.BackupVaultArn}"}}]}, True),
    ({"CopyActions": [{"DestinationBackupVaultArn": {
        "Fn::Sub": "arn:aws:backup:${AWS::Region}:${AWS::AccountId}:backup-vault:x"}}]}, True),
    ({"CopyActions": [{"DestinationBackupVaultArn": _DR_ARN}]}, False),
    ({"CopyActions": [{"DestinationBackupVaultArn": _PARAM}]}, False),
    ({"CopyActions": [{"DestinationBackupVaultArn": {
        "Fn::Sub": "arn:aws:backup:eu-north-1:${AWS::AccountId}:backup-vault:x"}}]}, False),
    ({"CopyActions": _PARAM}, False),
])
def test_copy_actions(tmp_path: Path, rule: dict, fires: bool) -> None:
    found = _cf(tmp_path, {"V": _vault(), "P": _plan(**rule), "S": _selection(Resources=["*"])})
    assert found == ({"CF-BAK-002": {"P"}} if fires else {})


def test_one_rule_copying_does_not_clear_another(tmp_path: Path) -> None:
    plan = _plan()
    plan["Properties"]["BackupPlan"]["BackupPlanRule"].append({"RuleName": "weekly"})
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": {"P": plan}}), encoding="utf-8")
    found = [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id == "CF-BAK-002"]
    assert len(found) == 1
    assert "weekly" in found[0].recommendation
    assert "daily" not in found[0].recommendation


@pytest.mark.parametrize(("name", "region_literal", "fires"), [
    ("cdk.out/same.template.json", "eu-west-1", True),
    ("cdk.out/other.template.json", "eu-north-1", False),
])
def test_a_literal_arn_is_compared_with_the_known_region(
    tmp_path: Path, name: str, region_literal: str, fires: bool
) -> None:
    from aws_arch_agent.rules import regions

    arn = f"arn:aws:backup:{region_literal}:111122223333:backup-vault:x"
    instance = {"Type": "AWS::EC2::Subnet", "Properties": {"AvailabilityZone": "eu-west-1a"}}
    path = tmp_path / name
    path.parent.mkdir(exist_ok=True)
    plan = _plan(CopyActions=[{"DestinationBackupVaultArn": arn}])
    path.write_text(json.dumps({"Resources": {"P": plan, "N": instance}}), encoding="utf-8")
    with regions.use_regions(None, env={}):
        found = _by_id(run_cf_rules_from_paths([path], repo_path=tmp_path))
    assert found == ({"CF-BAK-002": {"P"}} if fires else {})


def test_a_literal_arn_in_an_unknown_region_is_not_judged(tmp_path: Path) -> None:
    plan = _plan(CopyActions=[{"DestinationBackupVaultArn": _LOCAL_ARN}])
    assert _cf(tmp_path, {"P": plan}) == {}


@pytest.mark.parametrize(("lifecycle", "fires"), [
    ({"DeleteAfterDays": 6}, True),
    ({"DeleteAfterDays": "1"}, True),
    ({"DeleteAfterDays": 7}, False),
    ({"DeleteAfterDays": 35}, False),
    ({"DeleteAfterDays": _PARAM}, False),
    ({"MoveToColdStorageAfterDays": 1}, False),
    (None, False),
    (_PARAM, False),
])
def test_delete_after_days(tmp_path: Path, lifecycle: Any, fires: bool) -> None:
    rule = {} if lifecycle is None else {"Lifecycle": lifecycle}
    assert _cf(tmp_path, {"P": _plan(**rule)}) == ({"CF-BAK-003": {"P"}} if fires else {})


@pytest.mark.parametrize("plan_props", [_PARAM, {"BackupPlanRule": _PARAM}])
def test_an_unreadable_plan_is_not_judged(tmp_path: Path, plan_props: dict) -> None:
    plan = {"Type": "AWS::Backup::BackupPlan", "Properties": {"BackupPlan": plan_props}}
    assert _cf(tmp_path, {"P": plan}) == {}


# --- CF-BAK-005 ------------------------------------------------------------


def test_no_plan_is_one_finding_per_stack(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "A": _table(), "B": _table(),
        "F": {"Type": "AWS::EFS::FileSystem", "Properties": {}},
    })
    assert found == {"CF-BAK-005": {"A"}}


def test_a_vault_alone_is_not_a_plan(tmp_path: Path) -> None:
    assert _cf(tmp_path, {"V": _vault(), "T": _table()}) == {"CF-BAK-005": {"T"}}


@pytest.mark.parametrize("resource_type", [
    "AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::DynamoDB::Table", "AWS::EFS::FileSystem",
    "AWS::EC2::Volume", "AWS::FSx::FileSystem",
])
def test_every_stateful_type_counts(tmp_path: Path, resource_type: str) -> None:
    found = _cf(tmp_path, {"P": _plan(), "X": {"Type": resource_type, "Properties": {}}})
    assert found == {"CF-BAK-005": {"X"}}


def test_a_plan_reports_each_unselected_resource(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "P": _plan(), "S": _selection(Resources=[{"Fn::GetAtt": ["A", "Arn"]}]),
        "A": _table(), "B": _table(), "C": _table(),
    })
    assert found == {"CF-BAK-005": {"B", "C"}}


@pytest.mark.parametrize(("entry", "fires"), [
    ({"Fn::GetAtt": ["T", "Arn"]}, False),
    ({"Fn::Sub": "${T.Arn}"}, False),
    ({"Fn::GetAtt": ["Other", "Arn"]}, True),
    ("*", False),
    ("arn:aws:dynamodb:*:*:table/*", False),
    ("arn:aws:dynamodb:eu-west-1:111122223333:table/orders", False),
    ("arn:aws:rds:*:*:db:*", True),
    ("arn:aws:elasticfilesystem:*:*:file-system/*", True),
    (_PARAM, False),
    ({"Fn::Sub": "arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/${Param}"}, False),
])
def test_selection_by_arn(tmp_path: Path, entry: Any, fires: bool) -> None:
    other = {"Type": "AWS::SQS::Queue", "Properties": {}}
    found = _cf(tmp_path, {"P": _plan(), "S": _selection(Resources=[entry]), "T": _table(), "Other": other})
    assert found == ({"CF-BAK-005": {"T"}} if fires else {})


@pytest.mark.parametrize(("tags", "condition", "fires"), [
    ([{"Key": "backup", "Value": "daily"}], {"ConditionKey": "backup", "ConditionValue": "daily"}, False),
    ([{"Key": "backup", "Value": "never"}], {"ConditionKey": "backup", "ConditionValue": "daily"}, True),
    ([{"Key": "other", "Value": "daily"}], {"ConditionKey": "backup", "ConditionValue": "daily"}, True),
    (None, {"ConditionKey": "backup", "ConditionValue": "daily"}, True),
    ([{"Key": "backup", "Value": _PARAM}], {"ConditionKey": "backup", "ConditionValue": "daily"}, False),
    (_PARAM, {"ConditionKey": "backup", "ConditionValue": "daily"}, False),
    (None, {"ConditionKey": "backup", "ConditionValue": _PARAM}, False),
    (None, {"ConditionKey": _PARAM, "ConditionValue": "daily"}, False),
])
def test_selection_by_tag(tmp_path: Path, tags: Any, condition: dict, fires: bool) -> None:
    table = _table(Tags=tags) if tags is not None else _table()
    found = _cf(tmp_path, {"P": _plan(), "S": _selection(ListOfTags=[condition]), "T": table})
    assert found == ({"CF-BAK-005": {"T"}} if fires else {})


def test_efs_tags_are_read_from_file_system_tags(tmp_path: Path) -> None:
    efs = {"Type": "AWS::EFS::FileSystem", "Properties": {"FileSystemTags": [{"Key": "backup", "Value": "y"}]}}
    condition = {"ConditionKey": "backup", "ConditionValue": "y"}
    assert _cf(tmp_path, {"P": _plan(), "S": _selection(ListOfTags=[condition]), "F": efs}) == {}


@pytest.mark.parametrize(("value", "fires"), [("y", False), ("n", True)])
def test_fsx_tags_are_read(tmp_path: Path, value: str, fires: bool) -> None:
    fsx = {"Type": "AWS::FSx::FileSystem", "Properties": {"Tags": [{"Key": "backup", "Value": value}]}}
    condition = {"ConditionKey": "backup", "ConditionValue": "y"}
    found = _cf(tmp_path, {"P": _plan(), "S": _selection(ListOfTags=[condition]), "F": fsx})
    assert found == ({"CF-BAK-005": {"F"}} if fires else {})


def test_any_one_tag_in_list_of_tags_selects(tmp_path: Path) -> None:
    conditions = [{"ConditionKey": "a", "ConditionValue": "1"}, {"ConditionKey": "b", "ConditionValue": "2"}]
    table = _table(Tags=[{"Key": "b", "Value": "2"}])
    assert _cf(tmp_path, {"P": _plan(), "S": _selection(ListOfTags=conditions), "T": table}) == {}


@pytest.mark.parametrize(("tags", "fires"), [
    ([{"Key": "backup", "Value": "y"}], False),
    ([{"Key": "backup", "Value": "n"}], True),
    (None, True),
])
def test_string_equals_conditions_narrow_a_wildcard(tmp_path: Path, tags: Any, fires: bool) -> None:
    conditions = {"StringEquals": [{"ConditionKey": "aws:ResourceTag/backup", "ConditionValue": "y"}]}
    table = _table(Tags=tags) if tags is not None else _table()
    found = _cf(tmp_path, {"P": _plan(), "S": _selection(Resources=["*"], Conditions=conditions), "T": table})
    assert found == ({"CF-BAK-005": {"T"}} if fires else {})


def test_other_conditions_do_not_narrow_a_selection(tmp_path: Path) -> None:
    conditions = {"StringLike": [{"ConditionKey": "aws:ResourceTag/backup", "ConditionValue": "y*"}]}
    selection = _selection(Resources=["*"], Conditions=conditions)
    assert _cf(tmp_path, {"P": _plan(), "S": selection, "T": _table()}) == {}


@pytest.mark.parametrize("selection", [
    {"Type": "AWS::Backup::BackupSelection", "Properties": {"BackupSelection": _PARAM}},
    _selection(Resources=_PARAM),
    _selection(ListOfTags=_PARAM),
    _selection(),
])
def test_an_unreadable_selection_counts_for_every_resource(tmp_path: Path, selection: dict) -> None:
    assert _cf(tmp_path, {"P": _plan(), "S": selection, "T": _table()}) == {}


def test_a_selection_with_its_plan_elsewhere_is_read(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "S": _selection(Resources=[{"Fn::GetAtt": ["A", "Arn"]}]), "A": _table(), "B": _table(),
    })
    assert found == {"CF-BAK-005": {"B"}}


@pytest.mark.parametrize("props", [
    {"DBClusterIdentifier": "c"},
    {"DBClusterIdentifier": _PARAM},
    {"SourceDBInstanceIdentifier": "primary"},
])
def test_members_and_replicas_hold_no_data_of_their_own(tmp_path: Path, props: dict) -> None:
    db = {"Type": "AWS::RDS::DBInstance", "Properties": props}
    assert _cf(tmp_path, {"P": _plan(), "D": db}) == {}


# --- Terraform -------------------------------------------------------------


def test_terraform_hardened_stack_has_no_findings(tmp_path: Path) -> None:
    assert _tf(tmp_path, f"""
resource "aws_backup_vault" "v" {{
  name        = "v"
  kms_key_arn = aws_kms_key.k.arn
}}
resource "aws_backup_plan" "p" {{
  name = "p"
  rule {{
    {_TF_RULE}
    lifecycle {{
      delete_after = 35
    }}
    copy_action {{
      destination_vault_arn = aws_backup_vault.dr.arn
    }}
  }}
}}
resource "aws_backup_selection" "s" {{
  name         = "s"
  plan_id      = aws_backup_plan.p.id
  iam_role_arn = "arn:role"
  resources    = [aws_dynamodb_table.t.arn]
}}
resource "aws_dynamodb_table" "t" {{
  name = "t"
}}
""") == {}


def test_terraform_findings(tmp_path: Path) -> None:
    assert _tf(tmp_path, f"""
resource "aws_backup_vault" "v" {{
  name = "v"
}}
resource "aws_backup_plan" "p" {{
  name = "p"
  rule {{
    {_TF_RULE}
    lifecycle {{
      delete_after = 3
    }}
  }}
}}
resource "aws_backup_selection" "s" {{
  name         = "s"
  plan_id      = aws_backup_plan.p.id
  iam_role_arn = "arn:role"
  resources    = [aws_dynamodb_table.a.arn]
}}
resource "aws_dynamodb_table" "a" {{
  name = "a"
}}
resource "aws_dynamodb_table" "b" {{
  name = "b"
}}
resource "aws_fsx_lustre_file_system" "f" {{
  subnet_ids = ["s"]
}}
""") == {
        "CF-BAK-001": {"aws_backup_vault.v"},
        "CF-BAK-002": {"aws_backup_plan.p"},
        "CF-BAK-003": {"aws_backup_plan.p"},
        "CF-BAK-005": {"aws_dynamodb_table.b", "aws_fsx_lustre_file_system.f"},
    }


def test_terraform_no_plan_is_one_finding_per_stack(tmp_path: Path) -> None:
    found = _tf(tmp_path, """
resource "aws_dynamodb_table" "a" {
  name = "a"
}
resource "aws_ebs_volume" "b" {
  availability_zone = "eu-west-1a"
}
""")
    assert list(found) == ["CF-BAK-005"] and len(found["CF-BAK-005"]) == 1


@pytest.mark.parametrize("rule_body", [
    'lifecycle {\n delete_after = var.days\n}',
    'dynamic "lifecycle" {\n for_each = var.x\n content {\n delete_after = 1\n }\n}',
])
def test_terraform_unknown_lifecycle_is_not_judged(tmp_path: Path, rule_body: str) -> None:
    found = _tf(tmp_path, f"""
resource "aws_backup_plan" "p" {{
  name = "p"
  rule {{
    {_TF_RULE}
    copy_action {{
      destination_vault_arn = var.dr
    }}
    {rule_body}
  }}
}}
""")
    assert found == {}


@pytest.mark.parametrize("copy", [
    'copy_action {\n destination_vault_arn = var.dr\n}',
    'copy_action {\n destination_vault_arn = aws_backup_vault.dr.arn\n}',
    'dynamic "copy_action" {\n for_each = var.x\n content {\n destination_vault_arn = each.value\n }\n}',
])
def test_terraform_copy_from_an_expression_is_not_judged(tmp_path: Path, copy: str) -> None:
    found = _tf(tmp_path, f"""
resource "aws_backup_plan" "p" {{
  name = "p"
  rule {{
    {_TF_RULE}
    {copy}
  }}
}}
""")
    assert found == {}


def test_terraform_dynamic_rule_is_not_judged(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_backup_plan" "p" {
  name = "p"
  dynamic "rule" {
    for_each = var.rules
    content {
      rule_name = rule.key
    }
  }
}
""") == {}


_TF_LOCKED = """
resource "aws_backup_vault" "v" {
  name        = "v"
  kms_key_arn = "arn:key"
}
resource "aws_dynamodb_table" "t" {
  name = "t"
  tags = { Environment = "prod" }
}
resource "aws_backup_plan" "p" {
  name = "p"
}
resource "aws_backup_selection" "s" {
  name         = "s"
  plan_id      = "x"
  iam_role_arn = "arn:role"
  resources    = ["*"]
}
"""


def test_terraform_prod_vault_with_no_lock_fires(tmp_path: Path) -> None:
    assert _tf(tmp_path, _TF_LOCKED) == {"CF-BAK-004": {"aws_backup_vault.v"}}


@pytest.mark.parametrize("name", ["aws_backup_vault.v.name", '"v"', "var.unknown"])
def test_terraform_lock_resource_clears_the_vault(tmp_path: Path, name: str) -> None:
    lock = f'resource "aws_backup_vault_lock_configuration" "l" {{\n backup_vault_name = {name}\n}}\n'
    assert _tf(tmp_path, _TF_LOCKED + lock) == {}


def test_terraform_lock_on_another_vault_does_not_clear(tmp_path: Path) -> None:
    extra = """
resource "aws_backup_vault" "w" {
  name        = "w"
  kms_key_arn = "arn:key"
}
resource "aws_backup_vault_lock_configuration" "l" {
  backup_vault_name = aws_backup_vault.w.name
}
"""
    assert _tf(tmp_path, _TF_LOCKED + extra) == {"CF-BAK-004": {"aws_backup_vault.v"}}


@pytest.mark.parametrize(("selection", "fires"), [
    ('selection_tag {\n type = "STRINGEQUALS"\n key = "backup"\n value = "y"\n}', False),
    ('selection_tag {\n type = "STRINGEQUALS"\n key = "backup"\n value = "n"\n}', True),
    ('selection_tag {\n type = "STRINGEQUALS"\n key = "backup"\n value = var.v\n}', False),
    ('dynamic "selection_tag" {\n for_each = var.x\n content {\n key = "a"\n }\n}', False),
    ('resources = var.arns', False),
    ('resources = ["*"]\n condition {\n string_equals {\n key = "aws:ResourceTag/backup"\n value = "y"\n }\n}',
     False),
    ('resources = ["*"]\n condition {\n string_equals {\n key = "aws:ResourceTag/backup"\n value = "n"\n }\n}',
     True),
])
def test_terraform_selection(tmp_path: Path, selection: str, fires: bool) -> None:
    found = _tf(tmp_path, f"""
resource "aws_backup_plan" "p" {{
  name = "p"
}}
resource "aws_backup_selection" "s" {{
  name         = "s"
  plan_id      = aws_backup_plan.p.id
  iam_role_arn = "arn:role"
  {selection}
}}
resource "aws_dynamodb_table" "t" {{
  name = "t"
  tags = {{ backup = "y" }}
}}
""")
    assert found == ({"CF-BAK-005": {"aws_dynamodb_table.t"}} if fires else {})


def test_terraform_unknown_tags_count_as_selected(tmp_path: Path) -> None:
    assert _tf(tmp_path, """
resource "aws_backup_plan" "p" {
  name = "p"
}
resource "aws_backup_selection" "s" {
  name         = "s"
  plan_id      = aws_backup_plan.p.id
  iam_role_arn = "arn:role"
  selection_tag {
    type  = "STRINGEQUALS"
    key   = "backup"
    value = "y"
  }
}
resource "aws_dynamodb_table" "t" {
  name = "t"
  tags = var.tags
}
""") == {}


def test_terraform_a_similar_address_does_not_select(tmp_path: Path) -> None:
    found = _tf(tmp_path, """
resource "aws_backup_plan" "p" {
  name = "p"
}
resource "aws_backup_selection" "s" {
  name         = "s"
  plan_id      = aws_backup_plan.p.id
  iam_role_arn = "arn:role"
  resources    = [aws_dynamodb_table.orders2.arn]
}
resource "aws_dynamodb_table" "orders" {
  name = "orders"
}
resource "aws_dynamodb_table" "orders2" {
  name = "orders2"
}
""")
    assert found == {"CF-BAK-005": {"aws_dynamodb_table.orders"}}


def test_every_check_has_snippets_in_both_languages() -> None:
    for language in SNIPPETS.values():
        assert set(IDS) <= set(language)
