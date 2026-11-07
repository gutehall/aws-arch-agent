"""CF-PAR-001 / CF-PAR-002 on Terraform root-module variables."""
import json
from pathlib import Path

from aws_arch_agent.agent.v1 import _scan_terraform
from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import terraform_variable_findings
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import NO_DEFAULT, variables_from_terraform

IDS = {"CF-PAR-001", "CF-PAR-002"}

VARIABLES_TF = """\
variable "db_password" {
  type = string
}

variable "api_key" {
  type    = string
  default = "sk-live-123"
}

variable "github_token" {
  type      = string
  sensitive = true
}

variable "signing_key" {
  type      = string
  sensitive = true
  default   = "abc"
}

variable "client_secret" {
  type    = string
  default = ""
}

variable "db_credentials" {
  type    = map(string)
  default = { username = "app", password = "hunter2" }
}

variable "db_secret_arn" {
  type = string
}

variable "password_min_length" {
  type    = number
  default = 12
}

variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "max_tokens" {
  type    = number
  default = 4096
}

variable "app_token_limit" {
  type    = number
  default = 10
}

variable "admin_password" {
  type      = string
  sensitive = true
  default   = null
}

variable "session_secret" {
  type    = string
  default = null
}

resource "aws_s3_bucket" "b" {
  bucket = "b"
}
"""


def _found(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.evidence.split(" ")[0], f.id) for f in findings if f.id in IDS}


def _findings(tmp_path: Path, text: str = VARIABLES_TF, name: str = "variables.tf") -> list[Finding]:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return terraform_variable_findings(variables_from_terraform(tmp_path))


def test_secret_variables(tmp_path: Path) -> None:
    findings = _findings(tmp_path)
    assert _found(findings) == {
        ("var.db_password", "CF-PAR-001"),     # plain secret
        ("var.api_key", "CF-PAR-002"),         # committed default
        ("var.signing_key", "CF-PAR-002"),     # sensitive does not hide a committed default
        ("var.client_secret", "CF-PAR-001"),   # an empty default commits nothing
        ("var.db_credentials", "CF-PAR-002"),  # a map default with values
        ("var.session_secret", "CF-PAR-001"),  # default = null is no default
    }
    by = {f.evidence.split(" ")[0]: f for f in findings}
    assert by["var.db_password"].severity == "Medium"
    assert by["var.api_key"].severity == "High"
    assert "sensitive is not true" in by["var.api_key"].recommendation
    assert "sensitive is not true" not in by["var.signing_key"].recommendation
    assert by["var.db_password"].line == 1
    assert by["var.api_key"].line == 5
    assert all(f.file.endswith("variables.tf") for f in findings)
    assert all("aws_secretsmanager_secret_version" in f.recommendation for f in findings)


def test_variables_are_read_from_tf_json(tmp_path: Path) -> None:
    # region's default text equals the secret variable's name: the line is the key's.
    doc = {"variable": {"region": {"default": "db_password"}, "db_password": {"type": "string"}}}
    findings = _findings(tmp_path, json.dumps(doc, indent=2), "variables.tf.json")
    assert _found(findings) == {("var.db_password", "CF-PAR-001")}
    assert findings[0].line == 6


def test_expressions_are_not_judged() -> None:
    """Terraform allows neither in these arguments, but a non-literal value is not reported."""
    from aws_arch_agent.rules.terraform_model import TfVariable, _Expr

    found = terraform_variable_findings([
        TfVariable("db_password", _Expr("${random_password.db.result}"), True, "v.tf", 1),
        TfVariable("api_key", NO_DEFAULT, _Expr("${var.hide}"), "v.tf", 5),
    ])
    assert found == []


def test_cloudformation_count_parameters_are_not_secrets(tmp_path: Path) -> None:
    from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths

    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Parameters": {
        "MaxTokens": {"Type": "Number", "Default": 4096},
        "MinimumPasswordAge": {"Type": "Number", "Default": 1},
        "ApiToken": {"Type": "String"},
        "MinioSecretKey": {"Type": "String"},
        "MAX_API_TOKENS": {"Type": "Number"},
    }, "Resources": {}}), encoding="utf-8")
    found = {f.evidence.split(" ")[0] for f in run_cf_rules_from_paths([path], repo_path=tmp_path)
             if f.id in IDS}
    assert found == {"ApiToken", "MinioSecretKey"}


def test_variable_records(tmp_path: Path) -> None:
    (tmp_path / "variables.tf").write_text(VARIABLES_TF, encoding="utf-8")
    variables = {v.name: v for v in variables_from_terraform(tmp_path)}
    assert variables["db_password"].default is NO_DEFAULT
    assert variables["github_token"].sensitive is True
    assert variables["region"].default == "eu-north-1"


def test_fixes_point_at_the_variable(tmp_path: Path) -> None:
    findings = attach_fixes(_findings(tmp_path), "terraform")
    code = {f.evidence.split(" ")[0]: f.suggested_code or "" for f in findings}
    assert code["var.db_password"].startswith('variable "db_password" {')
    assert "sensitive = true" in code["var.db_password"]
    assert "TF_VAR_api_key" in code["var.api_key"]
    assert "default =" not in code["var.api_key"]


def test_terraform_scan_reports_variables(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(VARIABLES_TF, encoding="utf-8")
    findings, warnings = _scan_terraform(tmp_path, [tmp_path], None, None)
    assert warnings == []
    rows = {(f.evidence.split(" ")[0], f.id, f.file) for f in findings if f.id in IDS}
    assert ("var.db_password", "CF-PAR-001", "main.tf") in rows
    excluded, _ = _scan_terraform(tmp_path, [tmp_path], None, ["CF-PAR-001"])
    assert not any(f.id == "CF-PAR-001" for f in excluded)


def test_child_module_variables_are_not_read(tmp_path: Path) -> None:
    child = tmp_path / "modules" / "db"
    child.mkdir(parents=True)
    (child / "variables.tf").write_text('variable "db_password" {\n  type = string\n}\n', encoding="utf-8")
    (tmp_path / "main.tf").write_text(
        'module "db" {\n  source      = "./modules/db"\n  db_password = var.root_password\n}\n\n'
        'variable "root_password" {\n  type      = string\n  sensitive = true\n}\n',
        encoding="utf-8",
    )
    findings, _ = _scan_terraform(tmp_path, [tmp_path], None, None)
    assert not any(f.id in IDS for f in findings)
