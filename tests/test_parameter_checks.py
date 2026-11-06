"""CF-PAR-001 / CF-PAR-002: CloudFormation parameters that hold secrets."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths
from aws_arch_agent.rules.fix_snippets import attach_fixes

IDS = {"CF-PAR-001", "CF-PAR-002"}


def _params(tmp_path: Path, parameters: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Parameters": parameters, "Resources": {}}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IDS]


def _found(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.evidence.split(" ")[0], f.id) for f in findings}


def test_secret_parameters(tmp_path: Path) -> None:
    findings = _params(tmp_path, {
        "DbPassword": {"Type": "String"},
        "ApiKey": {"Type": "String", "Default": "abc123"},
        "GithubToken": {"Type": "String", "NoEcho": True},
        "ClientSecret": {"Type": "String", "NoEcho": "true", "Default": "s3cr3t"},
        "MasterPassword": {"Type": "String", "NoEcho": True, "Default": ""},
        "Environment": {"Type": "String", "Default": "prod"},
        "DbSecretArn": {"Type": "String"},
        "KeyName": {"Type": "AWS::EC2::KeyPair::KeyName"},
        "PasswordLength": {"Type": "Number", "Default": 32},
        "DbPasswordParam": {"Type": "AWS::SSM::Parameter::Value<String>", "Default": "/db/password"},
        "AdminPasswd": {"Type": "String", "NoEcho": False},
    })
    assert _found(findings) == {
        ("DbPassword", "CF-PAR-001"),
        ("ApiKey", "CF-PAR-001"),
        ("ApiKey", "CF-PAR-002"),
        ("ClientSecret", "CF-PAR-002"),  # NoEcho hides it in the console, not in the repo
        ("AdminPasswd", "CF-PAR-001"),
    }
    severity = {f.id: f.severity for f in findings}
    assert severity == {"CF-PAR-001": "Medium", "CF-PAR-002": "High"}
    assert all("{{resolve:secretsmanager:" in f.recommendation for f in findings)


@pytest.mark.parametrize("name", ["DbPassword", "Passphrase", "SlackToken", "STRIPE_API_KEY",
                                  "PrivateKey", "SmtpCredentials", "AwsAccessKey", "OAuthClientSecret"])
def test_secret_names(tmp_path: Path, name: str) -> None:
    assert _found(_params(tmp_path, {name: {"Type": "String"}})) == {(name, "CF-PAR-001")}


@pytest.mark.parametrize("name", ["Stage", "TokenTtl", "SecretName", "ApiKeyId", "PasswordPolicy",
                                  "SecretRotationDays", "TokenUrl"])
def test_names_that_describe_a_secret_are_not_reported(tmp_path: Path, name: str) -> None:
    assert _params(tmp_path, {name: {"Type": "String"}}) == []


def test_fix_points_at_a_dynamic_reference(tmp_path: Path) -> None:
    findings = attach_fixes(_params(tmp_path, {"DbPassword": {"Type": "String", "Default": "x"}}),
                            "cloudformation")
    assert all("{{resolve:secretsmanager:" in (f.suggested_code or "") for f in findings)
    assert all("instead of !Ref DbPassword" in (f.suggested_code or "") for f in findings)
