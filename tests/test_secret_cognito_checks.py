"""CF-SM-001 (Secrets Manager rotation) and CF-COG-* (Cognito user pools) (DM3-528)."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import CF_COVERS_STATIC, run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = {"CF-SM-001", "CF-COG-001", "CF-COG-002", "CF-COG-003"}


def _found(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.evidence.split(" ")[0], f.id) for f in findings if f.id in IDS}


def _by(findings: list[Finding]) -> dict[tuple[str, str], Finding]:
    return {(f.evidence.split(" ")[0], f.id): f for f in findings if f.id in IDS}


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IDS]


def _secret(**props) -> dict:
    return {"Type": "AWS::SecretsManager::Secret", "Properties": props}


def _rotation(secret_id) -> dict:
    return {"Type": "AWS::SecretsManager::RotationSchedule", "Properties": {
        "SecretId": secret_id, "RotationRules": {"ScheduleExpression": "rate(30 days)"}}}


STRONG = {"MinimumLength": 14, "RequireLowercase": True, "RequireUppercase": True,
          "RequireNumbers": True, "RequireSymbols": True}


def _pool(**props) -> dict:
    base = {"MfaConfiguration": "ON", "Policies": {"PasswordPolicy": STRONG},
            "UserPoolTier": "PLUS", "UserPoolAddOns": {"AdvancedSecurityMode": "ENFORCED"}}
    base.update(props)
    return {"Type": "AWS::Cognito::UserPool", "Properties": {k: v for k, v in base.items() if v is not None}}


def test_cloudformation_rotation(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Plain": _secret(),
        "ByRef": _secret(),
        "ByRefRotation": _rotation({"Ref": "ByRef"}),
        "ByName": _secret(Name="app/db"),
        "ByNameRotation": _rotation("app/db"),
        "ByArn": _secret(Name="app/api"),
        "ByArnRotation": _rotation("arn:aws:secretsmanager:eu-north-1:111122223333:secret:app/api-AbC123"),
        "BySub": _secret(),
        "BySubRotation": _rotation({"Fn::Sub": "${BySub}"}),
    })
    assert _found(findings) == {("Plain", "CF-SM-001")}
    assert findings[0].severity == "Medium"


def test_cloudformation_unlinked_rotation_covers_every_secret(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "A": _secret(),
        "Imported": _rotation({"Fn::ImportValue": "SharedSecretArn"}),
    })
    assert _found(findings) == set()


def test_cloudformation_cognito(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Strong": _pool(),
        "Optional": _pool(MfaConfiguration="OPTIONAL"),
        "MfaOff": _pool(MfaConfiguration="OFF"),
        "MfaUnset": _pool(MfaConfiguration=None),
        "MfaParam": _pool(MfaConfiguration={"Ref": "Mfa"}),
        "DefaultPolicy": _pool(Policies=None),
        "SignInOnly": _pool(Policies={"SignInPolicy": {"AllowedFirstAuthFactors": ["PASSWORD"]}}),
        "Short": _pool(Policies={"PasswordPolicy": {**STRONG, "MinimumLength": 8}}),
        "ShortString": _pool(Policies={"PasswordPolicy": {**STRONG, "MinimumLength": "10"}}),
        "NoClasses": _pool(Policies={"PasswordPolicy": {"MinimumLength": 16}}),
        "SomeClasses": _pool(Policies={"PasswordPolicy": {"MinimumLength": 16, "RequireSymbols": True}}),
        "ClassParam": _pool(Policies={"PasswordPolicy": {"MinimumLength": 16, "RequireSymbols": {"Ref": "S"}}}),
        "PolicyParam": _pool(Policies={"Fn::If": ["Prod", {"PasswordPolicy": STRONG}, {"Ref": "AWS::NoValue"}]}),
        "ThreatOff": _pool(UserPoolAddOns={"AdvancedSecurityMode": "OFF"}),
        "ThreatAudit": _pool(UserPoolAddOns={"AdvancedSecurityMode": "AUDIT"}),
        "ThreatUnsetEssentials": _pool(UserPoolAddOns=None, UserPoolTier=None),
        "ThreatParam": _pool(UserPoolAddOns={"AdvancedSecurityMode": {"Ref": "Mode"}}),
        "TierParam": _pool(UserPoolAddOns=None, UserPoolTier={"Ref": "Tier"}),
        "NoLength": _pool(Policies={"PasswordPolicy": {k: v for k, v in STRONG.items() if k != "MinimumLength"}}),
    })
    assert _found(findings) == {
        ("MfaOff", "CF-COG-001"), ("MfaUnset", "CF-COG-001"),
        ("DefaultPolicy", "CF-COG-002"), ("SignInOnly", "CF-COG-002"),
        ("Short", "CF-COG-002"), ("ShortString", "CF-COG-002"), ("NoClasses", "CF-COG-002"),
        ("ThreatOff", "CF-COG-003"), ("ThreatUnsetEssentials", "CF-COG-003"),
        ("TierParam", "CF-COG-003"), ("NoLength", "CF-COG-002"),
    }
    by = _by(findings)
    assert by[("MfaOff", "CF-COG-001")].severity == "High"
    assert by[("Short", "CF-COG-002")].severity == "Medium"
    assert by[("Short", "CF-COG-002")].recommendation.startswith("MinimumLength is 8.")
    assert by[("DefaultPolicy", "CF-COG-002")].recommendation.startswith("No PasswordPolicy is set")
    assert by[("NoClasses", "CF-COG-002")].recommendation.startswith("No character class is required.")
    assert by[("ThreatOff", "CF-COG-003")].severity == "Low"
    assert "Plus feature plan" not in by[("ThreatOff", "CF-COG-003")].recommendation  # already PLUS
    assert "Plus feature plan" in by[("ThreatUnsetEssentials", "CF-COG-003")].recommendation
    assert "Plus feature plan" not in by[("TierParam", "CF-COG-003")].recommendation  # may be PLUS
    assert by[("NoLength", "CF-COG-002")].recommendation.startswith("MinimumLength is 8.")


def test_cloudformation_fixes(tmp_path: Path) -> None:
    findings = attach_fixes(_cf(tmp_path, {
        "Secret": _secret(),
        "Pool": _pool(MfaConfiguration="OFF", Policies=None, UserPoolAddOns=None, UserPoolTier=None),
    }), "cloudformation")
    code = {(f.evidence.split(" ")[0], f.id): f.suggested_code or "" for f in findings}
    assert code[("Secret", "CF-SM-001")].startswith("SecretRotation:\n  Type: AWS::SecretsManager::RotationSchedule")
    assert "SecretId: !Ref Secret" in code[("Secret", "CF-SM-001")]
    assert 'MfaConfiguration: "ON"' in code[("Pool", "CF-COG-001")]
    assert "MinimumLength: 12" in code[("Pool", "CF-COG-002")]
    assert "AdvancedSecurityMode: ENFORCED" in code[("Pool", "CF-COG-003")]
    assert all("In CDK" not in f.recommendation for f in findings)


def test_template_checks_replace_the_cdk_rules() -> None:
    assert CF_COVERS_STATIC["CF-SM-001"] == ("SEC-015",)
    assert CF_COVERS_STATIC["CF-COG-001"] == ("SEC-034",)
    assert CF_COVERS_STATIC["CF-COG-002"] == ("SEC-035",)
    assert CF_COVERS_STATIC["CF-COG-003"] == ("SEC-036",)


SECRET_COGNITO_TF = """\
resource "aws_secretsmanager_secret" "plain" {
  name = "plain"
}

resource "aws_secretsmanager_secret" "rotated" {
  name = "rotated"
}

resource "aws_secretsmanager_secret_rotation" "rotated" {
  secret_id           = aws_secretsmanager_secret.rotated.id
  rotation_lambda_arn = aws_lambda_function.rotate.arn
  rotation_rules {
    automatically_after_days = 30
  }
}

resource "aws_secretsmanager_secret" "by_arn" {
  name = "by-arn"
}

resource "aws_secretsmanager_secret_rotation" "by_arn" {
  secret_id           = aws_secretsmanager_secret.by_arn.arn
  rotation_lambda_arn = aws_lambda_function.rotate.arn
}

resource "aws_secretsmanager_secret" "by_name" {
  name = "app/by-name"
}

resource "aws_secretsmanager_secret_rotation" "by_name" {
  secret_id           = "app/by-name"
  rotation_lambda_arn = aws_lambda_function.rotate.arn
  rotation_rules {
    automatically_after_days = 30
  }
}

resource "aws_cognito_user_pool" "strong" {
  name              = "strong"
  mfa_configuration = "ON"
  user_pool_tier    = "PLUS"
  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }
}

resource "aws_cognito_user_pool" "defaults" {
  name = "defaults"
}

resource "aws_cognito_user_pool" "weak" {
  name              = "weak"
  mfa_configuration = "OPTIONAL"
  password_policy {
    minimum_length = 8
  }
  user_pool_add_ons {
    advanced_security_mode = "AUDIT"
  }
}

resource "aws_cognito_user_pool" "from_var" {
  name              = "v"
  mfa_configuration = var.mfa
  password_policy {
    minimum_length    = var.length
    require_lowercase = true
  }
  user_pool_add_ons {
    advanced_security_mode = var.mode
  }
}

resource "aws_cognito_user_pool" "dynamic_policy" {
  name              = "dyn"
  mfa_configuration = "ON"
  dynamic "password_policy" {
    for_each = var.policies
    content {
      minimum_length = password_policy.value
    }
  }
  user_pool_tier = "PLUS"
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }
}
"""


def _tf(tmp_path: Path, text: str = SECRET_COGNITO_TF) -> list[Finding]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    resources = resources_from_terraform(tmp_path)
    return [f for f in run_resource_checks(resources, tmp_path) if f.id in IDS]


def test_terraform_secrets_and_cognito(tmp_path: Path) -> None:
    findings = _tf(tmp_path)
    assert _found(findings) == {
        ("aws_secretsmanager_secret.plain", "CF-SM-001"),
        ("aws_cognito_user_pool.defaults", "CF-COG-001"),
        ("aws_cognito_user_pool.defaults", "CF-COG-002"),
        ("aws_cognito_user_pool.defaults", "CF-COG-003"),
        ("aws_cognito_user_pool.weak", "CF-COG-002"),
    }
    assert all(f.line for f in findings)
    weak = _by(findings)[("aws_cognito_user_pool.weak", "CF-COG-002")]
    assert weak.recommendation.startswith("MinimumLength is 8. No character class is required.")


def test_terraform_unlinked_rotation_covers_every_secret(tmp_path: Path) -> None:
    findings = _tf(tmp_path, """\
resource "aws_secretsmanager_secret" "a" {
  name = "a"
}

resource "aws_secretsmanager_secret_rotation" "shared" {
  secret_id           = var.secret_arn
  rotation_lambda_arn = aws_lambda_function.rotate.arn
}
""")
    assert _found(findings) == set()


def test_terraform_fixes(tmp_path: Path) -> None:
    findings = attach_fixes(_tf(tmp_path), "terraform")
    code = {(f.evidence.split(" ")[0], f.id): f.suggested_code or "" for f in findings}
    assert "secret_id           = aws_secretsmanager_secret.plain.id" in code[
        ("aws_secretsmanager_secret.plain", "CF-SM-001")]
    assert 'mfa_configuration = "ON"' in code[("aws_cognito_user_pool.defaults", "CF-COG-001")]
    assert "minimum_length    = 12" in code[("aws_cognito_user_pool.weak", "CF-COG-002")]
    assert all("In CDK" not in f.recommendation for f in findings)


def test_rotation_with_an_unknown_arn_still_covers_every_secret(tmp_path: Path) -> None:
    """A literal ARN that matches no secret here may be any of them: nothing is reported."""
    findings = _cf(tmp_path, {
        "A": _secret(Name="app/a"),
        "Other": _rotation("arn:aws:secretsmanager:eu-north-1:111122223333:secret:app/other-AbC123"),
    })
    assert _found(findings) == set()
