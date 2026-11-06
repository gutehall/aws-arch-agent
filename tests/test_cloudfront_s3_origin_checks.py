"""CF-CF-004: CloudFront S3 origins without Origin Access Control."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import resources_from_terraform

BUCKET = {"Fn::GetAtt": ["Bucket", "RegionalDomainName"]}


def _dist(*origins: dict) -> dict:
    return {"Type": "AWS::CloudFront::Distribution", "Properties": {"DistributionConfig": {
        "Enabled": True, "WebACLId": "arn:w",
        "DefaultCacheBehavior": {"ViewerProtocolPolicy": "redirect-to-https"},
        "Origins": list(origins)}}}


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id == "CF-CF-004"]


def _by_name(findings: list[Finding]) -> dict[str, str]:
    return {f.evidence.split(" ")[0]: f.severity for f in findings}


def test_cloudformation_s3_origins(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "None": _dist({"Id": "s3", "DomainName": BUCKET, "S3OriginConfig": {}}),
        "EmptyOai": _dist({"Id": "s3", "DomainName": "b.s3.eu-north-1.amazonaws.com",
                           "S3OriginConfig": {"OriginAccessIdentity": ""}}),
        "Oai": _dist({"Id": "s3", "DomainName": BUCKET, "S3OriginConfig": {
            "OriginAccessIdentity": {"Fn::Sub": "origin-access-identity/cloudfront/${Oai}"}}}),
        "Oac": _dist({"Id": "s3", "DomainName": BUCKET, "S3OriginConfig": {"OriginAccessIdentity": ""},
                      "OriginAccessControlId": {"Fn::GetAtt": ["Oac", "Id"]}}),
        "DomainOnly": _dist({"Id": "legacy", "DomainName": "b.s3.amazonaws.com",
                             "CustomOriginConfig": {"OriginProtocolPolicy": "https-only"}}),
        "Website": _dist({"Id": "site", "DomainName": "b.s3-website.eu-north-1.amazonaws.com",
                          "CustomOriginConfig": {"OriginProtocolPolicy": "http-only"}}),
        "Api": _dist({"Id": "api", "DomainName": "api.example.com",
                      "CustomOriginConfig": {"OriginProtocolPolicy": "https-only"}}),
        "Intrinsic": _dist({"Fn::If": ["C", {}, {}]}),
    })
    assert _by_name(findings) == {
        "None": "Medium",
        "EmptyOai": "Medium",  # OriginAccessIdentity "" is no OAI
        "Oai": "Low",
        "DomainOnly": "Medium",
    }
    oai = next(f for f in findings if f.evidence.startswith("Oai"))
    assert oai.title.endswith("legacy Origin Access Identity")
    assert oai.recommendation.startswith("Legacy OAI on origins: s3;")


def test_cloudformation_mixed_origins_get_one_finding_at_the_worse_severity(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {"Mixed": _dist(
        {"Id": "a", "DomainName": BUCKET, "S3OriginConfig": {}},
        {"Id": "b", "DomainName": BUCKET, "S3OriginConfig": {"OriginAccessIdentity": "origin-access-identity/cloudfront/E1"}},
        {"Id": "c", "DomainName": BUCKET, "S3OriginConfig": {}},
    )})
    assert [f.severity for f in findings] == ["Medium"]
    assert findings[0].recommendation.startswith(
        "No OAC or OAI on origins: a, c; the bucket must then be public for CloudFront to read it. "
        "Legacy OAI on origins: b;")


def test_cloudformation_fix(tmp_path: Path) -> None:
    findings = attach_fixes(_cf(tmp_path, {"Web": _dist({"Id": "s3", "DomainName": BUCKET, "S3OriginConfig": {}})}),
                            "cloudformation")
    code = findings[0].suggested_code or ""
    assert code.startswith("Web:") and "OriginAccessControlId: !GetAtt WebOac.Id" in code


# --- Terraform ------------------------------------------------------------------

ORIGINS_TF = """\
resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "none" {
  enabled    = true
  web_acl_id = "arn:w"
  origin {
    origin_id   = "s3"
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
  }
}

resource "aws_cloudfront_distribution" "oai" {
  enabled    = true
  web_acl_id = "arn:w"
  origin {
    origin_id   = "s3"
    domain_name = aws_s3_bucket.b.bucket_regional_domain_name
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oai.cloudfront_access_identity_path
    }
  }
}

resource "aws_cloudfront_distribution" "oac" {
  enabled    = true
  web_acl_id = "arn:w"
  origin {
    origin_id                = "s3"
    domain_name              = aws_s3_bucket.b.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }
}

resource "aws_cloudfront_distribution" "oac_from_var" {
  enabled    = true
  web_acl_id = "arn:w"
  origin {
    origin_id                = "s3"
    domain_name              = "b.s3.amazonaws.com"
    origin_access_control_id = var.oac_id
  }
}

resource "aws_cloudfront_distribution" "website" {
  enabled    = true
  web_acl_id = "arn:w"
  origin {
    origin_id   = "site"
    domain_name = aws_s3_bucket_website_configuration.site.website_endpoint
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }
}
"""


def _tf(module: Path) -> list[Finding]:
    resources = resources_from_terraform(module)
    return [f for f in run_resource_checks(resources, module / "main.tf") if f.id == "CF-CF-004"]


def test_terraform_s3_origins(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ORIGINS_TF, encoding="utf-8")
    findings = _tf(tmp_path)
    assert _by_name(findings) == {
        "aws_cloudfront_distribution.none": "Medium",
        "aws_cloudfront_distribution.oai": "Low",
    }
    attach_fixes(findings, "terraform")
    none = next(f for f in findings if f.evidence.startswith("aws_cloudfront_distribution.none"))
    assert "origin_access_control_id = aws_cloudfront_origin_access_control.none.id" in (none.suggested_code or "")
    assert "In CDK" not in none.recommendation


def test_terraform_origin_access_control_is_mapped(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(ORIGINS_TF, encoding="utf-8")
    types = {r.name: r.type for r in resources_from_terraform(tmp_path)}
    assert types["aws_cloudfront_origin_access_control.oac"] == "cloudfront_origin_access_control"
