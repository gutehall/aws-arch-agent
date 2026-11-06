"""CF-CF-001..003 (CloudFront) and CF-WAF-001 (ALB / API stage without WAF in the template)."""
import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import (
    drop_static_covered_by_cf,
    run_cf_rules_from_paths,
    run_resource_checks,
)
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = {"CF-CF-001", "CF-CF-002", "CF-CF-003", "CF-WAF-001"}


def _found(findings: list[Finding]) -> set[tuple[str, str]]:
    return {(f.evidence.split(" ")[0], f.id) for f in findings if f.id in IDS}


def _cf(tmp_path: Path, resources: dict) -> list[Finding]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return [f for f in run_cf_rules_from_paths([path], repo_path=tmp_path) if f.id in IDS]


def _dist(**config) -> dict:
    return {"Type": "AWS::CloudFront::Distribution", "Properties": {"DistributionConfig": {
        "Enabled": True, **config}}}


ACM = {"AcmCertificateArn": "arn:aws:acm:us-east-1:111122223333:certificate/c", "SslSupportMethod": "sni-only"}
HTTPS = {"ViewerProtocolPolicy": "redirect-to-https"}


# --- CloudFront: CloudFormation ---------------------------------------------------


def test_cloudformation_cloudfront(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Open": _dist(DefaultCacheBehavior={"ViewerProtocolPolicy": "allow-all"},
                      CacheBehaviors=[{"PathPattern": "/api/*", "ViewerProtocolPolicy": "allow-all"},
                                      {"PathPattern": "/static/*", **HTTPS}],
                      WebACLId="arn:aws:wafv2:us-east-1:1:global/webacl/w/1"),
        "OldTls": _dist(DefaultCacheBehavior=HTTPS, WebACLId="arn:w",
                        ViewerCertificate={**ACM, "MinimumProtocolVersion": "TLSv1.2_2019"}),
        "TlsUnset": _dist(DefaultCacheBehavior=HTTPS, WebACLId="arn:w", ViewerCertificate=ACM),
        "DefaultCert": _dist(DefaultCacheBehavior=HTTPS, WebACLId="arn:w",
                             ViewerCertificate={"CloudFrontDefaultCertificate": True}),
        "NoAcl": _dist(DefaultCacheBehavior=HTTPS,
                       ViewerCertificate={**ACM, "MinimumProtocolVersion": "TLSv1.2_2021"}),
        "Good": _dist(DefaultCacheBehavior={"ViewerProtocolPolicy": "https-only"},
                      WebACLId={"Fn::GetAtt": ["Acl", "Arn"]},
                      ViewerCertificate={**ACM, "MinimumProtocolVersion": "TLSv1.2_2025"}),
        "Param": _dist(DefaultCacheBehavior={"ViewerProtocolPolicy": {"Ref": "Policy"}},
                       WebACLId={"Ref": "Acl"},
                       ViewerCertificate={**ACM, "MinimumProtocolVersion": {"Ref": "Tls"}}),
        "Intrinsic": {"Type": "AWS::CloudFront::Distribution",
                      "Properties": {"DistributionConfig": {"Fn::If": ["C", {}, {}]}}},
    })
    assert _found(findings) == {
        ("Open", "CF-CF-001"),
        ("OldTls", "CF-CF-002"),
        ("TlsUnset", "CF-CF-002"),  # unset with your own certificate means TLSv1
        ("NoAcl", "CF-CF-003"),
    }
    severity = {f.id: f.severity for f in findings}
    assert severity == {"CF-CF-001": "Medium", "CF-CF-002": "Medium", "CF-CF-003": "Low"}
    open_ = next(f for f in findings if f.id == "CF-CF-001")
    assert open_.recommendation.startswith("Behaviors with ViewerProtocolPolicy allow-all: default, /api/*.")
    unset = next(f for f in findings if f.evidence.startswith("TlsUnset"))
    assert "MinimumProtocolVersion is TLSv1." in unset.recommendation


# --- WAF: CloudFormation ---------------------------------------------------------


def _alb(**props) -> dict:
    return {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": props}


def _stage() -> dict:
    return {"Type": "AWS::ApiGateway::Stage", "Properties": {
        "RestApiId": {"Ref": "Api"}, "StageName": "prod",
        "AccessLogSetting": {"DestinationArn": "arn:log"}, "TracingEnabled": True}}


def _assoc(arn) -> dict:
    return {"Type": "AWS::WAFv2::WebACLAssociation",
            "Properties": {"ResourceArn": arn, "WebACLArn": {"Fn::GetAtt": ["Acl", "Arn"]}}}


def test_cloudformation_waf_associations(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {
        "Alb": _alb(),
        "AlbProtected": _alb(),
        "AlbInternal": _alb(Scheme="internal"),
        "Nlb": _alb(Type="network"),
        "Stage": _stage(),
        "StageProtected": _stage(),
        "AlbAcl": _assoc({"Ref": "AlbProtected"}),
        "StageAcl": _assoc({"Fn::Sub": "arn:${AWS::Partition}:apigateway:${AWS::Region}::/restapis/${Api}/stages/${StageProtected}"}),
    })
    assert _found(findings) == {("Alb", "CF-WAF-001"), ("Stage", "CF-WAF-001")}
    alb = next(f for f in findings if f.evidence.startswith("Alb "))
    assert alb.severity == "Low" and alb.title.endswith("in this template")


def test_cloudformation_waf_association_that_cannot_be_linked_covers_all(tmp_path: Path) -> None:
    findings = _cf(tmp_path, {"Alb": _alb(), "Acl": _assoc({"Ref": "LoadBalancerArnParam"})})
    assert _found(findings) == set()


def test_cloudformation_fixes(tmp_path: Path) -> None:
    findings = attach_fixes(_cf(tmp_path, {
        "Open": _dist(DefaultCacheBehavior={"ViewerProtocolPolicy": "allow-all"}, WebACLId="arn:w"),
        "Alb": _alb(),
    }), "cloudformation")
    code = {f.id: f.suggested_code or "" for f in findings}
    assert "redirect-to-https" in code["CF-CF-001"]
    assert "${AWS::Partition}:apigateway:${AWS::Region}" in code["CF-WAF-001"]
    assert code["CF-WAF-001"].startswith("AlbWebAcl:") and "ResourceArn: !Ref Alb" in code["CF-WAF-001"]


def test_static_rules_are_dropped_when_cf_reports_them() -> None:
    static = [Finding(id=i, title="t", recommendation="r") for i in ("SEC-018", "SEC-019", "SEC-024")]
    cf = [Finding(id=i, title="t", recommendation="r") for i in ("CF-CF-001", "CF-CF-002", "CF-WAF-001")]
    assert [f.id for f in drop_static_covered_by_cf(static + cf)] == [f.id for f in cf]


# --- Terraform ------------------------------------------------------------------

CLOUDFRONT_TF = """\
resource "aws_cloudfront_distribution" "open" {
  enabled    = true
  web_acl_id = aws_wafv2_web_acl.edge.arn
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
  ordered_cache_behavior {
    path_pattern           = "/api/*"
    viewer_protocol_policy = "https-only"
  }
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "aws_cloudfront_distribution" "old_tls" {
  enabled = true
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
  }
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.c.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1"
  }
}

resource "aws_cloudfront_distribution" "good" {
  enabled    = true
  web_acl_id = aws_wafv2_web_acl.edge.arn
  default_cache_behavior {
    viewer_protocol_policy = "https-only"
  }
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.c.arn
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

resource "aws_cloudfront_distribution" "unknown_policy" {
  enabled = true
  default_cache_behavior {
    viewer_protocol_policy = var.policy
  }
  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.c.arn
    minimum_protocol_version = "TLSv1.1_2016"
  }
}

resource "aws_lb" "public" {
  name = "public"
}

resource "aws_lb" "protected" {
  name = "protected"
}

resource "aws_lb" "internal" {
  name     = "internal"
  internal = true
}

resource "aws_lb" "counted" {
  count = 2
  name  = "counted-${count.index}"
}

resource "aws_wafv2_web_acl_association" "counted" {
  resource_arn = aws_lb.counted[0].arn
  web_acl_arn  = aws_wafv2_web_acl.regional.arn
}

resource "aws_lb" "internal_from_var" {
  name     = "iv"
  internal = var.internal
}

resource "aws_lb" "type_from_var" {
  name               = "tv"
  load_balancer_type = var.lb_type
}

resource "aws_lb" "network" {
  name               = "nlb"
  load_balancer_type = "network"
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.d.id
  stage_name    = "prod"
}

resource "aws_wafv2_web_acl_association" "protected" {
  resource_arn = aws_lb.protected.arn
  web_acl_arn  = aws_wafv2_web_acl.regional.arn
}
"""


def _tf(module: Path) -> list[Finding]:
    resources = resources_from_terraform(module)
    return [f for f in run_resource_checks(resources, module / "main.tf") if f.id in IDS]


def test_terraform_cloudfront_and_waf(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(CLOUDFRONT_TF, encoding="utf-8")
    assert _found(_tf(tmp_path)) == {
        ("aws_cloudfront_distribution.open", "CF-CF-001"),
        ("aws_cloudfront_distribution.old_tls", "CF-CF-002"),
        ("aws_cloudfront_distribution.old_tls", "CF-CF-003"),
        # An unknown viewer policy does not hide the TLS and WAF checks.
        ("aws_cloudfront_distribution.unknown_policy", "CF-CF-002"),
        ("aws_cloudfront_distribution.unknown_policy", "CF-CF-003"),
        ("aws_lb.public", "CF-WAF-001"),
        ("aws_api_gateway_stage.prod", "CF-WAF-001"),
        # aws_lb.counted is linked through its [0] index; an internal or type from a
        # variable may be an internal ALB or an NLB, so it is not reported.
    }


def test_terraform_fixes(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text(CLOUDFRONT_TF, encoding="utf-8")
    findings = attach_fixes(_tf(tmp_path), "terraform")
    code = {(f.evidence.split(" ")[0], f.id): f.suggested_code or "" for f in findings}
    assert "resource_arn = aws_lb.public.arn" in code[("aws_lb.public", "CF-WAF-001")]
    assert 'minimum_protocol_version = "TLSv1.2_2021"' in code[
        ("aws_cloudfront_distribution.old_tls", "CF-CF-002")]
    assert all("In CDK" not in f.recommendation for f in findings)
