"""Load balancers in templates: ELBv2 attributes, listeners and target groups (CF-ALB-*),
and Classic Load Balancers (CF-CLB-*)."""
from __future__ import annotations

import json
from pathlib import Path

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.terraform_model import resources_from_terraform

IDS = tuple(f"CF-ALB-00{n}" for n in range(1, 8)) + tuple(f"CF-CLB-00{n}" for n in range(1, 6))


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
    found = run_resource_checks(resources_from_terraform(tmp_path, warnings), tmp_path / "main.tf", warnings)
    assert warnings == []
    return _by_id(found)


def _lb(kind: str = "application", **attrs: str) -> dict:
    # All four settings good unless overridden.
    base = {
        "access_logs.s3.enabled": "true",
        "routing.http.drop_invalid_header_fields.enabled": "true",
        "deletion_protection.enabled": "true",
    }
    pairs = [{"Key": k, "Value": v} for k, v in {**base, **attrs}.items()]
    return {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "Properties": {"Type": kind, "LoadBalancerAttributes": pairs}}


def _listener(protocol: str, actions: list | None = None, **props: object) -> dict:
    body = {"LoadBalancerArn": {"Ref": "Lb"}, "Protocol": protocol, "Port": 443,
            "DefaultActions": actions or [{"Type": "forward", "TargetGroupArn": {"Ref": "Tg"}}], **props}
    return {"Type": "AWS::ElasticLoadBalancingV2::Listener", "Properties": body}


_REDIRECT = [{"Type": "redirect", "RedirectConfig": {"Protocol": "HTTPS", "Port": "443",
                                                       "StatusCode": "HTTP_301"}}]


def test_load_balancer_attributes(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Good": _lb(),
        "Bare": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {}},
        "Monitor": _lb(**{"routing.http.desync_mitigation_mode": "monitor"}),
        "Nlb": _lb("network", **{"routing.http.drop_invalid_header_fields.enabled": "false"}),
        "Param": _lb(**{"deletion_protection.enabled": {"Ref": "Protect"}}),  # type: ignore[arg-type]
    })
    assert found == {
        "CF-ALB-001": {"Bare"},
        "CF-ALB-004": {"Bare"},  # header and desync attributes apply to ALBs only
        "CF-ALB-005": {"Bare"},
        "CF-ALB-006": {"Monitor"},
    }


def test_listeners(tmp_path: Path) -> None:
    found = _cf(tmp_path, {
        "Http": _listener("HTTP"),
        "HttpRedirect": _listener("HTTP", _REDIRECT),
        "HttpsDefault": _listener("HTTPS"),  # no SslPolicy: ELBSecurityPolicy-2016-08
        "HttpsOld": _listener("HTTPS", SslPolicy="ELBSecurityPolicy-TLS13-1-1-2021-06"),
        "HttpsGood": _listener("HTTPS", SslPolicy="ELBSecurityPolicy-TLS13-1-2-2021-06"),
        "Tls": _listener("TLS", SslPolicy="ELBSecurityPolicy-FS-1-1-2019-08"),
        "TlsParam": _listener("TLS", SslPolicy={"Ref": "Policy"}),
        "Tcp": _listener("TCP"),
    })
    assert found == {"CF-ALB-002": {"Http"}, "CF-ALB-003": {"HttpsDefault", "HttpsOld", "Tls"}}


def test_target_group_health_checks(tmp_path: Path) -> None:
    def tg(**props: object) -> dict:
        return {"Type": "AWS::ElasticLoadBalancingV2::TargetGroup", "Properties": props}

    found = _cf(tmp_path, {
        "NoPath": tg(Protocol="HTTP", Port=80),
        "Path": tg(Protocol="HTTP", Port=80, HealthCheckPath="/health"),
        "Off": tg(Protocol="TCP", Port=80, HealthCheckEnabled=False),
        "Tcp": tg(Protocol="TCP", Port=80),
        "Lambda": tg(TargetType="lambda"),
    })
    assert found == {"CF-ALB-007": {"NoPath", "Off"}}


def _clb(**props: object) -> dict:
    return {"Type": "AWS::ElasticLoadBalancing::LoadBalancer", "Properties": props}


def test_classic_load_balancer(tmp_path: Path) -> None:
    good = dict(
        Listeners=[{"LoadBalancerPort": "443", "InstancePort": "80", "Protocol": "HTTPS",
                    "SSLCertificateId": "arn:aws:acm:eu-west-1:111122223333:certificate/abc"}],
        AccessLoggingPolicy={"Enabled": True, "S3BucketName": "logs"},
        CrossZone=True,
        ConnectionDrainingPolicy={"Enabled": True, "Timeout": 300},
    )
    found = _cf(tmp_path, {
        "Good": _clb(**good),
        "Bare": _clb(Listeners=[{"LoadBalancerPort": "80", "InstancePort": "80", "Protocol": "HTTP"}]),
        "IamCert": _clb(**{**good, "Listeners": [{
            "LoadBalancerPort": "443", "InstancePort": "80", "Protocol": "SSL",
            "SSLCertificateId": "arn:aws:iam::111122223333:server-certificate/web"}]}),
        "Param": _clb(**{**good, "CrossZone": {"Ref": "CrossZone"}}),
    })
    assert found == {
        "CF-CLB-001": {"Bare"},
        "CF-CLB-002": {"IamCert"},
        "CF-CLB-003": {"Bare"},
        "CF-CLB-004": {"Bare"},
        "CF-CLB-005": {"Bare"},
    }


LB_TF = """\
resource "aws_lb" "app" {
  load_balancer_type = "application"
}
resource "aws_lb" "hardened" {
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  access_logs {
    bucket  = "logs"
    enabled = true
  }
}
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}
resource "aws_lb_listener" "redirect" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = "arn:aws:acm:eu-west-1:111122223333:certificate/abc"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}
resource "aws_lb_target_group" "web" {
  port     = 80
  protocol = "HTTP"
}
resource "aws_lb_target_group" "checked" {
  port     = 80
  protocol = "HTTP"
  health_check {
    path = "/health"
  }
}
resource "aws_elb" "legacy" {
  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }
}
"""


def test_terraform_load_balancers(tmp_path: Path) -> None:
    assert _tf(tmp_path, LB_TF) == {
        "CF-ALB-001": {"aws_lb.app"},
        "CF-ALB-002": {"aws_lb_listener.http"},
        "CF-ALB-003": {"aws_lb_listener.https"},  # no ssl_policy: ELBSecurityPolicy-2016-08
        "CF-ALB-004": {"aws_lb.app"},
        "CF-ALB-005": {"aws_lb.app"},
        "CF-ALB-007": {"aws_lb_target_group.web"},
        "CF-CLB-001": {"aws_elb.legacy"},
        "CF-CLB-003": {"aws_elb.legacy"},
        "CF-CLB-005": {"aws_elb.legacy"},  # cross-zone is on by default in Terraform
    }


def test_terraform_unknown_values_are_not_judged(tmp_path: Path) -> None:
    found = _tf(tmp_path, """\
variable "protect" { type = bool }
variable "policy" { type = string }
resource "aws_lb" "app" {
  drop_invalid_header_fields = true
  enable_deletion_protection = var.protect
  access_logs {
    bucket  = "logs"
    enabled = true
  }
}
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  protocol          = "HTTPS"
  ssl_policy        = var.policy
  default_action {
    type             = "forward"
    target_group_arn = "arn"
  }
}
""")
    assert found == {}
