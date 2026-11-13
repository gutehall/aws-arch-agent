"""SEC 9: plain TCP load balancer listeners (CF-NLB-001) and Redshift clusters that do not
require SSL (CF-RS-008), on CloudFormation and Terraform."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.cf_template import CF_THEMES, CF_TITLES


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _cfn(resources: dict) -> str:
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _scan(root: Path, rel: str, text: str) -> list:
    _write(root / "prod" / rel, text)
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _found(findings: list, check_id: str) -> list:
    return [f for f in findings if f.id == check_id]


def _listener(protocol: str, port: object) -> dict:
    return {"Listener": {"Type": "AWS::ElasticLoadBalancingV2::Listener", "Properties": {
        "LoadBalancerArn": "arn", "Protocol": protocol, "Port": port,
        "DefaultActions": [{"Type": "forward", "TargetGroupArn": "arn"}]}}}


def _tf_listener(protocol: str, port: object) -> str:
    return (f'resource "aws_lb_listener" "nlb" {{\n  load_balancer_arn = "arn"\n'
            f'  protocol = "{protocol}"\n  port = {port}\n'
            '  default_action {\n    type = "forward"\n    target_group_arn = "arn"\n  }\n}\n')


# CF-NLB-001


@pytest.mark.parametrize("port", [80, 5432, "6379"])
def test_tcp_listener_fails_cf_nlb_001(tmp_path: Path, port: object) -> None:
    hits = _found(_scan(tmp_path, "stack.json", _cfn(_listener("TCP", port))), "CF-NLB-001")
    assert len(hits) == 1
    assert f"port {int(port)}" in hits[0].recommendation


@pytest.mark.parametrize(("protocol", "port"), [("TLS", 443), ("TCP", 443), ("TCP", 8443),
                                                ("UDP", 53), ("HTTPS", 443)])
def test_tls_or_passthrough_listener_passes(tmp_path: Path, protocol: str, port: int) -> None:
    findings = _scan(tmp_path, "stack.json", _cfn(_listener(protocol, port)))
    assert _found(findings, "CF-NLB-001") == []


def test_parameter_port_is_not_judged(tmp_path: Path) -> None:
    findings = _scan(tmp_path, "stack.json", _cfn(_listener("TCP", {"Ref": "Port"})))
    assert _found(findings, "CF-NLB-001") == []


def test_terraform_tcp_listener(tmp_path: Path) -> None:
    assert len(_found(_scan(tmp_path, "main.tf", _tf_listener("TCP", 80)), "CF-NLB-001")) == 1
    other = tmp_path / "tls"
    assert _found(_scan(other, "main.tf", _tf_listener("TLS", 443)), "CF-NLB-001") == []


# CF-RS-008


def _cluster(**props: object) -> dict:
    base = {"NodeType": "ra3.xlplus", "MasterUsername": "warehouse_admin", "DBName": "analytics",
            "ClusterType": "single-node", "Encrypted": True}
    base.update(props)
    return {"Warehouse": {"Type": "AWS::Redshift::Cluster", "Properties": base}}


def test_default_parameter_group_fails_cf_rs_008(tmp_path: Path) -> None:
    hits = _found(_scan(tmp_path, "stack.json", _cfn(_cluster())), "CF-RS-008")
    assert len(hits) == 1
    assert "require_ssl" in hits[0].recommendation


def test_named_parameter_group_passes(tmp_path: Path) -> None:
    findings = _scan(tmp_path, "stack.json",
                     _cfn(_cluster(ClusterParameterGroupName={"Ref": "RequireSsl"})))
    assert _found(findings, "CF-RS-008") == []


def test_terraform_redshift_cluster(tmp_path: Path) -> None:
    body = ('resource "aws_redshift_cluster" "w" {\n  cluster_identifier = "w"\n'
            '  node_type = "ra3.xlplus"\n  master_username = "warehouse_admin"\n'
            '  database_name = "analytics"\n  encrypted = true\n}\n')
    assert len(_found(_scan(tmp_path, "main.tf", body), "CF-RS-008")) == 1
    other = tmp_path / "ssl"
    body = body.replace("  encrypted = true\n", "  encrypted = true\n"
                        "  cluster_parameter_group_name = aws_redshift_parameter_group.ssl.name\n")
    assert _found(_scan(other, "main.tf", body), "CF-RS-008") == []


# Tables and the answer


def test_checks_are_titled_themed_and_mapped() -> None:
    for check in ("CF-NLB-001", "CF-RS-008"):
        assert CF_TITLES[check] and CF_THEMES[check]
        assert well_architected.best_practices_of(check) == ("SEC09-BP02",)
        assert well_architected.question_of(check) == "SEC 9"


def test_sec9_is_fully_checked() -> None:
    (sec9,) = [a for a in well_architected.answers([]) if a.question.id == "SEC 9"]
    assert sec9.not_checked == ()
