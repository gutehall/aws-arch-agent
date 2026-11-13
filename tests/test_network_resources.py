"""PERF 4: selecting and configuring networking. Edge latency watched (REPO-064), network
configuration tuned on metrics (REPO-065), redundant dedicated connectivity or VPN
(REPO-066), load balancing (REPO-067), and current network protocols (REPO-068)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import ORG_RULE_IDS
from aws_arch_agent.rules import well_architected
from aws_arch_agent.rules.repo_practices import (
    EdgeLatencyUnwatched,
    LoadBalancingMissing,
    NetworkMetricsUnused,
    OldNetworkProtocol,
    SingleHybridLink,
)

SOURCES = ("cdk", "cloudformation", "terraform")
_PATHS = {"cdk": "lib/stack.ts", "cloudformation": "stack.template.json",
          "terraform": "main.tf"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _stack(root: Path, source: str, *parts: object, env: str = "prod") -> None:
    if source == "cloudformation":
        merged: dict = {}
        for part in parts:
            merged.update(part)  # type: ignore[call-overload]
        body = json.dumps({"Resources": merged}, indent=2)
    else:
        body = "".join(str(p) for p in parts)
    _write(root / env / _PATHS[source], body)


# REPO-064 and REPO-065: an edge with a latency alarm, a fixed threshold, or flow logs.

EDGE = {
    "cdk": "const api = new apigateway.RestApi(this, 'Api');\n",
    "cloudformation": {"Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}}},
    "terraform": 'resource "aws_api_gateway_rest_api" "api" {\n  name = "api"\n}\n',
}
LATENCY_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Slow', { metric: api.metricLatency(), "
           "threshold: 500, evaluationPeriods: 3 });\n",
    "cloudformation": {"Slow": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "AWS/ApiGateway", "MetricName": "Latency", "Threshold": 500}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "slow" {\n'
                 '  namespace   = "AWS/ApiGateway"\n  metric_name = "Latency"\n'
                 '  threshold   = 500\n}\n',
}
PARAM_LATENCY_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Slow', { metric: api.metricLatency(), "
           "threshold: props.latencyMs, evaluationPeriods: 3 });\n",
    "cloudformation": {"Slow": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "AWS/ApiGateway", "MetricName": "Latency",
        "Threshold": {"Ref": "LatencyMs"}}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "slow" {\n'
                 '  namespace   = "AWS/ApiGateway"\n  metric_name = "Latency"\n'
                 '  threshold   = var.latency_ms\n}\n',
}
ERROR_ALARM = {
    "cdk": "new cloudwatch.Alarm(this, 'Errors', { metric: api.metricServerError(), "
           "threshold: 1, evaluationPeriods: 1 });\n",
    "cloudformation": {"Errors": {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "Namespace": "AWS/ApiGateway", "MetricName": "5XXError", "Threshold": 1}}},
    "terraform": 'resource "aws_cloudwatch_metric_alarm" "errors" {\n'
                 '  namespace   = "AWS/ApiGateway"\n  metric_name = "5XXError"\n'
                 '  threshold   = 1\n}\n',
}
FLOW_LOG = {
    "cdk": "const vpc = new ec2.Vpc(this, 'Vpc');\nvpc.addFlowLog('Flow');\n",
    "cloudformation": {"Flow": {"Type": "AWS::EC2::FlowLog", "Properties": {
        "ResourceType": "VPC", "TrafficType": "ALL"}}},
    "terraform": 'resource "aws_flow_log" "vpc" {\n  traffic_type = "ALL"\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_edge_without_latency_alarm_fails_repo_064(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, EDGE[source])
    (finding,) = EdgeLatencyUnwatched().run(tmp_path)
    assert finding.id == "REPO-064"
    assert "API Gateway in prod/" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_latency_alarm_passes_repo_064(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, EDGE[source], PARAM_LATENCY_ALARM[source])
    assert EdgeLatencyUnwatched().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_error_alarm_does_not_pass_repo_064(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, EDGE[source], ERROR_ALARM[source])
    assert len(EdgeLatencyUnwatched().run(tmp_path)) == 1


def test_python_cdk_edge_repo_064(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "lb = elbv2.ApplicationLoadBalancer(self, 'Lb', vpc=vpc, internet_facing=True)\n")
    assert EdgeLatencyUnwatched().run(tmp_path)
    _write(tmp_path / "prod" / "alarms.py",
           "cloudwatch.Alarm(self, 'Slow', metric=lb.metrics.target_response_time(), "
           "threshold=1, evaluation_periods=3)\n")
    assert EdgeLatencyUnwatched().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_edge_without_tuning_signal_fails_repo_065(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, EDGE[source], PARAM_LATENCY_ALARM[source])
    (finding,) = NetworkMetricsUnused().run(tmp_path)
    assert finding.id == "REPO-065"
    assert "has no numeric threshold" in finding.evidence
    assert "no VPC Flow Logs" in finding.evidence


@pytest.mark.parametrize("control", (LATENCY_ALARM, FLOW_LOG), ids=("threshold", "flow-log"))
@pytest.mark.parametrize("source", SOURCES)
def test_threshold_or_flow_logs_pass_repo_065(tmp_path: Path, source: str,
                                              control: dict) -> None:
    _stack(tmp_path, source, EDGE[source], control[source])
    assert NetworkMetricsUnused().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_error_threshold_does_not_pass_repo_065(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, EDGE[source], ERROR_ALARM[source])
    (finding,) = NetworkMetricsUnused().run(tmp_path)
    assert "no alarm on an edge latency metric" in finding.evidence


def test_python_cdk_flow_logs_pass_repo_065(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "distribution = cloudfront.Distribution(self, 'Cdn', default_behavior=b)\n")
    assert NetworkMetricsUnused().run(tmp_path)
    _write(tmp_path / "prod" / "network.py",
           "vpc = ec2.Vpc(self, 'Vpc', flow_logs={'all': ec2.FlowLogOptions()})\n")
    assert NetworkMetricsUnused().run(tmp_path) == []


# REPO-066: one Direct Connect or VPN link with no second path.

VPN = {
    "cdk": "new ec2.VpnConnection(this, 'Vpn', { vpc, ip: '203.0.113.10' });\n",
    "cloudformation": {
        "Cgw": {"Type": "AWS::EC2::CustomerGateway", "Properties": {"IpAddress": "1.2.3.4"}},
        "Vpn": {"Type": "AWS::EC2::VPNConnection", "Properties": {"Type": "ipsec.1"}},
    },
    "terraform": 'resource "aws_customer_gateway" "office" {\n  ip_address = "1.2.3.4"\n}\n'
                 'resource "aws_vpn_connection" "office" {\n  type = "ipsec.1"\n}\n',
}
SECOND_VPN = {
    "cdk": "new ec2.VpnConnection(this, 'Vpn2', { vpc, ip: '203.0.113.11' });\n",
    "cloudformation": {
        "Cgw2": {"Type": "AWS::EC2::CustomerGateway", "Properties": {"IpAddress": "1.2.3.5"}},
        "Vpn2": {"Type": "AWS::EC2::VPNConnection", "Properties": {"Type": "ipsec.1"}},
    },
    "terraform": 'resource "aws_customer_gateway" "backup" {\n  ip_address = "1.2.3.5"\n}\n'
                 'resource "aws_vpn_connection" "backup" {\n  type = "ipsec.1"\n}\n',
}
DX = ('resource "aws_dx_connection" "main" {\n  bandwidth = "1Gbps"\n}\n'
      'resource "aws_dx_private_virtual_interface" "main" {\n  vlan = 4094\n}\n')


@pytest.mark.parametrize("source", SOURCES)
def test_single_vpn_fails_repo_066(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, VPN[source])
    (finding,) = SingleHybridLink().run(tmp_path)
    assert finding.id == "REPO-066"
    assert "one VPN connection in prod/" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_second_vpn_passes_repo_066(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, VPN[source], SECOND_VPN[source])
    assert SingleHybridLink().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_no_hybrid_link_passes_repo_066(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, EDGE[source])
    assert SingleHybridLink().run(tmp_path) == []


def test_single_direct_connect_fails_and_vpn_backup_passes_repo_066(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", DX)
    (finding,) = SingleHybridLink().run(tmp_path)
    assert "one Direct Connect connection" in finding.evidence
    _stack(tmp_path, "terraform", DX, VPN["terraform"])
    assert SingleHybridLink().run(tmp_path) == []
    _stack(tmp_path, "terraform", DX, 'resource "aws_dx_lag" "main" {\n  n = 2\n}\n')
    assert SingleHybridLink().run(tmp_path) == []
    _stack(tmp_path, "terraform", 'resource "aws_dx_connection" "main" {\n  count = 2\n}\n')
    assert SingleHybridLink().run(tmp_path) == []


def test_python_cdk_vpn_options_repo_066(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "ec2.Vpc(self, 'Vpc', vpn_connections={'office': ec2.VpnConnectionOptions("
           "ip='203.0.113.10')})\n")
    assert SingleHybridLink().run(tmp_path)
    _write(tmp_path / "prod" / "stack.py",
           "ec2.Vpc(self, 'Vpc', vpn_connections={'office': ec2.VpnConnectionOptions("
           "ip='203.0.113.10'), 'backup': ec2.VpnConnectionOptions(ip='203.0.113.11')})\n")
    assert SingleHybridLink().run(tmp_path) == []


# REPO-067: internet-facing instances with no load balancer, single-target target groups.

PUBLIC_INSTANCE = {
    "cdk": "new ec2.Instance(this, 'Web', { vpc, instanceType, machineImage, "
           "vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC } });\n",
    "cloudformation": {"Web": {"Type": "AWS::EC2::Instance", "Properties": {
        "NetworkInterfaces": [{"DeviceIndex": "0", "AssociatePublicIpAddress": True}]}}},
    "terraform": 'resource "aws_instance" "web" {\n  ami = "ami-1"\n'
                 '  associate_public_ip_address = true\n}\n',
}
PRIVATE_INSTANCE = {
    "cdk": "new ec2.Instance(this, 'Web', { vpc, instanceType, machineImage });\n",
    "cloudformation": {"Web": {"Type": "AWS::EC2::Instance", "Properties": {}}},
    "terraform": 'resource "aws_instance" "web" {\n  ami = "ami-1"\n}\n',
}
LOAD_BALANCER = {
    "cdk": "new elbv2.ApplicationLoadBalancer(this, 'Lb', { vpc, internetFacing: true });\n",
    "cloudformation": {"Lb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                              "Properties": {}}},
    "terraform": 'resource "aws_lb" "web" {\n  internal = false\n}\n',
}
SINGLE_TARGET = {
    "cdk": "listener.addTargets('Web', { port: 80, targets: [new targets.InstanceTarget(web)] });\n",
    "cloudformation": {"Tg": {"Type": "AWS::ElasticLoadBalancingV2::TargetGroup", "Properties": {
        "Port": 80, "Targets": [{"Id": {"Ref": "Web"}}]}}},
    "terraform": 'resource "aws_lb_target_group" "web" {\n  port = 80\n}\n'
                 'resource "aws_lb_target_group_attachment" "web" {\n'
                 '  target_group_arn = aws_lb_target_group.web.arn\n'
                 '  target_id        = aws_instance.web.id\n}\n',
}
FLEET_TARGET = {
    "cdk": "listener.addTargets('Web', { port: 80, targets: [asg] });\n",
    "cloudformation": {
        "Tg": {"Type": "AWS::ElasticLoadBalancingV2::TargetGroup", "Properties": {"Port": 80}},
        "Asg": {"Type": "AWS::AutoScaling::AutoScalingGroup", "Properties": {
            "TargetGroupARNs": [{"Ref": "Tg"}], "MinSize": "2", "MaxSize": "4"}},
    },
    "terraform": 'resource "aws_lb_target_group" "web" {\n  port = 80\n}\n'
                 'resource "aws_autoscaling_group" "web" {\n'
                 '  target_group_arns = [aws_lb_target_group.web.arn]\n}\n',
}


@pytest.mark.parametrize("source", SOURCES)
def test_public_instance_without_load_balancer_fails_repo_067(tmp_path: Path,
                                                              source: str) -> None:
    _stack(tmp_path, source, PUBLIC_INSTANCE[source])
    (finding,) = LoadBalancingMissing().run(tmp_path)
    assert finding.id == "REPO-067"
    assert "internet-facing EC2 instance" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_load_balancer_or_private_instance_passes_repo_067(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, PUBLIC_INSTANCE[source], LOAD_BALANCER[source])
    assert LoadBalancingMissing().run(tmp_path) == []
    _stack(tmp_path, source, PRIVATE_INSTANCE[source])
    assert LoadBalancingMissing().run(tmp_path) == []


@pytest.mark.parametrize("source", SOURCES)
def test_single_target_fails_repo_067(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LOAD_BALANCER[source], SINGLE_TARGET[source])
    (finding,) = LoadBalancingMissing().run(tmp_path)
    assert "with one target" in finding.evidence


@pytest.mark.parametrize("source", SOURCES)
def test_fleet_target_passes_repo_067(tmp_path: Path, source: str) -> None:
    _stack(tmp_path, source, LOAD_BALANCER[source], FLEET_TARGET[source])
    assert LoadBalancingMissing().run(tmp_path) == []


def test_elastic_ip_and_python_cdk_repo_067(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", PRIVATE_INSTANCE["terraform"],
           'resource "aws_eip" "web" {\n  instance = aws_instance.web.id\n}\n')
    assert LoadBalancingMissing().run(tmp_path)
    other = tmp_path / "other"
    _write(other / "prod" / "stack.py",
           "ec2.Instance(self, 'Web', vpc=vpc, instance_type=t, machine_image=ami, "
           "associate_public_ip_address=True)\n")
    assert LoadBalancingMissing().run(other)
    _write(other / "prod" / "stack.py",
           "listener.add_targets('Web', port=80, targets=[targets.InstanceTarget(a), "
           "targets.InstanceTarget(b)])\n")
    assert LoadBalancingMissing().run(other) == []


# REPO-068: older protocols at the edge.

OLD_PROTOCOL = {
    "cdk": "new cloudfront.Distribution(this, 'Cdn', { defaultBehavior, "
           "httpVersion: cloudfront.HttpVersion.HTTP1_1 });\n",
    "cloudformation": {"Cdn": {"Type": "AWS::CloudFront::Distribution", "Properties": {
        "DistributionConfig": {"HttpVersion": "http1.1", "Enabled": True}}}},
    "terraform": 'resource "aws_cloudfront_distribution" "cdn" {\n'
                 '  http_version = "http1.1"\n}\n',
}
NEW_PROTOCOL = {
    "cdk": "new cloudfront.Distribution(this, 'Cdn', { defaultBehavior, "
           "httpVersion: cloudfront.HttpVersion.HTTP2_AND_3, "
           "minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021 });\n",
    "cloudformation": {"Cdn": {"Type": "AWS::CloudFront::Distribution", "Properties": {
        "DistributionConfig": {"HttpVersion": "http2and3", "ViewerCertificate": {
            "MinimumProtocolVersion": "TLSv1.2_2021"}}}}},
    "terraform": 'resource "aws_cloudfront_distribution" "cdn" {\n'
                 '  http_version = "http2and3"\n  viewer_certificate {\n'
                 '    minimum_protocol_version = "TLSv1.2_2021"\n  }\n}\n',
}
OLD_TLS = {
    "cdk": "lb.addListener('Https', { port: 443, certificates, "
           "sslPolicy: elbv2.SslPolicy.TLS11 });\n",
    "cloudformation": {"Https": {"Type": "AWS::ElasticLoadBalancingV2::Listener", "Properties": {
        "Protocol": "HTTPS", "SslPolicy": "ELBSecurityPolicy-TLS-1-1-2017-01"}}},
    "terraform": 'resource "aws_lb_listener" "https" {\n  protocol   = "HTTPS"\n'
                 '  ssl_policy = "ELBSecurityPolicy-2016-08"\n}\n',
}
HTTP_FORWARD = {
    "cdk": "const lb = new elbv2.ApplicationLoadBalancer(this, 'Lb', { vpc, "
           "internetFacing: true });\nconst http = lb.addListener('Http', { port: 80 });\n"
           "http.addTargets('Web', { port: 8080, targets: [asg] });\n",
    "cloudformation": {
        "Lb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {}},
        "Http": {"Type": "AWS::ElasticLoadBalancingV2::Listener", "Properties": {
            "LoadBalancerArn": {"Ref": "Lb"}, "Protocol": "HTTP", "Port": 80,
            "DefaultActions": [{"Type": "forward", "TargetGroupArn": {"Ref": "Tg"}}]}},
    },
    "terraform": 'resource "aws_lb" "web" {\n  internal = false\n}\n'
                 'resource "aws_lb_listener" "http" {\n'
                 '  load_balancer_arn = aws_lb.web.arn\n  protocol = "HTTP"\n  port = 80\n'
                 '  default_action {\n    type = "forward"\n'
                 '    target_group_arn = aws_lb_target_group.web.arn\n  }\n}\n',
}
HTTP_REDIRECT = {
    "cdk": "const lb = new elbv2.ApplicationLoadBalancer(this, 'Lb', { vpc, "
           "internetFacing: true });\nlb.addListener('Http', { port: 80, defaultAction: "
           "elbv2.ListenerAction.redirect({ protocol: 'HTTPS', port: '443' }) });\n",
    "cloudformation": {
        "Lb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {}},
        "Http": {"Type": "AWS::ElasticLoadBalancingV2::Listener", "Properties": {
            "LoadBalancerArn": {"Ref": "Lb"}, "Protocol": "HTTP", "Port": 80,
            "DefaultActions": [{"Type": "redirect", "RedirectConfig": {
                "Protocol": "HTTPS", "Port": "443", "StatusCode": "HTTP_301"}}]}},
    },
    "terraform": 'resource "aws_lb" "web" {\n  internal = false\n}\n'
                 'resource "aws_lb_listener" "http" {\n'
                 '  load_balancer_arn = aws_lb.web.arn\n  protocol = "HTTP"\n  port = 80\n'
                 '  default_action {\n    type = "redirect"\n    redirect {\n'
                 '      protocol    = "HTTPS"\n      port        = "443"\n'
                 '      status_code = "HTTP_301"\n    }\n  }\n}\n',
}


@pytest.mark.parametrize("fixture", (OLD_PROTOCOL, OLD_TLS, HTTP_FORWARD),
                         ids=("http1.1", "old-tls", "http-forward"))
@pytest.mark.parametrize("source", SOURCES)
def test_old_protocol_fails_repo_068(tmp_path: Path, source: str, fixture: dict) -> None:
    _stack(tmp_path, source, fixture[source])
    (finding,) = OldNetworkProtocol().run(tmp_path)
    assert finding.id == "REPO-068"
    assert "prod/" in finding.evidence


@pytest.mark.parametrize("fixture", (NEW_PROTOCOL, HTTP_REDIRECT), ids=("new", "redirect"))
@pytest.mark.parametrize("source", SOURCES)
def test_current_protocol_passes_repo_068(tmp_path: Path, source: str, fixture: dict) -> None:
    _stack(tmp_path, source, fixture[source])
    assert OldNetworkProtocol().run(tmp_path) == []


def test_internal_load_balancer_and_tls_variants_repo_068(tmp_path: Path) -> None:
    internal = HTTP_FORWARD["terraform"].replace("internal = false", "internal = true")
    _stack(tmp_path, "terraform", internal)
    assert OldNetworkProtocol().run(tmp_path) == []
    _stack(tmp_path, "terraform", 'resource "aws_api_gateway_domain_name" "api" {\n'
           '  security_policy = "TLS_1_0"\n}\n')
    assert "API Gateway domain on TLS 1.0" in OldNetworkProtocol().run(tmp_path)[0].evidence
    _write(tmp_path / "prod" / "main.tf", "")
    _write(tmp_path / "prod" / "cdn.yaml",
           "Resources:\n  Cdn:\n    Type: AWS::CloudFront::Distribution\n    Properties:\n"
           "      DistributionConfig:\n        ViewerCertificate:\n"
           "          MinimumProtocolVersion: TLSv1_2016\n")
    assert "viewer TLS below 1.2" in OldNetworkProtocol().run(tmp_path)[0].evidence
    _write(tmp_path / "prod" / "cdn.yaml",
           "Resources:\n  Cdn:\n    Type: AWS::CloudFront::Distribution\n    Properties:\n"
           "      DistributionConfig:\n        ViewerCertificate:\n"
           "          MinimumProtocolVersion: TLSv1.2_2021\n")
    assert OldNetworkProtocol().run(tmp_path) == []


def test_python_cdk_old_protocol_repo_068(tmp_path: Path) -> None:
    _write(tmp_path / "prod" / "stack.py",
           "cloudfront.Distribution(self, 'Cdn', default_behavior=b, "
           "minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2016)\n")
    assert OldNetworkProtocol().run(tmp_path)
    _write(tmp_path / "prod" / "stack.py",
           "cloudfront.Distribution(self, 'Cdn', default_behavior=b, "
           "minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021)\n")
    assert OldNetworkProtocol().run(tmp_path) == []


# Shared: dev paths, saved reports, mapping.

RULES = (EdgeLatencyUnwatched(), NetworkMetricsUnused(), SingleHybridLink(),
         LoadBalancingMissing(), OldNetworkProtocol())
FIRING = {
    "REPO-064": EDGE, "REPO-065": EDGE, "REPO-066": VPN, "REPO-067": PUBLIC_INSTANCE,
    "REPO-068": OLD_PROTOCOL,
}


@pytest.mark.parametrize("env", ("dev", "staging"))
@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_dev_paths_are_skipped(tmp_path: Path, rule, env: str) -> None:
    _stack(tmp_path, "terraform", FIRING[rule.id]["terraform"], env=env)
    assert rule.run(tmp_path) == []
    _stack(tmp_path, "terraform", FIRING[rule.id]["terraform"])
    assert rule.run(tmp_path)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_saved_report_quoting_the_finding_neither_passes_nor_fires(tmp_path: Path,
                                                                   rule) -> None:
    _stack(tmp_path, "terraform", FIRING[rule.id]["terraform"])
    (hit,) = rule.run(tmp_path)
    report = json.dumps({"findings": [hit.model_dump()]})
    text = f"{hit.title}\n{hit.evidence}\n{hit.recommendation}\n"
    _write(tmp_path / "reports" / "report.json", report)
    _write(tmp_path / "reports" / "report.md", text)
    assert len(rule.run(tmp_path)) == 1
    empty = tmp_path / "empty"
    _write(empty / "reports" / "report.json", report)
    _write(empty / "reports" / "report.md", text)
    assert rule.run(empty) == []


@pytest.mark.parametrize("rule_id,practice", (
    ("REPO-064", "PERF04-BP01"), ("REPO-065", "PERF04-BP07"), ("REPO-066", "PERF04-BP03"),
    ("REPO-067", "PERF04-BP04"), ("REPO-068", "PERF04-BP05"),
))
def test_rule_maps_to_one_practice(rule_id: str, practice: str) -> None:
    assert well_architected.best_practices_of(rule_id) == (practice,)
    assert rule_id not in ORG_RULE_IDS


def test_perf4_is_fully_checked() -> None:
    (perf4,) = [a for a in well_architected.answers([]) if a.question.id == "PERF 4"]
    assert perf4.not_checked == ()


def test_perf4_is_not_met_when_a_new_rule_fires(tmp_path: Path) -> None:
    _stack(tmp_path, "terraform", VPN["terraform"])
    findings = SingleHybridLink().run(tmp_path)
    (perf4,) = [a for a in well_architected.answers(findings) if a.question.id == "PERF 4"]
    assert not perf4.met
