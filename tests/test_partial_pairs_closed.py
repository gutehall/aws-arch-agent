"""The seven once-partial CDK rules: what each template check now also reads, and what each
narrowed CDK rule no longer reports. The V2 merge of each pair is in test_cf_covers_static.py."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aws_arch_agent.rules.cf_template import CF_PARTLY_COVERS_STATIC, run_cf_rules_from_paths, run_resource_checks
from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.terraform_model import resources_from_terraform

RULE_BY_ID = {r.id: r for r in ALL_RULES}


def _ids(tmp_path: Path, resources: dict) -> dict[str, set[str]]:
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    out: dict[str, set[str]] = {}
    for f in run_cf_rules_from_paths([path], repo_path=tmp_path):
        out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _tf(tmp_path: Path, text: str) -> dict[str, set[str]]:
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    out: dict[str, set[str]] = {}
    for f in run_resource_checks(resources_from_terraform(tmp_path, []), tmp_path / "main.tf"):
        out.setdefault(f.id, set()).add((f.evidence or "").split(" ")[0])
    return out


def _r(rtype: str, **props: Any) -> dict:
    return {"Type": rtype, "Properties": props}


def _cdk(tmp_path: Path, rule_id: str, source: str) -> list:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir(exist_ok=True)
    (tmp_path / "lib" / "stack.ts").write_text(source + "\n", encoding="utf-8")
    return RULE_BY_ID[rule_id].run(tmp_path, "typescript")


def test_no_cdk_rule_is_left_partial() -> None:
    partial = {r for rules, _why in CF_PARTLY_COVERS_STATIC.values() for r in rules}
    assert partial <= {"OPS-001", "BP-001"}  # the trail and tag policy entries, explained in the map


# --- SEC-055 / CF-NACL-001 ---------------------------------------------------------------------


def test_vpc_without_custom_nacl(tmp_path: Path) -> None:
    vpc = _r("AWS::EC2::VPC", CidrBlock="10.0.0.0/16")
    assert _ids(tmp_path, {"Vpc": vpc}).get("CF-NACL-001") == {"Vpc"}
    acl = _r("AWS::EC2::NetworkAcl", VpcId={"Ref": "Vpc"})
    assert "CF-NACL-001" not in _ids(tmp_path, {"Vpc": vpc, "Acl": acl})


def test_terraform_vpc_without_custom_nacl(tmp_path: Path) -> None:
    vpc = 'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n'
    assert _tf(tmp_path, vpc).get("CF-NACL-001") == {"aws_vpc.main"}
    acl = 'resource "aws_network_acl" "private" {\n  vpc_id = aws_vpc.main.id\n}\n'
    assert "CF-NACL-001" not in _tf(tmp_path, vpc + acl)


# --- REL-001 / CF-RDS-003 ----------------------------------------------------------------------

_CLUSTER = _r("AWS::RDS::DBCluster", Engine="aurora-mysql")


def _member(**extra: Any) -> dict:
    return _r("AWS::RDS::DBInstance", Engine="aurora-mysql", DBClusterIdentifier={"Ref": "Cluster"},
              DBInstanceClass="db.r7g.large", **extra)


def test_aurora_cluster_with_one_instance(tmp_path: Path) -> None:
    assert _ids(tmp_path, {"Cluster": _CLUSTER, "W": _member()}).get("CF-RDS-003") == {"Cluster"}


@pytest.mark.parametrize("resources", [
    {"Cluster": _CLUSTER, "W": _member(), "R": _member()},
    {"Cluster": _CLUSTER},  # members elsewhere: not judged
    {"Cluster": _r("AWS::RDS::DBCluster", Engine="aurora-mysql", EngineMode="serverless")},
    {"Cluster": _r("AWS::RDS::DBCluster", Engine="mysql", DBClusterInstanceClass="db.m6gd.large")},
    {"Cluster": _r("AWS::RDS::DBCluster", Engine={"Ref": "Engine"}), "W": _member()},
])
def test_aurora_cluster_multi_az_or_not_judged(tmp_path: Path, resources: dict) -> None:
    assert "Cluster" not in _ids(tmp_path, resources).get("CF-RDS-003", set())


def test_terraform_aurora_members(tmp_path: Path) -> None:
    cluster = 'resource "aws_rds_cluster" "db" {\n  engine = "aurora-postgresql"\n}\n'
    one = ('resource "aws_rds_cluster_instance" "w" {\n  engine = "aurora-postgresql"\n'
           '  cluster_identifier = aws_rds_cluster.db.id\n  instance_class = "db.r7g.large"\n}\n')
    assert _tf(tmp_path, cluster + one).get("CF-RDS-003") == {"aws_rds_cluster.db"}
    two = one.replace('"w" {', '"w" {\n  count = 2')
    assert "aws_rds_cluster.db" not in _tf(tmp_path, cluster + two).get("CF-RDS-003", set())
    variable = one.replace('"w" {', '"w" {\n  count = var.instances')
    assert "aws_rds_cluster.db" not in _tf(tmp_path, cluster + variable).get("CF-RDS-003", set())


# --- COST-002 / CF-ECS-013 ---------------------------------------------------------------------


def test_ecs_service_that_nothing_scales(tmp_path: Path) -> None:
    svc = _r("AWS::ECS::Service", DesiredCount=2)
    assert _ids(tmp_path, {"Svc": svc}).get("CF-ECS-013") == {"Svc"}


@pytest.mark.parametrize("extra", [
    {"T": _r("AWS::ApplicationAutoScaling::ScalableTarget", ServiceNamespace="ecs",
             ResourceId={"Fn::Join": ["/", ["service", {"Ref": "Cluster"}, {"Fn::GetAtt": ["Svc", "Name"]}]]})},
    {"T": _r("AWS::ApplicationAutoScaling::ScalableTarget", ServiceNamespace="ecs",
             ResourceId={"Ref": "SomeParameter"})},  # cannot be tied: it may scale this one
])
def test_scaled_or_unlinked_ecs_service(tmp_path: Path, extra: dict) -> None:
    assert "CF-ECS-013" not in _ids(tmp_path, {"Svc": _r("AWS::ECS::Service", DesiredCount=2), **extra})


def test_daemon_service_and_other_namespaces(tmp_path: Path) -> None:
    daemon = _r("AWS::ECS::Service", SchedulingStrategy="DAEMON")
    assert "CF-ECS-013" not in _ids(tmp_path, {"Svc": daemon})
    table_target = _r("AWS::ApplicationAutoScaling::ScalableTarget", ServiceNamespace="dynamodb",
                      ResourceId="table/t")
    found = _ids(tmp_path, {"Svc": _r("AWS::ECS::Service", DesiredCount=2), "T": table_target})
    assert found.get("CF-ECS-013") == {"Svc"}


def test_terraform_ecs_scaling(tmp_path: Path) -> None:
    svc = 'resource "aws_ecs_service" "api" {\n  name = "api"\n  desired_count = 2\n}\n'
    assert _tf(tmp_path, svc).get("CF-ECS-013") == {"aws_ecs_service.api"}
    target = ('resource "aws_appautoscaling_target" "api" {\n  service_namespace = "ecs"\n'
              '  resource_id = "service/main/${aws_ecs_service.api.name}"\n'
              '  scalable_dimension = "ecs:service:DesiredCount"\n  min_capacity = 1\n  max_capacity = 4\n}\n')
    assert "CF-ECS-013" not in _tf(tmp_path, svc + target)


# --- PERF-002 / CF-PERF-002 --------------------------------------------------------------------


def test_alb_without_cache_and_lambda_alone(tmp_path: Path) -> None:
    alb = _r("AWS::ElasticLoadBalancingV2::LoadBalancer", Type="application")
    assert _ids(tmp_path, {"Lb": alb}).get("CF-PERF-002") == {"Template"}
    nlb = _r("AWS::ElasticLoadBalancingV2::LoadBalancer", Type="network")
    assert "CF-PERF-002" not in _ids(tmp_path, {"Lb": nlb})
    fn = _r("AWS::Lambda::Function", Runtime="nodejs22.x")
    assert "CF-PERF-002" not in _ids(tmp_path, {"Fn": fn})  # PERF-002 does not count a lone function


@pytest.mark.parametrize("cache", [
    _r("AWS::DAX::Cluster", NodeType="dax.r5.large"),
    _r("AWS::ApiGateway::Stage", RestApiId={"Ref": "Api"}, StageName="prod", CacheClusterEnabled=True),
    _r("AWS::ElastiCache::ReplicationGroup", ReplicationGroupDescription="c"),
])
def test_dax_or_api_cache_counts_as_a_cache(tmp_path: Path, cache: dict) -> None:
    api = _r("AWS::ApiGateway::RestApi", Name="api")
    assert "CF-PERF-002" not in _ids(tmp_path, {"Api": api, "Cache": cache})


# --- PERF-008 and SUST-001 narrowed ------------------------------------------------------------


def test_perf_008_reads_rds_files_only(tmp_path: Path) -> None:
    ec2 = "new ec2.Instance(this, 'I', { instanceType: new ec2.InstanceType('m7g.xlarge') });"
    assert _cdk(tmp_path, "PERF-008", ec2) == []
    rds = "new rds.DatabaseInstance(this, 'Db', {\n  instanceType: new ec2.InstanceType('r6g.xlarge'),\n});"
    assert [f.id for f in _cdk(tmp_path, "PERF-008", rds)] == ["PERF-008"]


def test_sust_001_reads_fleets_not_a_lone_instance(tmp_path: Path) -> None:
    assert _cdk(tmp_path, "SUST-001", "new ec2.Instance(this, 'I', { vpc, instanceType, machineImage });") == []
    fleet = "new autoscaling.AutoScalingGroup(this, 'G', { vpc, instanceType, machineImage });"
    assert [f.id for f in _cdk(tmp_path, "SUST-001", fleet)] == ["SUST-001"]


def test_aurora_member_in_a_remote_module_is_not_judged(tmp_path: Path) -> None:
    cluster = 'resource "aws_rds_cluster" "db" {\n  engine = "aurora-postgresql"\n}\n'
    one = ('resource "aws_rds_cluster_instance" "w" {\n  engine = "aurora-postgresql"\n'
           '  cluster_identifier = aws_rds_cluster.db.id\n}\n')
    module = 'module "readers" {\n  source = "git::https://example.com/readers.git"\n}\n'
    assert "aws_rds_cluster.db" not in _tf(tmp_path, cluster + one + module).get("CF-RDS-003", set())


# --- PERF-015 / CF-LAM-010 and REL-010 / CF-LAM-011 (once advice) ------------------------------


@pytest.mark.parametrize(("props", "fires"), [
    ({"Runtime": "java21"}, True),
    ({"Runtime": "java21", "SnapStart": {"ApplyOn": "None"}}, True),
    ({"Runtime": "java21", "SnapStart": {"ApplyOn": "PublishedVersions"}}, False),
    ({"Runtime": "python3.13"}, False),
    ({"Runtime": {"Ref": "Runtime"}}, False),
    ({"PackageType": "Image"}, False),
])
def test_java_snapstart(tmp_path: Path, props: dict, fires: bool) -> None:
    assert ("CF-LAM-010" in _ids(tmp_path, {"Fn": _r("AWS::Lambda::Function", **props)})) is fires


def test_terraform_java_snapstart(tmp_path: Path) -> None:
    fn = 'resource "aws_lambda_function" "f" {\n  runtime = "java21"\n}\n'
    assert _tf(tmp_path, fn).get("CF-LAM-010") == {"aws_lambda_function.f"}
    on = fn.replace("}\n", '  snap_start {\n    apply_on = "PublishedVersions"\n  }\n}\n')
    assert "CF-LAM-010" not in _tf(tmp_path, on)


_DB = _r("AWS::RDS::DBInstance", Engine="postgres", DBInstanceClass="db.t4g.micro")
_FN_TO_DB = _r("AWS::Lambda::Function", Runtime="nodejs22.x", Environment={"Variables": {
    "DB_HOST": {"Fn::GetAtt": ["Db", "Endpoint.Address"]}}})


def test_function_outside_vpc_that_names_a_private_db(tmp_path: Path) -> None:
    assert _ids(tmp_path, {"Db": _DB, "Fn": _FN_TO_DB}).get("CF-LAM-011") == {"Fn"}


@pytest.mark.parametrize("resources", [
    {"Db": _DB, "Fn": {**_FN_TO_DB, "Properties": {**_FN_TO_DB["Properties"],
                                                    "VpcConfig": {"SubnetIds": ["subnet-1"]}}}},
    {"Db": _r("AWS::RDS::DBInstance", Engine="postgres", PubliclyAccessible=True), "Fn": _FN_TO_DB},
    {"Db": _DB, "Fn": _r("AWS::Lambda::Function", Runtime="nodejs22.x")},
])
def test_function_in_vpc_public_store_or_no_store(tmp_path: Path, resources: dict) -> None:
    assert "CF-LAM-011" not in _ids(tmp_path, resources)


def test_terraform_function_outside_vpc(tmp_path: Path) -> None:
    db = 'resource "aws_db_instance" "main" {\n  engine = "postgres"\n}\n'
    fn = ('resource "aws_lambda_function" "f" {\n  runtime = "nodejs22.x"\n'
          '  environment {\n    variables = {\n      DB_HOST = aws_db_instance.main.address\n    }\n  }\n}\n')
    assert _tf(tmp_path, db + fn).get("CF-LAM-011") == {"aws_lambda_function.f"}
    in_vpc = fn.replace("}\n}\n", '}\n  vpc_config {\n    subnet_ids = ["s"]\n    security_group_ids = ["g"]\n  }\n}\n', 1)
    assert "CF-LAM-011" not in _tf(tmp_path, db + in_vpc)
