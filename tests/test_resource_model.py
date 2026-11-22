"""Shared resource model: CloudFormation parses into Resource; CF-* checks run on Resource."""
import json
from pathlib import Path

from aws_arch_agent.rules.cf_template import (
    _PER_RESOURCE_TYPES,
    run_cf_rules,
    run_resource_checks,
)
from aws_arch_agent.rules.resource_model import (
    CANONICAL_TYPES,
    CF_TYPE_TO_CANONICAL,
    Resource,
    resources_from_cf_template,
)

FIXTURE = Path(__file__).parent / "fixtures" / "minimal-cdk" / "cdk.out"


def test_cf_template_parses_into_resources(tmp_path: Path) -> None:
    path = tmp_path / "s.template.json"
    doc = {
        "Resources": {
            "Data": {"Type": "AWS::S3::Bucket", "Properties": {"VersioningConfiguration": {}}},
            "Topic": {"Type": "AWS::SNS::Subscription"},
        }
    }
    resources = resources_from_cf_template(path, doc)
    by_name = {r.name: r for r in resources}
    assert by_name["Data"].type == "s3_bucket"
    assert by_name["Data"].source_type == "AWS::S3::Bucket"
    assert by_name["Data"].properties == {"VersioningConfiguration": {}}
    assert by_name["Data"].file == str(path)
    assert by_name["Topic"].type is None
    assert by_name["Topic"].properties == {}


def test_malformed_resources(tmp_path: Path) -> None:
    path = tmp_path / "bad.template.json"
    doc = {"Resources": {"NotObj": "x", "BadProps": {"Type": "AWS::S3::Bucket", "Properties": [1]}}}
    warnings: list[str] = []
    resources = resources_from_cf_template(path, doc, warnings)
    assert [r.name for r in resources] == ["BadProps"]
    assert resources[0].malformed == "Properties is not an object"
    assert any("NotObj" in w for w in warnings)


def test_canonical_types_cover_every_checked_type() -> None:
    assert _PER_RESOURCE_TYPES <= CANONICAL_TYPES
    # One canonical type per CloudFormation type, except where several CloudFormation
    # types carry the same thing on purpose (a policy document).
    shared = {"iam_policy", "resource_policy", "waf_association"}
    values = [v for v in CF_TYPE_TO_CANONICAL.values() if v not in shared]
    assert len(set(values)) == len(values)


def test_checks_run_on_resources_without_a_template(tmp_path: Path) -> None:
    """A source other than CloudFormation (Terraform) only has to build Resource records."""
    path = tmp_path / "main.tf"
    resources = [
        Resource(type="s3_bucket", name="aws_s3_bucket.data", file=str(path), line=3,
                 source_type="aws_s3_bucket"),
        Resource(type="vpc", name="aws_vpc.main", file=str(path), source_type="aws_vpc"),
    ]
    findings = run_resource_checks(resources, path)
    ids = {f.id for f in findings}
    assert {"CF-S3-001", "CF-S3-003", "CF-VPC-001", "CF-FL-001"} <= ids
    s3 = next(f for f in findings if f.id == "CF-S3-001")
    assert s3.evidence == "aws_s3_bucket.data (aws_s3_bucket)"
    assert (s3.file, s3.line) == (str(path), 3)


def test_unresolved_intrinsics_stay_non_findings(tmp_path: Path) -> None:
    resources = [
        Resource(type="sqs_queue", name="Q", source_type="AWS::SQS::Queue",
                 properties={"SqsManagedSseEnabled": True, "RedrivePolicy": {"Ref": "Policy"}}),
        Resource(type="db_instance", name="Db", source_type="AWS::RDS::DBInstance",
                 properties={"StorageEncrypted": True, "MultiAZ": True, "DeletionProtection": True,
                             "BackupRetentionPeriod": {"Ref": "Days"}}),
    ]
    ids = {f.id for f in run_resource_checks(resources, tmp_path / "t.json")}
    assert "CF-SQS-002" not in ids
    assert "CF-RDS-002" not in ids


def test_synth_fixture_findings_are_stable() -> None:
    """cdk synth output goes through the model with the same ids and evidence as before."""
    findings = run_cf_rules(FIXTURE, repo_path=FIXTURE.parent)
    doc = json.loads((FIXTURE / "MinimalStack.template.json").read_text(encoding="utf-8"))
    cf_types = {r["Type"] for r in doc["Resources"].values()}
    for f in findings:
        assert f.id.startswith("CF-")
        assert f.file == "cdk.out/MinimalStack.template.json"
        if f.evidence and f.evidence.endswith(")"):
            assert f.evidence.rsplit("(", 1)[1].rstrip(")") in cf_types


def test_cf_cost_properties_pass_through_and_count_is_one(tmp_path: Path) -> None:
    """The cost properties Terraform maps arrive from CloudFormation as written."""
    path = tmp_path / "cost.template.json"
    props = {
        "AWS::RDS::DBInstance": {"AllocatedStorage": "100", "StorageType": "gp3"},
        "AWS::ECS::Service": {"DesiredCount": 3, "TaskDefinition": {"Ref": "Task"}},
        "AWS::ECS::TaskDefinition": {
            "Cpu": "512", "Memory": "1024", "RequiresCompatibilities": ["FARGATE"],
            "RuntimePlatform": {"CpuArchitecture": "ARM64", "OperatingSystemFamily": "LINUX"},
        },
        "AWS::OpenSearchService::Domain": {
            "ClusterConfig": {
                "InstanceType": "r6g.large.search", "InstanceCount": 3,
                "DedicatedMasterEnabled": True, "DedicatedMasterType": "m6g.large.search",
                "DedicatedMasterCount": 3,
            },
            "EBSOptions": {"EBSEnabled": True, "VolumeSize": 100, "VolumeType": "gp3"},
        },
        "AWS::ElastiCache::CacheCluster": {"CacheNodeType": "cache.t4g.small", "NumCacheNodes": 2},
        "AWS::ElastiCache::ReplicationGroup": {
            "CacheNodeType": "cache.r7g.large", "NumCacheClusters": 2,
            "NumNodeGroups": 3, "ReplicasPerNodeGroup": 1,
        },
        "AWS::Redshift::Cluster": {"NodeType": "ra3.xlplus", "NumberOfNodes": 2},
        "AWS::Kinesis::Stream": {"ShardCount": 4, "StreamModeDetails": {"StreamMode": "PROVISIONED"}},
        "AWS::EC2::VPCEndpoint": {
            "ServiceName": "com.amazonaws.eu-west-1.ecr.api", "VpcEndpointType": "Interface",
            "SubnetIds": [{"Ref": "A"}, {"Ref": "B"}],
        },
        "AWS::AutoScaling::AutoScalingGroup": {
            "MinSize": "1", "MaxSize": "4", "DesiredCapacity": "2",
            "LaunchTemplate": {"LaunchTemplateId": {"Ref": "Lt"}, "Version": "1"},
            "LaunchConfigurationName": "legacy-lc",
        },
        "AWS::Lambda::Function": {"MemorySize": 1024, "Architectures": ["arm64"]},
        "AWS::EC2::Volume": {"VolumeType": "gp3", "Size": 200, "Iops": 6000, "Throughput": 250},
    }
    doc = {"Resources": {
        f"R{i}": {"Type": rtype, "Properties": body} for i, rtype, body in
        ((i, t, b) for i, (t, b) in enumerate(props.items()))
    }}
    resources = resources_from_cf_template(path, doc)
    assert len(resources) == len(props)
    for res in resources:
        assert res.type == CF_TYPE_TO_CANONICAL[res.source_type]
        assert res.properties == props[res.source_type]
        assert res.count == 1
