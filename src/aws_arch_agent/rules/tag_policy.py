"""Required tag policy for template resources (DM3-543).

Config:

    tags:
      required: [CostCenter, Owner, Environment]
      allowed:                     # optional: values a key may take
        Environment: [prod, staging, dev]

CF-TAG-001 reports each taggable resource that misses a required tag, or has a value
the policy does not allow, at its file and line. Tags set for a whole stack count for
every resource under it: CDK Tags.of(app) is already on each resource in synth output,
and Terraform provider default_tags are merged in (Resource.inherited_tags). With no
tags.required the check is off. Keys and values are case-sensitive, as in AWS.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, List

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.resource_model import Resource

CHECK_ID = "CF-TAG-001"
# The repo-wide tag guesses a policy check replaces where templates are scanned.
REPLACED_STATIC_RULES = ("BP-001", "COST-015")


@dataclass(frozen=True)
class TagPolicy:
    required: tuple[str, ...]
    allowed: dict[str, tuple[str, ...]] = field(default_factory=dict)


# Taggable resource types and the property that holds their tags. Types not listed are
# not checked: not every resource supports tags. Terraform types all use `tags`
# (aws_autoscaling_group also repeated `tag` blocks).
_CF_TAGGABLE: dict[str, str] = {
    **{t: "Tags" for t in (
        "AWS::EC2::Instance", "AWS::EC2::Volume", "AWS::EC2::VPC", "AWS::EC2::Subnet",
        "AWS::EC2::SecurityGroup", "AWS::EC2::NatGateway", "AWS::EC2::EIP",
        "AWS::EC2::InternetGateway", "AWS::EC2::RouteTable", "AWS::EC2::TransitGateway",
        "AWS::EC2::VPCEndpoint",
        "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::ElasticLoadBalancingV2::TargetGroup",
        "AWS::AutoScaling::AutoScalingGroup",
        "AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::DynamoDB::Table", "AWS::S3::Bucket",
        "AWS::Lambda::Function", "AWS::SQS::Queue", "AWS::SNS::Topic", "AWS::KMS::Key",
        "AWS::Logs::LogGroup", "AWS::ECS::Cluster", "AWS::ECS::Service", "AWS::ECS::TaskDefinition",
        "AWS::ECR::Repository", "AWS::EKS::Cluster", "AWS::EKS::Nodegroup",
        "AWS::ElastiCache::ReplicationGroup", "AWS::ElastiCache::CacheCluster",
        "AWS::OpenSearchService::Domain", "AWS::Redshift::Cluster", "AWS::DocDB::DBCluster",
        "AWS::Neptune::DBCluster", "AWS::MSK::Cluster", "AWS::Kinesis::Stream",
        "AWS::CloudFront::Distribution", "AWS::ApiGateway::RestApi", "AWS::ApiGateway::Stage",
        "AWS::ApiGatewayV2::Api", "AWS::StepFunctions::StateMachine",
        "AWS::SecretsManager::Secret", "AWS::CloudTrail::Trail", "AWS::IAM::Role",
    )},
    "AWS::EFS::FileSystem": "FileSystemTags",
    "AWS::Cognito::UserPool": "UserPoolTags",
}
TF_TAGGABLE: frozenset[str] = frozenset({
    "aws_instance", "aws_ebs_volume", "aws_vpc", "aws_subnet", "aws_security_group",
    "aws_nat_gateway", "aws_eip", "aws_internet_gateway", "aws_route_table",
    "aws_ec2_transit_gateway", "aws_vpc_endpoint", "aws_lb", "aws_alb", "aws_lb_target_group",
    "aws_autoscaling_group", "aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table",
    "aws_s3_bucket", "aws_lambda_function", "aws_sqs_queue", "aws_sns_topic", "aws_kms_key",
    "aws_cloudwatch_log_group", "aws_ecs_cluster", "aws_ecs_service", "aws_ecs_task_definition",
    "aws_ecr_repository", "aws_eks_cluster", "aws_eks_node_group",
    "aws_elasticache_replication_group", "aws_elasticache_cluster", "aws_opensearch_domain",
    "aws_redshift_cluster", "aws_docdb_cluster", "aws_neptune_cluster", "aws_msk_cluster",
    "aws_kinesis_stream", "aws_cloudfront_distribution", "aws_api_gateway_rest_api",
    "aws_api_gateway_stage", "aws_apigatewayv2_api", "aws_sfn_state_machine",
    "aws_secretsmanager_secret", "aws_cloudtrail", "aws_iam_role", "aws_efs_file_system",
    "aws_cognito_user_pool",
})

_active: TagPolicy | None = None


def active_policy() -> TagPolicy | None:
    return _active


@contextmanager
def use_tag_policy(policy: TagPolicy | None) -> Iterator[None]:
    """Check resources against this policy for the duration of a scan (None: off)."""
    global _active
    previous, _active = _active, policy
    try:
        yield
    finally:
        _active = previous


class _Unknown:
    """A tag value the scan cannot read: the key is set, its value is not known."""


UNKNOWN = _Unknown()


def _tag_map(raw: Any) -> dict[str, Any] | None:
    """{key: value} from a CloudFormation tag list or map; None when it cannot be read."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        if raw and all(k == "Ref" or k.startswith("Fn::") for k in raw):
            return None  # an intrinsic
        return {str(k): (v if type(v) is str else UNKNOWN) for k, v in raw.items()}
    if not isinstance(raw, list):
        return None
    out: dict[str, Any] = {}
    for item in raw:
        if not isinstance(item, dict):
            return None
        key = item.get("Key")
        if type(key) is not str:
            return None  # a key from an intrinsic: any key may be set
        value = item.get("Value")
        out[key] = value if type(value) is str else UNKNOWN
    return out


def _effective_tags(res: Resource) -> dict[str, Any] | None:
    """The resource's tags with inherited stack tags under them; None when unknown."""
    if res.source_type in _CF_TAGGABLE:
        own = _tag_map(res.properties.get(_CF_TAGGABLE[res.source_type]))
    elif res.source_type in TF_TAGGABLE:
        if "Tags" in res.unresolved or res.inherited_tags is None:
            return None
        own = _tag_map(res.properties.get("Tags"))
    else:
        return None
    if own is None:
        return None
    return {**(res.inherited_tags or {}), **own}


def is_taggable(res: Resource) -> bool:
    return res.source_type in _CF_TAGGABLE or res.source_type in TF_TAGGABLE


def findings(resources: List[Resource], template_path: Path) -> List[Finding]:
    """CF-TAG-001 for each taggable resource that breaks the active policy."""
    policy = _active
    if policy is None or not policy.required:
        return []
    out: List[Finding] = []
    for res in resources:
        if res.malformed or not is_taggable(res):
            continue
        tags = _effective_tags(res)
        if tags is None:
            continue  # tags from a variable or intrinsic: not judged
        missing = [k for k in policy.required if k not in tags]
        not_allowed = [
            f"{k}={tags[k]}" for k, values in policy.allowed.items()
            if k in tags and type(tags[k]) is str and tags[k] not in values
        ]
        if not missing and not not_allowed:
            continue
        parts = []
        if missing:
            parts.append(f"Missing required tag{'s' if len(missing) > 1 else ''}: {', '.join(missing)}.")
        if not_allowed:
            allowed = "; ".join(
                f"{k}: {', '.join(policy.allowed[k])}" for k in policy.allowed
                if any(v.startswith(f"{k}=") for v in not_allowed)
            )
            parts.append(f"Value not allowed: {', '.join(not_allowed)} (allowed {allowed}).")
        out.append(Finding(
            id=CHECK_ID,
            title="Resource does not meet the required tag policy",
            severity="Medium",
            category="Cost Optimization",
            file=res.file or str(template_path),
            line=res.line,
            evidence=f"{res.name} ({res.source_type})",
            recommendation=(
                " ".join(parts) + " The tag policy is tags.required in the config. Untagged "
                "resources cannot be split by team or product on the bill. Tag the resource, or "
                "tag the whole stack (CDK Tags.of(app).add, Terraform provider default_tags)."
            ),
        ))
    return out
