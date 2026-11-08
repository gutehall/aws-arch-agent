"""Source-neutral resource record the template checks run on.

CloudFormation (synth output, --templates, raw templates) parses into Resource
records today; Terraform maps its aws_* types onto the same canonical types.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# CloudFormation type -> canonical type. Names follow the Terraform aws_* type
# without the prefix where one exists, so both sources meet on the same key.
CF_TYPE_TO_CANONICAL: dict[str, str] = {
    "AWS::S3::Bucket": "s3_bucket",
    "AWS::RDS::DBInstance": "db_instance",
    "AWS::RDS::DBCluster": "rds_cluster",
    "AWS::RDS::DBParameterGroup": "db_parameter_group",
    "AWS::RDS::DBClusterParameterGroup": "rds_cluster_parameter_group",
    "AWS::EC2::Instance": "instance",
    "AWS::EC2::LaunchTemplate": "launch_template",
    "AWS::EC2::SecurityGroup": "security_group",
    "AWS::EC2::SecurityGroupIngress": "security_group_ingress_rule",
    "AWS::EC2::SecurityGroupEgress": "security_group_egress_rule",
    "AWS::EC2::NetworkAcl": "network_acl",
    "AWS::EC2::NetworkAclEntry": "network_acl_entry",
    "AWS::EC2::TransitGateway": "transit_gateway",
    # Routes tie a NAT gateway to the subnets it serves (CF-NAT-001).
    "AWS::EC2::Route": "route",
    "AWS::EC2::RouteTable": "route_table",
    "AWS::EC2::SubnetRouteTableAssociation": "route_table_association",
    "AWS::EC2::VPC": "vpc",
    "AWS::EC2::Subnet": "subnet",
    "AWS::EC2::VPCEndpoint": "vpc_endpoint",
    "AWS::EC2::FlowLog": "flow_log",
    "AWS::EC2::NatGateway": "nat_gateway",
    "AWS::EC2::EIP": "eip",
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "lb",
    "AWS::ElasticLoadBalancingV2::Listener": "lb_listener",
    "AWS::ElasticLoadBalancingV2::TargetGroup": "lb_target_group",
    "AWS::ElasticLoadBalancing::LoadBalancer": "elb",
    "AWS::CloudTrail::Trail": "cloudtrail",
    "AWS::KMS::Key": "kms_key",
    "AWS::SSM::Parameter": "ssm_parameter",
    "AWS::Lambda::Function": "lambda_function",
    "AWS::DynamoDB::Table": "dynamodb_table",
    "AWS::Logs::LogGroup": "cloudwatch_log_group",
    "AWS::Logs::DeliverySource": "cloudwatch_log_delivery_source",
    "AWS::SQS::Queue": "sqs_queue",
    "AWS::SNS::Topic": "sns_topic",
    "AWS::EC2::Volume": "ebs_volume",
    "AWS::EFS::FileSystem": "efs_file_system",
    "AWS::EFS::AccessPoint": "efs_access_point",
    "AWS::Kinesis::Stream": "kinesis_stream",
    "AWS::Kinesis::StreamConsumer": "kinesis_stream_consumer",
    "AWS::KinesisAnalyticsV2::Application": "kinesis_analytics_application",
    "AWS::KinesisFirehose::DeliveryStream": "firehose_delivery_stream",
    "AWS::OpenSearchService::Domain": "opensearch_domain",
    "AWS::Redshift::Cluster": "redshift_cluster",
    "AWS::DocDB::DBCluster": "docdb_cluster",
    "AWS::Neptune::DBCluster": "neptune_cluster",
    "AWS::MSK::Cluster": "msk_cluster",
    # WAF associations attach a web ACL to an ALB or API Gateway stage (CF-WAF-001).
    "AWS::WAFv2::WebACLAssociation": "waf_association",
    "AWS::WAFRegional::WebACLAssociation": "waf_association",
    "AWS::CloudFront::OriginAccessControl": "cloudfront_origin_access_control",
    "AWS::ApiGateway::RestApi": "api_gateway_rest_api",
    "AWS::ApiGateway::Stage": "api_gateway_stage",
    "AWS::ApiGatewayV2::Api": "apigatewayv2_api",
    "AWS::ApiGatewayV2::Stage": "apigatewayv2_stage",
    "AWS::ApiGateway::Method": "api_gateway_method",
    "AWS::ApiGateway::DomainName": "api_gateway_domain_name",
    "AWS::ApiGateway::UsagePlan": "api_gateway_usage_plan",
    "AWS::ApiGatewayV2::DomainName": "apigatewayv2_domain_name",
    "AWS::ApiGatewayV2::Route": "apigatewayv2_route",
    "AWS::AutoScaling::AutoScalingGroup": "autoscaling_group",
    "AWS::AutoScaling::LaunchConfiguration": "launch_configuration",
    "AWS::AutoScaling::ScalingPolicy": "autoscaling_policy",
    "AWS::AutoScaling::ScheduledAction": "autoscaling_schedule",
    "AWS::ApplicationAutoScaling::ScalableTarget": "scalable_target",
    "AWS::ECS::Cluster": "ecs_cluster",
    "AWS::ECS::Service": "ecs_service",
    "AWS::EKS::Cluster": "eks_cluster",
    "AWS::CloudFront::Distribution": "cloudfront_distribution",
    "AWS::ElastiCache::CacheCluster": "elasticache_cluster",
    "AWS::ElastiCache::ReplicationGroup": "elasticache_replication_group",
    # IAM: documents live on a policy resource (PolicyDocument) or inline on a
    # principal (Policies). Terraform's split inline-policy types map to iam_policy.
    "AWS::IAM::Policy": "iam_policy",
    "AWS::IAM::ManagedPolicy": "iam_policy",
    "AWS::IAM::RolePolicy": "iam_policy",
    "AWS::IAM::UserPolicy": "iam_policy",
    "AWS::IAM::GroupPolicy": "iam_policy",
    "AWS::IAM::Role": "iam_role",
    "AWS::IAM::User": "iam_user",
    "AWS::IAM::Group": "iam_group",
    # Resource policies: a PolicyDocument on its own resource, read by CF-RP-001.
    "AWS::SQS::QueuePolicy": "resource_policy",
    "AWS::SNS::TopicPolicy": "resource_policy",
    "AWS::S3::BucketPolicy": "resource_policy",
    "AWS::ECR::Repository": "ecr_repository",
    "AWS::ECS::TaskDefinition": "ecs_task_definition",
    "AWS::SecretsManager::Secret": "secretsmanager_secret",
    "AWS::SecretsManager::RotationSchedule": "secretsmanager_secret_rotation",
    "AWS::Cognito::UserPool": "cognito_user_pool",
    "AWS::Lambda::Permission": "lambda_permission",
    "AWS::Lambda::Url": "lambda_url",
    "AWS::Lambda::EventSourceMapping": "lambda_event_source_mapping",
    "AWS::Lambda::Alias": "lambda_alias",
    "AWS::Lambda::Version": "lambda_version",
    "AWS::CodeBuild::Project": "codebuild_project",
    "AWS::CodePipeline::Pipeline": "codepipeline",
    "AWS::CodeStarNotifications::NotificationRule": "codestar_notification_rule",
    "AWS::Events::Rule": "events_rule",
    "AWS::Events::EventBus": "event_bus",
    "AWS::Events::EventBusPolicy": "event_bus_policy",
    "AWS::StepFunctions::StateMachine": "sfn_state_machine",
    "AWS::Backup::BackupVault": "backup_vault",
    "AWS::Backup::BackupPlan": "backup_plan",
    "AWS::Backup::BackupSelection": "backup_selection",
    "AWS::FSx::FileSystem": "fsx_file_system",
    "AWS::FSx::DataRepositoryAssociation": "fsx_data_repository_association",
    "AWS::SageMaker::NotebookInstance": "sagemaker_notebook_instance",
    "AWS::SageMaker::EndpointConfig": "sagemaker_endpoint_config",
    "AWS::Route53::HostedZone": "route53_hosted_zone",
    "AWS::Route53::RecordSet": "route53_record_set",
    "AWS::Route53::RecordSetGroup": "route53_record_set_group",
    "AWS::Route53::DNSSEC": "route53_dnssec",
    "AWS::Route53::KeySigningKey": "route53_key_signing_key",
    "AWS::CertificateManager::Certificate": "acm_certificate",
    "AWS::GlobalAccelerator::EndpointGroup": "globalaccelerator_endpoint_group",
    "AWS::AppSync::GraphQLApi": "appsync_graphql_api",
    "AWS::AppSync::ApiCache": "appsync_api_cache",
    "AWS::Transfer::Server": "transfer_server",
    "AWS::AppRunner::Service": "apprunner_service",
    "AWS::ElasticBeanstalk::Environment": "elastic_beanstalk_environment",
    "AWS::ElasticBeanstalk::ConfigurationTemplate": "elastic_beanstalk_configuration_template",
    "AWS::Athena::WorkGroup": "athena_workgroup",
    "AWS::Glue::Job": "glue_job",
    "AWS::Glue::SecurityConfiguration": "glue_security_configuration",
    "AWS::EMR::Cluster": "emr_cluster",
    "AWS::EMR::SecurityConfiguration": "emr_security_configuration",
    "AWS::DMS::ReplicationInstance": "dms_replication_instance",
    "AWS::DMS::Endpoint": "dms_endpoint",
}

# Terraform only: CloudFormation sets these on the rule, the vault and the file system.
CANONICAL_TYPES: frozenset[str] = frozenset(CF_TYPE_TO_CANONICAL.values()) | {
    "events_target", "backup_vault_lock", "efs_backup_policy", "autoscaling_attachment",
    "route53_query_log",
}


@dataclass
class Resource:
    """One declared resource.

    type: canonical type (e.g. "s3_bucket"), or None when no check covers it.
    name: logical id (CloudFormation) or address (Terraform).
    properties: CloudFormation-shaped properties the checks read.
    source_type: the type as written in the source (e.g. "AWS::S3::Bucket").
    malformed: why the properties could not be read (they are then empty). The resource
    still counts for template-level checks; per-resource checks skip it with a warning.
    unresolved: property names whose value depends on input the scan cannot see
    (Terraform var.* / local.*). Checks that read them report nothing.
    policies: resource-level DeletionPolicy and UpdateReplacePolicy, when set. Terraform
    lifecycle.prevent_destroy = true maps to Retain for both.
    references: Terraform addresses the block refers to (see field comment).
    """

    type: str | None
    name: str
    properties: dict[str, Any] = field(default_factory=dict)
    file: str = ""
    line: int | None = None
    source_type: str = ""
    malformed: str | None = None
    unresolved: frozenset[str] = frozenset()
    policies: dict[str, Any] = field(default_factory=dict)
    # Terraform only: addresses (aws_eip.nat) this block's arguments point at, all of them,
    # including ones no adapter maps. CloudFormation references are read from properties.
    references: frozenset[str] = frozenset()
    # Tags set for the whole stack that apply to this resource (Terraform provider
    # default_tags). None means they exist but cannot be read (from a variable).
    inherited_tags: dict[str, Any] | None = field(default_factory=dict)


def resources_from_cf_template(
    path: Path, doc: dict, warnings: list[str] | None = None
) -> list[Resource]:
    """Parse a CloudFormation template's Resources into Resource records.

    A resource that is not an object is skipped with a warning. Properties that are not
    an object are recorded as malformed rather than dropped.
    """
    if warnings is None:
        warnings = []
    raw = doc.get("Resources", {}) or {}
    if not isinstance(raw, dict):
        return []
    out: list[Resource] = []
    for logical_id, body in raw.items():
        name = str(logical_id)
        if not isinstance(body, dict):
            warnings.append(
                f"CF rules skipped resource {name} in {path.name}: resource is not an object"
            )
            continue
        source_type = body.get("Type", "Unknown")
        if not isinstance(source_type, str):
            source_type = "Unknown"
        props = body.get("Properties", {}) or {}
        malformed = None
        if not isinstance(props, dict):
            malformed = "Properties is not an object"
            props = {}
        out.append(
            Resource(
                type=CF_TYPE_TO_CANONICAL.get(source_type),
                name=name,
                properties=props,
                file=str(path),
                line=None,
                source_type=source_type,
                malformed=malformed,
                policies={
                    k: body[k] for k in ("DeletionPolicy", "UpdateReplacePolicy") if k in body
                },
            )
        )
    return out
