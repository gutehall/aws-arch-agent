"""CloudFormation template-based rules (S3, RDS, ALB, CloudTrail, KMS, Lambda, DynamoDB, etc.) run after cdk synth."""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any, Callable, List

from aws_arch_agent.models import Finding, Severity
from aws_arch_agent.rules.secret_names import is_literal_secret, is_secret_name
from aws_arch_agent.rules import (
    environments,
    estimates,
    generations,
    iam_policy,
    lambda_runtimes,
    nonprod,
    regions,
    stack_cost,
    tag_policy,
)
from aws_arch_agent.rules.resource_model import Resource, resources_from_cf_template
from aws_arch_agent.rules.terraform_model import TfVariable
from aws_arch_agent.tools.cdk_synth import list_cf_templates
from aws_arch_agent.tools.cfn_yaml import parse_template_text
from aws_arch_agent.tools.paths import to_repo_relative

# Sensitive ports for security group checks (SSH, RDP, Postgres, MySQL, Mongo)
# Ports CF-SG-001 reports when open to the internet: SSH, RDP, databases (Security Hub
# EC2.13, EC2.14) and the high-risk ports of Security Hub EC2.19.
SENSITIVE_PORTS = {
    20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306, 3389, 4333, 5000, 5432,
    5500, 5601, 8080, 8088, 8888, 9200, 9300, 27017,
}

# Static rule dropped when the CF rule already reported that control.
CF_COVERS_STATIC: dict[str, tuple[str, ...]] = {
    "CF-S3-001": ("SEC-005",),
    "CF-S3-002": ("SEC-006",),
    "CF-VPC-001": ("SEC-022",),
    "CF-FL-001": ("OPS-002",),
    "CF-EC2-001": ("SEC-066",),
    "CF-SNS-001": ("SEC-014",),
    "CF-LAM-003": ("SEC-068",),
    "CF-CF-001": ("SEC-018",),
    "CF-CF-002": ("SEC-019",),
    "CF-CF-003": ("SEC-024",),
    "CF-WAF-001": ("SEC-024",),
    "CF-EFS-001": ("SEC-037",),
    "CF-KIN-001": ("SEC-038",),
    "CF-KIN-002": ("REL-019",),
    "CF-EC-001": ("SEC-025",),
    "CF-EC-002": ("SEC-025",),
    "CF-OS-001": ("SEC-039",),
    "CF-OS-002": ("SEC-039",),
    "CF-OS-003": ("SEC-041",),
    "CF-OS-004": ("SEC-040",),
    "CF-RS-001": ("SEC-059",),
    "CF-DOCDB-001": ("SEC-060",),
    "CF-NEP-001": ("SEC-061",),
    "CF-MSK-001": ("SEC-044",),
    "CF-MSK-002": ("SEC-045",),
    "CF-EBS-002": ("COST-008",),
    "CF-GEN-001": ("SUST-007",),
    "CF-S3-006": ("COST-013",),
    "CF-S3-007": ("COST-007",),
    "CF-DDB-003": ("COST-003",),
    "CF-EIP-001": ("COST-012",),
    "CF-SM-001": ("SEC-015",),
    "CF-COG-001": ("SEC-034",),
    "CF-COG-002": ("SEC-035",),
    "CF-COG-003": ("SEC-036",),
    "CF-ECR-001": ("SEC-028",),
    "CF-ECR-002": ("SEC-029",),
    "CF-ECR-003": ("SEC-030",),
    "CF-ECS-002": ("SEC-020",),
    "CF-ECS-003": ("SEC-058",),
    "CF-IAM-001": ("SEC-001",),
    "CF-IAM-002": ("SEC-001",),
    "CF-IAM-003": ("SEC-002",),
    # Action "*" on Resource "*" is reported once, as admin, so it covers both wildcards.
    "CF-IAM-008": ("SEC-067", "SEC-001", "SEC-002"),
    "CF-SQS-001": ("SEC-013",),
    "CF-SQS-002": ("REL-008",),
    "CF-SQS-003": ("REL-024",),
    "CF-SFN-001": ("REL-015",),
    "CF-SFN-002": ("OPS-012",),
    "CF-EB-001": ("OPS-013",),
    "CF-EB-002": ("REL-029",),
    # Sensitive ports include SSH (SEC-003) and the DB ports (SEC-004). CF-SG-002 is the
    # same rule open on every port, reported instead of CF-SG-001.
    "CF-SG-001": ("SEC-003", "SEC-004"),
    "CF-SG-002": ("SEC-003", "SEC-004"),
    "CF-SG-003": ("SEC-054",),
    "CF-NAT-001": ("REL-012",),
    "CF-TGW-002": ("OPS-016",),
    "CF-DDB-001": ("REL-004",),
    "CF-DDB-002": ("SEC-008",),
    # RetentionDays.INFINITE synthesises to a log group with no RetentionInDays.
    "CF-CW-001": ("COST-001",),
    "CF-CW-002": ("SEC-062",),
    "CF-APIGW-001": ("OPS-005",),
    "CF-APIGW-V2-001": ("OPS-005",),
    # OPS-003 looks at API Gateway and Lambda only, which these three checks cover.
    "CF-APIGW-002": ("OPS-003",),
    "CF-CB-003": ("SEC-053",),
    "CF-CB-004": ("OPS-020",),
    "CF-CP-001": ("SEC-052",),
    "CF-CP-002": ("REL-021",),
    "CF-CP-003": ("OPS-017",),
    "CF-APIGW-003": ("SEC-009",),
    "CF-APIGW-V2-003": ("SEC-009",),
    "CF-APIGW-004": ("SEC-010",),
    "CF-APIGW-005": ("REL-006",),
    "CF-APIGW-V2-004": ("REL-006",),
    "CF-APIGW-006": ("REL-028",),
    "CF-APIGW-008": ("PERF-004",),
    "CF-APIGW-V2-002": ("OPS-003",),
    "CF-LAM-002": ("OPS-003",),
    # Reports every function without a DLQ, a superset of REL-003 (no DLQ and no onFailure).
    "CF-LAM-001": ("REL-003",),
    "CF-LAM-004": ("SEC-057",),
    "CF-LAM-005": ("SEC-017", "BP-002"),
    "CF-LAM-006": ("REL-027",),
    "CF-LAM-007": ("REL-009",),
    "CF-RDS-002": ("REL-002",),
    "CF-RDS-004": ("SEC-064",),
    "CF-RDS-005": ("REL-030",),
    "CF-RDS-006": ("SEC-021",),
    "CF-RDS-007": ("OPS-009",),
    "CF-RDS-014": ("COST-010",),
    "CF-S3-003": ("REL-031",),
    "CF-KMS-001": ("SEC-007",),
    "CF-KMS-002": ("SEC-023",),
    "CF-SSM-001": ("SEC-033",),
    # Checks every ELBv2 load balancer, so NLBs too.
    "CF-ALB-001": ("OPS-006",),
    "CF-ALB-002": ("SEC-011",),
    "CF-ALB-003": ("SEC-012",),
    "CF-ALB-007": ("REL-007",),
    # COST-006 is a NAT gateway with no VPC endpoints: CF-COST-002 reports every NAT
    # gateway, and CF-VPC-002/003 the missing S3 and DynamoDB gateway endpoints.
    "CF-COST-002": ("COST-006",),
    "CF-VPC-002": ("COST-006",),
    "CF-VPC-003": ("COST-006",),
}

# Template checks that name a CDK rule's control but cover only part of it, so the CDK
# finding stays. Each value is (CDK rules, why the pair is not in CF_COVERS_STATIC).
CF_PARTLY_COVERS_STATIC: dict[str, tuple[tuple[str, ...], str]] = {
    "CF-RDS-003": (("REL-001",), "checks DB instances only; REL-001 also flags DatabaseCluster"),
    "CF-PERF-001": (("PERF-001",), "checks Lambda only; PERF-001 also flags EC2 and ECS"),
    "CF-PERF-002": (("PERF-002",), "API Gateway and Lambda only; PERF-002 also counts load "
                    "balancers, API caches and DAX"),
    "CF-PERF-003": (("PERF-008",), "RDS only; PERF-008 matches any large instanceType"),
    "CF-PERF-004": (("PERF-008",), "EC2 only; PERF-008 matches any large instanceType"),
    "CF-SUST-001": (("SUST-001",), "Auto Scaling groups only; SUST-001 also flags EC2 "
                    "instances and ECS services"),
    "CF-SUST-002": (("SUST-001",), "Fargate only; SUST-001 also flags EC2 instances"),
    "CF-SUST-003": (("SUST-001",), "launch templates only; SUST-001 also flags ECS services"),
    "CF-CT-001": (("OPS-001",), "checks an existing trail; OPS-001 reports no trail at all"),
    "CF-CT-002": (("OPS-001",), "checks an existing trail; OPS-001 reports no trail at all"),
    "CF-CT-003": (("OPS-001",), "checks an existing trail; OPS-001 reports no trail at all"),
    "CF-NACL-001": (("SEC-055",), "checks ACL entries that open 22 or 3389; SEC-055 reports a "
                    "VPC with no custom network ACL"),
    # Not a gap: tag_policy.REPLACED_STATIC_RULES drops BP-001 once the policy ran.
    "CF-TAG-001": (("BP-001",), "replaced through tag_policy.REPLACED_STATIC_RULES"),
}


def _is_large_instance_class(instance_class: Any) -> bool:
    """True if instance class suggests right-sizing review (xlarge, 2xlarge, etc.)."""
    if not instance_class or not isinstance(instance_class, str):
        return False
    s = instance_class.lower()
    return (
        "2xlarge" in s or "4xlarge" in s or "8xlarge" in s
        or "12xlarge" in s or "16xlarge" in s or "24xlarge" in s
        or s.endswith("xlarge")
    )


def _is_intrinsic(value: dict) -> bool:
    """True when every key is Ref or Fn::*, so the value is not a literal map."""
    if not value:
        return False
    return all(isinstance(key, str) and (key == "Ref" or key.startswith("Fn::")) for key in value)


def _redrive_has_dlq(redrive: Any) -> bool | None:
    """True when a dead-letter target is set, False when absent, None when unresolved."""
    if isinstance(redrive, str):
        try:
            parsed = json.loads(redrive)
        except json.JSONDecodeError:
            return None
        return _redrive_has_dlq(parsed)
    if not isinstance(redrive, dict):
        return None
    if "deadLetterTargetArn" in redrive or "DeadLetterTargetArn" in redrive:
        return True
    if _is_intrinsic(redrive):
        return None
    return False


_DISABLED_SSE = frozenset({"NONE", "DISABLED", "UNENCRYPTED"})


def _s3_encryption_disabled(enc: Any) -> bool:
    """True when the template opts out of encryption. Omission is the SSE-S3 default."""
    if not isinstance(enc, dict):
        return False
    configs = enc.get("ServerSideEncryptionConfiguration")
    if isinstance(configs, dict):
        configs = [configs]
    if not isinstance(configs, list):
        return False
    for item in configs:
        if not isinstance(item, dict):
            continue
        default = item.get("ServerSideEncryptionByDefault")
        if not isinstance(default, dict):
            continue
        algorithm = default.get("SSEAlgorithm")
        if isinstance(algorithm, str) and algorithm.strip().upper() in _DISABLED_SSE:
            return True
    return False


def _backup_retention_missing(value: Any) -> bool:
    """Zero days disables backups. An unresolved intrinsic is not treated as zero."""
    if value is None:
        return True
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, str):
        return value.strip() == "0"
    return False


def _port_in_sensitive(from_port: Any, to_port: Any) -> bool:
    """True if the port range overlaps any sensitive port."""
    if from_port is None or to_port is None:
        return True
    try:
        f, t = int(from_port), int(to_port)
        return any(f <= p <= t for p in SENSITIVE_PORTS)
    except (TypeError, ValueError):
        return True


def _read_template(path: Path) -> tuple[dict, str | None]:
    """Parse one template. A bad file is an error string, not an empty template."""
    if not path.is_file():
        return {}, f"Template file not found: {path}"
    try:
        text = path.read_text(encoding="utf-8")
        doc = parse_template_text(path, text) or {}
    except Exception as exc:
        return {}, f"Failed to parse template {path.name}: {exc}"
    if not isinstance(doc, dict):
        return {}, f"Template {path.name} is not an object"
    return doc, None


# Canonical types with per-resource checks (the rest only feed template-level counts).
_PER_RESOURCE_TYPES = frozenset({
    "s3_bucket", "db_instance", "rds_cluster", "instance", "lb", "cloudtrail", "kms_key",
    "lambda_function", "dynamodb_table", "security_group", "security_group_ingress_rule",
    "cloudwatch_log_group", "sqs_queue", "api_gateway_stage", "apigatewayv2_stage",
    "autoscaling_group", "ecs_service", "eks_cluster",
    "iam_policy", "iam_role", "iam_user", "iam_group",
    "resource_policy", "ecr_repository", "lambda_permission",
    "sns_topic", "ebs_volume", "efs_file_system", "kinesis_stream",
    "elasticache_replication_group", "launch_template",
    "opensearch_domain", "redshift_cluster", "docdb_cluster", "neptune_cluster", "msk_cluster",
    "cloudfront_distribution", "subnet", "ecs_task_definition",
    "secretsmanager_secret", "cognito_user_pool", "eip", "launch_configuration",
    "elasticache_cluster", "scalable_target",
    "security_group_egress_rule", "network_acl_entry", "network_acl", "transit_gateway",
    "lb_listener", "lb_target_group", "elb", "lambda_url",
    "sfn_state_machine", "events_rule", "events_target", "event_bus", "event_bus_policy",
})
# Parameter groups only feed CF-RDS-006; they have no checks of their own.


# Properties each per-resource check reads. A finding is dropped when any of them is unresolved.
CHECK_PROPERTIES: dict[str, frozenset[str]] = {
    check_id: frozenset(props) for check_id, props in {
        "CF-S3-001": {"PublicAccessBlockConfiguration"},
        "CF-S3-002": {"BucketEncryption"},
        "CF-S3-003": {"VersioningConfiguration"},
        "CF-S3-004": {"LoggingConfiguration"},
        "CF-S3-005": {"BucketPolicy"},
        "CF-RDS-001": {"StorageEncrypted", "DBClusterIdentifier"},
        "CF-RDS-002": {"BackupRetentionPeriod", "DBClusterIdentifier"},
        "CF-RDS-003": {"MultiAZ", "DBClusterIdentifier"},
        "CF-RDS-005": {"DeletionProtection", "DBClusterIdentifier"},
        "CF-RDS-004": {"PubliclyAccessible"},
        "CF-RDS-006": set(),  # _ssl_enforced reads the group and skips what it cannot read
        "CF-RDS-007": {"MonitoringInterval"},
        "CF-RDS-008": {"EnableIAMDatabaseAuthentication", "Engine", "DBClusterIdentifier"},
        "CF-RDS-009": {"AutoMinorVersionUpgrade"},
        "CF-RDS-010": {"CopyTagsToSnapshot", "DBClusterIdentifier", "Engine"},
        "CF-RDS-011": {"EnableCloudwatchLogsExports", "DBClusterIdentifier", "Engine"},
        "CF-RDS-012": {"Port", "Engine", "DBClusterIdentifier", "SnapshotIdentifier"},
        "CF-RDS-013": {"MasterUsername", "Engine", "DBClusterIdentifier"},
        "CF-RDS-014": {"DBInstanceClass", "DBClusterInstanceClass", "Engine"},
        "CF-PERF-003": {"DBInstanceClass"},
        "CF-PERF-004": {"InstanceType"},
        "CF-EC2-001": {"MetadataOptions", "LaunchTemplate", "LaunchTemplateData"},
        "CF-ALB-001": {"LoadBalancerAttributes"},
        "CF-ALB-002": {"Protocol", "DefaultActions"},
        "CF-ALB-003": {"Protocol", "SslPolicy"},
        "CF-ALB-004": {"LoadBalancerAttributes", "Type"},
        "CF-ALB-005": {"LoadBalancerAttributes"},
        "CF-ALB-006": {"LoadBalancerAttributes", "Type"},
        "CF-ALB-007": {"Protocol", "TargetType", "HealthCheckEnabled", "HealthCheckPath"},
        "CF-CLB-001": {"Listeners"},
        "CF-CLB-002": {"Listeners"},
        "CF-CLB-003": {"AccessLoggingPolicy"},
        "CF-CLB-004": {"CrossZone"},
        "CF-CLB-005": {"ConnectionDrainingPolicy"},
        "CF-CT-001": {"EnableLogFileValidation"},
        "CF-CT-002": {"IsMultiRegionTrail"},
        "CF-CT-003": {"KmsKeyId"},
        "CF-KMS-001": {"KeyPolicy"},
        "CF-SNS-001": {"KmsMasterKeyId"},
        "CF-EBS-001": {"Encrypted", "SnapshotId", "BlockDeviceMappings"},
        "CF-EFS-001": {"Encrypted"},
        "CF-KIN-001": {"StreamEncryption"},
        "CF-EC-001": {"AtRestEncryptionEnabled", "Engine"},
        "CF-EC-002": {"TransitEncryptionEnabled"},
        "CF-OS-001": {"EncryptionAtRestOptions"},
        "CF-OS-002": {"NodeToNodeEncryptionOptions"},
        "CF-RS-001": {"Encrypted", "SnapshotIdentifier"},
        "CF-DOCDB-001": {"StorageEncrypted", "SnapshotIdentifier"},
        "CF-NEP-001": {"StorageEncrypted", "SnapshotIdentifier", "SourceDBClusterIdentifier"},
        "CF-MSK-001": {"EncryptionInfo"},
        "CF-RP-001": {
            "PolicyDocument", "RepositoryPolicyText", "Policy", "Statement", "Condition",
            "Principal", "SourceArn", "SourceAccount", "PrincipalOrgID", "FunctionUrlAuthType",
        },
        "CF-LAM-001": {"DeadLetterConfig"},
        "CF-LAM-002": {"TracingConfig"},
        "CF-LAM-003": {"Runtime", "PackageType"},
        "CF-LAM-004": {"AuthType"},
        "CF-LAM-005": {"Environment"},
        "CF-LAM-006": {"ReservedConcurrentExecutions"},
        # Template-level: they read Timeout, VpcConfig and references and skip the unknown.
        "CF-LAM-007": set(),
        "CF-LAM-008": set(),
        "CF-CF-001": {"DistributionConfig"},
        "CF-CF-002": {"DistributionConfig"},
        "CF-CF-003": {"DistributionConfig"},
        "CF-CF-004": {"DistributionConfig"},
        # Reads DBClusterIdentifier on instances only; _deletion_finding checks it.
        "CF-DEL-001": set(),
        "CF-SM-001": set(),  # judged on the template's rotation schedules
        "CF-EBS-002": {"VolumeType"},  # Size only feeds the estimate
        "CF-EIP-001": {"InstanceId", "NetworkInterfaceId", "PublicIpv4Pool"},
        "CF-TAG-001": set(),  # tag_policy reads Tags and skips unreadable ones itself
        "CF-GEN-001": set(),  # reads only literal types; an unknown one is absent, not judged
        "CF-S3-006": {"LifecycleConfiguration"},
        "CF-S3-007": {"LifecycleConfiguration", "IntelligentTieringConfigurations"},
        "CF-DDB-003": {"BillingMode"},
        "CF-COG-001": {"MfaConfiguration"},
        "CF-COG-002": {"Policies"},
        "CF-COG-003": {"UserPoolAddOns", "UserPoolTier"},
        "CF-ECR-001": {"ImageScanningConfiguration"},
        "CF-ECR-002": {"ImageTagMutability"},
        "CF-ECR-003": {"LifecyclePolicy"},
        "CF-ECS-001": {"ContainerDefinitions"},
        "CF-ECS-002": {"ContainerDefinitions", "RuntimePlatform"},
        "CF-ECS-003": {"ContainerDefinitions", "RuntimePlatform"},
        "CF-EC2-002": {"MapPublicIpOnLaunch"},
        "CF-EC2-003": {"NetworkInterfaces"},
        "CF-WAF-001": {"Type", "Scheme"},
        "CF-PERF-001": {"Architectures"},
        "CF-DDB-001": {"PointInTimeRecoverySpecification"},
        "CF-DDB-002": {"SSESpecification"},
        "CF-SG-001": {"SecurityGroupIngress", "CidrIp", "CidrIpv6", "FromPort", "ToPort"},
        "CF-SG-002": {"SecurityGroupIngress", "CidrIp", "CidrIpv6", "FromPort", "ToPort", "IpProtocol"},
        "CF-SG-003": {"SecurityGroupEgress", "CidrIp", "CidrIpv6", "FromPort", "ToPort", "IpProtocol"},
        "CF-NACL-001": {"Entries", "Egress", "RuleAction", "CidrBlock", "Ipv6CidrBlock",
                        "Protocol", "PortRange"},
        "CF-TGW-001": {"AutoAcceptSharedAttachments"},
        # Template-level: they read AZs and references and skip what they cannot read.
        "CF-NAT-001": set(),
        "CF-TGW-002": set(),
        "CF-CW-001": {"RetentionInDays"},
        "CF-CW-002": {"KmsKeyId"},
        "CF-SQS-001": {"SqsManagedSseEnabled", "KmsMasterKeyId"},
        "CF-SQS-002": {"RedrivePolicy"},
        "CF-APIGW-001": {"AccessLogSetting"},
        "CF-APIGW-002": {"TracingEnabled"},
        "CF-APIGW-V2-001": {"AccessLogSettings"},
        "CF-APIGW-V2-002": {"TracingEnabled"},
        # Template-level: _error_handling_findings skips what it cannot read.
        **{c: set() for c in ("CF-SFN-001", "CF-SFN-002", "CF-SFN-003", "CF-EB-001", "CF-EB-002",
                              "CF-SQS-003")},
        # Template-level: _warehouse_findings skips what it cannot read.
        **{c: set() for c in ("CF-RS-002", "CF-RS-003", "CF-RS-004", "CF-RS-005", "CF-RS-006", "CF-RS-007",
                              "CF-DOCDB-002", "CF-DOCDB-003", "CF-DOCDB-004", "CF-NEP-002", "CF-NEP-003",
                              "CF-NEP-004", "CF-NEP-005")},
        # Template-level: _search_streaming_findings skips what it cannot read.
        **{c: set() for c in ("CF-OS-003", "CF-OS-004", "CF-OS-005", "CF-OS-006", "CF-OS-007",
                              "CF-MSK-002", "CF-MSK-003", "CF-KIN-002")},
        # Template-level: _kms_ssm_findings skips what it cannot read.
        **{c: set() for c in ("CF-KMS-002", "CF-KMS-003", "CF-SSM-001", "CF-SSM-002")},
        # Template-level: _ci_cd_findings skips what it cannot read.
        **{c: set() for c in ("CF-CB-001", "CF-CB-002", "CF-CB-003", "CF-CB-004", "CF-CB-005",
                              "CF-CP-001", "CF-CP-002", "CF-CP-003")},
        # Template-level: _api_gateway_findings skips what it cannot read.
        **{c: set() for c in ("CF-APIGW-003", "CF-APIGW-004", "CF-APIGW-005", "CF-APIGW-006",
                              "CF-APIGW-007", "CF-APIGW-008", "CF-APIGW-009", "CF-APIGW-V2-003",
                              "CF-APIGW-V2-004")},
        "CF-SUST-001": {"MixedInstancesPolicy"},
        "CF-SUST-002": {"CapacityProviderStrategy", "LaunchType"},
        "CF-EKS-001": {"Logging"},
        "CF-IAM-001": {"PolicyDocument", "Policies"},
        "CF-IAM-002": {"PolicyDocument", "Policies"},
        "CF-IAM-003": {"PolicyDocument", "Policies"},
        # Known admin access stays admin whatever else is unknown, so nothing drops it.
        "CF-IAM-008": set(),
        "CF-IAM-004": {"AssumeRolePolicyDocument"},
        "CF-IAM-005": {"AssumeRolePolicyDocument"},
        "CF-IAM-006": {"AssumeRolePolicyDocument"},
        "CF-IAM-007": {"AssumeRolePolicyDocument"},
        "CF-EKS-002": {"ResourcesVpcConfig"},
        "CF-EKS-003": {"EncryptionConfig"},
    }.items()
}


# Themes of each template check. Every check the module can emit is listed;
# tests/test_themes.py fails when one is missing.
_F, _SB, _ID, _DP, _NET, _RES, _OBS, _SUS = (
    "finops", "security-baseline", "identity", "data-protection",
    "network-exposure", "resilience", "observability", "sustainability",
)
CF_THEMES: dict[str, tuple[str, ...]] = {
    "CF-ALB-001": (_OBS,), "CF-ALB-002": (_DP, _NET), "CF-ALB-003": (_DP, _NET),
    "CF-ALB-004": (_NET,), "CF-ALB-005": (_RES,), "CF-ALB-006": (_NET,), "CF-ALB-007": (_RES,),
    "CF-CLB-001": (_DP, _NET), "CF-CLB-002": (_DP,), "CF-CLB-003": (_OBS,), "CF-CLB-004": (_RES,),
    "CF-CLB-005": (_RES,), "CF-APIGW-001": (_OBS,), "CF-APIGW-002": (_OBS,),
    "CF-APIGW-V2-001": (_OBS,), "CF-APIGW-V2-002": (_OBS,),
    "CF-APIGW-003": (_ID, _NET), "CF-APIGW-004": (_DP, _NET), "CF-APIGW-005": (_RES,),
    "CF-APIGW-006": (_RES,), "CF-APIGW-007": (_DP,), "CF-APIGW-008": (_F,), "CF-APIGW-009": (_ID,),
    "CF-APIGW-V2-003": (_ID, _NET), "CF-APIGW-V2-004": (_RES,),
    "CF-CB-001": (_DP, _ID), "CF-CB-002": (_DP, _ID), "CF-CB-003": (_SB,), "CF-CB-004": (_OBS,),
    "CF-CB-005": (_OBS, _DP), "CF-CP-001": (_DP,), "CF-CP-002": (_RES,), "CF-CP-003": (_OBS,),
    "CF-CF-001": (_DP, _NET), "CF-CF-002": (_DP, _NET), "CF-CF-003": (_NET,), "CF-CF-004": (_NET, _ID),
    "CF-COG-001": (_ID,), "CF-COG-002": (_ID,), "CF-COG-003": (_ID,),
    "CF-COST-002": (_F,), "CF-CT-001": (_OBS, _SB), "CF-CT-002": (_OBS,), "CF-CT-003": (_OBS, _DP),
    "CF-CW-001": (_F, _DP), "CF-CW-002": (_DP,),
    "CF-DDB-001": (_RES, _DP), "CF-DDB-002": (_DP,), "CF-DEL-001": (_DP, _RES), "CF-DOCDB-001": (_DP,),
    "CF-EBS-001": (_DP,), "CF-EBS-002": (_F,), "CF-EC-001": (_DP,), "CF-EC-002": (_DP,),
    "CF-EC2-001": (_SB, _ID), "CF-EC2-002": (_NET,), "CF-EC2-003": (_NET,),
    "CF-ECR-001": (_SB,), "CF-ECR-002": (_SB,), "CF-ECR-003": (_SB, _F),
    "CF-ECS-001": (_SB,), "CF-ECS-002": (_SB,), "CF-ECS-003": (_SB,), "CF-EFS-001": (_DP,),
    "CF-EIP-001": (_F,), "CF-EKS-001": (_OBS,), "CF-EKS-002": (_NET,), "CF-EKS-003": (_DP,),
    "CF-ENV-001": (_F,), "CF-ENV-002": (_F,), "CF-ENV-003": (_F,), "CF-ENV-004": (_F,),
    "CF-ENV-005": (_F,), "CF-ENV-006": (_F,), "CF-FL-001": (_OBS, _NET),
    "CF-GEN-001": (_F, _SUS), "CF-IAM-001": (_ID,), "CF-IAM-002": (_ID,), "CF-IAM-003": (_ID,),
    "CF-IAM-004": (_ID,), "CF-IAM-005": (_ID,), "CF-IAM-006": (_ID,), "CF-IAM-007": (_ID,),
    "CF-IAM-008": (_ID,), "CF-KIN-001": (_DP,), "CF-KMS-001": (_ID, _DP),
    "CF-RS-002": (_NET,), "CF-RS-003": (_RES,), "CF-RS-004": (_OBS,), "CF-RS-005": (_SB,),
    "CF-RS-006": (_NET,), "CF-RS-007": (_SB,), "CF-DOCDB-002": (_RES,), "CF-DOCDB-003": (_OBS,),
    "CF-DOCDB-004": (_RES, _DP), "CF-NEP-002": (_OBS,), "CF-NEP-003": (_RES, _DP), "CF-NEP-004": (_RES,),
    "CF-NEP-005": (_ID,),
    "CF-KIN-002": (_RES,), "CF-MSK-002": (_ID,), "CF-MSK-003": (_NET,), "CF-OS-003": (_NET,),
    "CF-OS-004": (_ID,), "CF-OS-005": (_DP, _NET), "CF-OS-006": (_OBS,), "CF-OS-007": (_RES,),
    "CF-KMS-002": (_DP,), "CF-KMS-003": (_RES,), "CF-SSM-001": (_DP,), "CF-SSM-002": (_F,),
    "CF-LAM-001": (_RES,), "CF-LAM-002": (_OBS,), "CF-LAM-003": (_SB,),
    "CF-LAM-004": (_ID, _NET), "CF-LAM-005": (_DP, _ID), "CF-LAM-006": (_RES,),
    "CF-LAM-007": (_RES,), "CF-LAM-008": (_RES,),
    "CF-MSK-001": (_DP,), "CF-NEP-001": (_DP,), "CF-OS-001": (_DP,), "CF-OS-002": (_DP,),
    "CF-PAR-001": (_DP, _ID), "CF-PAR-002": (_DP, _ID),
    "CF-PERF-001": (_F, _SUS), "CF-PERF-002": (_RES,), "CF-PERF-003": (_F,), "CF-PERF-004": (_F,),
    "CF-RDS-001": (_DP,), "CF-RDS-002": (_RES, _DP), "CF-RDS-003": (_RES,), "CF-RDS-004": (_NET,),
    "CF-RDS-006": (_DP, _NET), "CF-RDS-007": (_OBS,), "CF-RDS-008": (_ID,), "CF-RDS-009": (_SB,),
    "CF-RDS-010": (_F,), "CF-RDS-011": (_OBS,), "CF-RDS-012": (_NET,), "CF-RDS-013": (_ID,),
    "CF-RDS-014": (_F, _SUS),
    "CF-RDS-005": (_RES, _DP), "CF-RP-001": (_ID, _NET), "CF-RS-001": (_DP,),
    "CF-S3-001": (_NET, _DP), "CF-S3-002": (_DP,), "CF-S3-003": (_RES, _DP), "CF-S3-004": (_OBS,),
    "CF-S3-006": (_F, _DP), "CF-S3-007": (_F,), "CF-DDB-003": (_F, _RES),
    "CF-S3-005": (_DP, _NET), "CF-SG-001": (_NET,), "CF-SG-002": (_NET,), "CF-SG-003": (_NET,),
    "CF-NACL-001": (_NET,), "CF-NAT-001": (_RES,), "CF-TGW-001": (_NET, _ID), "CF-TGW-002": (_OBS, _NET), "CF-SM-001": (_DP, _ID), "CF-SNS-001": (_DP,),
    "CF-SFN-001": (_RES,), "CF-SFN-002": (_OBS,), "CF-SFN-003": (_OBS,), "CF-EB-001": (_OBS, _RES),
    "CF-EB-002": (_RES,), "CF-SQS-003": (_RES,),
    "CF-SQS-001": (_DP,), "CF-SQS-002": (_RES,),
    "CF-SUST-001": (_SUS, _F), "CF-SUST-002": (_SUS, _F), "CF-SUST-003": (_SUS, _F),
    "CF-TAG-001": (_F,), "CF-VPC-001": (_NET, _F), "CF-VPC-002": (_F,), "CF-VPC-003": (_F,), "CF-WAF-001": (_NET,),
}


def _imds_finding(res: Resource, template_path: Path, options: Any, defers: bool) -> Finding | None:
    """CF-EC2-001 for one instance or launch template.

    options: the MetadataOptions object. defers: an instance that takes its metadata
    settings from a launch template (that template is checked on its own).
    Only literal values are judged: an intrinsic or variable gives no finding.
    """
    if options is not None and (not isinstance(options, dict) or _is_intrinsic(options)):
        return None
    options = options or {}
    tokens = options.get("HttpTokens")
    endpoint = options.get("HttpEndpoint")
    if endpoint == "disabled" or tokens == "required":
        return None
    if endpoint is not None and type(endpoint) is not str:
        return None  # endpoint from a variable or intrinsic: it may be disabled
    if tokens is None:
        if defers:
            return None
        severity: Severity = "Medium"
        detail = (
            "MetadataOptions.HttpTokens is not set. The instance then requires IMDSv2 only "
            "if its AMI declares ImdsSupport v2.0 or the account default requires it."
        )
    elif type(tokens) is str and tokens == "optional":
        severity = "High"
        detail = "MetadataOptions.HttpTokens is optional, so IMDSv1 requests are accepted."
    else:
        return None
    return Finding(
        id="CF-EC2-001",
        title="EC2 instance metadata does not require IMDSv2",
        severity=severity,
        category="Security",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            f"{detail} With IMDSv1, an SSRF bug in the workload can read the instance role's "
            "credentials. Set HttpTokens: required. "
            "In CDK: set requireImdsv2: true, or apply InstanceRequireImdsv2Aspect to the app."
        ),
    )
_IAM_TYPES = frozenset({"iam_policy", "iam_role", "iam_user", "iam_group"})

# CloudFront security policies, oldest first. Below TLSv1.2_2021 allows weak TLS or ciphers.
_CLOUDFRONT_TLS = (
    "SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016", "TLSv1.2_2018", "TLSv1.2_2019",
    "TLSv1.2_2021", "TLSv1.2_2025", "TLSv1.3_2025",
)
_CLOUDFRONT_TLS_MIN = _CLOUDFRONT_TLS.index("TLSv1.2_2021")


def _cloudfront_findings(res: Resource, template_path: Path) -> List[Finding]:
    """CF-CF-001 (allow-all behavior), CF-CF-002 (old TLS policy), CF-CF-003 (no WebACLId),
    CF-CF-004 (S3 origin without Origin Access Control).

    Only literal values are judged. The default *.cloudfront.net certificate is not given
    a TLS finding: its minimum protocol cannot be set.
    """
    config = res.properties.get("DistributionConfig")
    if not isinstance(config, dict) or _is_intrinsic(config):
        return []
    out: List[Finding] = []

    def add(fid: str, severity: Severity, title: str, recommendation: str) -> None:
        out.append(Finding(
            id=fid, title=title, severity=severity, category="Security",
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    behaviors = [("default", config.get("DefaultCacheBehavior"))]
    extra = config.get("CacheBehaviors")
    for item in extra if isinstance(extra, list) else []:
        path = item.get("PathPattern") if isinstance(item, dict) else None
        behaviors.append((path if type(path) is str else "a path", item))
    open_paths = [
        name for name, b in behaviors
        if isinstance(b, dict) and b.get("ViewerProtocolPolicy") == "allow-all"
    ]
    if open_paths:
        add("CF-CF-001", "Medium", "CloudFront behavior allows plain HTTP",
            f"Behaviors with ViewerProtocolPolicy allow-all: {', '.join(open_paths)}. "
            "Set redirect-to-https or https-only (Security Hub CloudFront.3). "
            "In CDK: viewerProtocolPolicy: ViewerProtocolPolicy.REDIRECT_TO_HTTPS.")

    cert = config.get("ViewerCertificate")
    if isinstance(cert, dict) and not _is_intrinsic(cert) and _flag(cert.get("CloudFrontDefaultCertificate")) is False:
        version = cert.get("MinimumProtocolVersion", "TLSv1")  # the default with your own certificate
        if type(version) is str and version in _CLOUDFRONT_TLS and _CLOUDFRONT_TLS.index(version) < _CLOUDFRONT_TLS_MIN:
            add("CF-CF-002", "Medium", "CloudFront allows TLS older than TLSv1.2_2021",
                f"MinimumProtocolVersion is {version}. Set TLSv1.2_2021 or newer "
                "(Security Hub CloudFront.15). "
                "In CDK: minimumProtocolVersion: SecurityPolicyProtocol.TLS_V1_2_2021.")

    if config.get("WebACLId") is None:
        add("CF-CF-003", "Low", "CloudFront distribution has no WAF web ACL",
            "Set WebACLId to an AWS WAF web ACL (scope CLOUDFRONT) to filter common attacks "
            "(Security Hub CloudFront.6). In CDK: webAclId on the Distribution.")
    out.extend(_s3_origin_findings(res, template_path, config))
    return out


# S3 REST endpoints: bucket.s3.amazonaws.com, bucket.s3.eu-north-1.amazonaws.com,
# bucket.s3-eu-north-1.amazonaws.com, bucket.s3.dualstack.eu-north-1.amazonaws.com.
_S3_REST_DOMAIN = re.compile(r"\.s3(?:[.-][a-z0-9-]+){0,2}\.amazonaws\.com(?:\.cn)?$", re.IGNORECASE)
# Website endpoints (bucket.s3-website-eu-north-1..., bucket.s3-website.eu-north-1...) cannot use OAC.
_S3_WEBSITE_DOMAIN = re.compile(r"\.s3-website[.-]", re.IGNORECASE)
# Terraform bucket attributes that are an S3 REST domain.
_S3_DOMAIN_ATTR = re.compile(r"\baws_s3_bucket\.[\w-]+\.bucket(?:_regional)?_domain_name\b")


def _is_s3_origin(origin: dict) -> bool:
    domain = origin.get("DomainName")
    if isinstance(domain, str) and _S3_WEBSITE_DOMAIN.search(domain):
        return False
    if origin.get("S3OriginConfig") is not None:
        return True
    # A Terraform expression is a str subclass: a template string or a bucket attribute.
    return isinstance(domain, str) and (
        _S3_REST_DOMAIN.search(domain) is not None or _S3_DOMAIN_ATTR.search(domain) is not None
    )


def _s3_origin_access(origin: dict) -> str | None:
    """"oac", "oai", "none", or None when unknown, for one S3 origin."""
    if origin.get("OriginAccessControlId") not in (None, ""):
        return "oac"
    config = origin.get("S3OriginConfig")
    if isinstance(config, dict) and _is_intrinsic(config):
        return None
    oai = config.get("OriginAccessIdentity") if isinstance(config, dict) else None
    if isinstance(oai, dict) and "Fn::Unresolved" in oai:  # a Terraform variable: unknown
        return None
    if oai not in (None, ""):
        return "oai"
    return "none"


def _s3_origin_findings(res: Resource, template_path: Path, config: dict) -> List[Finding]:
    """CF-CF-004: an S3 origin without Origin Access Control (Medium), or with only a
    legacy Origin Access Identity (Low)."""
    origins = config.get("Origins")
    by_access: dict[str, list[str]] = {}
    for i, origin in enumerate(origins if isinstance(origins, list) else []):
        if not isinstance(origin, dict) or _is_intrinsic(origin) or not _is_s3_origin(origin):
            continue
        access = _s3_origin_access(origin)
        if access in ("oai", "none"):
            name = origin.get("Id")
            by_access.setdefault(access, []).append(name if type(name) is str else f"origin {i + 1}")
    if not by_access:
        return []
    # One finding per distribution: findings are deduplicated on id, file and evidence.
    none, oai = by_access.get("none", []), by_access.get("oai", [])
    parts = []
    if none:
        parts.append(f"No OAC or OAI on origins: {', '.join(none)}; the bucket must then be "
                     "public for CloudFront to read it.")
    if oai:
        parts.append(f"Legacy OAI on origins: {', '.join(oai)}; OAI does not support SSE-KMS "
                     "or newer Regions.")
    return [Finding(
        id="CF-CF-004",
        title=("CloudFront S3 origin has no Origin Access Control" if none
               else "CloudFront S3 origin uses a legacy Origin Access Identity"),
        severity="Medium" if none else "Low",
        category="Security",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            " ".join(parts)
            + " Create an AWS::CloudFront::OriginAccessControl, set OriginAccessControlId on the "
            "origin, and allow cloudfront.amazonaws.com with aws:SourceArn of the distribution "
            "in the bucket policy (Security Hub CloudFront.13). "
            "In CDK: origins.S3BucketOrigin.withOriginAccessControl(bucket)."
        ),
    )]


def _references(text: str, name: str) -> bool:
    """True when a dumped ResourceArn refers to a resource by logical id or Terraform address."""
    if "." in name:  # Terraform address: aws_lb.app -> aws_lb.app.arn, aws_lb.app[0].arn
        return re.search(rf"(?<![\w.]){re.escape(name)}(?:\[[^\]]*\])?\.", text) is not None
    return f'"{name}"' in text or f"${{{name}}}" in text or f"${{{name}." in text


def _waf_coverage(resources: List[Resource]) -> tuple[set[str], bool]:
    """Names of ALBs and API stages a WAF association in this template points at.

    The second value is True when an association points at something the scan cannot
    tie to a resource: it may then cover any of them.
    """
    targets = [r.name for r in resources if r.type in ("lb", "api_gateway_stage")]
    covered: set[str] = set()
    unlinked = False
    for r in resources:
        if r.type != "waf_association":
            continue
        arn = r.properties.get("ResourceArn")
        text = arn if type(arn) is str else json.dumps(arn, default=str)
        hits = {name for name in targets if _references(text, name)}
        covered |= hits
        unlinked = unlinked or not hits
    return covered, unlinked


def _rotation_coverage(resources: List[Resource]) -> tuple[set[str], bool]:
    """Names of secrets a rotation schedule in this template points at.

    A schedule points at a secret by Ref / Terraform address, or by the secret's literal
    name. The second value is True when a schedule points at something the scan cannot
    tie to a secret: it may then rotate any of them.
    """
    secrets = [r for r in resources if r.type == "secretsmanager_secret"]
    covered: set[str] = set()
    unlinked = False
    for r in resources:
        if r.type != "secretsmanager_secret_rotation":
            continue
        target = r.properties.get("SecretId")
        text = target if type(target) is str else json.dumps(target, default=str)
        hits = {s.name for s in secrets if _references(text, s.name) or _names_secret(target, s)}
        covered |= hits
        unlinked = unlinked or not hits
    return covered, unlinked


def _names_secret(target: Any, secret: Resource) -> bool:
    """A literal SecretId that is the secret's Name, or its ARN (which ends ':secret:<Name>-<6 chars>')."""
    name = secret.properties.get("Name")
    if type(target) is not str or type(name) is not str:
        return False
    return target == name or re.search(rf":secret:{re.escape(name)}-[A-Za-z0-9]{{6}}$", target) is not None


def _rotation_finding(res: Resource, template_path: Path) -> Finding:
    """CF-SM-001 for a secret that no rotation schedule in this template points at."""
    return Finding(
        id="CF-SM-001",
        title="Secrets Manager secret is not rotated",
        severity="Medium",
        category="Security",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            "No AWS::SecretsManager::RotationSchedule (Terraform aws_secretsmanager_secret_rotation) "
            "in this template points at it, so the secret keeps its value until someone changes "
            "it by hand (Security Hub SecretsManager.1). Add a rotation schedule with a rotation "
            "Lambda or a hosted rotation function. A secret for a third-party credential that "
            "cannot be rotated this way can exclude CF-SM-001. In CDK: secret.addRotationSchedule()."
        ),
    )


_PASSWORD_CLASSES = ("RequireLowercase", "RequireUppercase", "RequireNumbers", "RequireSymbols")


def _cognito_findings(res: Resource, template_path: Path) -> List[Finding]:
    """CF-COG-001 (MFA off), CF-COG-002 (weak password policy), CF-COG-003 (no threat protection)."""
    props = res.properties
    out: List[Finding] = []

    def add(fid: str, severity: Severity, title: str, recommendation: str) -> None:
        out.append(Finding(
            id=fid, title=title, severity=severity, category="Security",
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    mfa = props.get("MfaConfiguration")
    if mfa is None or mfa == "OFF":
        add("CF-COG-001", "High", "Cognito user pool does not use MFA",
            f"MfaConfiguration is {'not set (OFF)' if mfa is None else 'OFF'}, so a password alone "
            "signs a user in. Set it to ON, or to OPTIONAL with threat protection, and enable "
            "EnabledMfas (SOFTWARE_TOKEN_MFA). In CDK: mfa: cognito.Mfa.REQUIRED.")

    weak = _weak_password_policy(props.get("Policies"))
    if weak:
        add("CF-COG-002", "Medium", "Cognito password policy is weak",
            f"{weak} Set Policies.PasswordPolicy.MinimumLength to 12 or more and require "
            "lowercase, uppercase, numbers and symbols. "
            "In CDK: passwordPolicy with minLength: 12 and every require flag set to true.")

    add_ons = props.get("UserPoolAddOns")
    if add_ons is None:
        mode: Any = None
    elif isinstance(add_ons, dict) and not _is_intrinsic(add_ons):
        mode = add_ons.get("AdvancedSecurityMode")
    else:
        mode = "unknown"  # an intrinsic: not judged
    if mode is None or mode == "OFF":
        tier = props.get("UserPoolTier", "ESSENTIALS")
        plan = "" if type(tier) is not str or tier == "PLUS" else (
            "Threat protection needs the Plus feature plan (UserPoolTier: PLUS), which costs more "
            "per active user. ")
        add("CF-COG-003", "Low", "Cognito threat protection is off",
            "UserPoolAddOns.AdvancedSecurityMode is not set or OFF, so compromised-credential and "
            f"adaptive-authentication checks do not run. {plan}Set it to ENFORCED, or AUDIT to "
            "log risks first. In CDK: featurePlan: cognito.FeaturePlan.PLUS and "
            "standardThreatProtectionMode: cognito.StandardThreatProtectionMode.FULL_FUNCTION.")
    return out


def _weak_password_policy(policies: Any) -> str | None:
    """Why the password policy is weak, or None when it is strong or cannot be read.

    No PasswordPolicy means the Cognito default: 8 characters, every character class.
    Inside a PasswordPolicy, an unset class requirement is false.
    """
    if policies is not None and (not isinstance(policies, dict) or _is_intrinsic(policies)):
        return None
    policy = (policies or {}).get("PasswordPolicy")
    if policy is None:
        return "No PasswordPolicy is set, so Cognito requires only 8 characters."
    if not isinstance(policy, dict) or _is_intrinsic(policy):
        return None
    reasons = []
    length = policy.get("MinimumLength", 8)
    if type(length) is str and length.isdigit():
        length = int(length)
    if type(length) is int and length < 12:
        reasons.append(f"MinimumLength is {length}.")
    flags = {k: _flag(policy.get(k)) for k in _PASSWORD_CLASSES}
    if None not in flags.values():
        missing = [k for k, on in flags.items() if not on]
        if len(missing) == len(_PASSWORD_CLASSES):
            reasons.append("No character class is required.")
    return " ".join(reasons) or None


def _gp2_finding(res: Resource, template_path: Path) -> Finding | None:
    """CF-EBS-002: a volume on gp2, set or by default (AWS::EC2::Volume and aws_ebs_volume
    default to gp2). The estimate needs a literal Size; a volume sized by its snapshot has none."""
    volume_type = res.properties.get("VolumeType", "gp2")
    if volume_type != "gp2":
        return None  # another type, or an intrinsic
    finding = Finding(
        id="CF-EBS-002",
        title="EBS volume uses gp2 instead of gp3",
        severity="Low",
        category="Cost Optimization",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            ("VolumeType is gp2." if "VolumeType" in res.properties else "VolumeType is not set, so it is gp2.")
            + " gp3 costs about 20% less per GB and includes 3,000 IOPS and 125 MB/s at any "
            "size. Set VolumeType to gp3. Over 1,000 GiB, set Iops to keep the gp2 baseline "
            "(3 per GiB); over 170 GiB, set Throughput if the workload needs more than 125 MB/s. "
            "In CDK: volumeType: ec2.EbsDeviceVolumeType.GP3."
        ),
    )
    return estimates.apply(finding, estimates.gp2_volume(res.properties.get("Size")))


def _eips_in_use(resources: List[Resource]) -> set[str]:
    """Elastic IPs another resource in this template refers to (a NAT gateway's AllocationId,
    an EIPAssociation, a load balancer's SubnetMappings, ...), or that name their instance."""
    eips = [r for r in resources if r.type == "eip"]
    used = {e.name for e in eips if e.properties.get("InstanceId") or e.properties.get("NetworkInterfaceId")}
    for r in resources:
        if r.type == "eip":
            continue
        if r.source_type.startswith("AWS::"):
            text = json.dumps(r.properties, default=str)
            used |= {e.name for e in eips if _references(text, e.name)}
        else:
            used |= {e.name for e in eips if e.name in r.references}
    return used


def _eip_finding(res: Resource, template_path: Path) -> Finding | None:
    """CF-EIP-001: an Elastic IP nothing in this template uses. Public IPv4 addresses are
    billed by the hour attached or not; one from your own BYOIP pool is not."""
    pool = res.properties.get("PublicIpv4Pool")
    if pool is not None and pool != "amazon":
        return None
    finding = Finding(
        id="CF-EIP-001",
        title="Elastic IP is not used in this template",
        severity="Low",
        category="Cost Optimization",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            "No NAT gateway, instance, network interface, association or load balancer in this "
            "template uses it, and every public IPv4 address is billed by the hour. If nothing "
            "outside the template uses it either, release it."
        ),
    )
    return estimates.apply(finding, estimates.idle_public_ipv4())


def _autoscaled_tables(resources: List[Resource]) -> tuple[set[str], bool]:
    """DynamoDB tables an Application Auto Scaling target in this template scales.

    A target names its table in ResourceId (table/<name>): by Ref, Terraform address or the
    table's literal name. The second value is True when a DynamoDB target names something
    the scan cannot tie to a table: it may then scale any of them.
    """
    tables = [r for r in resources if r.type == "dynamodb_table"]
    covered: set[str] = set()
    unlinked = False
    for r in resources:
        if r.type != "scalable_target":
            continue
        namespace = r.properties.get("ServiceNamespace")
        if type(namespace) is str and namespace != "dynamodb":
            continue
        target = r.properties.get("ResourceId")
        text = target if type(target) is str else json.dumps(target, default=str)
        if "/index/" in text:
            continue  # scales a global secondary index, not the table's own capacity
        hits = {
            t.name for t in tables
            if _references(text, t.name) or t.name in r.references
            or (type(t.properties.get("TableName")) is str
                and re.search(rf"table/{re.escape(t.properties['TableName'])}(?:$|[\"/])", text) is not None)
        }
        covered |= hits
        unlinked = unlinked or not hits
    return covered, unlinked


# Services with a free gateway VPC endpoint: (service name suffix, check id, label).
_GATEWAY_SERVICES = (("s3", "CF-VPC-002", "S3"), ("dynamodb", "CF-VPC-003", "DynamoDB"))


def _endpoint_service(value: Any) -> str | None:
    """The service an endpoint's ServiceName names: "s3", "dynamodb", "" for another
    service, or None when the scan cannot tell (a Ref, a data source, a variable)."""
    if isinstance(value, dict) and len(value) == 1:
        fn, arg = next(iter(value.items()))
        if fn == "Fn::Sub":
            value = arg[0] if isinstance(arg, list) and arg else arg
        elif fn == "Fn::Join" and isinstance(arg, list) and len(arg) == 2 \
                and type(arg[0]) is str and isinstance(arg[1], list):
            value = arg[0].join(p if type(p) is str else "${x}" for p in arg[1])
    if not isinstance(value, str) or value.endswith("}"):
        return None
    match = re.search(r"\.(s3|dynamodb)$", value)
    if match:
        return match.group(1)
    # A service name ends in a literal segment: com.amazonaws.<region>.ec2, aws.sagemaker...
    return "" if re.match(r"^(?:com\.amazonaws|aws)\.", value) else None


def _endpoint_is_gateway(res: Resource) -> bool | None:
    """Gateway is the default type in CloudFormation and Terraform. None: not readable."""
    if "VpcEndpointType" in res.unresolved:
        return None
    kind = res.properties.get("VpcEndpointType", "Gateway")
    return kind.lower() == "gateway" if type(kind) is str else None


def _points_at(res: Resource, key: str, target: Resource) -> bool:
    """True when res refers to target: in property key (CloudFormation), or anywhere in
    the block (Terraform)."""
    if res.source_type.startswith("AWS::"):
        value = res.properties.get(key)
        text = value if type(value) is str else json.dumps(value, default=str)
        return _references(text, target.name)
    return target.name in res.references



# Engine family -> (default port, parameter that enforces TLS, values that turn it on).
_RDS_ENGINES: dict[str, tuple[int, str, tuple[str, ...]]] = {
    "aurora-postgresql": (5432, "rds.force_ssl", ("1",)),
    "aurora-mysql": (3306, "require_secure_transport", ("on", "1", "true")),
    "aurora": (3306, "require_secure_transport", ("on", "1", "true")),
    "postgres": (5432, "rds.force_ssl", ("1",)),
    "mysql": (3306, "require_secure_transport", ("on", "1", "true")),
    "mariadb": (3306, "require_secure_transport", ("on", "1", "true")),
    "sqlserver": (1433, "rds.force_ssl", ("1",)),
    "oracle": (1521, "", ()),  # TLS is an option group setting, not read
    "db2": (50000, "", ()),
}
# Engines with IAM database authentication and Graviton (db.*g) instance classes.
_RDS_OPEN_SOURCE = ("aurora", "mysql", "mariadb", "postgres")
_DEFAULT_DB_USERS = frozenset({"admin", "postgres", "root", "sa", "administrator", "master", "awsuser"})
_GRAVITON_CLASS = re.compile(r"^db\.[a-z]+\d+g[a-z]*\.")


def _rds_engine(props: dict) -> str | None:
    """The engine family key in _RDS_ENGINES, or None when unknown."""
    engine = props.get("Engine")
    if not isinstance(engine, str):
        return None
    engine = engine.strip().lower()
    for family in _RDS_ENGINES:  # aurora-* before aurora, before the plain engines
        if engine == family or engine.startswith(family + "-"):
            return family
    return None


def _major_version(value: Any) -> int | None:
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        match = re.match(r"\s*(\d+)", value)
        return int(match.group(1)) if match else None
    return None


def _ssl_enforced(res: Resource, family: str, param_groups: List[Resource]) -> bool | None:
    """True when the linked parameter group turns TLS on, False when it does not (or no
    group / a default group is linked), None when the group cannot be read.

    RDS for PostgreSQL 15 and later sets rds.force_ssl=1 in its default parameter groups,
    and a custom group starts from those defaults, so only an explicit 0 turns it off.
    """
    _port, name, on = _RDS_ENGINES[family]
    key = "DBClusterParameterGroupName" if res.type == "rds_cluster" else "DBParameterGroupName"
    if key in res.unresolved or "EngineVersion" in res.unresolved:
        return None
    linked = res.properties.get(key)
    default_group = linked is None or (isinstance(linked, str) and linked.lower().startswith("default."))
    group = None if default_group else next((g for g in param_groups if _points_at(res, key, g) or (
        isinstance(linked, str) and g.properties.get("Name") == linked)), None)
    # PostgreSQL's major version, from EngineVersion or the group family (postgres16). With
    # neither, AWS picks the current default major, which is 15 or later: unknown here.
    major = _major_version(res.properties.get("EngineVersion"))
    if major is None and group is not None:
        major = _major_version(re.sub(r"^\D+", "", str(group.properties.get("Family", ""))))
    if family == "postgres" and major is None:
        on_by_default: bool | None = None
    else:
        on_by_default = family == "postgres" and major is not None and major >= 15
    if default_group:
        return on_by_default
    if group is None or group.malformed or "Parameters" in group.unresolved:
        return None
    params = group.properties.get("Parameters")
    if not isinstance(params, dict) or _is_intrinsic(params):
        return None
    if name not in params:
        return on_by_default
    value = params[name]
    if isinstance(value, bool):
        value = "1" if value else "0"
    if not isinstance(value, (str, int)):
        return None
    return str(value).strip().lower() in on


def _rds_settings_findings(
    res: Resource, template_path: Path, param_groups: List[Resource]
) -> List[Finding]:
    """CF-RDS-006..014 on a DB instance or cluster.

    An Aurora member instance (DBClusterIdentifier) takes its engine settings from the
    cluster, so it is judged only for what is set per instance: enhanced monitoring, minor
    version upgrades and the instance class.
    """
    props = res.properties
    instance = res.type == "db_instance"
    member = instance and "DBClusterIdentifier" in props
    restored = any(k in props for k in ("SnapshotIdentifier", "DBSnapshotIdentifier",
                                         "SourceDBInstanceIdentifier", "SourceDBClusterIdentifier"))
    family = _rds_engine(props)
    open_source = family is not None and family.startswith(_RDS_OPEN_SOURCE)
    aurora = family is not None and family.startswith("aurora")
    out: List[Finding] = []

    def add(check_id: str, title: str, severity: Severity, category: str, recommendation: str) -> None:
        out.append(Finding(
            id=check_id, title=title, severity=severity, category=category,
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    owns_settings = not member and not (instance and aurora)
    if owns_settings and family is not None and _RDS_ENGINES[family][1]:
        if _ssl_enforced(res, family, param_groups) is False:
            param = _RDS_ENGINES[family][1]
            value = "1" if param == "rds.force_ssl" else "ON"
            group = "DB cluster parameter group" if res.type == "rds_cluster" else "DB parameter group"
            add("CF-RDS-006", "RDS does not require TLS connections", "Medium", "Security",
                f"Link a {group} that sets {param} to {value}, so clients cannot connect in clear "
                "text. A default parameter group does not set it. In CDK: parameters: "
                f"{{ '{param}': '{value}' }} on an rds.ParameterGroup.")

    if instance:
        interval = props.get("MonitoringInterval")
        if interval is None or interval in (0, "0"):
            add("CF-RDS-007", "RDS enhanced monitoring not enabled", "Low", "Operational Excellence",
                "Set MonitoringInterval (for example 60) and MonitoringRoleArn, so OS metrics are "
                "collected for the DB instance (Security Hub RDS.6). In CDK: monitoringInterval: "
                "Duration.seconds(60).")

    if owns_settings and open_source and props.get("EnableIAMDatabaseAuthentication") is not True:
        control = "RDS.12" if res.type == "rds_cluster" else "RDS.10"
        add("CF-RDS-008", "RDS IAM database authentication not enabled", "Low", "Security",
            "Set EnableIAMDatabaseAuthentication: true, so apps can connect with short-lived IAM "
            f"tokens instead of a stored password (Security Hub {control}). In CDK: "
            "iamAuthentication: true.")

    if props.get("AutoMinorVersionUpgrade") is False:
        add("CF-RDS-009", "RDS automatic minor version upgrades are off", "Low", "Security",
            "Set AutoMinorVersionUpgrade: true, so security patches in minor engine versions are "
            "applied in the maintenance window (Security Hub RDS.13).")

    if owns_settings and props.get("CopyTagsToSnapshot") is not True:
        control = "RDS.16" if res.type == "rds_cluster" else "RDS.17"
        add("CF-RDS-010", "RDS does not copy tags to snapshots", "Low", "Operational Excellence",
            "Set CopyTagsToSnapshot: true, so snapshots carry the owner and cost tags (Security Hub "
            f"{control}). In CDK: copyTagsToSnapshot: true.")

    if owns_settings and family is not None:
        exports = props.get("EnableCloudwatchLogsExports")
        if exports is None or exports == []:
            add("CF-RDS-011", "RDS logs are not exported to CloudWatch Logs", "Low", "Operational Excellence",
                "Set EnableCloudwatchLogsExports to the engine's logs (for example postgresql, or "
                "error, general and slowquery for MySQL), so they are kept and searchable (Security "
                "Hub RDS.9). In CDK: cloudwatchLogsExports.")

    if owns_settings and family is not None and not restored:
        port = props.get("Port")
        default_port = _RDS_ENGINES[family][0]
        if port is None or str(port).strip() == str(default_port):
            add("CF-RDS-012", "RDS uses the engine's default port", "Low", "Security",
                f"Set Port to something other than {default_port}. It does not stop a targeted "
                "attack, but it drops much automated scanning (Security Hub RDS.23). In CDK: port.")
        user = props.get("MasterUsername")
        if isinstance(user, str) and user.strip().lower() in _DEFAULT_DB_USERS:
            control = "RDS.24" if res.type == "rds_cluster" else "RDS.25"
            add("CF-RDS-013", "RDS uses a default master username", "Low", "Security",
                f"MasterUsername is {user!r}, a name attackers try first. Use a custom name (Security "
                f"Hub {control}). It can only be set when the database is created. In CDK: "
                "credentials: rds.Credentials.fromGeneratedSecret('<custom name>').")

    db_class = props.get("DBInstanceClass") if instance else props.get("DBClusterInstanceClass")
    if open_source and isinstance(db_class, str) and db_class.startswith("db.") \
            and db_class != "db.serverless" and not _GRAVITON_CLASS.match(db_class):
        add("CF-RDS-014", "RDS instance class is not Graviton", "Low", "Cost Optimization",
            f"{db_class} is x86. The Graviton class of the same size (db.r7g, db.m7g, db.t4g) costs "
            "less for the same work on this engine. In CDK: ec2.InstanceClass.R7G or M7G.")
    return out


# A value the scan cannot read: an intrinsic, or a Terraform expression.
_UNKNOWN = object()


def _lb_attribute(attrs: Any, key: str) -> Any:
    """An ELBv2 LoadBalancerAttributes value as lower-case text, None when not set, or
    _UNKNOWN when the list or the value is not a literal."""
    if attrs is None:
        return None
    if not isinstance(attrs, list):
        return _UNKNOWN
    for item in attrs:
        if not isinstance(item, dict) or item.get("Key") != key:
            continue
        value = item.get("Value")
        if isinstance(value, bool):
            return "true" if value else "false"
        return value.strip().lower() if isinstance(value, str) else _UNKNOWN
    return None


# ELBv2 security policies that allow TLS 1.0 or 1.1. ELBSecurityPolicy-2016-08 is also
# what CloudFormation, the CLI, CDK and Terraform use when SslPolicy is not set.
_WEAK_ELB_POLICY = re.compile(
    r"^ELBSecurityPolicy-(?:2015-05|2016-08|FS-2018-06|TLS-1-[01]-|FS-1-1-|TLS13-1-[01]-)"
)
_DEFAULT_ELB_POLICY = "ELBSecurityPolicy-2016-08"


def _redirects_to_https(actions: Any) -> bool | None:
    """True when a listener's default action redirects to HTTPS. None when unreadable."""
    if not isinstance(actions, list):
        return None if actions is not None else False
    for action in actions:
        if not isinstance(action, dict):
            return None
        kind = action.get("Type")
        if not isinstance(kind, str):
            return None
        if kind.lower() != "redirect":
            continue
        config = action.get("RedirectConfig")
        protocol = config.get("Protocol") if isinstance(config, dict) else None
        if not isinstance(protocol, str):
            return None
        if protocol.upper() == "HTTPS":
            return True
    return False


def _is_acm_certificate(value: Any) -> bool | None:
    """True for an ACM certificate, False for an IAM server certificate, None when the
    value cannot be read (a Ref to a parameter, an import, a name).

    A Terraform reference names the resource type (aws_acm_certificate.web.arn)."""
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    if ":acm:" in text or "aws_acm_certificate" in text:
        return True
    if (":iam:" in text and "server-certificate" in text) or "aws_iam_server_certificate" in text:
        return False
    return None


def _flag_off(block: Any, key: str) -> bool:
    """True when a {key: bool} setting is missing or false; False when it is on or when the
    block or the value is an intrinsic the scan cannot read."""
    if block is None:
        return True
    if not isinstance(block, dict) or _is_intrinsic(block):
        return False
    value = block.get(key)
    if value is None or value is False:
        return True
    return isinstance(value, str) and value.strip().lower() == "false"


def _load_balancer_findings(res: Resource, template_path: Path) -> List[Finding]:
    """ELBv2 load balancers (CF-ALB-001, 004, 005, 006), listeners (CF-ALB-002, 003),
    target groups (CF-ALB-007) and Classic Load Balancers (CF-CLB-001..005)."""
    props = res.properties
    out: List[Finding] = []

    def add(check_id: str, title: str, severity: Severity, category: str, recommendation: str) -> None:
        out.append(Finding(
            id=check_id, title=title, severity=severity, category=category,
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    if res.type == "lb":
        attrs = props.get("LoadBalancerAttributes")
        kind = props.get("Type", "application")
        if _lb_attribute(attrs, "access_logs.s3.enabled") in (None, "false"):
            add("CF-ALB-001", "ALB access logs not enabled (template-level)", "Low", "Observability",
                "Consider enabling access logs to S3 for audit and incident analysis, balanced against "
                "cost (Security Hub ELB.5).")
        if kind == "application" and _lb_attribute(
                attrs, "routing.http.drop_invalid_header_fields.enabled") in (None, "false"):
            add("CF-ALB-004", "ALB does not drop invalid HTTP headers", "Low", "Security",
                "Set the attribute routing.http.drop_invalid_header_fields.enabled to true, so headers "
                "that do not match the HTTP spec are removed before they reach the targets (Security "
                "Hub ELB.4). In Terraform: drop_invalid_header_fields = true.")
        if _lb_attribute(attrs, "deletion_protection.enabled") in (None, "false"):
            add("CF-ALB-005", "Load balancer deletion protection not enabled", "Low", "Reliability",
                "Set the attribute deletion_protection.enabled to true for production load balancers, so "
                "they cannot be deleted by mistake (Security Hub ELB.6). In CDK: deletionProtection: true.")
        if kind == "application" and _lb_attribute(attrs, "routing.http.desync_mitigation_mode") == "monitor":
            add("CF-ALB-006", "ALB desync mitigation mode is monitor", "Low", "Security",
                "Set routing.http.desync_mitigation_mode to defensive (the default) or strictest. Monitor "
                "lets requests that may be HTTP desync attacks through (Security Hub ELB.12).")

    if res.type == "lb_listener":
        protocol = props.get("Protocol")
        protocol = protocol.upper() if isinstance(protocol, str) else None
        if protocol == "HTTP" and _redirects_to_https(props.get("DefaultActions")) is False:
            add("CF-ALB-002", "HTTP listener does not redirect to HTTPS", "Medium", "Security",
                "Make the HTTP listener's default action a redirect to HTTPS (port 443, HTTP_301), so "
                "no request is served in clear text (Security Hub ELB.1). In CDK: redirectHTTP: true, or "
                "ListenerAction.redirect({ protocol: 'HTTPS', port: '443' }).")
        if protocol in ("HTTPS", "TLS"):
            policy = props.get("SslPolicy", _DEFAULT_ELB_POLICY)
            if isinstance(policy, str) and _WEAK_ELB_POLICY.match(policy):
                unset = "SslPolicy" not in props
                add("CF-ALB-003", "Listener TLS policy allows TLS 1.0 or 1.1", "Medium", "Security",
                    ("No SslPolicy is set, so the listener uses ELBSecurityPolicy-2016-08, which allows "
                     "TLS 1.0. " if unset else f"{policy} allows TLS below 1.2. ")
                    + "Set SslPolicy to ELBSecurityPolicy-TLS13-1-2-2021-06 or newer. In CDK: "
                    "sslPolicy: elbv2.SslPolicy.RECOMMENDED_TLS.")

    if res.type == "lb_target_group" and props.get("TargetType", "instance") != "lambda":
        protocol = props.get("Protocol")
        enabled = props.get("HealthCheckEnabled")
        if enabled is False or (isinstance(enabled, str) and enabled.lower() == "false"):
            add("CF-ALB-007", "Target group health checks are off", "Low", "Reliability",
                "Turn health checks on, so the load balancer stops sending traffic to failed targets. "
                "In CDK: healthCheck: { enabled: true, path: '/health' }.")
        elif isinstance(protocol, str) and protocol.upper() in ("HTTP", "HTTPS") \
                and "HealthCheckPath" not in props:
            add("CF-ALB-007", "Target group has no health check path", "Low", "Reliability",
                "Set HealthCheckPath to an endpoint that checks the app and its dependencies. The "
                "default is /, which often only shows that the web server is up. In CDK: "
                "healthCheck: { path: '/health' }.")

    if res.type == "elb":
        listeners = props.get("Listeners")
        listeners = [x for x in listeners if isinstance(x, dict)] if isinstance(listeners, list) else []
        protocols = [x.get("Protocol") for x in listeners]
        if protocols and all(isinstance(p, str) and p.upper() in ("HTTP", "TCP") for p in protocols):
            add("CF-CLB-001", "Classic Load Balancer has no HTTPS or SSL listener", "Medium", "Security",
                "Add an HTTPS or SSL listener with a certificate and stop serving clear text (Security "
                "Hub ELB.3). Better: move to an Application or Network Load Balancer.")
        if any(_is_acm_certificate(x.get("SSLCertificateId")) is False for x in listeners
               if str(x.get("Protocol", "")).upper() in ("HTTPS", "SSL")):
            add("CF-CLB-002", "Classic Load Balancer uses an IAM server certificate", "Low", "Security",
                "Use a certificate from AWS Certificate Manager, which renews it for you (Security Hub ELB.2).")
        if _flag_off(props.get("AccessLoggingPolicy"), "Enabled"):
            add("CF-CLB-003", "Classic Load Balancer access logs not enabled", "Low", "Observability",
                "Set AccessLoggingPolicy with Enabled: true and an S3 bucket (Security Hub ELB.5).")
        if _flag_off({"Enabled": props["CrossZone"]} if "CrossZone" in props else None, "Enabled"):
            add("CF-CLB-004", "Classic Load Balancer cross-zone load balancing is off", "Low", "Reliability",
                "Set CrossZone: true, so each AZ's nodes spread traffic over targets in every AZ "
                "(Security Hub ELB.9). It is off by default in CloudFormation.")
        if _flag_off(props.get("ConnectionDrainingPolicy"), "Enabled"):
            add("CF-CLB-005", "Classic Load Balancer connection draining is off", "Low", "Reliability",
                "Set ConnectionDrainingPolicy with Enabled: true, so in-flight requests finish when a "
                "target is removed (Security Hub ELB.7).")
    return out


def _lambda_access_findings(res: Resource, template_path: Path) -> List[Finding]:
    """CF-LAM-004 (function URL with no auth), CF-LAM-005 (secret in an environment
    variable) and CF-LAM-006 (no reserved concurrency)."""
    props = res.properties
    out: List[Finding] = []

    def add(check_id: str, title: str, severity: Severity, category: str, recommendation: str) -> None:
        out.append(Finding(
            id=check_id, title=title, severity=severity, category=category,
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    if res.type == "lambda_url":
        if props.get("AuthType") == "NONE":
            add("CF-LAM-004", "Lambda function URL has no authentication", "High", "Security",
                "AuthType NONE makes the function a public endpoint anyone can call. Set AuthType: "
                "AWS_IAM and sign requests, or put API Gateway with an authorizer in front. In CDK: "
                "authType: lambda.FunctionUrlAuthType.AWS_IAM.")
        return out

    env = props.get("Environment")
    variables = env.get("Variables") if isinstance(env, dict) else None
    if isinstance(variables, dict) and not _is_intrinsic(variables):
        names = sorted(k for k, v in variables.items() if is_secret_name(str(k)) and is_literal_secret(v))
        if names:
            add("CF-LAM-005", "Lambda environment variable holds a secret", "High", "Security",
                f"{', '.join(names)} look like secrets set as literal values, so they are in the "
                "template, the console and the function configuration. Store them in Secrets "
                "Manager or SSM Parameter Store (SecureString) and read them at runtime; pass "
                "only the secret's ARN or name in the environment.")

    if props.get("ReservedConcurrentExecutions") is None:
        add("CF-LAM-006", "Lambda function has no reserved concurrency", "Low", "Reliability",
            "Set ReservedConcurrentExecutions on functions that must keep capacity, or that must "
            "not exhaust the account's concurrency or a downstream database. In CDK: "
            "reservedConcurrentExecutions.")
    return out


def _lambda_wiring_findings(resources: List[Resource], template_path: Path) -> List[Finding]:
    """CF-LAM-007: the 3 second default timeout on a function an event source mapping
    polls for, or the 900 second maximum behind API Gateway (which stops waiting at 29
    seconds). CF-LAM-008: a VPC function whose subnets are all in one AZ (Security Hub
    Lambda.5).

    API Gateway is read from AWS::Lambda::Permission with principal apigateway.amazonaws.com.
    A subnet that is not in this template, or whose AZ cannot be read, is not judged.
    """
    functions = [r for r in resources if r.type == "lambda_function" and not r.malformed]
    if not functions:
        return []
    mappings = [r for r in resources if r.type == "lambda_event_source_mapping" and not r.malformed]
    api_permissions = [
        r for r in resources if r.type == "lambda_permission" and not r.malformed
        and isinstance(r.properties.get("Principal"), str)
        and r.properties["Principal"].startswith("apigateway.")
    ]
    subnets = [r for r in resources if r.type == "subnet" and not r.malformed]
    out: List[Finding] = []

    def finding(fn: Resource, check_id: str, title: str, severity: Severity, recommendation: str) -> Finding:
        return Finding(id=check_id, title=title, severity=severity, category="Reliability",
                       file=fn.file or str(template_path), line=fn.line,
                       evidence=f"{fn.name} ({fn.source_type})", recommendation=recommendation)

    for fn in functions:
        timeout = None if "Timeout" in fn.unresolved else fn.properties.get("Timeout", 3)
        polled = any(_points_at(m, "FunctionName", fn) for m in mappings)
        behind_api = any(_points_at(p, "FunctionName", fn) for p in api_permissions)
        if polled and timeout in (3, "3"):
            out.append(finding(
                fn, "CF-LAM-007", "Lambda timeout left at the 3 second default for a queue or stream", "Low", (
                    "An event source mapping polls for this function, and a batch that takes longer "
                    "than 3 seconds fails and is retried. Set Timeout to what a batch needs, and set "
                    "the SQS visibility timeout to at least 6 times that. In CDK: timeout.")))
        elif behind_api and timeout in (900, "900"):
            out.append(finding(
                fn, "CF-LAM-007", "Lambda timeout is 900 seconds behind API Gateway", "Low", (
                    "API Gateway stops waiting after 29 seconds by default, so a 15 minute timeout "
                    "only keeps failed calls running and billed. Set Timeout just above the API "
                    "timeout. In CDK: timeout: Duration.seconds(30).")))

        vpc = fn.properties.get("VpcConfig")
        ids = vpc.get("SubnetIds") if isinstance(vpc, dict) and "VpcConfig" not in fn.unresolved else None
        if not isinstance(ids, list) or not ids:
            continue
        azs: set[str] = set()
        for item in ids:
            text = item if type(item) is str else json.dumps(item, default=str)
            subnet = next((s for s in subnets if _references(text, s.name)), None)
            az = _az_key(subnet) if subnet is not None else None
            if az is None:
                azs = set()
                break
            azs.add(az)
        if len(azs) == 1:
            out.append(finding(
                fn, "CF-LAM-008", "Lambda function in a VPC uses subnets in one AZ", "Medium", (
                    "All of this function's subnets are in one Availability Zone, so an AZ failure "
                    "stops it. Give it subnets in at least two AZs (Security Hub Lambda.5). In CDK: "
                    "vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }.")))
    return out


_BODY_METHODS = ("POST", "PUT", "PATCH", "ANY")


def _is_true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _unread(value: Any) -> bool:
    """True for a value only known at deploy time: a Ref, Fn::If, or an unknown Terraform value."""
    return isinstance(value, dict) and _is_intrinsic(value)


def _api_gateway_findings(resources: List[Resource], template_path: Path) -> List[Finding]:
    """REST API (CF-APIGW-003..009) and HTTP / WebSocket API (CF-APIGW-V2-003/004) checks.

    Methods and stages are tied to their API by RestApiId / ApiId, usage plans by ApiStages.
    A value the scan cannot read is not judged; a usage plan it cannot tie to an API counts
    as throttling all of them.
    """
    usable = [r for r in resources if not r.malformed]
    of = {t: [r for r in usable if r.type == t] for t in (
        "api_gateway_rest_api", "api_gateway_method", "api_gateway_stage", "api_gateway_domain_name",
        "api_gateway_usage_plan", "apigatewayv2_api", "apigatewayv2_route", "apigatewayv2_stage",
        "apigatewayv2_domain_name")}
    out: List[Finding] = []

    def add(res: Resource, check_id: str, title: str, severity: Severity, category: str,
            recommendation: str) -> None:
        out.append(Finding(
            id=check_id, title=title, severity=severity, category=category,
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    def api_of(res: Resource, key: str, kind: str) -> Resource | None:
        return next((a for a in of[kind] if _points_at(res, key, a)), None)

    # REST methods: no auth, no request validation.
    for method in of["api_gateway_method"]:
        props = method.properties
        verb = props.get("HttpMethod")
        if not isinstance(verb, str) or verb.upper() == "OPTIONS":
            continue
        auth = props.get("AuthorizationType") or "NONE"
        if "AuthorizationType" not in method.unresolved and "ApiKeyRequired" not in method.unresolved \
                and auth == "NONE" and not _is_true(props.get("ApiKeyRequired")) \
                and not _unread(props.get("ApiKeyRequired")):
            add(method, "CF-APIGW-003", "API Gateway method has no authorization", "High", "Security",
                f"{verb.upper()} takes requests from anyone: AuthorizationType is NONE and no API key is "
                "required. Use an IAM, Cognito or Lambda authorizer; if the API is public on purpose, "
                "add throttling and WAF. In CDK: defaultMethodOptions with an authorizer.")
        if verb.upper() in _BODY_METHODS and "RequestValidatorId" not in method.unresolved \
                and not props.get("RequestValidatorId"):
            add(method, "CF-APIGW-006", "API Gateway method does not validate requests", "Low", "Reliability",
                f"{verb.upper()} takes a request body that API Gateway passes on unchecked. Add a request "
                "validator (body and parameters) and a model, so malformed requests are rejected before "
                "the backend. In CDK: requestValidatorOptions.")

    # TLS on the default endpoint and on custom domains.
    for rest_api in of["api_gateway_rest_api"]:
        props = rest_api.properties
        disabled = props.get("DisableExecuteApiEndpoint")
        if "SecurityPolicy" in rest_api.unresolved or _is_true(disabled) or _unread(disabled):
            continue
        endpoint = props.get("EndpointConfiguration")
        types = endpoint.get("Types") if isinstance(endpoint, dict) else None
        private = isinstance(types, list) and "PRIVATE" in types
        endpoint_unread = _unread(endpoint) or _unread(types) or (
            isinstance(types, list) and any(_unread(t) for t in types))
        policy = props.get("SecurityPolicy")
        # Regional and edge APIs default to TLS_1_0; Terraform's provider may not expose it.
        default_weak = policy is None and not private and not endpoint_unread \
            and rest_api.source_type.startswith("AWS::")
        if policy == "TLS_1_0" or default_weak:
            add(rest_api, "CF-APIGW-004", "API Gateway endpoint allows TLS 1.0", "Medium", "Security",
                ("No SecurityPolicy is set, so the default execute-api endpoint uses TLS_1_0. "
                 if default_weak else "SecurityPolicy is TLS_1_0. ")
                + "Set SecurityPolicy to TLS_1_2 or a SecurityPolicy_TLS13_* policy, or disable the "
                "default endpoint and serve the API from a custom domain.")
    for domain in of["api_gateway_domain_name"] + of["apigatewayv2_domain_name"]:
        if domain.type == "api_gateway_domain_name":
            policies = [domain.properties.get("SecurityPolicy")]
        else:
            configs = domain.properties.get("DomainNameConfigurations")
            policies = [c.get("SecurityPolicy") for c in configs if isinstance(c, dict)] \
                if isinstance(configs, list) else []
        if "TLS_1_0" in policies:  # domains default to TLS_1_2
            add(domain, "CF-APIGW-004", "API Gateway custom domain allows TLS 1.0", "Medium", "Security",
                "SecurityPolicy is TLS_1_0. Set it to TLS_1_2 or a SecurityPolicy_TLS13_* policy. In CDK: "
                "securityPolicy: apigateway.SecurityPolicy.TLS_1_2.")

    # REST stages: throttling, cache encryption, caching for GET, client certificate.
    plans = [p for p in of["api_gateway_usage_plan"] if p.properties.get("Throttle") or any(
        isinstance(s, dict) and s.get("Throttle") for s in p.properties.get("ApiStages") or [])]
    for stage in of["api_gateway_stage"]:
        props = stage.properties
        api = api_of(stage, "RestApiId", "api_gateway_rest_api")
        settings_known = "MethodSettings" not in stage.unresolved
        settings = props.get("MethodSettings")
        settings = [m for m in settings if isinstance(m, dict)] if isinstance(settings, list) else []
        throttled = any(m.get("ThrottlingRateLimit") is not None or m.get("ThrottlingBurstLimit") is not None
                        for m in settings)
        # A plan the scan cannot tie (or a stage with no known API) may throttle this stage.
        planned = any(api is None or _points_at(p, "ApiStages", api) or _points_at(p, "ApiStages", stage)
                      or not any(_points_at(p, "ApiStages", a) for a in of["api_gateway_rest_api"])
                      for p in plans)
        if settings_known and not throttled and not planned:
            add(stage, "CF-APIGW-005", "API Gateway stage has no throttling", "Low", "Reliability",
                "Set ThrottlingRateLimit and ThrottlingBurstLimit in MethodSettings, or attach a usage plan "
                "with a throttle, so one client cannot use up the account's API Gateway limit. In CDK: "
                "deployOptions: { throttlingRateLimit, throttlingBurstLimit }.")
        if settings_known and any(_is_true(m.get("CachingEnabled")) and not _is_true(m.get("CacheDataEncrypted"))
                                  and not _unread(m.get("CacheDataEncrypted")) for m in settings):
            add(stage, "CF-APIGW-007", "API Gateway cache data is not encrypted", "Medium", "Security",
                "Set CacheDataEncrypted: true in every MethodSettings entry that turns caching on "
                "(Security Hub APIGateway.5). In CDK: cacheDataEncrypted: true.")
        has_get = api is not None and any(
            _points_at(m, "RestApiId", api) and str(m.properties.get("HttpMethod", "")).upper() == "GET"
            for m in of["api_gateway_method"])
        if has_get and "CacheClusterEnabled" not in stage.unresolved and not _is_true(props.get("CacheClusterEnabled")):
            add(stage, "CF-APIGW-008", "API Gateway stage does not cache GET responses", "Low",
                "Performance Efficiency",
                "This API has GET methods and the stage has no cache. If responses can be reused, set "
                "CacheClusterEnabled with a CacheClusterSize and turn CachingEnabled on for those methods "
                "(the cache is billed per hour). In CDK: deployOptions: { cachingEnabled: true }.")
        if "ClientCertificateId" not in stage.unresolved and not props.get("ClientCertificateId"):
            add(stage, "CF-APIGW-009", "API Gateway stage has no client certificate", "Low", "Security",
                "Set ClientCertificateId to an AWS::ApiGateway::ClientCertificate, so the backend can check "
                "that calls come from API Gateway (Security Hub APIGateway.2). Not needed for Lambda "
                "integrations, which API Gateway calls with IAM.")

    # HTTP and WebSocket APIs.
    for route in of["apigatewayv2_route"]:
        key = route.properties.get("RouteKey")
        if not isinstance(key, str) or key.upper().startswith("OPTIONS ") or "AuthorizationType" in route.unresolved:
            continue
        api = api_of(route, "ApiId", "apigatewayv2_api")
        protocol = api.properties.get("ProtocolType") if api is not None else None
        # WebSocket APIs authorize on $connect only; an HTTP route key is "VERB /path".
        if (protocol == "WEBSOCKET" or (" " not in key and key != "$default")) and key != "$connect":
            continue
        # $default exists on both kinds of API, so it needs a known HTTP API.
        if key == "$default" and protocol != "HTTP":
            continue
        if (route.properties.get("AuthorizationType") or "NONE") == "NONE":
            add(route, "CF-APIGW-V2-003", "API Gateway route has no authorization", "High", "Security",
                f"Route {key} takes requests from anyone. Set AuthorizationType to JWT, AWS_IAM or CUSTOM "
                "with an authorizer (Security Hub APIGateway.8). In CDK: defaultAuthorizer on the HttpApi.")
    for stage in of["apigatewayv2_stage"]:
        if "DefaultRouteSettings" in stage.unresolved:
            continue
        defaults = stage.properties.get("DefaultRouteSettings")
        if isinstance(defaults, dict) and _is_intrinsic(defaults):
            continue
        defaults = defaults if isinstance(defaults, dict) else {}
        if defaults.get("ThrottlingRateLimit") is None and defaults.get("ThrottlingBurstLimit") is None:
            add(stage, "CF-APIGW-V2-004", "API Gateway V2 stage has no default route throttling", "Low",
                "Reliability",
                "Set DefaultRouteSettings with ThrottlingRateLimit and ThrottlingBurstLimit, so one client "
                "cannot use up the account's limit. In CDK: throttle on the HttpStage.")
    return out


# user:secret@ or a bare token@ in a URL. A bare short name (git@, user@) is not a credential.
_URL_CREDENTIALS = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/@\s:]+:[^/@\s]+|[A-Za-z0-9_-]{20,})@")
_AWS_KEY_VALUE = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
# Security Hub CodeBuild.2 fails on these names whatever the value, when stored as plain text.
_AWS_KEY_NAMES = frozenset({"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"})


def _has_url_credentials(location: Any) -> bool:
    if type(location) is not str or "{{" in location or "${" in location:
        return False
    return _URL_CREDENTIALS.match(location) is not None


def _plaintext_secret_names(environment: Any) -> list[str]:
    """Names of PLAINTEXT build variables that hold a secret. Never the values: they go in reports."""
    variables = environment.get("EnvironmentVariables") if isinstance(environment, dict) else None
    names: set[str] = set()
    for item in variables if isinstance(variables, list) else []:
        if not isinstance(item, dict) or item.get("Type", "PLAINTEXT") != "PLAINTEXT":
            continue
        name, value = item.get("Name"), item.get("Value")
        named = isinstance(name, str) and (
            name in _AWS_KEY_NAMES or (is_secret_name(name) and is_literal_secret(value)))
        if named or (type(value) is str and _AWS_KEY_VALUE.fullmatch(value.strip())):
            names.add(name if isinstance(name, str) else "(unnamed)")
    return sorted(names)


def _log_statuses(logs: Any) -> tuple[str, str, dict] | None:
    """(CloudWatch status, S3 status, S3 settings) with the service defaults, ENABLED and
    DISABLED, or None when a status cannot be read."""
    logs = logs if isinstance(logs, dict) else {}
    if _unread(logs):
        return None
    cloudwatch, s3 = logs.get("CloudWatchLogs") or {}, logs.get("S3Logs") or {}
    if not isinstance(cloudwatch, dict) or not isinstance(s3, dict) or _unread(cloudwatch) or _unread(s3):
        return None
    cloudwatch_status, s3_status = cloudwatch.get("Status", "ENABLED"), s3.get("Status", "DISABLED")
    if not isinstance(cloudwatch_status, str) or not isinstance(s3_status, str):
        return None
    return cloudwatch_status, s3_status, s3


def _prod_without_approval(pipeline: Resource) -> bool:
    """True when a deploy in a prod-named stage has no manual approval before it. In a
    prod-named pipeline with no prod-named stage, the last deploy is the one that counts.
    Actions with one RunOrder run together, so an approval only gates a later RunOrder."""
    stages = pipeline.properties.get("Stages")
    if "Stages" in pipeline.unresolved or not isinstance(stages, list):
        return False
    name = pipeline.properties.get("Name")
    pipeline_prod = environments.from_words(name if isinstance(name, str) else pipeline.name) == "prod"
    approved, saw_prod_stage = False, False
    last_deploy_approved: bool | None = None
    for stage in stages:
        actions = stage.get("Actions") if isinstance(stage, dict) else None
        if not isinstance(actions, list):
            return False
        groups: dict[int, set[str]] = {}
        for action in actions:
            type_id = action.get("ActionTypeId") if isinstance(action, dict) else None
            category = type_id.get("Category") if isinstance(type_id, dict) else None
            if not isinstance(category, str):
                return False
            try:
                groups.setdefault(int(action.get("RunOrder", 1)), set()).add(category)
            except (TypeError, ValueError):
                return False
        stage_name = stage.get("Name")
        stage_prod = isinstance(stage_name, str) and environments.from_words(stage_name) == "prod"
        for order in sorted(groups):
            if "Deploy" in groups[order]:
                if stage_prod and not approved:
                    return True
                saw_prod_stage = saw_prod_stage or stage_prod
                last_deploy_approved = approved
            if "Approval" in groups[order]:
                approved = True
    return pipeline_prod and not saw_prod_stage and last_deploy_approved is False


def _notifies(rule: Resource, pipeline: Resource, pipelines: List[Resource], projects: List[Resource]) -> bool:
    """True when a notification or EventBridge rule may report on this pipeline. A rule the
    scan cannot tie to a resource counts for all pipelines, unless it is for CodeBuild."""
    key = "EventPattern" if rule.type == "events_rule" else "Resource"
    if key in rule.unresolved:
        return True
    value = rule.properties.get(key)
    text = value if type(value) is str else json.dumps(value, default=str)
    if _points_at(rule, key, pipeline):
        return True
    if any(_points_at(rule, key, p) for p in pipelines):
        return False
    if rule.type == "events_rule":
        return "aws.codepipeline" in text or _unread(value)
    return ":codebuild:" not in text and not any(_points_at(rule, key, p) for p in projects)


def _ci_cd_findings(resources: List[Resource], template_path: Path) -> List[Finding]:
    """CodeBuild (CF-CB-001..005) and CodePipeline (CF-CP-001..003). A value the scan cannot
    read is not judged. Findings name secret variables and never quote a value or a URL."""
    usable = [r for r in resources if not r.malformed]
    projects = [r for r in usable if r.type == "codebuild_project"]
    pipelines = [r for r in usable if r.type == "codepipeline"]
    rules = [r for r in usable if r.type in ("codestar_notification_rule", "events_rule")]
    out: List[Finding] = []

    def add(res: Resource, check_id: str, title: str, severity: Severity, category: str,
            recommendation: str) -> None:
        out.append(Finding(
            id=check_id, title=title, severity=severity, category=category,
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    for project in projects:
        props = project.properties
        environment = props.get("Environment")
        names = _plaintext_secret_names(environment) if "Environment" not in project.unresolved else []
        if names:
            add(project, "CF-CB-001", "CodeBuild environment variable holds a secret in plain text", "High",
                "Security",
                f"Stored as PLAINTEXT: {', '.join(names)}. Anyone who can read the project configuration "
                "or the console sees the values (Security Hub CodeBuild.2). Store them in Secrets Manager or SSM "
                "Parameter Store and set Type to SECRETS_MANAGER or PARAMETER_STORE, or use the build "
                "role instead of AWS keys. In CDK: type: BuildEnvironmentVariableType.SECRETS_MANAGER.")
        secondary = props.get("SecondarySources")
        sources = [props.get("Source")] + (secondary if isinstance(secondary, list) else [])
        if any(isinstance(s, dict) and _has_url_credentials(s.get("Location")) for s in sources):
            add(project, "CF-CB-002", "CodeBuild source URL contains credentials", "High", "Security",
                "A source location has sign-in details or a token in its URL, so they are in the template "
                "and the project configuration (Security Hub CodeBuild.1). Keep only the repository path "
                "in the URL and connect to the provider with OAuth or an AWS CodeConnections connection. "
                "Rotate the exposed credential.")
        if isinstance(environment, dict) and _is_true(environment.get("PrivilegedMode")):
            add(project, "CF-CB-003", "CodeBuild project uses privileged mode", "Medium", "Security",
                "PrivilegedMode gives the build container elevated access to the build host. Turn it off "
                "unless the build must run the Docker daemon, for example to build images. In CDK: "
                "privileged: false.")
        statuses = None if "LogsConfig" in project.unresolved else _log_statuses(props.get("LogsConfig"))
        if statuses is not None:
            cloudwatch_status, s3_status, s3 = statuses
            if cloudwatch_status == "DISABLED" and s3_status == "DISABLED":
                add(project, "CF-CB-004", "CodeBuild project logs are turned off", "Low",
                    "Operational Excellence",
                    "Both CloudWatch Logs and S3 logs are off, so build output is lost (Security Hub "
                    "CodeBuild.4). Set LogsConfig.CloudWatchLogs.Status to ENABLED, or send logs to S3. "
                    "In CDK: logging.")
            if s3_status == "ENABLED" and _is_true(s3.get("EncryptionDisabled")):
                add(project, "CF-CB-005", "CodeBuild S3 logs are not encrypted", "Low", "Security",
                    "EncryptionDisabled is true on S3Logs, and build logs can hold sensitive output "
                    "(Security Hub CodeBuild.3). Remove it or set it to false. In CDK: encrypted: true.")

    for pipeline in pipelines:
        props = pipeline.properties
        stores = [props.get("ArtifactStore")] if "ArtifactStore" not in pipeline.unresolved else []
        if "ArtifactStores" not in pipeline.unresolved and isinstance(props.get("ArtifactStores"), list):
            stores += [s.get("ArtifactStore") for s in props["ArtifactStores"] if isinstance(s, dict)]
        if any(isinstance(s, dict) and not _unread(s) and not s.get("EncryptionKey") for s in stores):
            add(pipeline, "CF-CP-001", "CodePipeline artifact store has no customer KMS key", "Low", "Security",
                "With no EncryptionKey, artifacts use the AWS managed key for S3, which other accounts "
                "cannot be granted and you cannot control with a key policy. Set EncryptionKey to a "
                "customer KMS key. In CDK: an artifactBucket with encryptionKey, or crossAccountKeys: true.")
        if _prod_without_approval(pipeline):
            add(pipeline, "CF-CP-002", "CodePipeline deploys to production with no manual approval", "Low",
                "Reliability",
                "A production deploy runs with no manual approval action before it, so a bad change "
                "reaches production unreviewed. Add an action with Category Approval and Provider Manual "
                "in an earlier stage or RunOrder. In CDK: new ManualApprovalAction().")
        if not any(_notifies(r, pipeline, pipelines, projects) for r in rules):
            add(pipeline, "CF-CP-003", "CodePipeline has no notifications", "Low", "Operational Excellence",
                "No AWS::CodeStarNotifications::NotificationRule or EventBridge rule reports on this "
                "pipeline, so failed runs go unnoticed. Add a notification rule for failed executions. "
                "In CDK: pipeline.notifyOn() or pipeline.onStateChange().")
    return out


# Resources that hold data for as long as the key that encrypts it exists.
_KEY_DATA_TYPES = frozenset({
    "db_instance", "rds_cluster", "dynamodb_table", "s3_bucket", "efs_file_system",
    "cloudwatch_log_group", "ebs_volume", "kinesis_stream", "opensearch_domain", "redshift_cluster", "docdb_cluster",
    "neptune_cluster", "msk_cluster", "elasticache_replication_group", "secretsmanager_secret",
})
_STANDARD_TIER_BYTES = 4096
# Data types that only the advanced tier supports.
_ADVANCED_DATA_TYPES = ("url", "json", "jsonc")


def _value_mentions(value: Any, name: str) -> bool:
    """True when a value, not a map key, names a resource. A tag's "Key" is not a key named Key."""
    if isinstance(value, dict):
        return any(_value_mentions(v, name) for v in value.values())
    if isinstance(value, list):
        return any(_value_mentions(v, name) for v in value)
    if not isinstance(value, str):
        return False
    return value == name or value.startswith(f"{name}.") or _references(json.dumps(value), name)


def _refers_to(res: Resource, target: Resource) -> bool:
    """True when res refers to target anywhere in its properties (CloudFormation, and merged
    Terraform blocks such as a bucket's encryption) or in its block (Terraform)."""
    return target.name in res.references or _value_mentions(res.properties, target.name)


def _parameter_name(parameter: Resource) -> str:
    """The last part of the parameter's name, which says what it holds (/app/db/password ->
    password), or the logical id or Terraform label when the name cannot be read."""
    name = parameter.properties.get("Name")
    if isinstance(name, dict) and isinstance(name.get("Fn::Sub"), str):
        name = name["Fn::Sub"]
    last = name.rstrip("/").rsplit("/", 1)[-1] if isinstance(name, str) else ""
    if not last or "${" in last:
        last = parameter.name.rsplit(".", 1)[-1]
    return last.replace("-", "_")  # is_secret_name reads api_key, not api-key


def _holds_setting(value: Any, resource_names: set[str]) -> bool:
    """True for a value that cannot be the secret itself: an ARN, a flag, a number, or a reference
    to a resource in the template. A template parameter or a dynamic reference can hold the
    secret, and a String parameter stores it in plain text."""
    if isinstance(value, (bool, int, float)):
        return True
    if isinstance(value, dict):
        attribute = value.get("Fn::GetAtt")
        attribute = attribute[-1] if isinstance(attribute, list) and attribute else attribute
        template = value.get("Fn::Sub")
        return value.get("Ref") in resource_names \
            or (isinstance(attribute, str) and attribute.endswith("Arn")) \
            or (isinstance(template, str) and template.startswith("arn:"))
    return type(value) is str and "{{resolve:" not in value and not is_literal_secret(value)


def _kms_ssm_findings(resources: List[Resource], template_path: Path) -> List[Finding]:
    """KMS keys (CF-KMS-002/003) and SSM parameters (CF-SSM-001/002). A setting the scan cannot
    read is not judged. CF-SSM-001 judges the name and type, so a value from a template parameter
    still counts. Findings never quote a parameter's value."""
    usable = [r for r in resources if not r.malformed]
    names = {r.name for r in usable}
    holders = [r for r in usable if r.type in _KEY_DATA_TYPES
               or (r.type == "ssm_parameter" and r.properties.get("Type") == "SecureString")]
    out: List[Finding] = []

    def add(res: Resource, check_id: str, title: str, severity: Severity, category: str,
            recommendation: str) -> None:
        out.append(Finding(
            id=check_id, title=title, severity=severity, category=category,
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    for key in (r for r in usable if r.type == "kms_key"):
        props = key.properties
        rotation = props.get("EnableKeyRotation")
        # Automatic rotation exists only for symmetric keys with AWS KMS key material.
        rotatable = props.get("KeySpec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT" \
            and props.get("Origin", "AWS_KMS") == "AWS_KMS" and not props.get("CustomKeyStoreId")
        if rotatable and not {"EnableKeyRotation", "KeySpec"} & key.unresolved \
                and not _is_true(rotation) and not _unread(rotation):
            add(key, "CF-KMS-002", "KMS key rotation is not enabled", "Medium", "Security",
                "Set EnableKeyRotation: true (Security Hub KMS.4). KMS then makes new key material "
                "every year and keeps the old material, so existing data still decrypts. In CDK: "
                "enableKeyRotation: true.")
        try:
            window = None if "PendingWindowInDays" in key.unresolved else int(props.get("PendingWindowInDays", 30))
        except (TypeError, ValueError):
            window = None
        users: list[str] = []
        if window is not None and window < 30:
            found = {r.name for r in holders if _refers_to(r, key)}
            # A split Terraform block, such as a bucket's encryption, refers to both.
            for side in (r for r in usable if r.type is None and key.name in r.references):
                found |= {r.name for r in holders if r.name in side.references}
            users = sorted(found)
        if users:
            add(key, "CF-KMS-003", "KMS key for stored data has a short deletion window", "Low", "Reliability",
                f"The waiting period is {window} days and this key encrypts {', '.join(users)}. Data is "
                "lost for good when the key is deleted, so keep the full time to cancel. Set "
                "PendingWindowInDays (Terraform deletion_window_in_days) to 30. In CDK: "
                "pendingWindow: Duration.days(30).")

    for parameter in (r for r in usable if r.type == "ssm_parameter"):
        props = parameter.properties
        value = props.get("Value")
        if props.get("Type") == "String" and is_secret_name(_parameter_name(parameter)) \
                and not _holds_setting(value, names):
            add(parameter, "CF-SSM-001", "SSM parameter that looks like a secret is not encrypted", "Medium",
                "Security",
                ("Its name looks like a secret and its type is String, so anyone who can read the parameter "
                 "sees the value in plain text. Use type = \"SecureString\" with a KMS key."
                 if not parameter.source_type.startswith("AWS::") else
                 "Its name looks like a secret and its type is String, so anyone who can read the parameter "
                 "sees the value in plain text. CloudFormation cannot create a SecureString: use "
                 "AWS::SecretsManager::Secret, or create the SecureString outside the stack and read it "
                 "with an ssm-secure dynamic reference, in a property that supports one.")
                + " In CDK: secretsmanager.Secret.")
        if "Tier" in parameter.unresolved or props.get("Tier") != "Advanced" or props.get("Policies") \
                or props.get("DataType") in _ADVANCED_DATA_TYPES or type(value) is not str:
            continue
        if len(value.encode("utf-8")) < _STANDARD_TIER_BYTES:
            add(parameter, "CF-SSM-002", "SSM parameter pays for the advanced tier it does not need", "Low",
                "Cost Optimization",
                "The value fits the free standard tier (4 KB) and no parameter policy is set. Unless the "
                "parameter is shared across accounts, use Tier: Standard. An advanced parameter cannot be "
                "downgraded: delete it and create it again. The tier does not change throughput, which is "
                "a separate account setting.")
    return out


_STREAM_CONSUMER_TYPES = frozenset({
    "lambda_event_source_mapping", "kinesis_stream_consumer", "kinesis_analytics_application",
    "firehose_delivery_stream",
})
_OPENSEARCH_LOGS = (("ES_APPLICATION_LOGS", "error"), ("AUDIT_LOGS", "audit"))


def _missing_opensearch_logs(options: Any) -> list[str]:
    """The log types not published. An entry with no Enabled value is on; an unread one counts."""
    options = options if isinstance(options, dict) else {}
    if _unread(options):
        return []
    missing = []
    for key, label in _OPENSEARCH_LOGS:
        entry = options.get(key)
        if entry is None or (isinstance(entry, dict) and entry.get("Enabled") is not None
                             and _flag(entry.get("Enabled")) is False):
            missing.append(label)
    return missing


def _thin_opensearch_cluster(config: Any) -> str | None:
    """Why the domain has too few data nodes or one zone. Unset means one node, zone awareness off."""
    config = config if isinstance(config, dict) else {}
    if _unread(config):
        return None
    try:
        count: int | None = int(config.get("InstanceCount", 1))
    except (TypeError, ValueError):
        count = None
    problems = []
    if count is not None and count < 3:
        problems.append(f"{count} data node{'' if count == 1 else 's'}")
    if _flag(config.get("ZoneAwarenessEnabled")) is False:
        problems.append("zone awareness off")
    return " and ".join(problems) or None


def _msk_auth_on(block: Any) -> bool | None:
    """Whether one MSK authentication method is on: None when unread."""
    if block is None:
        return False
    if not isinstance(block, dict) or _is_intrinsic(block):
        return None
    if block.get("Enabled") is None and block.get("CertificateAuthorityArnList"):
        return True
    return _flag(block.get("Enabled"))


def _msk_allows_anonymous(authentication: Any) -> bool:
    """True when anyone with network access can connect: unauthenticated is on, or no method
    that identifies a client is. A value the scan cannot read is not judged."""
    authentication = authentication if isinstance(authentication, dict) else {}
    if _unread(authentication):
        return False
    sasl = authentication.get("Sasl")
    if _unread(sasl):
        return False
    sasl = sasl if isinstance(sasl, dict) else {}
    secure = [_msk_auth_on(sasl.get("Iam")), _msk_auth_on(sasl.get("Scram")), _msk_auth_on(authentication.get("Tls"))]
    anonymous = _msk_auth_on(authentication.get("Unauthenticated"))
    if anonymous is True:
        return True
    return anonymous is False and all(on is False for on in secure)


def _search_streaming_findings(resources: List[Resource], template_path: Path) -> List[Finding]:
    """OpenSearch (CF-OS-003..007), MSK (CF-MSK-002/003) and Kinesis (CF-KIN-002). A value the
    scan cannot read is not judged."""
    usable = [r for r in resources if not r.malformed]
    consumers = [r for r in usable if r.type in _STREAM_CONSUMER_TYPES]
    out: List[Finding] = []

    def add(res: Resource, check_id: str, title: str, severity: Severity, category: str,
            recommendation: str) -> None:
        out.append(Finding(
            id=check_id, title=title, severity=severity, category=category,
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    for domain in (r for r in usable if r.type == "opensearch_domain"):
        props = domain.properties
        if "VPCOptions" not in domain.unresolved and not props.get("VPCOptions"):
            add(domain, "CF-OS-003", "OpenSearch domain is not in a VPC", "Medium", "Security",
                "With no VPCOptions the domain has a public endpoint, and a domain cannot move into a VPC "
                "later: create a new one and migrate (Security Hub Opensearch.2). In CDK: vpc and "
                "vpcSubnets.")
        if "AdvancedSecurityOptions" not in domain.unresolved \
                and _flag_off(props.get("AdvancedSecurityOptions"), "Enabled"):
            add(domain, "CF-OS-004", "OpenSearch domain has no fine-grained access control", "Medium",
                "Security",
                "Set AdvancedSecurityOptions.Enabled: true, so access is decided per user, index and "
                "document (Security Hub Opensearch.7). It also needs EnforceHTTPS and node-to-node and "
                "at-rest encryption. In CDK: fineGrainedAccessControl.")
        endpoint = props.get("DomainEndpointOptions")
        if "DomainEndpointOptions" not in domain.unresolved and not _unread(endpoint):
            endpoint = endpoint if isinstance(endpoint, dict) else {}
            policy = endpoint.get("TLSSecurityPolicy")
            weak = isinstance(policy, str) and "TLS-1-0" in policy
            if _flag(endpoint.get("EnforceHTTPS")) is False or weak:
                add(domain, "CF-OS-005", "OpenSearch domain allows HTTP or TLS below 1.2", "Medium", "Security",
                    ("TLSSecurityPolicy allows TLS 1.0. " if weak else "EnforceHTTPS is not true. ")
                    + "Set EnforceHTTPS: true and TLSSecurityPolicy to Policy-Min-TLS-1-2-PFS-2023-10 "
                    "(Security Hub Opensearch.8). In CDK: enforceHttps: true and tlsSecurityPolicy.")
        missing = [] if "LogPublishingOptions" in domain.unresolved else _missing_opensearch_logs(
            props.get("LogPublishingOptions"))
        if missing:
            add(domain, "CF-OS-006", "OpenSearch domain does not publish all its logs", "Low",
                "Operational Excellence",
                f"Not published: {' and '.join(missing)} logs. Send ES_APPLICATION_LOGS and AUDIT_LOGS to "
                "CloudWatch Logs in LogPublishingOptions (Security Hub Opensearch.4 and Opensearch.5). "
                "Audit logs also need fine-grained access control. In CDK: logging.")
        thin = None if "ClusterConfig" in domain.unresolved else _thin_opensearch_cluster(props.get("ClusterConfig"))
        if thin:
            add(domain, "CF-OS-007", "OpenSearch domain does not survive losing a node or zone", "Low", "Reliability",
                f"This domain has {thin}. Set InstanceCount to at least 3 and ZoneAwarenessEnabled: true "
                "(Security Hub Opensearch.6). In CDK: capacity.dataNodes and zoneAwareness.")

    for cluster in (r for r in usable if r.type == "msk_cluster"):
        props = cluster.properties
        if "ClientAuthentication" not in cluster.unresolved and _msk_allows_anonymous(props.get("ClientAuthentication")):
            add(cluster, "CF-MSK-002", "MSK cluster allows unauthenticated clients", "Medium", "Security",
                "Any client that can reach the brokers can read and write topics. Turn on IAM, SASL/SCRAM "
                "or mutual TLS in ClientAuthentication and turn Unauthenticated off (Security Hub MSK.6). "
                "In CDK: clientAuthentication.")
        info = props.get("BrokerNodeGroupInfo")
        connectivity = info.get("ConnectivityInfo") if isinstance(info, dict) else None
        public = connectivity.get("PublicAccess") if isinstance(connectivity, dict) else None
        if "BrokerNodeGroupInfo" not in cluster.unresolved and isinstance(public, dict) \
                and public.get("Type") == "SERVICE_PROVIDED_EIPS":
            add(cluster, "CF-MSK-003", "MSK cluster has public access on", "High", "Security",
                "PublicAccess gives the brokers internet addresses. Set PublicAccess.Type to DISABLED and "
                "connect from inside the VPC, through peering or PrivateLink (Security Hub MSK.4).")

    for stream in (r for r in usable if r.type == "kinesis_stream"):
        if "RetentionPeriodHours" in stream.unresolved:
            continue
        try:
            hours = int(stream.properties.get("RetentionPeriodHours", 24))
        except (TypeError, ValueError):
            continue
        readers = sorted(r.name for r in consumers if _refers_to(r, stream))
        if hours <= 24 and readers:
            add(stream, "CF-KIN-002", "Kinesis stream keeps records for only 24 hours", "Low", "Reliability",
                f"{', '.join(readers)} read this stream. If a consumer is down for longer than a day, "
                "records are lost. Set RetentionPeriodHours to cover your longest expected outage, such "
                "as 168 (billed per shard hour). In CDK: retentionPeriod: Duration.days(7).")
    return out


_MIN_BACKUP_DAYS = 7


def _days(res: Resource, key: str, default: int) -> int | None:
    """A retention setting in days, or None when the scan cannot read it."""
    if key in res.unresolved:
        return None
    try:
        return int(res.properties.get(key, default))
    except (TypeError, ValueError):
        return None


def _short_backups(res: Resource) -> int | None:
    """Days of backup under the minimum, or None. Unset on a cluster restored from a snapshot or
    another cluster is not judged: the template does not show what it starts with."""
    restored = any(res.properties.get(k) is not None for k in ("SnapshotIdentifier", "SourceDBClusterIdentifier"))
    if restored and res.properties.get("BackupRetentionPeriod") is None:
        return None
    days = _days(res, "BackupRetentionPeriod", 1)
    return days if days is not None and days < _MIN_BACKUP_DAYS else None


def _exports_audit_logs(res: Resource) -> bool | None:
    """Whether audit is in EnableCloudwatchLogsExports: None when the list cannot be read."""
    exports = res.properties.get("EnableCloudwatchLogsExports")
    if "EnableCloudwatchLogsExports" in res.unresolved:
        return None
    if exports is None:
        return False
    if not isinstance(exports, list):
        return None
    if any(isinstance(e, str) and e.lower() == "audit" for e in exports):
        return True
    # A Terraform expression is a str subclass, and may name audit once it is resolved.
    return False if all(type(e) is str for e in exports) else None


def _redshift_logs(cluster: Resource, clusters: List[Resource], logging: List[Resource]) -> bool:
    """True when the cluster logs, or may: an aws_redshift_logging the scan cannot tie to a
    cluster counts for all of them."""
    if "LoggingProperties" in cluster.unresolved or cluster.properties.get("LoggingProperties"):
        return True
    return any(cluster.name in r.references or not any(c.name in r.references for c in clusters)
               for r in logging)


def _warehouse_findings(resources: List[Resource], template_path: Path) -> List[Finding]:
    """Redshift (CF-RS-002..007), DocumentDB (CF-DOCDB-002..004) and Neptune (CF-NEP-002..005)
    beyond encryption. A value the scan cannot read is not judged."""
    usable = [r for r in resources if not r.malformed]
    clusters = [r for r in usable if r.type == "redshift_cluster"]
    logging = [r for r in usable if r.source_type == "aws_redshift_logging"]
    out: List[Finding] = []

    def add(res: Resource, check_id: str, title: str, severity: Severity, category: str,
            recommendation: str) -> None:
        out.append(Finding(
            id=check_id, title=title, severity=severity, category=category,
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    for cluster in clusters:
        props = cluster.properties
        if _is_true(props.get("PubliclyAccessible")):
            add(cluster, "CF-RS-002", "Redshift cluster is publicly accessible", "High", "Security",
                "PubliclyAccessible gives the cluster an internet-facing address. Set it to false and "
                "connect from inside the VPC (Security Hub Redshift.1). In CDK: publiclyAccessible: false.")
        if _days(cluster, "AutomatedSnapshotRetentionPeriod", 1) == 0:
            add(cluster, "CF-RS-003", "Redshift cluster has no automated snapshots", "Medium", "Reliability",
                "AutomatedSnapshotRetentionPeriod is 0, which turns automated snapshots off. Set it to at "
                "least 7 days, the minimum Security Hub Redshift.3 expects. In CDK: "
                "automatedSnapshotRetentionPeriod on a CfnCluster.")
        if not _redshift_logs(cluster, clusters, logging):
            add(cluster, "CF-RS-004", "Redshift cluster has no audit logging", "Low", "Operational Excellence",
                "Set LoggingProperties (Terraform aws_redshift_logging) to send connection and user logs "
                "to S3 or CloudWatch Logs (Security Hub Redshift.4). In CDK: loggingProperties.")
        upgrade = props.get("AllowVersionUpgrade")
        if upgrade is not None and _flag(upgrade) is False:  # unset: on
            add(cluster, "CF-RS-005", "Redshift cluster does not take major version upgrades", "Low", "Security",
                "AllowVersionUpgrade is false, so the cluster misses major version updates, which can "
                "include security patches. Set it to true (Security Hub Redshift.6). In CDK: "
                "allowVersionUpgrade: true.")
        if "EnhancedVpcRouting" not in cluster.unresolved and _flag(props.get("EnhancedVpcRouting")) is False:
            add(cluster, "CF-RS-006", "Redshift cluster does not use enhanced VPC routing", "Low", "Security",
                "COPY and UNLOAD traffic can leave the VPC, out of reach of its security groups and flow "
                "logs. Set EnhancedVpcRouting: true (Security Hub Redshift.7). In CDK: enhancedVpcRouting: true.")
        # A cluster restored from a snapshot keeps the snapshot's names.
        if props.get("SnapshotIdentifier") is None:
            defaults = []
            for key, default, label in (("MasterUsername", "awsuser", "admin user"), ("DBName", "dev", "database")):
                value = props.get(key)
                if isinstance(value, str) and value.lower() == default:
                    defaults.append(f"{label} {default}")
            if defaults:
                add(cluster, "CF-RS-007", "Redshift cluster uses a default name", "Low", "Security",
                    f"This cluster uses the default {' and '.join(defaults)}, which anyone can guess. Choose "
                    "other names (Security Hub Redshift.8 covers the admin user). The admin user cannot be "
                    "changed later: create a new cluster. In CDK: masterUser and defaultDatabaseName.")

    for docdb in (r for r in usable if r.type == "docdb_cluster"):
        days = _short_backups(docdb)
        if days is not None:
            add(docdb, "CF-DOCDB-002", "DocumentDB cluster keeps backups for under 7 days", "Low", "Reliability",
                f"BackupRetentionPeriod is {days}. Set it to at least 7 (Security Hub DocumentDB.2). In "
                "CDK: backup: { retention: Duration.days(7) }.")
        if _exports_audit_logs(docdb) is False:
            add(docdb, "CF-DOCDB-003", "DocumentDB cluster does not export audit logs", "Low", "Operational Excellence",
                "Add audit to EnableCloudwatchLogsExports (Security Hub DocumentDB.4), and set audit_logs in "
                "the cluster parameter group, or no events are logged. In CDK: "
                "exportAuditLogsToCloudWatch: true.")
        if "DeletionProtection" not in docdb.unresolved and _flag(docdb.properties.get("DeletionProtection")) is False:
            add(docdb, "CF-DOCDB-004", "DocumentDB cluster has no deletion protection", "Low", "Reliability",
                "Set DeletionProtection: true, so the cluster cannot be deleted by mistake (Security Hub "
                "DocumentDB.5). In CDK: deletionProtection: true.")

    for neptune in (r for r in usable if r.type == "neptune_cluster"):
        if _exports_audit_logs(neptune) is False:
            add(neptune, "CF-NEP-002", "Neptune cluster does not export audit logs", "Low", "Operational Excellence",
                "Add audit to EnableCloudwatchLogsExports (Security Hub Neptune.2), and set "
                "neptune_enable_audit_log to 1 in the cluster parameter group, or no events are logged. In "
                "CDK: cloudwatchLogsExports: [neptune.LogType.AUDIT].")
        if "DeletionProtection" not in neptune.unresolved and _flag(neptune.properties.get("DeletionProtection")) is False:
            add(neptune, "CF-NEP-003", "Neptune cluster has no deletion protection", "Low", "Reliability",
                "Set DeletionProtection: true, so the cluster cannot be deleted by mistake (Security Hub "
                "Neptune.4). In CDK: deletionProtection: true.")
        days = _short_backups(neptune)
        if days is not None:
            add(neptune, "CF-NEP-004", "Neptune cluster keeps backups for under 7 days", "Low", "Reliability",
                f"BackupRetentionPeriod is {days}. Set it to at least 7 (Security Hub Neptune.5). In CDK: "
                "backupRetention: Duration.days(7).")
        if "IamAuthEnabled" not in neptune.unresolved and _flag(neptune.properties.get("IamAuthEnabled")) is False:
            add(neptune, "CF-NEP-005", "Neptune cluster does not use IAM authentication", "Low", "Security",
                "Set IamAuthEnabled: true, so connections are signed with IAM credentials (Security Hub "
                "Neptune.7). In CDK: iamAuthentication: true.")
    return out


_DEFINITION_MAX_BYTES = 1_000_000


def _definition_text(value: Any) -> str | None:
    """A DefinitionString as text. Fn::Join parts that are not text become a placeholder: inside
    a JSON string that is harmless, and anywhere else the text no longer parses, so it is not judged."""
    if isinstance(value, str):
        return value
    if not isinstance(value, dict) or len(value) != 1:
        return None
    sub = value.get("Fn::Sub")
    if isinstance(sub, list) and sub:
        sub = sub[0]
    if isinstance(sub, str):
        return sub
    join = value.get("Fn::Join")
    if isinstance(join, list) and len(join) == 2 and isinstance(join[0], str) and isinstance(join[1], list):
        return join[0].join(p if isinstance(p, str) else "x" for p in join[1])
    return None


def _local_definition(location: str, res: Resource, template_path: Path) -> dict | None:
    """A DefinitionS3Location that is a local path, as `aws cloudformation package` takes it.
    Only a file under the template's own folder is read."""
    try:
        base = Path(res.file or template_path).parent.resolve()
        path = (base / location).resolve()
        if not path.is_relative_to(base) or not path.is_file() or path.stat().st_size > _DEFINITION_MAX_BYTES:
            return None
    except (OSError, ValueError):
        return None
    doc, error = _read_template(path)
    return None if error else doc


def _state_machine_definition(res: Resource, template_path: Path) -> dict | None:
    """The definition as data, or None when the scan cannot read it."""
    props = res.properties
    definition = props.get("Definition")
    if definition is not None:
        return definition if isinstance(definition, dict) and not _is_intrinsic(definition) else None
    if props.get("DefinitionString") is not None:
        text = _definition_text(props["DefinitionString"])
        try:
            parsed = json.loads(text) if text is not None else None
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    location = props.get("DefinitionS3Location")
    return _local_definition(location, res, template_path) if isinstance(location, str) else None


def _states(definition: Any) -> dict[str, dict]:
    states = definition.get("States") if isinstance(definition, dict) else None
    if not isinstance(states, dict):
        return {}
    return {str(name): state for name, state in states.items() if isinstance(state, dict)}


def _task_states(definition: Any) -> list[tuple[str, dict]]:
    """Every Task state, including those inside Parallel branches and Map states."""
    out: list[tuple[str, dict]] = []
    for name, state in _states(definition).items():
        if state.get("Type") == "Task":
            out.append((name, state))
        branches = state.get("Branches")
        nested = list(branches) if isinstance(branches, list) else []
        nested += [state.get("ItemProcessor"), state.get("Iterator")]
        for inner in nested:
            out.extend(_task_states(inner))
    return out


def _last_tasks(definition: Any) -> list[tuple[str, dict]]:
    """Top-level Task states that end the workflow. A failure inside a Parallel or Map state
    reaches the state around it, so nested tasks are not asked for a Catch."""
    states = _states(definition)
    return [
        (name, state) for name, state in states.items()
        if state.get("Type") == "Task" and (
            state.get("End") is True or states.get(str(state.get("Next")), {}).get("Type") == "Succeed")
    ]


def _shown(names: List[str]) -> str:
    return ", ".join(names[:5]) + (" ..." if len(names) > 5 else "")


def _no_retry_or_catch(definition: dict) -> str | None:
    """What CF-SFN-001 reports for a definition, or None."""
    parts = []
    no_retry = [name for name, state in _task_states(definition) if not state.get("Retry")]
    if no_retry:
        parts.append(f"Task states with no Retry: {_shown(no_retry)}.")
    no_catch = [name for name, state in _last_tasks(definition) if not state.get("Catch")]
    if no_catch:
        parts.append(f"Last tasks with no Catch: {_shown(no_catch)}.")
    return " ".join(parts) or None


def _tracing_off(res: Resource) -> bool:
    config = res.properties.get("TracingConfiguration")
    if "TracingConfiguration" in res.unresolved:
        return False
    if config is None:
        return True
    if not isinstance(config, dict) or _is_intrinsic(config):
        return False
    return _flag(config.get("Enabled")) is False


def _logging_off(res: Resource) -> bool:
    config = res.properties.get("LoggingConfiguration")
    if "LoggingConfiguration" in res.unresolved:
        return False
    if config is None:
        return True
    if not isinstance(config, dict) or (config and _is_intrinsic(config)):
        return False
    level = config.get("Level", "OFF")  # the service default
    return isinstance(level, str) and level.upper() == "OFF"


def _no_dead_letter(target: dict, res: Resource) -> bool:
    if "DeadLetterConfig" in res.unresolved:
        return False
    config = target.get("DeadLetterConfig")
    if not config:
        return True
    return isinstance(config, dict) and not _is_intrinsic(config) and not config.get("Arn")


def _no_retries(target: dict, res: Resource) -> bool:
    if "RetryPolicy" in res.unresolved:
        return False
    policy = target.get("RetryPolicy")
    if policy is None:
        return True
    return isinstance(policy, dict) and not _is_intrinsic(policy) \
        and policy.get("MaximumRetryAttempts") in (0, "0")


def _rule_targets(res: Resource) -> list[tuple[str, dict]]:
    """(label, target) for a Terraform target, or for each target of a CloudFormation rule."""
    if res.type == "events_target":
        return [(res.name, res.properties)]
    targets = res.properties.get("Targets")
    if not isinstance(targets, list):
        return []
    return [(str(t.get("Id", "unnamed")), t) for t in targets if isinstance(t, dict) and not _is_intrinsic(t)]


def _error_handling_findings(resources: List[Resource], template_path: Path) -> List[Finding]:
    """Step Functions (CF-SFN-001..003), EventBridge targets (CF-EB-001/002) and SQS visibility
    against its Lambda consumer (CF-SQS-003). A value the scan cannot read is not judged."""
    usable = [r for r in resources if not r.malformed]
    out: List[Finding] = []

    def add(res: Resource, check_id: str, title: str, severity: Severity, category: str,
            recommendation: str) -> None:
        out.append(Finding(
            id=check_id, title=title, severity=severity, category=category,
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    for machine in (r for r in usable if r.type == "sfn_state_machine"):
        definition = _state_machine_definition(machine, template_path)
        gaps = _no_retry_or_catch(definition) if definition is not None else None
        if gaps:
            add(machine, "CF-SFN-001", "Step Functions tasks have no retry or catch", "Low", "Reliability",
                f"{gaps} A short failure then fails the whole execution, with no handling. Add Retry for "
                "errors that pass, and Catch on the last task. In CDK: addRetry() and addCatch().")
        if _tracing_off(machine):
            add(machine, "CF-SFN-002", "Step Functions state machine has no X-Ray tracing", "Low",
                "Operational Excellence",
                "Set TracingConfiguration.Enabled: true to trace executions across services. In CDK: "
                "tracingEnabled: true.")
        if _logging_off(machine):
            add(machine, "CF-SFN-003", "Step Functions state machine has no logging", "Medium",
                "Operational Excellence",
                "Set LoggingConfiguration with Level ERROR or ALL and a CloudWatch Logs destination, or "
                "failed executions leave no log (Security Hub StepFunctions.1). In CDK: logs: { destination, "
                "level: sfn.LogLevel.ERROR }.")

    for res in (r for r in usable if r.type in ("events_rule", "events_target")):
        targets = _rule_targets(res)
        no_dlq = [label for label, target in targets if _no_dead_letter(target, res)]
        no_retry = [label for label, target in targets if _no_retries(target, res)]
        if no_dlq:
            add(res, "CF-EB-001", "EventBridge rule target has no dead-letter queue", "Low",
                "Operational Excellence",
                f"Targets: {_shown(no_dlq)}. An event that cannot be delivered is lost when retries run out. "
                "Set DeadLetterConfig.Arn to an SQS queue. In CDK: deadLetterQueue on the target.")
        if no_retry:
            add(res, "CF-EB-002", "EventBridge rule target has no retry policy", "Low", "Reliability",
                f"Targets: {_shown(no_retry)}. With no RetryPolicy, a failing target is retried on the "
                "default of 185 attempts over 24 hours; with MaximumRetryAttempts 0, it is not retried. Set "
                "RetryPolicy to what the target can take. In CDK: retryAttempts and maxEventAge on the target.")

    functions = [r for r in usable if r.type == "lambda_function"]
    mappings = [r for r in usable if r.type == "lambda_event_source_mapping"]
    for queue in (r for r in usable if r.type == "sqs_queue"):
        visibility = _days(queue, "VisibilityTimeout", 30)
        if visibility is None:
            continue
        consumers = {
            fn.name: timeout for m in mappings if _points_at(m, "EventSourceArn", queue)
            for fn in functions if _points_at(m, "FunctionName", fn)
            for timeout in [_days(fn, "Timeout", 3)]
            if timeout is not None and timeout > visibility
        }
        if consumers:
            name, timeout = max(consumers.items(), key=lambda item: item[1])
            add(queue, "CF-SQS-003", "SQS visibility timeout is shorter than its Lambda timeout", "Medium",
                "Reliability",
                f"VisibilityTimeout is {visibility} seconds and {name} can run for {timeout}, so a message "
                "becomes visible again while it is still being handled and runs twice. Set VisibilityTimeout "
                "to at least 6 times the function timeout, as AWS advises. In CDK: visibilityTimeout.")
    return out


_WORLD_V4, _WORLD_V6 = "0.0.0.0/0", "::/0"
_ALL_PROTOCOLS = ("-1", -1, "all")


def _open_to_world(rule: dict, v4: str = "CidrIp", v6: str = "CidrIpv6") -> bool:
    """True when a rule's literal CIDR is the whole IPv4 or IPv6 internet."""
    cidr, cidr6 = rule.get(v4), rule.get(v6)
    return (type(cidr) is str and cidr.strip() == _WORLD_V4) or (
        type(cidr6) is str and cidr6.strip() == _WORLD_V6)


def _all_ports(rule: dict) -> bool:
    """True for protocol -1, or a port range that spans every port. An intrinsic is not."""
    if rule.get("IpProtocol") in _ALL_PROTOCOLS:
        return True
    low, high = rule.get("FromPort"), rule.get("ToPort")
    if low is None and high is None:
        return rule.get("IpProtocol") is None  # Terraform protocol -1 drops both ports
    return low in (0, "0") and high in (65535, "65535")


def _sg_rules_of(res: Resource, key: str) -> list[dict]:
    """The rules of a security group (inline list) or of one standalone rule resource."""
    if res.type == "security_group":
        rules = res.properties.get(key)
        return [r for r in rules if isinstance(r, dict)] if isinstance(rules, list) else []
    return [res.properties]


def _security_group_findings(
    res: Resource, template_path: Path, default_egress_open: bool
) -> List[Finding]:
    """CF-SG-001 (sensitive port), CF-SG-002 (all ports) and CF-SG-003 (all egress) on a
    security group or a standalone ingress or egress rule.

    A rule open on every port is reported as CF-SG-002 only, not also as CF-SG-001. A
    CloudFormation group created with no SecurityGroupEgress gets the AWS default rule,
    which allows all outbound traffic; a standalone AWS::EC2::SecurityGroupEgress is added
    after creation and does not remove it. Terraform removes that default.
    """
    out: List[Finding] = []

    def finding(check_id: str, title: str, severity: Severity, recommendation: str) -> Finding:
        return Finding(
            id=check_id, title=title, severity=severity, category="Security",
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        )

    if res.type != "security_group_egress_rule":
        open_in = [r for r in _sg_rules_of(res, "SecurityGroupIngress") if _open_to_world(r)]
        if any(_all_ports(r) for r in open_in):
            out.append(finding(
                "CF-SG-002", "Security group allows all inbound traffic from 0.0.0.0/0 or ::/0", "High",
                (
                    "Remove the rule that opens every port to the internet, and allow only the "
                    "ports the service needs, usually 80 and 443 (Security Hub EC2.18). "
                    "Reach admin ports through Session Manager or a VPN instead."
                ),
            ))
        elif any(_port_in_sensitive(r.get("FromPort"), r.get("ToPort")) for r in open_in):
            out.append(finding(
                "CF-SG-001", "Security group allows 0.0.0.0/0 or ::/0 on sensitive port", "High",
                (
                    "Restrict ingress to specific CIDRs or security groups. Do not open SSH (22), "
                    "RDP (3389), database ports or other high-risk ports such as 21, 23, 445 or "
                    "8080 to the internet (Security Hub EC2.13, EC2.14, EC2.19)."
                ),
            ))
    if res.type != "security_group_ingress_rule":
        egress = _sg_rules_of(res, "SecurityGroupEgress")
        default_open = default_egress_open and "SecurityGroupEgress" not in res.properties
        if default_open or any(_open_to_world(r) and _all_ports(r) for r in egress):
            out.append(finding(
                "CF-SG-003", "Security group allows all outbound traffic to 0.0.0.0/0", "Low",
                (
                    ("No SecurityGroupEgress is set, so AWS keeps its default rule that allows all "
                     "outbound traffic. " if default_open else "")
                    + "Allow egress only to the ports and destinations the workload calls, such as "
                    "443 to a VPC endpoint or prefix list. In CDK: allowAllOutbound: false, then "
                    "connections.allowTo(...)."
                ),
            ))
    return out


_NACL_PORTS = (22, 3389)


def _nacl_entry_opens_admin_port(entry: dict) -> bool | None:
    """True when an inbound allow entry opens 22 or 3389 to the internet. None when a value
    it needs is not a literal."""
    egress = entry.get("Egress")
    if not (egress is None or egress is False or (isinstance(egress, str) and egress.lower() == "false")):
        return False
    action = entry.get("RuleAction")
    if type(action) is not str:
        return None
    if action.lower() != "allow" or not _open_to_world(entry, "CidrBlock", "Ipv6CidrBlock"):
        return False
    protocol = entry.get("Protocol")
    if protocol in _ALL_PROTOCOLS:
        return True
    if str(protocol).lower() not in ("6", "17", "tcp", "udp"):
        return None if isinstance(protocol, dict) else False
    ports = entry.get("PortRange")
    if not isinstance(ports, dict) or _is_intrinsic(ports):
        return None
    low, high = ports.get("From"), ports.get("To")
    if low is None or high is None:
        return None
    try:
        return any(int(low) <= p <= int(high) for p in _NACL_PORTS)
    except (TypeError, ValueError):
        return None


def _nacl_findings(res: Resource, template_path: Path) -> List[Finding]:
    """CF-NACL-001: a network ACL entry, or a Terraform aws_network_acl ingress block, that
    allows 22 or 3389 from the internet. Rule order is not read: a lower-numbered deny
    entry may still block the traffic."""
    if res.type == "network_acl":
        entries = res.properties.get("Entries")
        entries = [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []
    else:
        entries = [res.properties]
    if not any(_nacl_entry_opens_admin_port(e) for e in entries):
        return []
    return [Finding(
        id="CF-NACL-001",
        title="Network ACL allows SSH or RDP from 0.0.0.0/0 or ::/0",
        severity="Medium",
        category="Security",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            "Allow port 22 and 3389 only from known CIDRs, or deny them, in the network ACL "
            "(Security Hub EC2.21). Security groups still apply, but the ACL is the subnet-wide "
            "layer."
        ),
    )]


def _az_key(subnet: Resource) -> str | None:
    """The subnet's Availability Zone as a comparable key, or None when it is not set or
    cannot be read. CDK writes {"Fn::Select": [i, {"Fn::GetAZs": ""}]}, one i per AZ."""
    for key in ("AvailabilityZone", "AvailabilityZoneId"):
        if key in subnet.unresolved:
            return None
        value = subnet.properties.get(key)
        if value is not None:
            return json.dumps(value, sort_keys=True, default=str)
    return None


def _nat_single_az_findings(
    resources: List[Resource], template_path: Path,
    at: Callable[[Resource | None], tuple[str, int | None, str]],
) -> List[Finding]:
    """CF-NAT-001: one NAT gateway that private subnets in more than one AZ route through.

    The route tables that send traffic to the NAT gateway are found from AWS::EC2::Route
    (or Terraform inline routes), and their subnets from the route table associations. A
    subnet whose AZ cannot be read is not counted.
    """
    nats = [r for r in resources if r.type == "nat_gateway" and not r.malformed]
    if not nats:
        return []
    routes = [r for r in resources if r.type == "route" and not r.malformed]
    tables = [r for r in resources if r.type == "route_table" and not r.malformed]
    links = [r for r in resources if r.type == "route_table_association" and not r.malformed]
    subnets = [r for r in resources if r.type == "subnet" and not r.malformed]
    out: List[Finding] = []
    for nat in nats:
        served = [t for t in tables if _points_at(t, "Routes", nat) or any(
            _points_at(route, "NatGatewayId", nat) and _points_at(route, "RouteTableId", t)
            for route in routes)]
        azs: set[str] = set()
        for table in served:
            for link in links:
                if not _points_at(link, "RouteTableId", table):
                    continue
                for subnet in subnets:
                    if _points_at(link, "SubnetId", subnet):
                        az = _az_key(subnet)
                        if az is not None:
                            azs.add(az)
        if len(azs) < 2:
            continue
        file, line, _ = at(nat)
        out.append(Finding(
            id="CF-NAT-001",
            title="One NAT gateway serves private subnets in several Availability Zones",
            severity="Medium",
            category="Reliability",
            file=file,
            line=line,
            evidence=f"{nat.name} ({nat.source_type})",
            recommendation=(
                f"Private subnets in {len(azs)} AZs route through this NAT gateway. If its AZ fails, private subnets in the other AZs lose their route "
                "to the internet. Put one NAT gateway in each AZ and route each private subnet to "
                "the one in its own AZ. In CDK: natGateways equal to maxAzs. In dev, one NAT "
                "gateway may be an accepted saving."
            ),
        ))
    return out


def _tgw_flow_log_findings(
    resources: List[Resource], template_path: Path,
    at: Callable[[Resource | None], tuple[str, int | None, str]],
) -> List[Finding]:
    """CF-TGW-002: a transit gateway that no AWS::EC2::FlowLog / aws_flow_log points at.
    A transit gateway flow log the scan cannot tie to a gateway counts for all of them."""
    gateways = [r for r in resources if r.type == "transit_gateway" and not r.malformed]
    if not gateways:
        return []
    logs = [
        r for r in resources if r.type == "flow_log" and not r.malformed
        and r.properties.get("ResourceType") in ("TransitGateway", "TransitGatewayAttachment")
    ]
    out: List[Finding] = []
    for tgw in gateways:
        tied = [log for log in logs if _points_at(log, "ResourceId", tgw)]
        # A gateway log the scan cannot tie may be this one. An attachment log is not.
        unlinked = any("ResourceId" in log.unresolved or (
            log.properties.get("ResourceType") == "TransitGateway"
            and not any(_points_at(log, "ResourceId", g) for g in gateways)) for log in logs)
        if tied or unlinked:
            continue
        file, line, _ = at(tgw)
        out.append(Finding(
            id="CF-TGW-002",
            title="Transit gateway has no flow logs",
            severity="Low",
            category="Operational Excellence",
            file=file,
            line=line,
            evidence=f"{tgw.name} ({tgw.source_type})",
            recommendation=(
                "Add an AWS::EC2::FlowLog with ResourceType: TransitGateway and ResourceId set to "
                "this gateway, so traffic between attached VPCs can be traced. In Terraform: "
                "aws_flow_log with transit_gateway_id."
            ),
        ))
    return out


def _gateway_endpoint_findings(
    resources: List[Resource], template_path: Path,
    at: Callable[[Resource | None], tuple[str, int | None, str]],
) -> List[Finding]:
    """CF-VPC-002 / CF-VPC-003: a VPC with a NAT gateway and no gateway endpoint for S3 or
    DynamoDB. Its private subnets then reach the service through the NAT gateway, which
    bills every GB it processes; a gateway endpoint is free.

    NAT gateways and endpoints are tied to a VPC through their subnet and VpcId. One the
    scan cannot tie to a VPC is judged at template level: an endpoint then covers every
    VPC, and a NAT gateway counts for the template as a whole. An endpoint whose service
    or type cannot be read may be the missing one, so its VPC is not judged.
    """
    nats = [
        r for r in resources if r.type == "nat_gateway" and not r.malformed
        and "ConnectivityType" not in r.unresolved
        and r.properties.get("ConnectivityType", "public") == "public"  # a private NAT has no route out
    ]
    if not nats:
        return []
    vpcs = [r for r in resources if r.type == "vpc"]
    subnets = [r for r in resources if r.type == "subnet"]

    def vpc_of(res: Resource) -> Resource | None:
        return next((v for v in vpcs if _points_at(res, "VpcId", v)), None)

    def nat_vpc(nat: Resource) -> Resource | None:
        subnet = next((s for s in subnets if _points_at(nat, "SubnetId", s)), None)
        return vpc_of(subnet) if subnet is not None else None

    groups: list[tuple[Resource | None, Resource]] = []  # (VPC or None, first NAT gateway in it)
    for nat in nats:
        vpc = nat_vpc(nat)
        if all(g[0] is not vpc for g in groups):
            groups.append((vpc, nat))

    endpoints = []
    for r in resources:
        if r.type != "vpc_endpoint":
            continue
        service = None if r.malformed or "ServiceName" in r.unresolved \
            else _endpoint_service(r.properties.get("ServiceName"))
        endpoints.append((vpc_of(r), service, None if r.malformed else _endpoint_is_gateway(r)))

    per_gb = estimates.nat_processing_price()
    cost = f"NAT gateway data processing costs {per_gb}" if per_gb else "NAT gateway data processing is billed per GB"
    out: List[Finding] = []
    for vpc, nat in groups:
        for suffix, check_id, label in _GATEWAY_SERVICES:
            here = [e for e in endpoints if vpc is None or e[0] is None or e[0] is vpc]
            if any(service == suffix and gateway for _, service, gateway in here):
                continue
            if any((service is None and gateway is not False) or (service == suffix and gateway is None)
                   for _, service, gateway in here):
                continue  # an endpoint the scan cannot read may be this one
            anchor = vpc if vpc is not None else nat
            file, line, _ = at(anchor)
            where = "this VPC" if vpc is not None else "this template"
            out.append(Finding(
                id=check_id,
                title=f"{label} traffic goes through the NAT gateway",
                severity="Low",
                category="Cost Optimization",
                file=file,
                line=line,
                evidence=f"{anchor.name} ({anchor.source_type})",
                recommendation=(
                    f"{where.capitalize()} has a NAT gateway and no gateway VPC endpoint for {label}, so "
                    f"private subnets reach {label} through the NAT gateway. {cost}; a gateway endpoint "
                    f"for {label} carries no hourly or data charge. Add an AWS::EC2::VPCEndpoint with "
                    f"VpcEndpointType Gateway for {label} on the private route tables. An Interface "
                    f"endpoint for {label} is billed by the hour and GB: only the Gateway type is free. "
                    f"In CDK: vpc.addGatewayEndpoint('{label}', {{ service: "
                    f"ec2.GatewayVpcEndpointAwsService.{label.upper()} }})."
                ),
            ))
    return out


def _autoscaling_finding(res: Resource, template_path: Path) -> Finding | None:
    """CF-DDB-003: provisioned capacity that no scaling target in this template adjusts."""
    if "BillingMode" in res.unresolved or res.properties.get("BillingMode", "PROVISIONED") != "PROVISIONED":
        return None
    finding = Finding(
        id="CF-DDB-003",
        title="DynamoDB provisioned capacity has no autoscaling",
        severity="Medium",
        category="Cost Optimization",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            "BillingMode is PROVISIONED and no AWS::ApplicationAutoScaling::ScalableTarget "
            "(Terraform aws_appautoscaling_target) in this template scales the table, so it pays "
            "for its peak capacity all day and throttles above it. Add read and write scaling "
            "targets with target-tracking policies, or use PAY_PER_REQUEST for spiky traffic. "
            "In CDK: table.autoScaleReadCapacity(...).scaleOnUtilization(...)."
        ),
    )
    return estimates.apply(finding, estimates.dynamodb_provisioned(res.properties))


def _s3_storage_findings(res: Resource, template_path: Path) -> List[Finding]:
    """CF-S3-006 (no lifecycle rules) and CF-S3-007 (nothing moves to a cheaper class)."""
    props = res.properties
    lifecycle = props.get("LifecycleConfiguration")
    tiering = props.get("IntelligentTieringConfigurations")
    def make(fid: str, title: str, recommendation: str) -> Finding:
        return Finding(id=fid, title=title, severity="Low", category="Cost Optimization",
                       file=res.file or str(template_path), line=res.line,
                       evidence=f"{res.name} ({res.source_type})", recommendation=recommendation)

    if lifecycle is None:
        return [make(
            "CF-S3-006", "S3 bucket has no lifecycle rules",
            (
                "Objects stay in S3 Standard until someone deletes them. Add a "
                "LifecycleConfiguration that expires old objects and versions, and moves data "
                "read rarely to a cheaper class (Standard-IA, Glacier Instant Retrieval), or to "
                "INTELLIGENT_TIERING when access is unknown. In CDK: lifecycleRules."
            ),
        )]
    rules = lifecycle.get("Rules") if isinstance(lifecycle, dict) and not _is_intrinsic(lifecycle) else None
    if not isinstance(rules, list):
        return []
    if any(not isinstance(rule, dict) or _is_intrinsic(rule) for rule in rules):
        return []  # a rule from Fn::If: not judged
    enabled = [rule for rule in rules if rule.get("Status") != "Disabled"]
    if not enabled:
        return [make(
            "CF-S3-006", "S3 bucket has no lifecycle rules",
            "Every lifecycle rule is Disabled, so objects stay in S3 Standard until someone "
            "deletes them. Enable a rule that expires old objects and versions, and moves data "
            "read rarely to a cheaper class, or to INTELLIGENT_TIERING when access is unknown. "
            "In CDK: lifecycleRules.",
        )]
    if tiering:
        return []
    moves = any(
        rule.get("Transitions") or rule.get("NoncurrentVersionTransitions")
        or rule.get("Transition") or rule.get("NoncurrentVersionTransition")
        for rule in enabled
    )
    if moves:
        return []
    return [make(
        "CF-S3-007", "S3 bucket never moves objects to a cheaper storage class",
        (
            "The lifecycle rules only expire objects; nothing moves to a cheaper class. For data "
            "with unknown or changing access, add a transition to INTELLIGENT_TIERING (or an "
            "IntelligentTieringConfiguration); for data read rarely, to Standard-IA or Glacier "
            "Instant Retrieval. Intelligent-Tiering does not pay off for objects under 128 KB. "
            "In CDK: transitions with storageClass: s3.StorageClass.INTELLIGENT_TIERING."
        ),
    )]


def _gp2_block_devices(res: Resource, template_path: Path) -> Finding | None:
    """CF-EBS-002 on a launch template: block devices set to gp2. An unset type comes from
    the AMI's mapping, so only an explicit gp2 is reported."""
    data = res.properties.get("LaunchTemplateData")
    mappings = res.properties.get("BlockDeviceMappings")  # Terraform keeps them apart
    if mappings is None and isinstance(data, dict):
        mappings = data.get("BlockDeviceMappings")
    devices = []
    for i, item in enumerate(mappings if isinstance(mappings, list) else []):
        ebs = item.get("Ebs") if isinstance(item, dict) else None
        if isinstance(ebs, dict) and ebs.get("VolumeType") == "gp2":
            name = item.get("DeviceName")
            devices.append(name if type(name) is str else f"device {i + 1}")
    if not devices:
        return None
    return Finding(
        id="CF-EBS-002",
        title="Launch template block device uses gp2 instead of gp3",
        severity="Low",
        category="Cost Optimization",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            f"VolumeType is gp2 on {', '.join(devices)}. gp3 costs about 20% less per GB and "
            "includes 3,000 IOPS and 125 MB/s at any size. Set VolumeType to gp3 on each device "
            "(Iops over 1,000 GiB to keep the gp2 baseline). Every instance the template "
            "launches gets these volumes. In CDK: volume: ec2.BlockDeviceVolume.ebs(size, "
            "{ volumeType: ec2.EbsDeviceVolumeType.GP3 })."
        ),
    )


def _waf_finding(res: Resource, template_path: Path) -> Finding | None:
    """CF-WAF-001 for an internet-facing ALB or a REST API stage (callers check coverage)."""
    props = res.properties
    if res.type == "lb":
        lb_type, scheme = props.get("Type", "application"), props.get("Scheme", "internet-facing")
        if lb_type != "application" or scheme != "internet-facing":
            return None  # NLB/GWLB cannot have WAF; internal ALBs are out of scope
        what = "Application Load Balancer"
    else:
        what = "API Gateway REST API stage"
    return Finding(
        id="CF-WAF-001",
        title=f"{what} has no WAF web ACL in this template",
        severity="Low",
        category="Security",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            "No AWS::WAFv2::WebACLAssociation in this template points at it. If a web ACL is "
            "not attached elsewhere, associate one to filter common attacks (Security Hub "
            "ELB.16, APIGateway.4). In CDK: new wafv2.CfnWebACLAssociation."
        ),
    )


def _cdk_generated_subnet(props: dict) -> bool:
    """A public subnet that CDK ec2.Vpc creates: it maps public IPs by design."""
    tags = props.get("Tags")
    return isinstance(tags, list) and any(
        isinstance(t, dict) and t.get("Key") == "aws-cdk:subnet-type" and t.get("Value") == "Public"
        for t in tags
    )


def _public_ip_interfaces(interfaces: Any) -> list[str]:
    """Device indexes of network interfaces with AssociatePublicIpAddress true."""
    out: list[str] = []
    for i, item in enumerate(interfaces if isinstance(interfaces, list) else []):
        if isinstance(item, dict) and not _is_intrinsic(item) and _flag(item.get("AssociatePublicIpAddress")):
            index = item.get("DeviceIndex")
            out.append(str(index) if type(index) in (str, int) else str(i))
    return out


def _public_ip_findings(res: Resource, template_path: Path) -> List[Finding]:
    """CF-EC2-002 (subnet maps public IPs) and CF-EC2-003 (instance asks for one)."""
    props = res.properties
    out: List[Finding] = []

    def add(fid: str, title: str, detail: str) -> None:
        out.append(Finding(
            id=fid, title=title, severity="Medium", category="Security",
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})",
            recommendation=(
                f"{detail} Keep instances in private subnets and put a load balancer, NAT "
                "gateway or VPC endpoints in front of them (Security Hub EC2.15, EC2.9)."
            ),
        ))

    if res.type == "subnet":
        if _flag(props.get("MapPublicIpOnLaunch")) and not _cdk_generated_subnet(props):
            add("CF-EC2-002", "Subnet assigns public IPs automatically",
                "MapPublicIpOnLaunch is true, so every instance launched here gets a public IP. "
                "Set it to false unless the subnet only holds load balancers or NAT gateways.")
    elif res.type in ("instance", "launch_template"):
        interfaces = props.get("NetworkInterfaces")  # instance; Terraform launch templates too
        data = props.get("LaunchTemplateData")
        if interfaces is None and isinstance(data, dict):
            interfaces = data.get("NetworkInterfaces")
        devices = _public_ip_interfaces(interfaces)
        if devices:
            add("CF-EC2-003", "EC2 instance requests a public IP address",
                f"AssociatePublicIpAddress is true on network interface {', '.join(devices)}. "
                "Set it to false.")
    return out


# Stateful types whose data goes with the stack unless a policy keeps it (CF-DEL-001).
_STATEFUL_TYPES = frozenset({
    "db_instance", "rds_cluster", "dynamodb_table", "s3_bucket", "efs_file_system",
    "cloudwatch_log_group",
})
# Of those, the types CloudFormation can snapshot.
_SNAPSHOT_TYPES = frozenset({"db_instance", "rds_cluster"})


def _keeps_data(res: Resource, key: str) -> bool | None:
    """Whether DeletionPolicy / UpdateReplacePolicy keeps the data; None when not literal.

    No DeletionPolicy means Delete, except RDS clusters and standalone RDS instances,
    which CloudFormation snapshots by default. No UpdateReplacePolicy always means Delete.
    Snapshot on a type that cannot be snapshotted also means Delete. RetainExceptOnCreate
    is a DeletionPolicy value only.
    """
    value = res.policies.get(key)
    if value is None:
        is_rds = res.source_type.startswith("AWS::RDS::") and res.type in _SNAPSHOT_TYPES
        return key == "DeletionPolicy" and is_rds
    if type(value) is not str:
        return None  # Fn::If, or a Terraform expression
    if value == "Retain" or (value == "RetainExceptOnCreate" and key == "DeletionPolicy"):
        return True
    return value == "Snapshot" and res.type in _SNAPSHOT_TYPES


def _deletion_finding(res: Resource, template_path: Path) -> Finding | None:
    """CF-DEL-001: a stateful resource whose data is lost when the stack deletes or replaces it."""
    if res.type == "db_instance" and (
        res.properties.get("DBClusterIdentifier") or "DBClusterIdentifier" in res.unresolved
    ):
        return None  # an Aurora member (or maybe one): the cluster holds the data
    terraform = not res.source_type.startswith("AWS::")
    if terraform:
        keep = _keeps_data(res, "DeletionPolicy")
        if keep is None or keep:
            return None
        detail = (
            "lifecycle.prevent_destroy is not true, so terraform destroy, or a change that "
            "forces replacement, deletes it and its data. Add lifecycle { prevent_destroy = true }."
        )
    else:
        on_delete = _keeps_data(res, "DeletionPolicy")
        on_replace = _keeps_data(res, "UpdateReplacePolicy")
        # Only a policy known to delete is reported: one set with Fn::If is not judged.
        missing = [
            k for k, kept in (("DeletionPolicy", on_delete), ("UpdateReplacePolicy", on_replace))
            if kept is False
        ]
        if not missing:
            return None
        keep_value = "Snapshot or Retain" if res.type in _SNAPSHOT_TYPES else "Retain"
        when = {
            "DeletionPolicy": "the stack is deleted or the resource is removed from the template",
            "UpdateReplacePolicy": "an update replaces it",
        }
        detail = (
            f"{' and '.join(missing)} {'does' if len(missing) == 1 else 'do'} not keep the data, "
            f"so CloudFormation deletes it when {' or when '.join(when[k] for k in missing)}. "
            f"Set {' and '.join(missing)} to {keep_value}."
        )
    return Finding(
        id="CF-DEL-001",
        title="Stateful resource is deleted with the stack",
        severity="Medium",
        category="Reliability",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            f"{detail} Stacks for short-lived dev environments can exclude CF-DEL-001. "
            "In CDK: removalPolicy: RemovalPolicy.RETAIN (or SNAPSHOT for RDS), not DESTROY."
        ),
    )


def _ecr_findings(res: Resource, template_path: Path) -> List[Finding]:
    """CF-ECR-001 (scan on push), CF-ECR-002 (mutable tags), CF-ECR-003 (no lifecycle policy)."""
    props = res.properties
    out: List[Finding] = []

    def add(fid: str, title: str, recommendation: str) -> None:
        out.append(Finding(
            id=fid, title=title, severity="Low", category="Security",
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    scanning = props.get("ImageScanningConfiguration")
    if scanning is None:
        scan: bool | None = False
    elif isinstance(scanning, dict) and not _is_intrinsic(scanning):
        scan = _flag(scanning.get("ScanOnPush"))
    else:
        scan = None
    if scan is False:
        add("CF-ECR-001", "ECR repository does not scan images on push",
            "Set ImageScanningConfiguration.ScanOnPush to true. If the registry uses enhanced "
            "scanning (Amazon Inspector), that setting replaces this one and this finding can be "
            "excluded. In CDK: imageScanOnPush: true.")
    mutability = props.get("ImageTagMutability", "MUTABLE")
    if mutability in ("MUTABLE", "MUTABLE_WITH_EXCLUSION"):
        add("CF-ECR-002", "ECR image tags are mutable",
            "ImageTagMutability is MUTABLE, so a push can overwrite a tag that a deployment "
            "points at. Set it to IMMUTABLE. In CDK: imageTagMutability: ecr.TagMutability.IMMUTABLE.")
    if not props.get("LifecyclePolicy"):
        add("CF-ECR-003", "ECR repository has no lifecycle policy",
            "Old and untagged images pile up and keep known vulnerabilities around. Add a "
            "LifecyclePolicy that expires them. In CDK: repository.addLifecycleRule().")
    return out


def _is_root_user(user: str) -> bool:
    """root or UID 0, with or without a group (root:root, 0:0)."""
    return user.split(":", 1)[0].strip() in ("root", "0")


def _ecs_findings(res: Resource, template_path: Path) -> List[Finding]:
    """CF-ECS-001 (privileged), CF-ECS-002 (writable root filesystem), CF-ECS-003 (root user).

    One finding per check, naming the containers. A container whose value is not literal
    (an intrinsic or a Terraform expression) is not judged for that check.
    """
    containers = res.properties.get("ContainerDefinitions")
    if not isinstance(containers, list):
        return []
    # Windows containers support neither User nor ReadonlyRootFilesystem. A family the scan
    # cannot read may be Windows, so those two checks are skipped then too.
    platform = res.properties.get("RuntimePlatform")
    if platform is None:
        family: Any = None
    elif isinstance(platform, dict) and not _is_intrinsic(platform):
        family = platform.get("OperatingSystemFamily")
    else:
        family = {"unknown": platform}
    windows = family is not None and (type(family) is not str or family.upper().startswith("WINDOWS"))
    privileged: list[str] = []
    writable: list[str] = []
    root: list[str] = []
    no_user: list[str] = []
    for i, c in enumerate(containers):
        if not isinstance(c, dict) or _is_intrinsic(c):
            continue
        name = c.get("Name")
        label = name if type(name) is str else f"#{i + 1}"
        if _flag(c.get("Privileged")) is True:
            privileged.append(label)
        if windows:
            continue
        if _flag(c.get("ReadonlyRootFilesystem")) is False:
            writable.append(label)
        user = c.get("User")
        if user is None:
            no_user.append(label)
        elif type(user) is str and _is_root_user(user):
            root.append(label)
        elif type(user) is int and user == 0:
            root.append(label)
    out: List[Finding] = []

    def add(fid: str, severity: Severity, title: str, recommendation: str) -> None:
        out.append(Finding(
            id=fid, title=title, severity=severity, category="Security",
            file=res.file or str(template_path), line=res.line,
            evidence=f"{res.name} ({res.source_type})", recommendation=recommendation,
        ))

    if privileged:
        add("CF-ECS-001", "High", "ECS container runs in privileged mode",
            f"Privileged is true on {', '.join(privileged)}: the container gets root access to "
            "the host. Remove Privileged and grant only the Linux capabilities it needs "
            "(Security Hub ECS.4). In CDK: privileged: false.")
    if writable:
        add("CF-ECS-002", "Low", "ECS container root filesystem is writable",
            f"ReadonlyRootFilesystem is not true on {', '.join(writable)}. Set it to true and "
            "mount a volume for paths the app writes to (Security Hub ECS.5). "
            "In CDK: readonlyRootFilesystem: true.")
    if root:
        add("CF-ECS-003", "Medium", "ECS container runs as root",
            f"User is root or 0 on {', '.join(root)}."
            + (f" User is not set on {', '.join(no_user)}." if no_user else "")
            + " Set User to a non-root UID, such as 1000. In CDK: user: '1000'.")
    elif no_user:
        add("CF-ECS-003", "Low", "ECS container may run as root",
            f"User is not set on {', '.join(no_user)}, so the image decides, and many images "
            "run as root. Set User to a non-root UID, such as 1000. In CDK: user: '1000'.")
    return out


def _runtime_finding(res: Resource, template_path: Path) -> Finding | None:
    """CF-LAM-003: a deprecated (High) or soon-deprecated (Low) Lambda runtime.

    Container-image functions have no runtime. Only a literal identifier is judged.
    """
    runtime = res.properties.get("Runtime")
    if res.properties.get("PackageType") == "Image" or type(runtime) is not str:
        return None
    found = lambda_runtimes.status(runtime)
    if found is None:
        return None
    state, when = found
    target = lambda_runtimes.replacement(runtime)
    move = f" Move to {target}." if target else ""
    if state == "deprecated":
        severity: Severity = "High"
        title = "Lambda function uses a deprecated runtime"
        detail = (f"{runtime} was deprecated on {when.isoformat()}: it gets no security patches, "
                  "and AWS then blocks creating and updating functions on it (Security Hub Lambda.2).")
    else:
        severity = "Low"
        title = "Lambda function runtime is deprecated within 6 months"
        detail = f"{runtime} is deprecated on {when.isoformat()}. Plan the upgrade now."
    return Finding(
        id="CF-LAM-003",
        title=title,
        severity=severity,
        category="Security",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=f"{detail}{move} In CDK: set runtime to the current lambda.Runtime constant.",
    )


def _flag(value: Any) -> bool | None:
    """A literal boolean setting: True, False when unset or false, None when unknown."""
    if value is None or value is False:
        return False
    if value is True:
        return True
    if type(value) is str and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return None  # an intrinsic or a Terraform expression


# check id -> (severity, title, recommendation)
_ENCRYPTION: dict[str, tuple[Severity, str, str]] = {
    "CF-SNS-001": (
        "Low",
        "SNS topic has no KMS server-side encryption",
        "Set KmsMasterKeyId (alias/aws/sns or a customer managed key). Without it SNS keeps "
        "messages with its own disk encryption only (Security Hub SNS.1). "
        "In CDK: pass masterKey to sns.Topic.",
    ),
    "CF-EBS-001": (
        "Medium",
        "EBS volume is not encrypted",
        "Set Encrypted: true. The volume is then encrypted only if EBS encryption by default "
        "is turned on in the account and Region (Security Hub EC2.3, EC2.7). "
        "In CDK: set encrypted: true on the volume or block device.",
    ),
    "CF-EFS-001": (
        "Medium",
        "EFS file system is not encrypted at rest",
        "Set Encrypted: true. Encryption cannot be turned on for an existing file system "
        "(Security Hub EFS.1). In CDK: efs.FileSystem encrypts by default; do not set encrypted: false.",
    ),
    "CF-KIN-001": (
        "Medium",
        "Kinesis stream is not encrypted at rest",
        "Set StreamEncryption with EncryptionType KMS (alias/aws/kinesis or a customer managed "
        "key) (Security Hub Kinesis.1). In CDK: kinesis.Stream encrypts by default; do not set "
        "encryption: StreamEncryption.UNENCRYPTED.",
    ),
    "CF-EC-001": (
        "Medium",
        "ElastiCache replication group is not encrypted at rest",
        "Set AtRestEncryptionEnabled: true. Redis OSS defaults to false (Valkey to true), and "
        "the setting cannot be changed after the group is created (Security Hub ElastiCache.4).",
    ),
    "CF-EC-002": (
        "Medium",
        "ElastiCache replication group is not encrypted in transit",
        "Set TransitEncryptionEnabled: true so clients connect with TLS (Security Hub ElastiCache.5).",
    ),
    "CF-OS-001": (
        "Medium",
        "OpenSearch domain is not encrypted at rest",
        "Set EncryptionAtRestOptions.Enabled: true. It is off by default (Security Hub Opensearch.1). "
        "In CDK: set encryptionAtRest: { enabled: true } on the Domain.",
    ),
    "CF-OS-002": (
        "Medium",
        "OpenSearch domain does not encrypt node-to-node traffic",
        "Set NodeToNodeEncryptionOptions.Enabled: true. It is off by default (Security Hub "
        "Opensearch.3). In CDK: set nodeToNodeEncryption: true on the Domain.",
    ),
    "CF-RS-001": (
        "Low",
        "Redshift cluster sets Encrypted to false",
        "Remove Encrypted: false or set it to true. New provisioned clusters are encrypted by "
        "default since 2025; an explicit false asks for an unencrypted cluster (Security Hub Redshift.10).",
    ),
    "CF-DOCDB-001": (
        "Medium",
        "DocumentDB cluster is not encrypted at rest",
        "Set StorageEncrypted: true. It defaults to false in CloudFormation and cannot be "
        "changed after the cluster is created (Security Hub DocumentDB.1).",
    ),
    "CF-NEP-001": (
        "Medium",
        "Neptune cluster is not encrypted at rest",
        "Set StorageEncrypted: true. It cannot be changed after the cluster is created "
        "(Security Hub Neptune.1).",
    ),
    "CF-MSK-001": (
        "Medium",
        "MSK cluster allows unencrypted traffic",
        "Set EncryptionInfo.EncryptionInTransit.ClientBroker to TLS and InCluster to true "
        "(both are the default). Data at rest is always encrypted (Security Hub MSK.1).",
    ),
}


def _msk_plaintext(info: Any) -> str | None:
    """What an MSK EncryptionInfo leaves unencrypted, or None when nothing (or unknown).

    ClientBroker defaults to TLS and InCluster to true.
    """
    if info is None:
        return None
    if not isinstance(info, dict) or _is_intrinsic(info):
        return None
    transit = info.get("EncryptionInTransit")
    if transit is None:
        return None
    if not isinstance(transit, dict) or _is_intrinsic(transit):
        return None
    problems = []
    broker = transit.get("ClientBroker")
    if type(broker) is str and broker.upper() in ("PLAINTEXT", "TLS_PLAINTEXT"):
        problems.append(f"ClientBroker is {broker}")
    in_cluster = transit.get("InCluster")
    if in_cluster is not None and _flag(in_cluster) is False:
        problems.append("InCluster is false")
    return ("; ".join(problems) + ". ") if problems else None


def _unencrypted_block_devices(mappings: Any) -> list[str] | None:
    """Device names of launch template EBS mappings without Encrypted, or None when unknown.

    A mapping from a snapshot takes the snapshot's encryption, so it is not judged.
    """
    if mappings is None:
        return []
    if not isinstance(mappings, list):
        return None
    names: list[str] = []
    for item in mappings:
        ebs = item.get("Ebs") if isinstance(item, dict) else None
        if not isinstance(ebs, dict) or ebs.get("SnapshotId") is not None:
            continue
        encrypted = _flag(ebs.get("Encrypted"))
        if encrypted is False:
            name = item.get("DeviceName")
            names.append(name if type(name) is str else "a block device")
    return names


def _encryption_findings(res: Resource, template_path: Path) -> List[Finding]:
    """Encryption checks (see _ENCRYPTION) for one resource.

    Only literal settings are judged: an intrinsic or variable gives no finding.
    """
    props = res.properties
    ctype = res.type
    failed: list[tuple[str, str]] = []  # (check id, detail)
    if ctype == "sns_topic" and not props.get("KmsMasterKeyId"):
        failed.append(("CF-SNS-001", ""))
    elif ctype == "ebs_volume" and props.get("SnapshotId") is None:
        if _flag(props.get("Encrypted")) is False:
            failed.append(("CF-EBS-001", ""))
    elif ctype == "launch_template":
        data = props.get("LaunchTemplateData")
        mappings = props.get("BlockDeviceMappings")  # Terraform keeps them out of the data
        if mappings is None and isinstance(data, dict):
            mappings = data.get("BlockDeviceMappings")
        devices = _unencrypted_block_devices(mappings)
        if devices:
            failed.append(("CF-EBS-001", f"Unencrypted: {', '.join(devices)}. "))
    elif ctype == "efs_file_system" and _flag(props.get("Encrypted")) is False:
        failed.append(("CF-EFS-001", ""))
    elif ctype == "kinesis_stream" and props.get("StreamEncryption") is None:
        failed.append(("CF-KIN-001", ""))
    elif ctype == "elasticache_replication_group":
        at_rest = props.get("AtRestEncryptionEnabled")
        engine = props.get("Engine", "redis")
        if at_rest is not None:
            if _flag(at_rest) is False:
                failed.append(("CF-EC-001", ""))
        elif type(engine) is str and engine.lower() != "valkey":  # Valkey encrypts by default
            failed.append(("CF-EC-001", ""))
        if _flag(props.get("TransitEncryptionEnabled")) is False:
            failed.append(("CF-EC-002", ""))
    elif ctype == "opensearch_domain":
        for fid, key in (("CF-OS-001", "EncryptionAtRestOptions"), ("CF-OS-002", "NodeToNodeEncryptionOptions")):
            options = props.get(key)
            if options is None or (isinstance(options, dict) and not _is_intrinsic(options)):
                if _flag((options or {}).get("Enabled")) is False:
                    failed.append((fid, ""))
    elif ctype == "redshift_cluster":
        encrypted = props.get("Encrypted")
        restored = props.get("SnapshotIdentifier") is not None  # inherits the snapshot's setting
        if not restored and encrypted is not None and _flag(encrypted) is False:  # unset: encrypted
            failed.append(("CF-RS-001", ""))
    elif ctype in ("docdb_cluster", "neptune_cluster"):
        # A cluster restored from a snapshot or another cluster inherits its encryption.
        restored = any(props.get(k) is not None for k in ("SnapshotIdentifier", "SourceDBClusterIdentifier"))
        if not restored and _flag(props.get("StorageEncrypted")) is False:
            failed.append(("CF-DOCDB-001" if ctype == "docdb_cluster" else "CF-NEP-001", ""))
    elif ctype == "msk_cluster":
        detail = _msk_plaintext(props.get("EncryptionInfo"))
        if detail:
            failed.append(("CF-MSK-001", detail))
    out: List[Finding] = []
    for fid, detail in failed:
        severity, title, recommendation = _ENCRYPTION[fid]
        out.append(Finding(
            id=fid,
            title=title,
            severity=severity,
            category="Security",
            file=res.file or str(template_path),
            line=res.line,
            evidence=f"{res.name} ({res.source_type})",
            recommendation=detail + recommendation,
        ))
    return out


_RP_RECOMMENDATION = (
    "Name the accounts, roles or services that need access, or add a condition such as "
    "aws:SourceArn, aws:SourceAccount, aws:PrincipalOrgID or aws:SourceVpce."
)


def _event_bus_policy_document(res: Resource) -> dict | None:
    """AWS::Events::EventBusPolicy as a document: its one Statement, or the older Principal,
    Action and Condition properties (also aws_cloudwatch_event_permission)."""
    props = res.properties
    statement = props.get("Statement")
    if isinstance(statement, str):
        try:
            statement = json.loads(statement)
        except ValueError:
            return None
    if isinstance(statement, (dict, list)):
        return {"Statement": statement}
    if statement is None and props.get("Principal") == "*" and props.get("Condition") is None:
        action = props.get("Action", "events:PutEvents")
        return {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": action}]}
    return None


def _public_policy_finding(res: Resource, template_path: Path) -> Finding | None:
    """CF-RP-001 for a queue, topic, bucket, event bus or ECR repository policy, or CF-KMS-001 for
    a key policy, when an Allow statement is open to Principal "*" with no limiting condition."""
    if res.type == "event_bus_policy":
        doc = _event_bus_policy_document(res)
    else:
        key = {"ecr_repository": "RepositoryPolicyText", "kms_key": "KeyPolicy", "event_bus": "Policy"}.get(
            res.type or "", "PolicyDocument")
        doc = iam_policy.as_document(res.properties.get(key))
    actions = iam_policy.public_actions(doc) if doc is not None else None
    if actions is None:
        return None
    shown = ", ".join(actions[:5]) + (" ..." if len(actions) > 5 else "")
    allowed = f"Allowed to anyone: {shown}. " if shown else ""
    kms = res.type == "kms_key"
    return Finding(
        id="CF-KMS-001" if kms else "CF-RP-001",
        title="KMS key policy allows any principal" if kms else "Resource policy allows any principal",
        severity="High",
        category="Security",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            f"{allowed}A statement allows Principal '*' with no condition that limits the "
            f"caller, so anyone can use this resource. {_RP_RECOMMENDATION}"
            + (" In CDK: grant to a specific principal with key.grantDecrypt(role)." if kms else "")
        ),
    )


def _public_lambda_permission(res: Resource, template_path: Path) -> Finding | None:
    """CF-RP-001 for AWS::Lambda::Permission with Principal "*" and no source condition.

    A function URL permission with FunctionUrlAuthType AWS_IAM still needs IAM auth.
    """
    props = res.properties
    if props.get("Principal") != "*" or props.get("FunctionUrlAuthType") == "AWS_IAM":
        return None
    if any(props.get(k) is not None for k in ("SourceArn", "SourceAccount", "PrincipalOrgID")):
        return None
    return Finding(
        id="CF-RP-001",
        title="Lambda permission allows any principal",
        severity="High",
        category="Security",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            "Principal '*' with no SourceArn, SourceAccount or PrincipalOrgID lets anyone "
            "invoke the function. Set SourceArn to the calling resource (an API, bucket or "
            "rule), or name the principal. In CDK: fn.grantInvoke with a specific principal, "
            "or addPermission with sourceArn."
        ),
    )

_IAM_CDK_HINT = (
    " In CDK: use grant methods such as bucket.grantRead(role), or a PolicyStatement "
    "with specific actions and resources."
)

_IAM_FINDINGS: dict[str, tuple[str, Severity, str, str]] = {
    # kind -> (id, severity, title, recommendation)
    "admin": (
        "CF-IAM-008",
        "High",
        "IAM principal has full admin access",
        "AdministratorAccess, or Allow with Action '*' on Resource '*', lets this principal "
        "do anything in the account, so a leaked credential or a bug has no limit "
        "(Security Hub IAM.1). Grant only the actions and resources it needs. "
        "IAM Access Analyzer can generate a policy from CloudTrail activity.",
    ),
    "all_actions": (
        "CF-IAM-001",
        "High",
        "IAM policy allows all actions",
        "Replace Action '*' with the specific actions this principal needs. "
        "IAM Access Analyzer can generate a policy from CloudTrail activity.",
    ),
    "service_actions": (
        "CF-IAM-002",
        "Medium",
        "IAM policy allows every action of a service",
        "Replace '<service>:*' with the specific actions this principal needs, "
        "and scope Resource to the ARNs it uses.",
    ),
    "write_on_all_resources": (
        "CF-IAM-003",
        "Medium",
        "IAM policy allows write actions on all resources",
        "Scope Resource to the specific ARNs instead of '*'. Read-only actions and "
        "actions without resource-level permissions are not reported.",
    ),
}


def _policy_documents(props: dict) -> list[tuple[str, dict]]:
    """(label, document) pairs from PolicyDocument and inline Policies."""
    out: list[tuple[str, dict]] = []
    doc = iam_policy.as_document(props.get("PolicyDocument"))
    if doc is not None:
        out.append(("", doc))
    inline = props.get("Policies")
    for item in inline if isinstance(inline, list) else []:
        if not isinstance(item, dict):
            continue
        doc = iam_policy.as_document(item.get("PolicyDocument"))
        if doc is None:
            continue
        name = item.get("PolicyName")
        out.append((f" policy {name}" if type(name) is str else " inline policy", doc))
    return out


_TRUST_FINDINGS: dict[str, tuple[str, Severity, str, str]] = {
    # kind -> (id, severity, title, recommendation)
    "anyone": (
        "CF-IAM-004",
        "High",
        "IAM role can be assumed by any AWS account",
        "The trust policy allows sts:AssumeRole to Principal '*' with no condition. "
        "Name the accounts or roles that need it, or add a condition such as aws:PrincipalOrgID. "
        "In CDK: use iam.AccountPrincipal or iam.ArnPrincipal instead of iam.AnyPrincipal.",
    ),
    "github_oidc": (
        "CF-IAM-007",
        "High",
        "IAM role trusts GitHub Actions OIDC without restricting the repository",
        "With no condition on token.actions.githubusercontent.com:sub, a workflow in any "
        "GitHub repository can assume this role. Add a StringLike condition on sub, "
        "for example repo:<org>/<repo>:ref:refs/heads/main. "
        "In CDK: give the OpenIdConnectPrincipal a StringLike condition on the sub key.",
    ),
    "cross_account": (
        "CF-IAM-005",
        "Medium",
        "IAM role trusts another account without an external ID",
        "If this account is a third party, require an sts:ExternalId condition so it cannot "
        "be tricked into acting for someone else (the confused deputy problem). "
        "In CDK: pass externalIds to the Role.",
    ),
    "service": (
        "CF-IAM-006",
        "Low",
        "IAM service role trust has no aws:SourceAccount or aws:SourceArn",
        "Add an aws:SourceAccount or aws:SourceArn condition so the service can only "
        "assume this role for your resources (cross-service confused deputy). "
        "In CDK: add the condition with principal.withConditions on the ServicePrincipal.",
    ),
}


def _trust_findings(res: Resource, template_path: Path) -> List[Finding]:
    doc = iam_policy.as_document(res.properties.get("AssumeRolePolicyDocument"))
    if doc is None:
        return []
    out: List[Finding] = []
    for trust in iam_policy.trust_problems(doc):
        fid, severity, title, recommendation = _TRUST_FINDINGS[trust.kind]
        shown = ", ".join(trust.principals[:5]) + (" ..." if len(trust.principals) > 5 else "")
        out.append(Finding(
            id=fid,
            title=title,
            severity=severity,
            category="Security",
            file=res.file or str(template_path),
            line=res.line,
            evidence=f"{res.name} ({res.source_type})",
            recommendation=f"Trusted: {shown}. {recommendation}",
        ))
    return out


def _managed_admin(props: dict) -> bool:
    """ManagedPolicyArns (roles, users, groups; Terraform attachments) holds AdministratorAccess."""
    arns = props.get("ManagedPolicyArns")
    return isinstance(arns, list) and any(iam_policy.is_admin_policy_arn(a) for a in arns)


def _iam_findings(res: Resource, template_path: Path) -> List[Finding]:
    """One finding per kind per resource, naming the actions and the inline policy."""
    by_kind: dict[str, tuple[set[str], list[str]]] = {}
    if _managed_admin(res.properties):
        by_kind["admin"] = ({"*"}, [f" managed policy {iam_policy.ADMIN_POLICY}"])
    for label, doc in _policy_documents(res.properties):
        for broad in iam_policy.broadest(doc):
            actions, labels = by_kind.setdefault(broad.kind, (set(), []))
            actions.update(broad.actions)
            if label and label not in labels:
                labels.append(label)
    if "admin" in by_kind:  # Action "*" is reported once per resource, as admin
        by_kind.pop("all_actions", None)
    out: List[Finding] = []
    for kind, (actions, labels) in by_kind.items():
        fid, severity, title, recommendation = _IAM_FINDINGS[kind]
        shown = ", ".join(sorted(actions)[:5]) + (" ..." if len(actions) > 5 else "")
        where = f" (in{','.join(labels)})" if labels else ""
        out.append(Finding(
            id=fid,
            title=title,
            severity=severity,
            category="Security",
            file=res.file or str(template_path),
            line=res.line,
            # Evidence stays "name (type)": fix snippets read the resource from it.
            evidence=f"{res.name} ({res.source_type})",
            recommendation=f"Flagged: {shown}{where}. {recommendation}{_IAM_CDK_HINT}",
        ))
    return out
def _k8s_minor(version: Any) -> int | None:
    """Minor version of an EKS `Version` ("1.27" -> 27), or None when unknown.

    Unquoted YAML turns 1.30 into the float 1.3. EKS has no 1.3, so a one-digit
    minor read from a number is a dropped trailing zero.
    """
    if isinstance(version, bool) or not isinstance(version, (str, int, float)):
        return None
    if isinstance(version, str) and type(version) is not str:
        return None  # a Terraform expression, not a literal
    major, _, minor = str(version).strip().partition(".")
    if major != "1" or not minor.isdigit():
        return None
    if not isinstance(version, str) and len(minor) == 1:
        return int(minor) * 10
    return int(minor)


def _eks_public_endpoint(vpc_config: Any) -> list[str] | None:
    """Open CIDRs when the API endpoint is public to them, else None.

    EndpointPublicAccess defaults to true and PublicAccessCidrs to 0.0.0.0/0.
    """
    if not isinstance(vpc_config, dict) or _is_intrinsic(vpc_config):
        return None
    public = vpc_config.get("EndpointPublicAccess", True)
    if public is not True and public != "true":
        return None
    cidrs = vpc_config.get("PublicAccessCidrs")
    if cidrs is None:
        return ["0.0.0.0/0"]
    if not isinstance(cidrs, list):
        return None
    open_cidrs = [c for c in cidrs if type(c) is str and c in ("0.0.0.0/0", "::/0")]
    return open_cidrs or None


def _eks_encrypts_secrets(encryption: Any) -> bool | None:
    """True when a KMS key encrypts secrets, False when no EncryptionConfig, None when unknown."""
    if encryption is None:
        return False
    if not isinstance(encryption, list):
        return None
    for item in encryption:
        if not isinstance(item, dict) or _is_intrinsic(item):
            return None
        resources = item.get("Resources")
        if not isinstance(resources, list):
            return None
        if "secrets" in resources:
            return True
    return False


def _cf_bucket_policies(resources: List[Resource]) -> tuple[dict[str, Any], bool]:
    """PolicyDocument of each AWS::S3::BucketPolicy, keyed by the bucket's logical id.

    The second value is True when a policy names its bucket through an expression the
    scan cannot follow: it may then belong to any bucket in the template.
    """
    by_name = {
        r.properties.get("BucketName"): r.name
        for r in resources
        if r.source_type == "AWS::S3::Bucket" and type(r.properties.get("BucketName")) is str
    }
    policies: dict[str, Any] = {}
    unlinked = False
    for r in resources:
        if r.source_type != "AWS::S3::BucketPolicy":
            continue
        if r.malformed:  # its bucket is unknown
            unlinked = True
            continue
        bucket = r.properties.get("Bucket")
        if isinstance(bucket, dict) and set(bucket) == {"Ref"} and isinstance(bucket["Ref"], str):
            target: str | None = bucket["Ref"]
        elif isinstance(bucket, str):
            target = by_name.get(bucket)  # a name not in the template is another bucket
            if target is None:
                continue
        else:
            unlinked = True
            continue
        if target is not None:
            policies[target] = r.properties.get("PolicyDocument", {})  # missing: unknown, not absent
    return policies, unlinked


def _denies_plain_http(statement: dict) -> bool:
    """True for the TLS-only statement: Deny s3:* to everyone when aws:SecureTransport is false."""
    if statement.get("Effect") != "Deny":
        return False
    actions = statement.get("Action")
    actions = actions if isinstance(actions, list) else [actions]
    if not any(a in ("s3:*", "*") for a in actions):
        return False
    principal = statement.get("Principal")
    if isinstance(principal, dict):  # {"AWS": "*"}, or {"*": ["*"]} from aws_iam_policy_document
        principal = principal.get("AWS", principal.get("*"))
    if principal != "*" and principal != ["*"]:
        return False
    condition = statement.get("Condition")
    bool_cond = condition.get("Bool") if isinstance(condition, dict) else None
    if not isinstance(bool_cond, dict):
        return False
    for key, value in bool_cond.items():
        if isinstance(key, str) and key.lower() == "aws:securetransport":
            values = value if isinstance(value, list) else [value]
            return any(v is False or (isinstance(v, str) and v.lower() == "false") for v in values)
    return False


def _has_unknown_leaf(value: Any) -> bool:
    """True when a value holds a non-literal string (a Terraform reference or var)."""
    if isinstance(value, str):
        return type(value) is not str
    if isinstance(value, list):
        return any(_has_unknown_leaf(v) for v in value)
    if isinstance(value, dict):
        return any(_has_unknown_leaf(v) for v in value.values())
    return False


def _tls_enforced(document: Any) -> bool | None:
    """True when a bucket policy denies plain HTTP, False when it does not, None when unknown."""
    if document is None:
        return False
    if isinstance(document, str):
        if type(document) is not str:  # an expression the scan could not read
            return None
        try:
            return _tls_enforced(json.loads(document))
        except ValueError:
            return None
    if not isinstance(document, dict) or _is_intrinsic(document):
        return None
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return None
    unknown = False
    for statement in statements:
        if not isinstance(statement, dict) or _is_intrinsic(statement) or _has_unknown_leaf(
            [statement.get(k) for k in ("Effect", "Action", "Principal", "Condition")]
        ):
            unknown = True
        elif _denies_plain_http(statement):
            return True
    return None if unknown else False


def _one_saving_per_instance(resource_findings: List[Finding]) -> None:
    """Moving to a current generation (CF-GEN-001) and one size smaller (CF-PERF-003/004)
    are alternative fixes for one instance: their savings do not add up. Keep the
    generation saving and say so on the right-sizing finding."""
    if not any(f.id == "CF-GEN-001" and f.monthly_savings_usd for f in resource_findings):
        return
    for f in resource_findings:
        if f.id in ("CF-PERF-003", "CF-PERF-004") and f.monthly_savings_usd:
            f.monthly_savings_usd = None
            f.estimate_basis = (
                estimates._without_saving(f.estimate_basis or "")
                + " The saving is counted on CF-GEN-001 for this instance (the fixes do not add up)."
            ).strip()


def run_resource_checks(
    resources: List[Resource],
    template_path: Path,
    warnings: list[str] | None = None,
) -> List[Finding]:
    """Run the CF-* checks on one file's resources; return list of findings.

    Estimates are priced in the stack's region (see rules/regions.py).
    """
    with regions.for_stack(template_path, resources):
        return _run_resource_checks(resources, template_path, warnings)


def _run_resource_checks(
    resources: List[Resource],
    template_path: Path,
    warnings: list[str] | None = None,
) -> List[Finding]:
    if warnings is None:
        warnings = []
    findings: List[Finding] = []

    def count(*types: str) -> int:
        return sum(1 for r in resources if r.type in types)

    def _at(r: Resource | None) -> tuple[str, int | None, str]:
        """File, line, and evidence suffix for a template-level finding anchored at r.

        One CloudFormation template is one file, so this is the template path and no
        suffix. A Terraform module spans files, so the finding points at the resource
        that triggered it and the evidence names it.
        """
        if r is None or not r.file:
            return str(template_path), None, ""
        label = "" if r.source_type.startswith("AWS::") else f" ({r.name})"
        return r.file, r.line, label

    def _anchor(*types: str) -> tuple[str, int | None, str]:
        return _at(next((r for r in resources if r.type in types), None))

    vpc_count = count("vpc")
    vpce_count = count("vpc_endpoint")
    flow_log_count = count("flow_log")
    nat_count = count("nat_gateway")
    has_apigw = count(
        "api_gateway_rest_api", "api_gateway_stage", "apigatewayv2_api", "apigatewayv2_stage"
    ) > 0
    has_lambda = count("lambda_function") > 0
    has_cloudfront = count("cloudfront_distribution") > 0
    has_elasticache = count("elasticache_cluster", "elasticache_replication_group") > 0
    asg_count = count("autoscaling_group")
    cf_policies, cf_policy_unlinked = _cf_bucket_policies(resources)
    waf_covered, waf_unlinked = _waf_coverage(resources)
    rotated, rotation_unlinked = _rotation_coverage(resources)
    eips_in_use = _eips_in_use(resources)
    autoscaled, autoscaling_unlinked = _autoscaled_tables(resources)
    param_groups = [r for r in resources if r.type in ("db_parameter_group", "rds_cluster_parameter_group")]
    launch_templates_without_spot = 0
    first_lt_without_spot: Resource | None = None
    for r in resources:
        if r.type != "launch_template":
            continue
        if r.malformed:
            warnings.append(f"CF rules skipped resource {r.name} in {template_path.name}: {r.malformed}")
            continue
        if "LaunchTemplateData" in r.unresolved:
            continue
        ltd = r.properties.get("LaunchTemplateData") or {}
        if not isinstance(ltd, dict):
            warnings.append(
                f"CF rules skipped resource {r.name} in {template_path.name}: LaunchTemplateData is not an object"
            )
            continue
        inst_market = ltd.get("InstanceMarketOptions") or {}
        if isinstance(inst_market, dict) and inst_market.get("MarketType") != "spot":
            launch_templates_without_spot += 1
            if first_lt_without_spot is None:
                first_lt_without_spot = r

    for res in resources:
        logical_id = res.name
        if res.malformed:
            if res.type in _PER_RESOURCE_TYPES:
                warnings.append(
                    f"CF rules skipped resource {logical_id} in {template_path.name}: {res.malformed}"
                )
            continue
        first_new = len(findings)
        try:
                rtype = res.source_type
                ctype = res.type
                props = res.properties

                # --- S3 checks ---
                if ctype == "s3_bucket":
                    pab = props.get("PublicAccessBlockConfiguration")
                    if not pab or not all(pab.get(k) is True for k in [
                        "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
                    ]):
                        findings.append(Finding(
                            id="CF-S3-001",
                            title="S3 bucket may miss full PublicAccessBlock",
                            severity="High",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation=(
                                "Set PublicAccessBlockConfiguration with all four flags True for buckets that should not be public. "
                                "In CDK: blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL."
                            ),
                        ))

                    enc = props.get("BucketEncryption")
                    if _s3_encryption_disabled(enc):
                        findings.append(Finding(
                            id="CF-S3-002",
                            title="S3 bucket encryption explicitly disabled",
                            severity="Medium",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation=(
                                "S3 applies SSE-S3 when BucketEncryption is omitted. "
                                "Remove the explicit disable. Customer-managed KMS is not required here."
                            ),
                        ))

                    ver = props.get("VersioningConfiguration")
                    if not ver or ver.get("Status") != "Enabled":
                        findings.append(Finding(
                            id="CF-S3-003",
                            title="S3 bucket versioning not enabled",
                            severity="Low",
                            category="Reliability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Consider enabling versioning for better recovery and protection against accidental deletion (especially for data buckets).",
                        ))

                    logging_cfg = props.get("LoggingConfiguration")
                    if not logging_cfg or not logging_cfg.get("DestinationBucketName"):
                        findings.append(Finding(
                            id="CF-S3-004",
                            title="S3 bucket server access logging not configured",
                            severity="Low",
                            category="Operational Excellence",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation=(
                                "Consider enabling server access logging (LoggingConfiguration with DestinationBucketName) "
                                "for audit and security analysis. In CDK: bucket.addBucketLifecycleRule or use a logging bucket."
                            ),
                        ))

                    if "BucketPolicy" in props:  # Terraform: aws_s3_bucket_policy merged in
                        tls = _tls_enforced(props["BucketPolicy"])
                    elif cf_policy_unlinked and logical_id not in cf_policies:
                        tls = None
                    else:
                        tls = _tls_enforced(cf_policies.get(logical_id))
                    if tls is False:
                        findings.append(Finding(
                            id="CF-S3-005",
                            title="S3 bucket allows requests without TLS",
                            severity="Medium",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation=(
                                "No bucket policy in this template denies s3:* when aws:SecureTransport is false, "
                                "so the bucket accepts plain HTTP (AWS Security Hub control S3.5). "
                                "Add a bucket policy statement that denies those requests. "
                                "In CDK: enforceSSL: true."
                            ),
                        ))

                # --- RDS checks ---
                if ctype in ("db_instance", "rds_cluster"):
                    cluster_member = (
                        ctype == "db_instance" and "DBClusterIdentifier" in props
                    )
                    if not cluster_member:
                        storage_enc = props.get("StorageEncrypted")
                        if storage_enc is not True:
                            findings.append(Finding(
                                id="CF-RDS-001",
                                title="RDS storage encryption not enabled",
                                severity="High",
                                category="Security",
                                file=res.file or str(template_path),
                                line=res.line,
                                evidence=f"{logical_id} ({rtype})",
                                recommendation="Enable StorageEncrypted (and KMS CMK if required) for databases.",
                            ))

                        if _backup_retention_missing(props.get("BackupRetentionPeriod")):
                            findings.append(Finding(
                                id="CF-RDS-002",
                                title="RDS backup retention not set",
                                severity="Medium",
                                category="Reliability",
                                file=res.file or str(template_path),
                                line=res.line,
                                evidence=f"{logical_id} ({rtype})",
                                recommendation="Set BackupRetentionPeriod per RPO/RTO (e.g. 7–35 days).",
                            ))

                        maz = props.get("MultiAZ")
                        if ctype == "db_instance" and maz is not True:
                            findings.append(Finding(
                                id="CF-RDS-003",
                                title="RDS Multi-AZ not enabled",
                                severity="Medium",
                                category="Reliability",
                                file=res.file or str(template_path),
                                line=res.line,
                                evidence=f"{logical_id} ({rtype})",
                                recommendation="Enable MultiAZ for production workloads where high availability is required.",
                            ))

                        if props.get("DeletionProtection") is not True:
                            findings.append(Finding(
                                id="CF-RDS-005",
                                title="RDS deletion protection not enabled",
                                severity="Medium",
                                category="Reliability",
                                file=res.file or str(template_path),
                                line=res.line,
                                evidence=f"{logical_id} ({rtype})",
                                recommendation="Enable DeletionProtection for production databases to prevent accidental deletion.",
                            ))

                    if props.get("PubliclyAccessible") is True:
                        findings.append(Finding(
                            id="CF-RDS-004",
                            title="RDS instance is publicly accessible",
                            severity="High",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Set PubliclyAccessible to false unless the database must be reachable from the internet.",
                        ))

                    if ctype == "db_instance" and _is_large_instance_class(props.get("DBInstanceClass")):
                        findings.append(Finding(
                            id="CF-PERF-003",
                            title="RDS instance class is large — verify right-sizing",
                            severity="Low",
                            category="Performance Efficiency",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Review DBInstanceClass against actual workload; consider right-sizing to reduce cost and improve efficiency.",
                        ))
                        estimates.apply(findings[-1], estimates.rds_instance(props))

                # --- EC2 instance metadata: IMDSv2 required ---
                if ctype == "instance":
                    imds = _imds_finding(
                        res, template_path, props.get("MetadataOptions"),
                        defers="LaunchTemplate" in props,
                    )
                    if imds is not None:
                        findings.append(imds)
                if ctype == "launch_template":
                    ltd = props.get("LaunchTemplateData")
                    if isinstance(ltd, dict) and not _is_intrinsic(ltd):
                        imds = _imds_finding(res, template_path, ltd.get("MetadataOptions"), defers=False)
                        if imds is not None:
                            findings.append(imds)

                # --- EC2 Instance: large instance right-sizing (Performance Efficiency) ---
                if ctype == "instance":
                    if _is_large_instance_class(props.get("InstanceType")):
                        findings.append(Finding(
                            id="CF-PERF-004",
                            title="EC2 instance type is large — verify right-sizing",
                            severity="Low",
                            category="Performance Efficiency",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Review InstanceType against actual workload; consider right-sizing or autoscaling to match load.",
                        ))
                        estimates.apply(findings[-1], estimates.ec2_instance(props.get("InstanceType")))

                # --- RDS and Aurora settings beyond CF-RDS-001..005 ---
                if ctype in ("db_instance", "rds_cluster"):
                    findings.extend(_rds_settings_findings(res, template_path, param_groups))

                # --- Load balancers: ELBv2 attributes, listeners, target groups, Classic ---
                if ctype in ("lb", "lb_listener", "lb_target_group", "elb"):
                    findings.extend(_load_balancer_findings(res, template_path))

                # --- CloudTrail ---
                if ctype == "cloudtrail":
                    log = props.get("EnableLogFileValidation")
                    if log is not True:
                        findings.append(Finding(
                            id="CF-CT-001",
                            title="CloudTrail log file validation not enabled",
                            severity="Medium",
                            category="Operational Excellence",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Enable log file validation for CloudTrail to detect tampering.",
                        ))
                    if props.get("IsMultiRegionTrail") is not True:
                        findings.append(Finding(
                            id="CF-CT-002",
                            title="CloudTrail is not multi-region",
                            severity="Low",
                            category="Operational Excellence",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Consider enabling IsMultiRegionTrail for organization-wide audit coverage.",
                        ))
                    if not props.get("KmsKeyId"):
                        findings.append(Finding(
                            id="CF-CT-003",
                            title="CloudTrail log files not encrypted with KMS",
                            severity="Low",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Use KmsKeyId to encrypt CloudTrail log files for integrity and compliance.",
                        ))

                # --- VPC Flow Logs ---
                if ctype == "flow_log":
                    # Flow log exists; optional: check destination (CloudWatch Logs or S3)
                    pass  # Presence is good; no extra check for now

                # --- IAM policies (managed, inline, and on roles/users/groups) ---
                if ctype in _IAM_TYPES:
                    findings.extend(_iam_findings(res, template_path))
                if ctype == "iam_role":
                    findings.extend(_trust_findings(res, template_path))

                # --- gp2 volumes and unused Elastic IPs (cost estimates) ---
                if ctype == "ebs_volume":
                    gp2 = _gp2_finding(res, template_path)
                    if gp2 is not None:
                        findings.append(gp2)
                if ctype == "eip" and logical_id not in eips_in_use:
                    eip = _eip_finding(res, template_path)
                    if eip is not None:
                        findings.append(eip)

                # --- Secrets Manager rotation and Cognito user pools ---
                if ctype == "secretsmanager_secret" and not rotation_unlinked and logical_id not in rotated:
                    findings.append(_rotation_finding(res, template_path))
                if ctype == "cognito_user_pool":
                    findings.extend(_cognito_findings(res, template_path))

                # --- ECR repositories and ECS task definitions ---
                if ctype == "ecr_repository":
                    findings.extend(_ecr_findings(res, template_path))
                if ctype == "ecs_task_definition":
                    findings.extend(_ecs_findings(res, template_path))

                # --- S3 storage classes, DynamoDB autoscaling, launch template gp2 ---
                if ctype == "s3_bucket":
                    findings.extend(_s3_storage_findings(res, template_path))
                if ctype == "dynamodb_table" and not autoscaling_unlinked and logical_id not in autoscaled:
                    ddb = _autoscaling_finding(res, template_path)
                    if ddb is not None:
                        findings.append(ddb)
                if ctype == "launch_template":
                    gp2_devices = _gp2_block_devices(res, template_path)
                    if gp2_devices is not None:
                        findings.append(gp2_devices)

                # --- Previous-generation instance families ---
                findings.extend(generations.findings(res, template_path))

                # --- Stateful resources deleted with the stack ---
                if ctype in _STATEFUL_TYPES:
                    deletion = _deletion_finding(res, template_path)
                    if deletion is not None:
                        findings.append(deletion)

                # --- Public IPs on subnets and instances ---
                if ctype in ("subnet", "instance", "launch_template"):
                    findings.extend(_public_ip_findings(res, template_path))

                # --- CloudFront and WAF ---
                if ctype == "cloudfront_distribution":
                    findings.extend(_cloudfront_findings(res, template_path))
                if ctype in ("lb", "api_gateway_stage") and not waf_unlinked and logical_id not in waf_covered:
                    waf = _waf_finding(res, template_path)
                    if waf is not None:
                        findings.append(waf)

                # --- Encryption at rest / in transit for more data stores ---
                findings.extend(_encryption_findings(res, template_path))

                # --- Resource policies open to any principal (and KMS key policies) ---
                if ctype in ("resource_policy", "ecr_repository", "kms_key", "event_bus", "event_bus_policy"):
                    public = _public_policy_finding(res, template_path)
                    if public is not None:
                        findings.append(public)
                if ctype == "lambda_permission":
                    public = _public_lambda_permission(res, template_path)
                    if public is not None:
                        findings.append(public)

                # --- Lambda ---
                if ctype in ("lambda_function", "lambda_url"):
                    findings.extend(_lambda_access_findings(res, template_path))
                if ctype == "lambda_function":
                    deprecated = _runtime_finding(res, template_path)
                    if deprecated is not None:
                        findings.append(deprecated)
                    if not props.get("DeadLetterConfig", {}).get("TargetArn"):
                        findings.append(Finding(
                            id="CF-LAM-001",
                            title="Lambda function has no dead-letter configuration",
                            severity="Medium",
                            category="Reliability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Configure DeadLetterConfig (SQS or SNS) for async invocations to capture failed events.",
                        ))
                    tracing = props.get("TracingConfig", {}).get("Mode")
                    if tracing != "Active":
                        findings.append(Finding(
                            id="CF-LAM-002",
                            title="Lambda active tracing (X-Ray) not enabled",
                            severity="Low",
                            category="Observability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Set TracingConfig.Mode to Active for X-Ray tracing.",
                        ))
                    archs = props.get("Architectures") or []
                    if isinstance(archs, str):
                        archs = [archs]
                    # An intrinsic (!If, !Ref) decides the arch at deploy time: no finding.
                    arch_known = isinstance(archs, list) and all(isinstance(a, str) for a in archs)
                    if arch_known and "arm64" not in [a.lower() for a in archs]:
                        findings.append(Finding(
                            id="CF-PERF-001",
                            title="Lambda function does not use ARM64 (Graviton)",
                            severity="Low",
                            category="Performance Efficiency",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Consider Architectures: [arm64] for better price-performance. In CDK: architecture: lambda.Architecture.ARM_64.",
                        ))

                # --- DynamoDB ---
                if ctype == "dynamodb_table":
                    pitr = props.get("PointInTimeRecoverySpecification", {}).get("PointInTimeRecoveryEnabled")
                    if pitr is not True:
                        findings.append(Finding(
                            id="CF-DDB-001",
                            title="DynamoDB point-in-time recovery not enabled",
                            severity="Medium",
                            category="Reliability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Enable PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled for backup.",
                        ))
                    sse = props.get("SSESpecification", {})
                    if sse.get("SSEEnabled") is not True and not sse.get("SSEType"):
                        findings.append(Finding(
                            id="CF-DDB-002",
                            title="DynamoDB server-side encryption not explicitly enabled",
                            severity="Medium",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Enable SSESpecification (SSEEnabled or SSEType: KMS) for encryption at rest.",
                        ))

                # --- Security groups, network ACLs and transit gateways ---
                if ctype in ("security_group", "security_group_ingress_rule", "security_group_egress_rule"):
                    findings.extend(_security_group_findings(
                        res, template_path, default_egress_open=(
                            ctype == "security_group" and res.source_type.startswith("AWS::"))))
                if ctype in ("network_acl_entry", "network_acl"):
                    findings.extend(_nacl_findings(res, template_path))
                if ctype == "transit_gateway" and props.get("AutoAcceptSharedAttachments") == "enable":
                    findings.append(Finding(
                        id="CF-TGW-001",
                        title="Transit gateway accepts shared attachments automatically",
                        severity="Medium",
                        category="Security",
                        file=res.file or str(template_path),
                        line=res.line,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation=(
                            "Set AutoAcceptSharedAttachments: disable, so a VPC from an account the "
                            "gateway is shared with is attached only once you accept it "
                            "(Security Hub EC2.23). In Terraform: auto_accept_shared_attachments = \"disable\"."
                        ),
                    ))

                # --- CloudWatch Logs ---
                if ctype == "cloudwatch_log_group":
                    if props.get("RetentionInDays") is None:
                        findings.append(Finding(
                            id="CF-CW-001",
                            title="Log group has no retention period (infinite retention)",
                            severity="Low",
                            category="Cost Optimization",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Set RetentionInDays to limit cost and meet compliance (e.g. 30–365 days).",
                        ))
                    if not props.get("KmsKeyId"):
                        findings.append(Finding(
                            id="CF-CW-002",
                            title="Log group not encrypted with KMS",
                            severity="Low",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Set KmsKeyId for encryption at rest where required by compliance.",
                        ))

                # --- SQS ---
                if ctype == "sqs_queue":
                    if props.get("SqsManagedSseEnabled") is not True and not props.get("KmsMasterKeyId"):
                        findings.append(Finding(
                            id="CF-SQS-001",
                            title="SQS queue server-side encryption not explicitly configured",
                            severity="Low",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Enable SqsManagedSseEnabled or set KmsMasterKeyId for encryption.",
                        ))
                    redrive = props.get("RedrivePolicy")
                    has_dlq = False if redrive is None else _redrive_has_dlq(redrive)
                    if has_dlq is False:
                        findings.append(Finding(
                            id="CF-SQS-002",
                            title="SQS queue has no redrive policy (dead-letter queue)",
                            severity="Low",
                            category="Reliability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Consider RedrivePolicy with deadLetterTargetArn for failed messages.",
                        ))

                # --- API Gateway Stage (REST and V2) ---
                if ctype == "api_gateway_stage":
                    if not props.get("AccessLogSetting", {}).get("DestinationArn"):
                        findings.append(Finding(
                            id="CF-APIGW-001",
                            title="API Gateway REST stage access logging not enabled",
                            severity="Low",
                            category="Observability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Set AccessLogSetting with DestinationArn (e.g. CloudWatch Logs) for audit.",
                        ))
                    if props.get("TracingEnabled") is not True:
                        findings.append(Finding(
                            id="CF-APIGW-002",
                            title="API Gateway stage X-Ray tracing not enabled",
                            severity="Low",
                            category="Observability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Set TracingEnabled to true for X-Ray. DataTraceEnabled logs full bodies and is not tracing.",
                        ))
                if ctype == "apigatewayv2_stage":
                    if not props.get("AccessLogSettings", {}).get("DestinationArn"):
                        findings.append(Finding(
                            id="CF-APIGW-V2-001",
                            title="API Gateway V2 stage access logging not enabled",
                            severity="Low",
                            category="Observability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Set AccessLogSettings.DestinationArn for access logs.",
                        ))
                    if props.get("TracingEnabled") is not True:
                        findings.append(Finding(
                            id="CF-APIGW-V2-002",
                            title="API Gateway V2 stage X-Ray tracing not enabled",
                            severity="Low",
                            category="Observability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Set TracingEnabled to true for X-Ray. DataTraceEnabled logs full bodies and is not tracing.",
                        ))

                # --- Auto Scaling Group: Spot / mixed instances (Sustainability) ---
                if ctype == "autoscaling_group":
                    mixed = props.get("MixedInstancesPolicy") or {}
                    inst_dist = mixed.get("InstancesDistribution") or {}
                    spot_max = inst_dist.get("SpotMaxPrice")
                    spot_strategy = inst_dist.get("SpotAllocationStrategy")
                    has_spot = spot_max is not None or spot_strategy is not None
                    if not has_spot:
                        findings.append(Finding(
                            id="CF-SUST-001",
                            title="Auto Scaling Group does not use Spot or mixed instances",
                            severity="Low",
                            category="Sustainability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation=(
                                "Consider MixedInstancesPolicy with Spot (InstancesDistribution.SpotMaxPrice or SpotAllocationStrategy) "
                                "for fault-tolerant workloads to reduce cost and improve sustainability. In CDK: use mixedInstancesPolicy."
                            ),
                        ))

                # --- ECS Service: Fargate Spot (Sustainability) ---
                if ctype == "ecs_service":
                    strat = props.get("CapacityProviderStrategy") or []
                    if isinstance(strat, dict):
                        strat = [strat]
                    provider_names = [s.get("CapacityProvider") or s.get("capacityProvider") for s in strat if s]
                    has_fargate_spot = any(
                        p and ("SPOT" in str(p).upper() or "FARGATE_SPOT" in str(p))
                        for p in provider_names
                    )
                    launch_type = (props.get("LaunchType") or "").upper()
                    uses_fargate = launch_type == "FARGATE" or any(
                        p and "FARGATE" in str(p).upper() for p in provider_names
                    )
                    if uses_fargate and not has_fargate_spot:
                        findings.append(Finding(
                            id="CF-SUST-002",
                            title="ECS Fargate service does not use FARGATE_SPOT",
                            severity="Low",
                            category="Sustainability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation=(
                                "Consider CapacityProviderStrategy including FARGATE_SPOT for interruptible tasks "
                                "to reduce cost and improve sustainability. In CDK: capacityProviderStrategies with FARGATE_SPOT."
                            ),
                        ))

                # --- EKS ---
                if ctype == "eks_cluster":
                    logging = props.get("Logging", {})
                    cluster_logging = logging.get("ClusterLogging", []) if isinstance(logging.get("ClusterLogging"), list) else []
                    enabled = [c for c in cluster_logging if c.get("Enabled") is True]
                    if not enabled:
                        findings.append(Finding(
                            id="CF-EKS-001",
                            title="EKS cluster control plane logging not enabled",
                            severity="Low",
                            category="Operational Excellence",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Enable Logging.ClusterLogging for api, audit, or authenticator log types.",
                        ))
                    open_cidrs = _eks_public_endpoint(props.get("ResourcesVpcConfig", {}))
                    if open_cidrs:
                        findings.append(Finding(
                            id="CF-EKS-002",
                            title="EKS cluster API endpoint is public to the internet",
                            severity="High",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation=(
                                f"The Kubernetes API endpoint accepts requests from {', '.join(open_cidrs)}. "
                                "EndpointPublicAccess defaults to true and PublicAccessCidrs to 0.0.0.0/0. "
                                "Set EndpointPrivateAccess: true and EndpointPublicAccess: false, or limit "
                                "PublicAccessCidrs to known ranges. "
                                "In CDK: set endpointAccess to eks.EndpointAccess.PRIVATE, or restrict PUBLIC_AND_PRIVATE with onlyFrom."
                            ),
                        ))
                    encrypted = _eks_encrypts_secrets(props.get("EncryptionConfig"))
                    if encrypted is False:
                        minor = _k8s_minor(props.get("Version"))
                        old = minor is not None and minor < 28
                        version_note = (
                            f"This cluster runs Kubernetes 1.{minor}, before the default envelope "
                            "encryption of Kubernetes API data that EKS applies from 1.28. "
                            if old else
                            "From Kubernetes 1.28, EKS encrypts Kubernetes API data with an AWS-owned "
                            "key by default. A customer-managed key adds key policy control, rotation, "
                            "and CloudTrail records of its use. "
                        )
                        findings.append(Finding(
                            id="CF-EKS-003",
                            title="EKS secrets are not encrypted with a customer-managed KMS key",
                            severity="Medium" if old else "Low",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation=(
                                version_note
                                + "Add EncryptionConfig with Provider.KeyArn set to a KMS key and Resources: [secrets]. "
                                "In CDK: secretsEncryptionKey: kmsKey."
                            ),
                        ))

        except Exception as exc:
            warnings.append(
                f"CF rules skipped resource {logical_id} in {template_path.name}: {exc}"
            )
        if res.unresolved:
            findings[first_new:] = [
                f for f in findings[first_new:]
                if not (CHECK_PROPERTIES.get(f.id, frozenset()) & res.unresolved)
            ]
        _one_saving_per_instance(findings[first_new:])

    # --- Required tag policy (config tags.required; off without one) ---
    findings.extend(tag_policy.findings(resources, template_path))

    # --- Production-grade spend in dev and staging stacks ---
    stack_env = environments.resolve(template_path, resources)
    if stack_env in ("dev", "staging"):
        findings.extend(nonprod.findings(resources, template_path, stack_env))

    # --- Stack cost: price every resource the snapshot covers (report cost section) ---
    stack_cost.record(template_path, resources)

    # --- VPC endpoints (template-level: VPC present but no endpoints) ---
    if vpc_count > 0 and vpce_count == 0:
        findings.append(Finding(
            id="CF-VPC-001",
            title="VPC has no VPC endpoints in this template",
            severity="Low",
            category="Best Practices",
            file=_anchor("vpc")[0],
            line=_anchor("vpc")[1],
            evidence=f"Template has {vpc_count} VPC(s) and 0 VPCEndpoint(s)" + _anchor("vpc")[2],
            recommendation=(
                "Consider adding VPC endpoints (gateway for S3/DynamoDB, or interface for AWS APIs) "
                "to keep traffic within the network and reduce NAT costs."
            ),
        ))

    # --- VPC Flow Logs (template-level: VPC present but no flow log) ---
    if vpc_count > 0 and flow_log_count == 0:
        findings.append(Finding(
            id="CF-FL-001",
            title="VPC has no flow logs in this template",
            severity="Low",
            category="Operational Excellence",
            file=_anchor("vpc")[0],
            line=_anchor("vpc")[1],
            evidence=f"Template has {vpc_count} VPC(s) and 0 FlowLog(s)" + _anchor("vpc")[2],
            recommendation="Add AWS::EC2::FlowLog for network troubleshooting and security analysis.",
        ))

    # --- Caching (template-level: API/Lambda but no CloudFront/ElastiCache) ---
    if (has_apigw or has_lambda) and not has_cloudfront and not has_elasticache:
        findings.append(Finding(
            id="CF-PERF-002",
            title="Consider CloudFront or ElastiCache for caching",
            severity="Low",
            category="Performance Efficiency",
            file=_anchor("api_gateway_rest_api", "api_gateway_stage", "apigatewayv2_api", "apigatewayv2_stage", "lambda_function")[0],
            line=_anchor("api_gateway_rest_api", "api_gateway_stage", "apigatewayv2_api", "apigatewayv2_stage", "lambda_function")[1],
            evidence="Template has API Gateway or Lambda but no CloudFront or ElastiCache" + _anchor("api_gateway_rest_api", "api_gateway_stage", "apigatewayv2_api", "apigatewayv2_stage", "lambda_function")[2],
            recommendation="Consider CloudFront (for APIs/static content) or ElastiCache (for data) to improve latency and efficiency.",
        ))

    # --- NAT Gateway cost (template-level) ---
    if nat_count > 0:
        findings.append(Finding(
            id="CF-COST-002",
            title="NAT Gateway incurs data processing cost",
            severity="Low",
            category="Cost Optimization",
            file=_anchor("nat_gateway")[0],
            line=_anchor("nat_gateway")[1],
            evidence=f"Template has {nat_count} NAT Gateway(s)" + _anchor("nat_gateway")[2],
            recommendation="Consider VPC endpoints (S3, DynamoDB, or interface endpoints) to reduce NAT data processing costs.",
        ))
        estimates.apply(findings[-1], estimates.nat_gateways(nat_count))

    # --- Gateway endpoints: S3 and DynamoDB through a NAT gateway (CF-VPC-002/003) ---
    findings.extend(_gateway_endpoint_findings(resources, template_path, _at))

    # --- Step Functions, EventBridge and SQS error handling ---
    findings.extend(_error_handling_findings(resources, template_path))

    # --- Redshift, DocumentDB and Neptune beyond encryption ---
    findings.extend(_warehouse_findings(resources, template_path))

    # --- OpenSearch, MSK and Kinesis access and resilience ---
    findings.extend(_search_streaming_findings(resources, template_path))

    # --- KMS key rotation and deletion window, SSM parameters ---
    findings.extend(_kms_ssm_findings(resources, template_path))

    # --- CodeBuild and CodePipeline ---
    findings.extend(_ci_cd_findings(resources, template_path))

    # --- API Gateway auth, TLS, throttling, validation and caching ---
    findings.extend(_api_gateway_findings(resources, template_path))

    # --- Lambda timeouts against their triggers, and VPC functions in one AZ ---
    findings.extend(_lambda_wiring_findings(resources, template_path))

    # --- Network: one NAT gateway for several AZs, transit gateways without flow logs ---
    findings.extend(_nat_single_az_findings(resources, template_path, _at))
    findings.extend(_tgw_flow_log_findings(resources, template_path, _at))

    # --- Launch template Spot (template-level: LTs without Spot when no ASG) ---
    if launch_templates_without_spot > 0 and asg_count == 0:
        findings.append(Finding(
            id="CF-SUST-003",
            title="Launch template(s) do not use Spot",
            severity="Low",
            category="Sustainability",
            file=_at(first_lt_without_spot)[0],
            line=_at(first_lt_without_spot)[1],
            evidence=f"Template has {launch_templates_without_spot} LaunchTemplate(s) without Spot" + _at(first_lt_without_spot)[2],
            recommendation=(
                "Consider InstanceMarketOptions.MarketType: spot for interruptible workloads "
                "to reduce cost and improve sustainability."
            ),
        ))

    # De-dup by (id, evidence, file) for this template
    dedup = {}
    for f in findings:
        key = (f.id, f.file, f.evidence)
        dedup[key] = f
    # Record the stack's environment; some rules are skipped or softened outside prod.
    return environments.apply(list(dedup.values()), template_path, resources)


def _parameter_findings(template_path: Path, doc: dict) -> List[Finding]:
    """CF-PAR-001 (secret-named parameter without NoEcho) and CF-PAR-002 (with a Default).

    Parameters resolved from SSM (Type AWS::SSM::Parameter::Value<...>) hold no value of
    their own and are not reported.
    """
    params = doc.get("Parameters")
    out: List[Finding] = []
    for name, body in params.items() if isinstance(params, dict) else []:
        if type(name) is not str or not isinstance(body, dict):
            continue
        if not is_secret_name(name):
            continue
        ptype = body.get("Type")
        if type(ptype) is str and "AWS::SSM::Parameter" in ptype:  # incl. List<AWS::SSM::...>
            continue
        evidence = f"{name} (Parameter)"
        use_instead = (
            "Use a dynamic reference instead, such as "
            "'{{resolve:secretsmanager:my-secret:SecretString:password}}' or "
            "'{{resolve:ssm-secure:/my/parameter}}', or pass the secret's ARN. "
            "In CDK: create a secretsmanager.Secret and pass its secretValue."
        )
        default = body.get("Default")
        committed = (isinstance(default, str) and default != "") or (
            isinstance(default, (int, float)) and not isinstance(default, bool)
        )
        no_echo = _flag(body.get("NoEcho")) is True
        if committed:
            out.append(Finding(
                id="CF-PAR-002",
                title="Template parameter has a secret as its default value",
                severity="High",
                category="Security",
                file=str(template_path),
                line=None,
                evidence=evidence,
                recommendation=(
                    f"{name} looks like a secret and has a Default, so the value is committed "
                    "with the template"
                    + ("" if no_echo else ", and NoEcho is not true, so it also shows in stack events")
                    + f". Remove the Default and rotate the secret. {use_instead}"
                ),
            ))
        elif not no_echo:
            out.append(Finding(
                id="CF-PAR-001",
                title="Secret template parameter is not NoEcho",
                severity="Medium",
                category="Security",
                file=str(template_path),
                line=None,
                evidence=evidence,
                recommendation=(
                    f"{name} looks like a secret but NoEcho is not true, so its value shows in "
                    f"the console, the API and stack events. Set NoEcho: true. {use_instead}"
                ),
            ))
    return out


def _committed(default: Any) -> bool:
    """A default that puts a value in the repo: a non-empty string, a number, or a
    non-empty list or map."""
    if isinstance(default, bool) or (isinstance(default, str) and type(default) is not str):
        return False  # an expression (Terraform allows none here), not a literal value
    if isinstance(default, str):
        return default != ""
    if isinstance(default, (int, float)):
        return True
    return isinstance(default, (list, dict)) and len(default) > 0


def terraform_variable_findings(variables: List[TfVariable]) -> List[Finding]:
    """CF-PAR-001 / CF-PAR-002 for a Terraform root module's input variables.

    A variable named like a secret without sensitive = true shows its value in plan and
    apply output (Medium); one with a non-empty default commits the secret (High).
    """
    use_instead = (
        "Read the secret where it is used instead, with data "
        '"aws_secretsmanager_secret_version" or data "aws_ssm_parameter", or let the '
        "service manage it (manage_master_user_password = true for RDS)."
    )
    out: List[Finding] = []
    for var in variables:
        if not is_secret_name(var.name):
            continue
        sensitive_flag = _flag(var.sensitive)
        sensitive = sensitive_flag is True
        evidence = f"var.{var.name} (variable)"
        if _committed(var.default):
            out.append(Finding(
                id="CF-PAR-002",
                title="Terraform variable has a secret as its default value",
                severity="High",
                category="Security",
                file=var.file,
                line=var.line,
                evidence=evidence,
                recommendation=(
                    f"{var.name} looks like a secret and has a default, so the value is committed "
                    "with the code"
                    + ("" if sensitive else ", and sensitive is not true, so it also shows in plan output")
                    + f". Remove the default and rotate the secret. {use_instead}"
                ),
            ))
        elif sensitive_flag is False:  # unset or false; an expression is not judged
            out.append(Finding(
                id="CF-PAR-001",
                title="Secret Terraform variable is not sensitive",
                severity="Medium",
                category="Security",
                file=var.file,
                line=var.line,
                evidence=evidence,
                recommendation=(
                    f"{var.name} looks like a secret but sensitive is not true, so its value shows "
                    f"in plan and apply output. Set sensitive = true. {use_instead}"
                ),
            ))
    return out


def _run_cf_rules_on_template(
    template_path: Path,
    doc: dict,
    warnings: list[str] | None = None,
) -> List[Finding]:
    """Parse one CloudFormation template into resources and run the CF-* checks on them."""
    if warnings is None:
        warnings = []
    resources = resources_from_cf_template(template_path, doc, warnings)
    parameters = environments.apply(_parameter_findings(template_path, doc), template_path, resources)
    return run_resource_checks(resources, template_path, warnings) + parameters


def _store_repo_relative(findings: List[Finding], repo_path: Path | None) -> None:
    if repo_path is None:
        return
    for finding in findings:
        if finding.file:
            finding.file = to_repo_relative(finding.file, repo_path)


def drop_static_covered_by_cf(findings: List[Finding]) -> List[Finding]:
    """Drop a static finding when a CloudFormation finding already covers that control."""
    covered = {sid for f in findings for sid in CF_COVERS_STATIC.get(f.id, ())}
    if environments.only_nonprod():
        # Every stack is dev or staging: the CDK source Multi-AZ advice is prod-only.
        covered |= set(environments.PROD_ONLY_STATIC)
    if tag_policy.policy_checked():
        # Templates were checked against the tag policy, which replaces the repo-wide guesses.
        covered |= set(tag_policy.REPLACED_STATIC_RULES)
    if not covered:
        return findings
    return [f for f in findings if f.id not in covered]


def run_cf_rules_from_paths(
    template_paths: List[Path],
    repo_path: Path | None = None,
    warnings: list[str] | None = None,
) -> List[Finding]:
    """Run template-level checks on a list of template paths (JSON or YAML); return list of findings."""
    if warnings is None:
        warnings = []
    findings: List[Finding] = []
    for p in template_paths:
        doc, error = _read_template(p)
        if error:
            warnings.append(error)
            continue
        try:
            findings.extend(_run_cf_rules_on_template(p, doc, warnings))
        except Exception as exc:
            warnings.append(f"CF rules failed on {p.name}: {exc}")
    dedup = {}
    for f in findings:
        key = (f.id, f.file, f.evidence)
        dedup[key] = f
    result = list(dedup.values())
    _store_repo_relative(result, repo_path)
    return result


def run_cf_rules(
    cdk_out: Path,
    repo_path: Path | None = None,
    warnings: list[str] | None = None,
) -> List[Finding]:
    """Run template-level checks on all *.template.json under cdk_out; return list of findings."""
    templates = list_cf_templates(cdk_out)
    root = repo_path if repo_path is not None else cdk_out.parent
    return run_cf_rules_from_paths(templates, repo_path=root, warnings=warnings)
