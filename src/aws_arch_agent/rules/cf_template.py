"""CloudFormation template-based rules (S3, RDS, ALB, CloudTrail, KMS, Lambda, DynamoDB, etc.) run after cdk synth."""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import List, Any

from aws_arch_agent.models import Finding, Severity
from aws_arch_agent.rules import (
    environments,
    estimates,
    generations,
    iam_policy,
    lambda_runtimes,
    nonprod,
    stack_cost,
    tag_policy,
)
from aws_arch_agent.rules.resource_model import Resource, resources_from_cf_template
from aws_arch_agent.rules.terraform_model import TfVariable
from aws_arch_agent.tools.cdk_synth import list_cf_templates
from aws_arch_agent.tools.cfn_yaml import parse_template_text
from aws_arch_agent.tools.paths import to_repo_relative

# Sensitive ports for security group checks (SSH, RDP, Postgres, MySQL, Mongo)
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017}

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
    "CF-EC-001": ("SEC-025",),
    "CF-EC-002": ("SEC-025",),
    "CF-OS-001": ("SEC-039",),
    "CF-OS-002": ("SEC-039",),
    "CF-RS-001": ("SEC-059",),
    "CF-DOCDB-001": ("SEC-060",),
    "CF-NEP-001": ("SEC-061",),
    "CF-MSK-001": ("SEC-044",),
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
})


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
        "CF-PERF-003": {"DBInstanceClass"},
        "CF-PERF-004": {"InstanceType"},
        "CF-EC2-001": {"MetadataOptions", "LaunchTemplate", "LaunchTemplateData"},
        "CF-ALB-001": {"LoadBalancerAttributes"},
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
            "PolicyDocument", "RepositoryPolicyText",
            "Principal", "SourceArn", "SourceAccount", "PrincipalOrgID", "FunctionUrlAuthType",
        },
        "CF-LAM-001": {"DeadLetterConfig"},
        "CF-LAM-002": {"TracingConfig"},
        "CF-LAM-003": {"Runtime", "PackageType"},
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
        "CF-CW-001": {"RetentionInDays"},
        "CF-CW-002": {"KmsKeyId"},
        "CF-SQS-001": {"SqsManagedSseEnabled", "KmsMasterKeyId"},
        "CF-SQS-002": {"RedrivePolicy"},
        "CF-APIGW-001": {"AccessLogSetting"},
        "CF-APIGW-002": {"TracingEnabled"},
        "CF-APIGW-V2-001": {"AccessLogSettings"},
        "CF-APIGW-V2-002": {"TracingEnabled"},
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


# Themes of each template check (DM3-551). Every check the module can emit is listed;
# tests/test_themes.py fails when one is missing.
_F, _SB, _ID, _DP, _NET, _RES, _OBS, _SUS = (
    "finops", "security-baseline", "identity", "data-protection",
    "network-exposure", "resilience", "observability", "sustainability",
)
CF_THEMES: dict[str, tuple[str, ...]] = {
    "CF-ALB-001": (_OBS,), "CF-APIGW-001": (_OBS,), "CF-APIGW-002": (_OBS,),
    "CF-APIGW-V2-001": (_OBS,), "CF-APIGW-V2-002": (_OBS,),
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
    "CF-LAM-001": (_RES,), "CF-LAM-002": (_OBS,), "CF-LAM-003": (_SB,),
    "CF-MSK-001": (_DP,), "CF-NEP-001": (_DP,), "CF-OS-001": (_DP,), "CF-OS-002": (_DP,),
    "CF-PAR-001": (_DP, _ID), "CF-PAR-002": (_DP, _ID),
    "CF-PERF-001": (_F, _SUS), "CF-PERF-002": (_RES,), "CF-PERF-003": (_F,), "CF-PERF-004": (_F,),
    "CF-RDS-001": (_DP,), "CF-RDS-002": (_RES, _DP), "CF-RDS-003": (_RES,), "CF-RDS-004": (_NET,),
    "CF-RDS-005": (_RES, _DP), "CF-RP-001": (_ID, _NET), "CF-RS-001": (_DP,),
    "CF-S3-001": (_NET, _DP), "CF-S3-002": (_DP,), "CF-S3-003": (_RES, _DP), "CF-S3-004": (_OBS,),
    "CF-S3-006": (_F, _DP), "CF-S3-007": (_F,), "CF-DDB-003": (_F, _RES),
    "CF-S3-005": (_DP, _NET), "CF-SG-001": (_NET,), "CF-SM-001": (_DP, _ID), "CF-SNS-001": (_DP,),
    "CF-SQS-001": (_DP,), "CF-SQS-002": (_RES,),
    "CF-SUST-001": (_SUS, _F), "CF-SUST-002": (_SUS, _F), "CF-SUST-003": (_SUS, _F),
    "CF-TAG-001": (_F,), "CF-VPC-001": (_NET, _F), "CF-WAF-001": (_NET,),
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
        hits = {
            t.name for t in tables
            if _references(text, t.name) or t.name in r.references
            or (type(t.properties.get("TableName")) is str and text.endswith(f"table/{t.properties['TableName']}"))
        }
        covered |= hits
        unlinked = unlinked or not hits
    return covered, unlinked


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
    if not isinstance(rules, list) or tiering:
        return []
    moves = any(
        isinstance(rule, dict) and (
            rule.get("Transitions") or rule.get("NoncurrentVersionTransitions")
            or rule.get("Transition") or rule.get("NoncurrentVersionTransition")
        )
        for rule in rules
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


def _public_policy_finding(res: Resource, template_path: Path) -> Finding | None:
    """CF-RP-001 for a queue, topic, bucket or ECR repository policy, or CF-KMS-001 for a key
    policy, when an Allow statement is open to Principal "*" with no limiting condition."""
    key = {"ecr_repository": "RepositoryPolicyText", "kms_key": "KeyPolicy"}.get(
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
    """Run the CF-* checks on one file's resources; return list of findings."""
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

                # --- ALB access logs (heuristic) ---
                if ctype == "lb":
                    attrs = props.get("LoadBalancerAttributes")
                    # CDK may represent as list of {Key, Value}
                    has_logs = False
                    if isinstance(attrs, list):
                        for a in attrs:
                            if a.get("Key") == "access_logs.s3.enabled" and str(a.get("Value")).lower() == "true":
                                has_logs = True
                    if not has_logs:
                        findings.append(Finding(
                            id="CF-ALB-001",
                            title="ALB access logs not enabled (template-level)",
                            severity="Low",
                            category="Observability",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Consider enabling ALB access logs to S3 for audit and incident analysis (balance against cost).",
                        ))

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

                # --- S3 storage classes, DynamoDB autoscaling, launch template gp2 (DM3-548) ---
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

                # --- Previous-generation instance families (DM3-547) ---
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
                if ctype in ("resource_policy", "ecr_repository", "kms_key"):
                    public = _public_policy_finding(res, template_path)
                    if public is not None:
                        findings.append(public)
                if ctype == "lambda_permission":
                    public = _public_lambda_permission(res, template_path)
                    if public is not None:
                        findings.append(public)

                # --- Lambda ---
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

                # --- Security groups: open to 0.0.0.0/0 on sensitive ports ---
                if ctype == "security_group":
                    ingress = props.get("SecurityGroupIngress") or []
                    if isinstance(ingress, list):
                        for rule in ingress:
                            cidr = (rule.get("CidrIp") or "").strip()
                            cidr6 = (rule.get("CidrIpv6") or "").strip()
                            if (cidr == "0.0.0.0/0" or cidr6 == "::/0") and _port_in_sensitive(rule.get("FromPort"), rule.get("ToPort")):
                                findings.append(Finding(
                                    id="CF-SG-001",
                                    title="Security group allows 0.0.0.0/0 or ::/0 on sensitive port",
                                    severity="High",
                                    category="Security",
                                    file=res.file or str(template_path),
                                    line=res.line,
                                    evidence=f"{logical_id} ({rtype})",
                                    recommendation="Restrict ingress to specific CIDRs; avoid 0.0.0.0/0 on SSH (22), RDP (3389), DB ports.",
                                ))
                                break
                if ctype == "security_group_ingress_rule":
                    cidr = (props.get("CidrIp") or "").strip()
                    cidr6 = (props.get("CidrIpv6") or "").strip()
                    if cidr == "0.0.0.0/0" or cidr6 == "::/0":
                        if _port_in_sensitive(props.get("FromPort"), props.get("ToPort")):
                            findings.append(Finding(
                                id="CF-SG-001",
                                title="Security group ingress allows 0.0.0.0/0 or ::/0 on sensitive port",
                                severity="High",
                                category="Security",
                                file=res.file or str(template_path),
                                line=res.line,
                                evidence=f"{logical_id} ({rtype})",
                                recommendation="Restrict to specific CIDRs; avoid 0.0.0.0/0 on SSH, RDP, DB ports.",
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

    # --- Production-grade spend in dev and staging stacks (DM3-545) ---
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


# A parameter name that holds a secret (DbPassword, ApiKey, GithubToken, ...).
_SECRET_NAME = re.compile(
    r"pass(?:word|wd|phrase|code)|pwd|secret|token(?!iz)|api_?key|private_?key|credential|"
    r"auth_?key|access_?key|signing_?key|shared_?key|client_?secret|connection_?string",
    re.IGNORECASE,
)
# Names that point at a secret or describe one, without holding it (DbSecretArn, KeyName,
# PasswordMinLength, TokenIssuer). A secret parameter named *Param still holds the value.
_SECRET_REFERENCE = re.compile(
    r"(?:arn|name|id|length|policy|ttl|expiry|expiration|rotation|version|path|prefix|type|"
    r"enabled|count|url|uri|header|duration|days|audience|issuer|complexity|validity|format|"
    r"symbols|numbers|uppercase|lowercase|require\w*|tokens|limit|size)$",
    re.IGNORECASE,
)
# Counts and limits named after a secret word, such as MaxTokens or min_password_age.
# Case-sensitive, so the next word must start a new word: MinioSecretKey is a secret.
_SECRET_LIMIT = re.compile(r"^(?:max|Max|MAX|min|Min|MIN)(?:imum|IMUM)?(?:_|[A-Z0-9])")


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
        if not _is_secret_name(name):
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


def _is_secret_name(name: str) -> bool:
    return (
        bool(_SECRET_NAME.search(name))
        and not _SECRET_REFERENCE.search(name)
        and not _SECRET_LIMIT.match(name)
    )


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
        if not _is_secret_name(var.name):
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
