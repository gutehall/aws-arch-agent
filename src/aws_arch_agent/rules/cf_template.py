"""CloudFormation template-based rules (S3, RDS, ALB, CloudTrail, KMS, Lambda, DynamoDB, etc.) run after cdk synth."""
from __future__ import annotations
import json
from pathlib import Path
from typing import List, Any

from aws_arch_agent.models import Finding, Severity
from aws_arch_agent.rules import iam_policy
from aws_arch_agent.rules.resource_model import Resource, resources_from_cf_template
from aws_arch_agent.tools.cdk_synth import list_cf_templates
from aws_arch_agent.tools.cfn_yaml import parse_template_text
from aws_arch_agent.tools.paths import to_repo_relative

# Sensitive ports for security group checks (SSH, RDP, Postgres, MySQL, Mongo)
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017}

# Static rule dropped when the CF rule already reported that control.
CF_COVERS_STATIC: dict[str, str] = {
    "CF-S3-001": "SEC-005",
    "CF-S3-002": "SEC-006",
    "CF-VPC-001": "SEC-022",
    "CF-FL-001": "OPS-002",
    "CF-IAM-001": "SEC-001",
    "CF-IAM-002": "SEC-001",
    "CF-IAM-003": "SEC-002",
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
})


# Properties each per-resource check reads. A finding is dropped when any of them is unresolved.
CHECK_PROPERTIES: dict[str, frozenset[str]] = {
    check_id: frozenset(props) for check_id, props in {
        "CF-S3-001": {"PublicAccessBlockConfiguration"},
        "CF-S3-002": {"BucketEncryption"},
        "CF-S3-003": {"VersioningConfiguration"},
        "CF-S3-004": {"LoggingConfiguration"},
        "CF-RDS-001": {"StorageEncrypted", "DBClusterIdentifier"},
        "CF-RDS-002": {"BackupRetentionPeriod", "DBClusterIdentifier"},
        "CF-RDS-003": {"MultiAZ", "DBClusterIdentifier"},
        "CF-RDS-005": {"DeletionProtection", "DBClusterIdentifier"},
        "CF-RDS-004": {"PubliclyAccessible"},
        "CF-PERF-003": {"DBInstanceClass"},
        "CF-PERF-004": {"InstanceType"},
        "CF-ALB-001": {"LoadBalancerAttributes"},
        "CF-CT-001": {"EnableLogFileValidation"},
        "CF-CT-002": {"IsMultiRegionTrail"},
        "CF-CT-003": {"KmsKeyId"},
        "CF-KMS-001": {"KeyPolicy"},
        "CF-LAM-001": {"DeadLetterConfig"},
        "CF-LAM-002": {"TracingConfig"},
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
    }.items()
}


_IAM_TYPES = frozenset({"iam_policy", "iam_role", "iam_user", "iam_group"})

_IAM_CDK_HINT = (
    " In CDK: use grant methods such as bucket.grantRead(role), or a PolicyStatement "
    "with specific actions and resources."
)

_IAM_FINDINGS: dict[str, tuple[str, Severity, str, str]] = {
    # kind -> (id, severity, title, recommendation)
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


def _iam_findings(res: Resource, template_path: Path) -> List[Finding]:
    """One finding per kind per resource, naming the actions and the inline policy."""
    by_kind: dict[str, tuple[set[str], list[str]]] = {}
    for label, doc in _policy_documents(res.properties):
        for broad in iam_policy.broadest(doc):
            actions, labels = by_kind.setdefault(broad.kind, (set(), []))
            actions.update(broad.actions)
            if label and label not in labels:
                labels.append(label)
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

                # --- KMS Key policy ---
                if ctype == "kms_key":
                    policy = props.get("KeyPolicy")
                    if isinstance(policy, dict):
                        policy_str = json.dumps(policy)
                    else:
                        policy_str = str(policy) if policy else ""
                    if policy_str and ("*" in policy_str or '"AWS":"*"' in policy_str):
                        findings.append(Finding(
                            id="CF-KMS-001",
                            title="KMS key policy may allow wildcard principal",
                            severity="High",
                            category="Security",
                            file=res.file or str(template_path),
                            line=res.line,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Restrict KMS key policy to specific principals. Avoid Principal '*' or AWS:*.",
                        ))

                # --- Lambda ---
                if ctype == "lambda_function":
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

        except Exception as exc:
            warnings.append(
                f"CF rules skipped resource {logical_id} in {template_path.name}: {exc}"
            )
        if res.unresolved:
            findings[first_new:] = [
                f for f in findings[first_new:]
                if not (CHECK_PROPERTIES.get(f.id, frozenset()) & res.unresolved)
            ]

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
    return list(dedup.values())


def _run_cf_rules_on_template(
    template_path: Path,
    doc: dict,
    warnings: list[str] | None = None,
) -> List[Finding]:
    """Parse one CloudFormation template into resources and run the CF-* checks on them."""
    if warnings is None:
        warnings = []
    resources = resources_from_cf_template(template_path, doc, warnings)
    return run_resource_checks(resources, template_path, warnings)


def _store_repo_relative(findings: List[Finding], repo_path: Path | None) -> None:
    if repo_path is None:
        return
    for finding in findings:
        if finding.file:
            finding.file = to_repo_relative(finding.file, repo_path)


def drop_static_covered_by_cf(findings: List[Finding]) -> List[Finding]:
    """Drop a static finding when a CloudFormation finding already covers that control."""
    covered = {CF_COVERS_STATIC[f.id] for f in findings if f.id in CF_COVERS_STATIC}
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
