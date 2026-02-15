"""CloudFormation template-based rules (S3, RDS, ALB, CloudTrail, KMS, Lambda, DynamoDB, etc.) run after cdk synth."""
from __future__ import annotations
import json
from pathlib import Path
from typing import List, Dict, Any
from aws_arch_agent.models import Finding
from aws_arch_agent.tools.cdk_synth import list_cf_templates, load_json

# Sensitive ports for security group checks (SSH, RDP, Postgres, MySQL, Mongo)
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017}


def _walk_resources(template: dict) -> Dict[str, dict]:
    res = template.get("Resources", {}) or {}
    if isinstance(res, dict):
        return res
    return {}


def _get_prop(obj: dict, key: str) -> Any:
    props = obj.get("Properties", {}) or {}
    return props.get(key)


def _port_in_sensitive(from_port: Any, to_port: Any) -> bool:
    """True if the port range overlaps any sensitive port."""
    if from_port is None or to_port is None:
        return True
    try:
        f, t = int(from_port), int(to_port)
        return any(f <= p <= t for p in SENSITIVE_PORTS)
    except (TypeError, ValueError):
        return True


def run_cf_rules(cdk_out: Path) -> List[Finding]:
    """Run template-level checks on all *.template.json under cdk_out; return list of findings."""
    findings: List[Finding] = []
    templates = list_cf_templates(cdk_out)

    for t in templates:
        doc = load_json(t)
        resources = _walk_resources(doc)

        vpc_count = sum(1 for r in resources.values() if r.get("Type") == "AWS::EC2::VPC")
        vpce_count = sum(1 for r in resources.values() if r.get("Type") == "AWS::EC2::VPCEndpoint")
        flow_log_count = sum(1 for r in resources.values() if r.get("Type") == "AWS::EC2::FlowLog")

        for logical_id, r in resources.items():
            rtype = r.get("Type", "Unknown")
            props = r.get("Properties", {}) or {}

            # --- S3 checks ---
            if rtype == "AWS::S3::Bucket":
                pab = props.get("PublicAccessBlockConfiguration")
                if not pab or not all(pab.get(k) is True for k in [
                    "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
                ]):
                    findings.append(Finding(
                        id="CF-S3-001",
                        title="S3 bucket may miss full PublicAccessBlock",
                        severity="High",
                        category="Security",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation=(
                            "Set PublicAccessBlockConfiguration with all four flags True for buckets that should not be public. "
                            "In CDK: blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL."
                        ),
                    ))

                enc = props.get("BucketEncryption")
                if not enc:
                    findings.append(Finding(
                        id="CF-S3-002",
                        title="S3 bucket encryption not configured",
                        severity="Medium",
                        category="Security",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Enable S3 encryption (SSE-S3 or SSE-KMS) per requirements. In CDK: encryption: s3.BucketEncryption.S3_MANAGED/KMS.",
                    ))

                ver = props.get("VersioningConfiguration")
                if not ver or ver.get("Status") != "Enabled":
                    findings.append(Finding(
                        id="CF-S3-003",
                        title="S3 bucket versioning not enabled",
                        severity="Low",
                        category="Reliability",
                        file=str(t),
                        line=None,
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
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation=(
                            "Consider enabling server access logging (LoggingConfiguration with DestinationBucketName) "
                            "for audit and security analysis. In CDK: bucket.addBucketLifecycleRule or use a logging bucket."
                        ),
                    ))

            # --- RDS checks ---
            if rtype in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster"):
                storage_enc = props.get("StorageEncrypted")
                if storage_enc is not True:
                    findings.append(Finding(
                        id="CF-RDS-001",
                        title="RDS storage encryption not enabled",
                        severity="High",
                        category="Security",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Enable StorageEncrypted (and KMS CMK if required) for databases.",
                    ))

                br = props.get("BackupRetentionPeriod")
                # For clusters this is int days; for instances might exist
                if br is None:
                    findings.append(Finding(
                        id="CF-RDS-002",
                        title="RDS backup retention not set",
                        severity="Medium",
                        category="Reliability",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Set BackupRetentionPeriod per RPO/RTO (e.g. 7–35 days).",
                    ))

                maz = props.get("MultiAZ")
                if rtype == "AWS::RDS::DBInstance" and maz is not True:
                    findings.append(Finding(
                        id="CF-RDS-003",
                        title="RDS Multi-AZ not enabled",
                        severity="Medium",
                        category="Reliability",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Enable MultiAZ for production workloads where high availability is required.",
                    ))

                if props.get("PubliclyAccessible") is True:
                    findings.append(Finding(
                        id="CF-RDS-004",
                        title="RDS instance is publicly accessible",
                        severity="High",
                        category="Security",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Set PubliclyAccessible to false unless the database must be reachable from the internet.",
                    ))

                if props.get("DeletionProtection") is not True:
                    findings.append(Finding(
                        id="CF-RDS-005",
                        title="RDS deletion protection not enabled",
                        severity="Medium",
                        category="Reliability",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Enable DeletionProtection for production databases to prevent accidental deletion.",
                    ))

            # --- ALB access logs (heuristic) ---
            if rtype == "AWS::ElasticLoadBalancingV2::LoadBalancer":
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
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Consider enabling ALB access logs to S3 for audit and incident analysis (balance against cost).",
                    ))

            # --- CloudTrail ---
            if rtype == "AWS::CloudTrail::Trail":
                log = props.get("EnableLogFileValidation")
                if log is not True:
                    findings.append(Finding(
                        id="CF-CT-001",
                        title="CloudTrail log file validation not enabled",
                        severity="Medium",
                        category="Operational Excellence",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Enable log file validation for CloudTrail to detect tampering.",
                    ))
                if props.get("IsMultiRegionTrail") is not True:
                    findings.append(Finding(
                        id="CF-CT-002",
                        title="CloudTrail is not multi-region",
                        severity="Low",
                        category="Operational Excellence",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Consider enabling IsMultiRegionTrail for organization-wide audit coverage.",
                    ))
                if not props.get("KmsKeyId"):
                    findings.append(Finding(
                        id="CF-CT-003",
                        title="CloudTrail log files not encrypted with KMS",
                        severity="Low",
                        category="Security",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Use KmsKeyId to encrypt CloudTrail log files for integrity and compliance.",
                    ))

            # --- VPC Flow Logs ---
            if rtype == "AWS::EC2::FlowLog":
                # Flow log exists; optional: check destination (CloudWatch Logs or S3)
                pass  # Presence is good; no extra check for now

            # --- KMS Key policy ---
            if rtype == "AWS::KMS::Key":
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
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Restrict KMS key policy to specific principals. Avoid Principal '*' or AWS:*.",
                    ))

            # --- Lambda ---
            if rtype == "AWS::Lambda::Function":
                if not props.get("DeadLetterConfig", {}).get("TargetArn"):
                    findings.append(Finding(
                        id="CF-LAM-001",
                        title="Lambda function has no dead-letter configuration",
                        severity="Medium",
                        category="Reliability",
                        file=str(t),
                        line=None,
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
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Set TracingConfig.Mode to Active for X-Ray tracing.",
                    ))
                archs = props.get("Architectures") or []
                if isinstance(archs, str):
                    archs = [archs]
                if "arm64" not in [a.lower() for a in archs]:
                    findings.append(Finding(
                        id="CF-PERF-001",
                        title="Lambda function does not use ARM64 (Graviton)",
                        severity="Low",
                        category="Performance Efficiency",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Consider Architectures: [arm64] for better price-performance. In CDK: architecture: lambda.Architecture.ARM_64.",
                    ))

            # --- DynamoDB ---
            if rtype == "AWS::DynamoDB::Table":
                pitr = props.get("PointInTimeRecoverySpecification", {}).get("PointInTimeRecoveryEnabled")
                if pitr is not True:
                    findings.append(Finding(
                        id="CF-DDB-001",
                        title="DynamoDB point-in-time recovery not enabled",
                        severity="Medium",
                        category="Reliability",
                        file=str(t),
                        line=None,
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
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Enable SSESpecification (SSEEnabled or SSEType: KMS) for encryption at rest.",
                    ))

            # --- Security groups: open to 0.0.0.0/0 on sensitive ports ---
            if rtype == "AWS::EC2::SecurityGroup":
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
                                file=str(t),
                                line=None,
                                evidence=f"{logical_id} ({rtype})",
                                recommendation="Restrict ingress to specific CIDRs; avoid 0.0.0.0/0 on SSH (22), RDP (3389), DB ports.",
                            ))
                            break
            if rtype == "AWS::EC2::SecurityGroupIngress":
                cidr = (props.get("CidrIp") or "").strip()
                cidr6 = (props.get("CidrIpv6") or "").strip()
                if cidr == "0.0.0.0/0" or cidr6 == "::/0":
                    if _port_in_sensitive(props.get("FromPort"), props.get("ToPort")):
                        findings.append(Finding(
                            id="CF-SG-001",
                            title="Security group ingress allows 0.0.0.0/0 or ::/0 on sensitive port",
                            severity="High",
                            category="Security",
                            file=str(t),
                            line=None,
                            evidence=f"{logical_id} ({rtype})",
                            recommendation="Restrict to specific CIDRs; avoid 0.0.0.0/0 on SSH, RDP, DB ports.",
                        ))

            # --- CloudWatch Logs ---
            if rtype == "AWS::Logs::LogGroup":
                if props.get("RetentionInDays") is None:
                    findings.append(Finding(
                        id="CF-CW-001",
                        title="Log group has no retention period (infinite retention)",
                        severity="Low",
                        category="Cost Optimization",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Set RetentionInDays to limit cost and meet compliance (e.g. 30–365 days).",
                    ))
                if not props.get("KmsKeyId"):
                    findings.append(Finding(
                        id="CF-CW-002",
                        title="Log group not encrypted with KMS",
                        severity="Low",
                        category="Security",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Set KmsKeyId for encryption at rest where required by compliance.",
                    ))

            # --- SQS ---
            if rtype == "AWS::SQS::Queue":
                if props.get("SqsManagedSseEnabled") is not True and not props.get("KmsMasterKeyId"):
                    findings.append(Finding(
                        id="CF-SQS-001",
                        title="SQS queue server-side encryption not explicitly configured",
                        severity="Low",
                        category="Security",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Enable SqsManagedSseEnabled or set KmsMasterKeyId for encryption.",
                    ))
                redrive = props.get("RedrivePolicy") or {}
                if not redrive.get("deadLetterTargetArn") and not redrive.get("DeadLetterTargetArn"):
                    findings.append(Finding(
                        id="CF-SQS-002",
                        title="SQS queue has no redrive policy (dead-letter queue)",
                        severity="Low",
                        category="Reliability",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Consider RedrivePolicy with deadLetterTargetArn for failed messages.",
                    ))

            # --- API Gateway Stage (REST and V2) ---
            if rtype == "AWS::ApiGateway::Stage":
                if not props.get("AccessLogSetting", {}).get("DestinationArn"):
                    findings.append(Finding(
                        id="CF-APIGW-001",
                        title="API Gateway REST stage access logging not enabled",
                        severity="Low",
                        category="Observability",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Set AccessLogSetting with DestinationArn (e.g. CloudWatch Logs) for audit.",
                    ))
                method_settings = props.get("MethodSettings") or []
                tracing = any(
                    m.get("DataTraceEnabled") is True
                    for m in (method_settings if isinstance(method_settings, list) else [method_settings])
                )
                if not tracing:
                    findings.append(Finding(
                        id="CF-APIGW-002",
                        title="API Gateway stage X-Ray tracing not enabled",
                        severity="Low",
                        category="Observability",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Enable DataTraceEnabled in MethodSettings for X-Ray tracing.",
                    ))
            if rtype == "AWS::ApiGatewayV2::Stage":
                if not props.get("AccessLogSettings", {}).get("DestinationArn"):
                    findings.append(Finding(
                        id="CF-APIGW-001",
                        title="API Gateway V2 stage access logging not enabled",
                        severity="Low",
                        category="Observability",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Set AccessLogSettings.DestinationArn for access logs.",
                    ))
                if props.get("DefaultRouteSettings", {}).get("DataTraceEnabled") is not True:
                    findings.append(Finding(
                        id="CF-APIGW-002",
                        title="API Gateway V2 stage X-Ray tracing not enabled",
                        severity="Low",
                        category="Observability",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Set DefaultRouteSettings.DataTraceEnabled to true for X-Ray.",
                    ))

            # --- Auto Scaling Group: Spot / mixed instances (Sustainability) ---
            if rtype == "AWS::AutoScaling::AutoScalingGroup":
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
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation=(
                            "Consider MixedInstancesPolicy with Spot (InstancesDistribution.SpotMaxPrice or SpotAllocationStrategy) "
                            "for fault-tolerant workloads to reduce cost and improve sustainability. In CDK: use mixedInstancesPolicy."
                        ),
                    ))

            # --- ECS Service: Fargate Spot (Sustainability) ---
            if rtype == "AWS::ECS::Service":
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
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation=(
                            "Consider CapacityProviderStrategy including FARGATE_SPOT for interruptible tasks "
                            "to reduce cost and improve sustainability. In CDK: capacityProviderStrategies with FARGATE_SPOT."
                        ),
                    ))

            # --- EKS ---
            if rtype == "AWS::EKS::Cluster":
                logging = props.get("Logging", {})
                cluster_logging = logging.get("ClusterLogging", []) if isinstance(logging.get("ClusterLogging"), list) else []
                enabled = [c for c in cluster_logging if c.get("Enabled") is True]
                if not enabled:
                    findings.append(Finding(
                        id="CF-EKS-001",
                        title="EKS cluster control plane logging not enabled",
                        severity="Low",
                        category="Operational Excellence",
                        file=str(t),
                        line=None,
                        evidence=f"{logical_id} ({rtype})",
                        recommendation="Enable Logging.ClusterLogging for api, audit, or authenticator log types.",
                    ))

        # --- VPC endpoints (template-level: VPC present but no endpoints) ---
        if vpc_count > 0 and vpce_count == 0:
            findings.append(Finding(
                id="CF-VPC-001",
                title="VPC has no VPC endpoints in this template",
                severity="Low",
                category="Best Practices",
                file=str(t),
                line=None,
                evidence=f"Template has {vpc_count} VPC(s) and 0 VPCEndpoint(s)",
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
                file=str(t),
                line=None,
                evidence=f"Template has {vpc_count} VPC(s) and 0 FlowLog(s)",
                recommendation="Add AWS::EC2::FlowLog for network troubleshooting and security analysis.",
            ))

    # De-dup by (id, evidence, file)
    dedup = {}
    for f in findings:
        key = (f.id, f.file, f.evidence)
        dedup[key] = f
    return list(dedup.values())
