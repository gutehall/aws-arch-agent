# AWS Arch Agent - Complete Rules Reference

This document provides a comprehensive list of all rules checked by AWS Arch Agent.

## Overview

AWS Arch Agent checks **170 static analysis rules** plus additional CloudFormation template rules across all 6 AWS Well-Architected Framework pillars.

## Static Analysis Rules (V1 & V2 Modes)

These rules run on your CDK TypeScript/Python code and execute in both V1 and V2 modes.

### Security (65 rules)

**Encryption & Data Protection:**
- SEC-006: S3 bucket encryption missing
- SEC-008: DynamoDB table encryption missing
- SEC-013: SQS queue encryption missing
- SEC-014: SNS topic encryption missing
- SEC-025: ElastiCache encryption missing
- SEC-028: ECR repository image scanning not enabled
- SEC-033: SSM Parameter Store not using SecureString
- SEC-037: EFS encryption not enabled
- SEC-038: Kinesis stream encryption not enabled
- SEC-039: OpenSearch domain encryption not enabled
- SEC-042: Athena query result encryption not enabled
- SEC-043: Glue job encryption not configured
- SEC-044: MSK cluster encryption not configured
- SEC-047: SageMaker encryption not enabled
- SEC-050: FSx file system encryption not enabled
- SEC-052: CodePipeline artifact encryption not enabled

**IAM & Access Control:**
- SEC-001: IAM policy with wildcard actions
- SEC-002: IAM policy with wildcard resources
- SEC-007: KMS key policy with wildcard principal
- SEC-023: KMS key rotation not enabled
- SEC-034: Cognito User Pool MFA not required
- SEC-035: Cognito User Pool password policy may be weak
- SEC-036: Cognito advanced security features not enabled
- SEC-009: API Gateway endpoint may not require authentication
- SEC-010: API Gateway may not enforce TLS 1.2+

**Network Security:**
- SEC-003: SSH (port 22) open to 0.0.0.0/0
- SEC-004: Database ports open to 0.0.0.0/0
- SEC-005: S3 public access not blocked
- SEC-011: ALB may not redirect HTTP to HTTPS
- SEC-012: ALB SSL policy may be outdated
- SEC-041: OpenSearch domain not in VPC
- SEC-046: SageMaker notebook instance not in VPC
- SEC-054: Security Group egress too permissive (0.0.0.0/0)
- SEC-055: Network ACLs not configured

**Secrets Management:**
- SEC-015: Secrets Manager secret may miss rotation
- SEC-016: Hardcoded secrets or API keys detected
- SEC-017: Lambda environment variables may contain secrets
- SEC-033: SSM Parameter Store not using SecureString

**Compliance & Monitoring:**
- SEC-024: WAF missing on public endpoints
- SEC-026: Security Hub not enabled
- SEC-027: GuardDuty not enabled
- SEC-048: AppSync API logging not enabled
- SEC-051: Transfer Family server logging not enabled

**Container & Compute Security:**
- SEC-019: ECS container may not use read-only root filesystem
- SEC-028: ECR repository image scanning not enabled
- SEC-029: ECR image tag immutability not configured
- SEC-030: ECR repository lifecycle policy missing
- SEC-053: CodeBuild project using privileged mode

**DNS & Certificate Security:**
- SEC-031: Route 53 health checks not configured
- SEC-032: Route 53 DNSSEC not enabled

**Application Security:**
- SEC-018: CloudFront may not enforce HTTPS-only
- SEC-020: CloudFront using legacy TLS (< 1.2)
- SEC-021: RDS may not enforce SSL connections
- SEC-040: OpenSearch fine-grained access control not enabled
- SEC-045: MSK cluster client authentication not configured
- SEC-049: AppSync API not protected by WAF

**Infrastructure Protection:**
- SEC-022: VPC endpoints missing (S3/DynamoDB traffic via internet)
- SEC-056: Stack termination protection not enabled

**Additional Security (SEC-057 to SEC-065):**
- SEC-057: Lambda function URL without authentication
- SEC-058: ECS task may run as root user
- SEC-059: Redshift cluster encryption not enabled
- SEC-060: DocumentDB cluster encryption not enabled
- SEC-061: Neptune database encryption not enabled
- SEC-062: CloudWatch Logs not encrypted with KMS
- SEC-063: Backup vault encryption not configured
- SEC-064: RDS instance may be publicly accessible
- SEC-065: Amazon Macie not enabled for sensitive data discovery

### Reliability (31 rules)

**High Availability:**
- REL-001: RDS instance missing multi-AZ
- REL-016: ElastiCache cluster missing multi-AZ/automatic failover
- REL-011: RDS missing read replicas for read-heavy workloads
- REL-012: NAT Gateway deployed in single AZ only

**Backup & Recovery:**
- REL-002: RDS backup retention period too short or missing
- REL-004: DynamoDB point-in-time recovery (PITR) not enabled
- REL-005: DynamoDB backup vault not configured
- REL-013: AWS Backup vault not configured
- REL-014: Cross-region backup not configured
- REL-017: EFS backup policy not configured

**Error Handling:**
- REL-003: Lambda missing DLQ or on-failure destination
- REL-008: SQS queue missing dead-letter queue
- REL-009: Lambda timeout may be too short
- REL-015: Step Functions missing retry policies
- REL-013: EventBridge missing DLQ

**Throttling & Limits:**
- REL-006: API Gateway throttling not configured
- REL-010: Lambda may have VPC connectivity issues

**Application Reliability:**
- REL-007: ALB health checks not configured properly
- REL-018: EFS lifecycle policy not configured
- REL-019: Kinesis stream retention period too short
- REL-020: Global Accelerator health checks not configured
- REL-021: CodePipeline missing manual approval for production
- REL-022: ACM certificate validation method not specified

**Additional Reliability (REL-023 to REL-031):**
- REL-023: Blue-green deployment not configured for critical services
- REL-024: SQS visibility timeout may need review
- REL-025: DynamoDB global tables not configured for multi-region
- REL-026: S3 replication not configured for critical buckets
- REL-027: Lambda reserved concurrency not configured for critical functions
- REL-028: API Gateway request validation not configured
- REL-029: EventBridge rule retry policy not configured
- REL-030: RDS deletion protection not enabled
- REL-031: S3 bucket versioning not enabled

### Operational Excellence (25 rules)

**Logging:**
- OPS-001: CloudTrail not enabled
- OPS-002: VPC Flow Logs not enabled
- OPS-005: API Gateway access logging not enabled
- OPS-006: ALB access logging not enabled
- OPS-007: CloudFront access logging not enabled
- OPS-015: Glue job CloudWatch metrics not enabled
- OPS-016: Transit Gateway flow logs not enabled
- OPS-020: CodeBuild project logging not configured

**Monitoring & Observability:**
- OPS-003: X-Ray tracing not enabled for Lambda
- OPS-008: ECS Container Insights not enabled
- OPS-009: RDS Enhanced Monitoring not enabled
- OPS-010: CloudWatch alarms missing
- OPS-012: Step Functions X-Ray tracing not enabled
- OPS-018: App Runner observability not configured

**Event-Driven Architecture:**
- OPS-004: DynamoDB table may benefit from streams
- OPS-013: EventBridge rule missing DLQ

**Configuration Tracking:**
- OPS-011: SNS topic for alarm notifications not configured
- OPS-014: AWS Config not enabled
- OPS-017: CodePipeline notifications not configured
- OPS-019: Glue job bookmarks not enabled

**Additional OpsEx (OPS-021 to OPS-025):**
- OPS-021: CloudWatch dashboards not configured
- OPS-022: Resource tagging strategy may be incomplete
- OPS-023: SSM Parameter Store not using advanced tier
- OPS-024: Lambda function may benefit from reserved concurrency
- OPS-025: S3 replication metrics not enabled

### Performance Efficiency (19 rules)

**Compute Optimization:**
- PERF-001: Compute may not use Graviton/ARM
- PERF-005: Lambda memory not optimized
- PERF-007: ECS task sizing (CPU/memory) may need review
- PERF-008: RDS instance class may be oversized
- PERF-010: OpenSearch instance types not optimized

**Caching:**
- PERF-002: No caching layer detected
- PERF-004: API Gateway caching not enabled
- PERF-006: CloudFront caching strategy not optimized
- PERF-013: AppSync API caching not enabled

**Resource Configuration:**
- PERF-003: DynamoDB table may use provisioned capacity (consider on-demand)
- PERF-012: EFS performance mode not configured

**Global Performance:**
- PERF-009: Kinesis enhanced fan-out not used
- PERF-011: Global Accelerator not used for global traffic
- PERF-014: S3 Transfer Acceleration not enabled for global uploads

**Additional Performance (PERF-015 to PERF-019):**
- PERF-015: Lambda SnapStart not enabled for Java functions
- PERF-016: Aurora not using I/O-Optimized for high I/O workloads
- PERF-017: EBS io2 Block Express not used for high IOPS
- PERF-018: CloudWatch Contributor Insights not enabled
- PERF-019: RDS Proxy not used for connection pooling

### Cost Optimization (18 rules)

**Resource Right-Sizing:**
- COST-002: Compute resources may miss autoscaling
- COST-003: DynamoDB provisioned capacity may miss autoscaling
- COST-004: Lambda provisioned concurrency may be overprovisioned
- COST-008: EBS volumes using gp2 instead of gp3
- COST-010: RDS not using Graviton instances

**Storage Optimization:**
- COST-001: Log retention may be infinite (cost risk)
- COST-007: S3 Intelligent-Tiering not enabled
- COST-013: S3 lifecycle policy not configured for cost optimization

**Network Costs:**
- COST-006: NAT Gateway incurs data processing costs
- COST-011: CloudFront using all edge locations (Price Class All)
- COST-012: Elastic IP allocated but may not be used

**Reserved Capacity:**
- COST-005: RDS not using Reserved Instances (savings opportunity)
- COST-009: ElastiCache may benefit from reserved nodes

**Additional Cost (COST-014 to COST-018):**
- COST-014: AWS Budgets not configured
- COST-015: Cost allocation tags may not be configured
- COST-016: Savings Plans opportunity for compute workloads
- COST-017: Lambda memory/CPU may not be optimized
- COST-018: S3 Storage Lens not enabled

### Best Practices (5 rules)

- BP-001: Standard tags missing (Environment, Owner, etc.)
- BP-002: Using environment variables instead of Secrets Manager
- BP-003: Resource naming convention may not be followed
- BP-004: CDK Aspects not used for policy enforcement
- BP-005: CDK context not used for environment-specific config

### Sustainability (7 rules)

- SUST-001: Spot instances not considered for batch/non-critical workloads
- SUST-002: Resource right-sizing opportunities detected
- SUST-003: Scheduled scaling not configured for predictable patterns
- SUST-004: Consider async processing for batch workloads
- SUST-005: Consider managed services over self-managed
- SUST-006: CloudFront compression not enabled
- SUST-007: Latest generation instance types not used

---

## CloudFormation Template Rules (V2 Mode)

CloudFormation template rules run in V2 when the agent has access to template files. They produce findings with higher signal than code heuristics alone.

**When CF rules run:**

- After **`cdk synth`** — templates in `cdk.out/*.template.json` are analyzed.
- With **`--templates`** — you provide a path to a directory or file; the agent discovers templates and skips synth. No Node.js or CDK required. You can omit `--repo` when using `--templates` (the templates path is used as the repo root).

**Template formats:** JSON (including `*.template.json`) and YAML (`*.yaml`, `*.yml`). With `--templates`, the agent discovers all of these under the given path.

## Rules (by resource)

- **S3**: CF-S3-001 (PublicAccessBlock), CF-S3-002 (encryption), CF-S3-003 (versioning), CF-S3-004 (server access logging)
- **RDS**: CF-RDS-001 (StorageEncrypted), CF-RDS-002 (BackupRetentionPeriod), CF-RDS-003 (MultiAZ), CF-RDS-004 (PubliclyAccessible), CF-RDS-005 (DeletionProtection), CF-PERF-003 (large instance right-sizing)
- **ALB**: CF-ALB-001 (access logs)
- **CloudTrail**: CF-CT-001 (log file validation), CF-CT-002 (multi-region), CF-CT-003 (KMS encryption)
- **KMS**: CF-KMS-001 (key policy wildcard principal)
- **VPC**: CF-VPC-001 (no VPC endpoints), CF-FL-001 (no flow logs)
- **Lambda**: CF-LAM-001 (no DLQ), CF-LAM-002 (X-Ray not enabled), CF-PERF-001 (ARM64 not used)
- **DynamoDB**: CF-DDB-001 (PITR not enabled), CF-DDB-002 (SSE not enabled)
- **Security groups**: CF-SG-001 (0.0.0.0/0 or ::/0 on sensitive ports)
- **CloudWatch Logs**: CF-CW-001 (no retention), CF-CW-002 (no KMS)
- **SQS**: CF-SQS-001 (encryption not configured), CF-SQS-002 (no redrive/DLQ)
- **API Gateway**: CF-APIGW-001 (access logging), CF-APIGW-002 (X-Ray tracing)
- **Auto Scaling**: CF-SUST-001 (no Spot / mixed instances)
- **ECS**: CF-SUST-002 (Fargate without FARGATE_SPOT)
- **EC2**: CF-PERF-004 (large instance right-sizing)
- **Launch Template**: CF-SUST-003 (no Spot when no ASG in template)
- **EKS**: CF-EKS-001 (control plane logging not enabled)
- **Template-level**: CF-PERF-002 (consider caching when API/Lambda, no CloudFront/ElastiCache), CF-COST-002 (NAT Gateway cost hint)

## By pillar (AWS Well-Architected 6 pillars)

| Pillar | CF rule IDs |
|--------|-------------|
| Operational Excellence | CF-S3-004, CF-CT-001, CF-CT-002, CF-FL-001, CF-EKS-001 |
| Security | CF-S3-001, CF-S3-002, CF-RDS-001, CF-RDS-004, CF-CT-003, CF-KMS-001, CF-SG-001, CF-CW-002, CF-SQS-001, CF-DDB-002 |
| Reliability | CF-S3-003, CF-RDS-002, CF-RDS-003, CF-RDS-005, CF-LAM-001, CF-DDB-001, CF-SQS-002 |
| Performance Efficiency | CF-PERF-001, CF-PERF-002, CF-PERF-003, CF-PERF-004 |
| Cost Optimization | CF-CW-001, CF-COST-002 |
| Sustainability | CF-SUST-001, CF-SUST-002, CF-SUST-003 |
| Observability (reported under Operational Excellence) | CF-ALB-001, CF-LAM-002, CF-APIGW-001, CF-APIGW-002 |
| Best Practices | CF-VPC-001 |

## See also

- [REFERENCE.md](REFERENCE.md) — CLI options and static (code) rule IDs (OPS-001, SEC-001, etc.).
- [CONFIG.md](CONFIG.md) — `templates` and `no_synth` config keys for V2.
