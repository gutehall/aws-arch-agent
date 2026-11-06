# AWS Arch Agent - Complete Rules Reference

This document provides a comprehensive list of all rules checked by AWS Arch Agent.

## Overview

AWS Arch Agent checks **170 static analysis rules** plus additional CloudFormation template rules across all 6 AWS Well-Architected Framework pillars.

## Static Analysis Rules (V1 & V2 Modes)

These rules run on your CDK TypeScript/Python code and execute in both V1 and V2 modes.

### Security (68 rules)

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
- SEC-020: ECS task definition not using read-only root filesystem
- SEC-028: ECR repository image scanning not enabled
- SEC-029: ECR image tag immutability not configured
- SEC-030: ECR repository lifecycle policy missing
- SEC-053: CodeBuild project using privileged mode

**DNS & Certificate Security:**
- SEC-031: Route 53 health checks not configured
- SEC-032: Route 53 DNSSEC not enabled

**Application Security:**
- SEC-018: CloudFront may not enforce HTTPS-only
- SEC-019: CloudFront using legacy SSL/TLS
- SEC-021: RDS may not enforce SSL connections
- SEC-040: OpenSearch fine-grained access control not enabled
- SEC-045: MSK cluster client authentication not configured
- SEC-049: AppSync API not protected by WAF

**Infrastructure Protection:**
- SEC-022: VPC endpoints missing (S3/DynamoDB traffic via internet)
- SEC-056: Stack termination protection not enabled

**Additional Security (SEC-057 to SEC-068):**
- SEC-057: Lambda function URL without authentication
- SEC-058: ECS task may run as root user
- SEC-059: Redshift cluster encryption not enabled
- SEC-060: DocumentDB cluster encryption not enabled
- SEC-061: Neptune database encryption not enabled
- SEC-062: CloudWatch Logs not encrypted with KMS
- SEC-063: Backup vault encryption not configured
- SEC-064: RDS instance may be publicly accessible
- SEC-065: Amazon Macie not enabled for sensitive data discovery
- SEC-066: EC2 instance or launch template may not require IMDSv2
- SEC-068: Lambda function uses a deprecated runtime (`lambda.Runtime.X`; High when deprecated, Low within 6 months)
- SEC-067: IAM principal has full admin access (`ManagedPolicy.fromAwsManagedPolicyName('AdministratorAccess')` or its ARN)

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
- OPS-013: EventBridge rules not using DLQ

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

### Operational Excellence (24 rules)

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
- OPS-024: folded into REL-027; reserved concurrency is not reported twice
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

## CloudFormation Template Rules

CloudFormation template rules run when the agent has access to template files. They produce findings with higher signal than code heuristics alone.

**When CF rules run:**

- In **V1** (the default) when the repo source is CloudFormation (`--iac auto` detects it, or `--iac cloudformation`). The agent discovers real templates (any `.json`, `.yaml`, `.yml`, or `.template` with `AWSTemplateFormatVersion` or an `AWS::` resource; `node_modules`, `cdk.out`, and dot dirs are skipped) and runs these rules instead of the CDK code heuristics. No synth, no `--mode v2`. YAML short tags (`!Ref`, `!Sub`, `!GetAtt`) are read as their long-form intrinsics.
- In **V1** on **Terraform** root modules (`*.tf`, `*.tf.json`; `--iac auto` detects them, or `--iac terraform`). `aws_*` resources map onto the same checks and ids; findings point at the HCL file and line. Values from `var.*` / `local.*` produce no finding. No `terraform init`; child and registry modules are not read.
- In **V2** after **`cdk synth`** — templates in `cdk.out/*.template.json` are analyzed.
- In **V2** with **`--templates`** — you provide a path to a directory or file; the agent discovers templates and skips synth. No Node.js or CDK required. You can omit `--repo` when using `--templates` (the templates path is used as the repo root).

**Template formats:** JSON (including `*.template.json`) and YAML (`*.yaml`, `*.yml`). With `--templates`, the agent discovers all of these under the given path.

## Rules (by resource)

- **S3**: CF-S3-001 (PublicAccessBlock), CF-S3-002 (encryption), CF-S3-003 (versioning), CF-S3-004 (server access logging), CF-S3-005 (no bucket policy in the template denies `s3:*` when `aws:SecureTransport` is false; Terraform reads `aws_s3_bucket_policy`, CDK `enforceSSL: true` clears it)
- **RDS**: CF-RDS-001 (StorageEncrypted), CF-RDS-002 (BackupRetentionPeriod), CF-RDS-003 (MultiAZ), CF-RDS-004 (PubliclyAccessible), CF-RDS-005 (DeletionProtection), CF-PERF-003 (large instance right-sizing)
- **ALB**: CF-ALB-001 (access logs)
- **CloudTrail**: CF-CT-001 (log file validation), CF-CT-002 (multi-region), CF-CT-003 (KMS encryption)
- **KMS**: CF-KMS-001 (key policy allows Principal `*` with no condition that limits the caller; `kms:CallerAccount` and `kms:ViaService` count as limits. The standard root key policy with Resource `*` is not reported)
- **Resource policies**: CF-RP-001 (High): an Allow with Principal `*` or `{"AWS": "*"}` and no condition on `aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalOrgID`, `aws:SourceVpce` (or another caller key) on `AWS::SQS::QueuePolicy`, `AWS::SNS::TopicPolicy`, `AWS::S3::BucketPolicy` and `AWS::ECR::Repository` `RepositoryPolicyText`; and `AWS::Lambda::Permission` with Principal `*` and no `SourceArn`, `SourceAccount` or `PrincipalOrgID` (a function URL with `FunctionUrlAuthType: AWS_IAM` is not reported). `aws:SourceIp` and `aws:SecureTransport` do not count as limits. Terraform: `aws_sqs_queue_policy`, `aws_sns_topic_policy`, `aws_s3_bucket_policy`, `aws_ecr_repository_policy`, `aws_lambda_permission`. The inline `policy` argument of `aws_sqs_queue` and `aws_sns_topic` is not read yet.
- **IAM**: CF-IAM-001 (Allow with Action `*`), CF-IAM-002 (Allow with `<service>:*`), CF-IAM-003 (Allow with write actions on Resource `*`). Read on: managed and inline policies, roles, users, and groups. Terraform: `jsonencode(...)`, heredoc JSON, JSON strings, and `data.aws_iam_policy_document`. Read-only actions and actions without resource-level permissions (X-Ray, `cloudwatch:PutMetricData`, Lambda VPC network interfaces) are not reported by CF-IAM-003. A field set from a variable or intrinsic is not guessed. Allow statements with `NotAction` or `NotResource` are not analyzed yet. In V2, CF-IAM-001/002 replace SEC-001 and CF-IAM-003 replaces SEC-002.
- **IAM admin access**: CF-IAM-008 (High, Security Hub IAM.1): a role, user, group or policy attachment with the AWS managed policy `AdministratorAccess`, or an Allow statement with Action `*` and Resource `*`. Read on CloudFormation `ManagedPolicyArns` (literal, `Fn::Join` or `Fn::Sub`, as CDK synth writes it; an ARN inside `Fn::If` is not guessed) and inline policies; Terraform `managed_policy_arns`, `aws_iam_role_policy_attachment`, `aws_iam_user_policy_attachment`, `aws_iam_group_policy_attachment`, `aws_iam_policy_attachment`, the role/user/group `*_policy_attachments_exclusive`, and `data.aws_iam_policy` looked up by name or ARN. Action `*` on Resource `*` is reported once, as CF-IAM-008, not also as CF-IAM-001. In V2, CF-IAM-008 replaces SEC-067, SEC-001 and SEC-002.
- **IAM role trust** (`AssumeRolePolicyDocument`, Terraform `assume_role_policy`): CF-IAM-004 (any AWS account can assume the role: Principal `*` with no condition, High), CF-IAM-007 (GitHub Actions OIDC with no condition on `token.actions.githubusercontent.com:sub`, High), CF-IAM-005 (a literal account principal with no `sts:ExternalId`, Medium), CF-IAM-006 (a service that acts across accounts, such as Config, CloudTrail, SNS, EventBridge or S3, with no `aws:SourceAccount` or `aws:SourceArn`, Low; compute execution roles for Lambda, EC2 and ECS are not reported)
- **VPC**: CF-VPC-001 (no VPC endpoints), CF-FL-001 (no flow logs)
- **Parameters and variables**: CF-PAR-001 (a parameter named like a secret, such as `DbPassword`, `ApiKey` or `GithubToken`, without `NoEcho: true`, Medium), CF-PAR-002 (the same with a non-empty `Default`, so the secret is committed with the template, High; reported instead of CF-PAR-001, NoEcho or not). Names that point at a secret (`DbSecretArn`, `KeyName`, `PasswordLength`) and `AWS::SSM::Parameter::Value` types are not reported. Use a `{{resolve:secretsmanager:...}}` or `{{resolve:ssm-secure:...}}` dynamic reference instead. Terraform root-module `variable` blocks get the same checks with the same name rules: CF-PAR-001 for a secret-named variable without `sensitive = true` (its value shows in plan and apply output, Medium), CF-PAR-002 for one with a non-empty `default` (High, sensitive or not). The fix reads the secret with `data "aws_secretsmanager_secret_version"` or `data "aws_ssm_parameter"` instead. Variables in child modules are not read
- **Secrets Manager**: CF-SM-001 (Medium): an `AWS::SecretsManager::Secret` / `aws_secretsmanager_secret` that no `AWS::SecretsManager::RotationSchedule` / `aws_secretsmanager_secret_rotation` in this template points at, by `Ref`, Terraform address or the secret's literal name. A schedule the scan cannot tie to a secret counts for all of them. In V2 it replaces SEC-015
- **Cognito** (`AWS::Cognito::UserPool`, `aws_cognito_user_pool`): CF-COG-001 (`MfaConfiguration` unset or `OFF`, High; `OPTIONAL` is not reported), CF-COG-002 (password policy with `MinimumLength` below 12, or no character class required, Medium; no `PasswordPolicy` means the Cognito default of 8 characters), CF-COG-003 (`UserPoolAddOns.AdvancedSecurityMode` unset or `OFF`, Low; threat protection needs `UserPoolTier: PLUS`, and the recommendation says so when the pool is on another plan). In V2 they replace SEC-034, SEC-035 and SEC-036
- **ECR** (`AWS::ECR::Repository`, `aws_ecr_repository` with `aws_ecr_lifecycle_policy`): CF-ECR-001 (`ImageScanningConfiguration.ScanOnPush` not true, Low; registry-level enhanced scanning replaces it, so exclude the rule id where that is on), CF-ECR-002 (`ImageTagMutability` unset, `MUTABLE` or `MUTABLE_WITH_EXCLUSION`, Low), CF-ECR-003 (no `LifecyclePolicy` or linked `aws_ecr_lifecycle_policy`, Low; a Terraform lifecycle policy the scan cannot tie to a repository counts for all of them). In V2 they replace SEC-028, SEC-029 and SEC-030
- **ECS** (`AWS::ECS::TaskDefinition`, `aws_ecs_task_definition`): one finding per check per task definition, naming the containers. CF-ECS-001 (`Privileged` true, High), CF-ECS-002 (`ReadonlyRootFilesystem` not true, Low), CF-ECS-003 (`User` is `root` or `0`, with or without a group, Medium; `User` unset, so the image decides, Low). Terraform `container_definitions` is read from `jsonencode([...])`, a JSON string or a heredoc; `file()`, `templatefile()` and interpolated text are not read. Windows task definitions (`RuntimePlatform.OperatingSystemFamily`) are skipped for CF-ECS-002 and CF-ECS-003. In V2, CF-ECS-002 and CF-ECS-003 replace SEC-020 and SEC-058
- **Public IPs**: CF-EC2-002 (`AWS::EC2::Subnet` / `aws_subnet` with `MapPublicIpOnLaunch` true, Medium; subnets that CDK `ec2.Vpc` creates, tagged `aws-cdk:subnet-type`, are not reported because CDK public subnets map public IPs by design), CF-EC2-003 (an instance or launch template network interface, or `aws_instance.associate_public_ip_address`, with `AssociatePublicIpAddress` true, Medium)
- **CloudFront** (`AWS::CloudFront::Distribution`, `aws_cloudfront_distribution`): CF-CF-001 (a cache behavior with `ViewerProtocolPolicy: allow-all`, Medium), CF-CF-002 (`ViewerCertificate.MinimumProtocolVersion` below `TLSv1.2_2021`, Medium; unset with your own certificate means `TLSv1`; the default `*.cloudfront.net` certificate is not reported because its minimum cannot be set), CF-CF-003 (no `WebACLId`, Low), CF-CF-004 (an S3 origin, by `S3OriginConfig` or an `*.s3[.region].amazonaws.com` / Terraform `bucket_regional_domain_name` domain, without `OriginAccessControlId`: Medium with neither OAC nor OAI, Low with only a legacy Origin Access Identity; S3 website endpoints are skipped because they cannot use OAC)
- **WAF**: CF-WAF-001 (Low): an internet-facing Application Load Balancer or an API Gateway REST API stage that no `AWS::WAFv2::WebACLAssociation` / `aws_wafv2_web_acl_association` (or WAF Classic regional association) in this template points at. Network and Gateway Load Balancers and internal ALBs are not reported. An association the scan cannot tie to a resource counts for all of them
- **Lambda**: CF-LAM-001 (no DLQ), CF-LAM-002 (X-Ray not enabled), CF-LAM-003 (deprecated runtime, High; deprecated within 6 months, Low; container images skipped; dates in `rules/lambda_runtimes.py`), CF-PERF-001 (ARM64 not used)
- **Non-production spend** (only in stacks that resolve to `dev` or `staging`, see `environments` in [CONFIG.md](CONFIG.md); Low): CF-ENV-001 (Multi-AZ RDS instance or ElastiCache replication group, with the single-AZ saving for RDS), CF-ENV-002 (Lambda provisioned concurrency on an alias or version, or `aws_lambda_provisioned_concurrency_config`), CF-ENV-003 (an EC2 or RDS instance above `nonprod.max_instance_size`, default `large`, with the saving at that size), CF-ENV-004 (more than one NAT gateway, with the saving from sharing one), CF-ENV-005 (log retention over 30 days, or never expiring), CF-ENV-006 (DynamoDB provisioned capacity, priced; on demand is suggested). The advice that says the opposite is prod-only. CF-RDS-003 (Multi-AZ), CF-DEL-001 (retain on delete) and CF-CW-001 (set a 30–365 day retention) are skipped in dev and staging. The CDK source rules REL-001, REL-016 (Multi-AZ) and COST-003 (DynamoDB autoscaling) are dropped when every stack in `cdk synth` output is dev or staging; with `--templates`, which may hold only some of the app's stacks, they stay. No stack gets both pieces of advice
- **Tag policy**: CF-TAG-001 (Medium): a taggable resource that misses a tag in config `tags.required`, or has a value `tags.allowed` does not list. Off without a policy. Stack-level tags (CDK `Tags.of(app)`, Terraform provider `default_tags`) count. See [CONFIG.md](CONFIG.md)
- **Cost** (with estimates): CF-EBS-002 (an `AWS::EC2::Volume` / `aws_ebs_volume` on gp2, set or by default, Low), CF-EIP-001 (an `AWS::EC2::EIP` / `aws_eip` that no NAT gateway, instance, network interface, association or load balancer in this template uses, Low; addresses from a BYOIP pool are not reported). In V2 they replace COST-008 and COST-012. CF-COST-002 (NAT gateway), CF-PERF-003 (large RDS instance) and CF-PERF-004 (large EC2 instance) also carry estimates. See [Cost estimates](#cost-estimates)
- **Data kept on delete**: CF-DEL-001 (Medium): an `AWS::RDS::DBInstance`, `AWS::RDS::DBCluster`, `AWS::DynamoDB::Table`, `AWS::S3::Bucket`, `AWS::EFS::FileSystem` or `AWS::Logs::LogGroup` whose `DeletionPolicy` or `UpdateReplacePolicy` is not `Retain`, `RetainExceptOnCreate` or (RDS only) `Snapshot`. No `DeletionPolicy` on an RDS cluster or standalone instance counts as `Snapshot`, the CloudFormation default; no `UpdateReplacePolicy` counts as `Delete` for every type. Aurora member instances (`DBClusterIdentifier`) are not reported, and a policy set with `Fn::If` is not judged (the other one still is). `RetainExceptOnCreate` counts only as a `DeletionPolicy`. On `cdk synth` output this is `removalPolicy: RemovalPolicy.DESTROY`, or an L1 construct with no removal policy. Terraform: the same types (`aws_db_instance`, `aws_rds_cluster`, `aws_dynamodb_table`, `aws_s3_bucket`, `aws_efs_file_system`, `aws_cloudwatch_log_group`) without `lifecycle { prevent_destroy = true }`. Dev stacks that are meant to be torn down can exclude the rule id
- **DynamoDB**: CF-DDB-001 (PITR not enabled), CF-DDB-002 (SSE not enabled)
- **Security groups**: CF-SG-001 (0.0.0.0/0 or ::/0 on sensitive ports)
- **CloudWatch Logs**: CF-CW-001 (no retention), CF-CW-002 (no KMS)
- **SQS**: CF-SQS-001 (encryption not configured), CF-SQS-002 (no redrive/DLQ)
- **SNS**: CF-SNS-001 (no `KmsMasterKeyId`, Low: SNS still keeps its own disk encryption)
- **EBS**: CF-EBS-001 (`AWS::EC2::Volume` or a launch template EBS block device without `Encrypted: true`, Medium; a volume from a snapshot takes the snapshot's setting and is not reported. Account-level EBS encryption by default is not visible to the scan)
- **EFS**: CF-EFS-001 (`Encrypted` not true, Medium)
- **Kinesis**: CF-KIN-001 (no `StreamEncryption`, Medium; Terraform `encryption_type` defaults to `NONE`)
- **ElastiCache** (`AWS::ElastiCache::ReplicationGroup`): CF-EC-001 (not encrypted at rest, Medium; Redis OSS defaults to off, Valkey to on, so an unset value on Valkey is not reported), CF-EC-002 (`TransitEncryptionEnabled` not true, Medium)
- **OpenSearch** (`AWS::OpenSearchService::Domain`): CF-OS-001 (`EncryptionAtRestOptions.Enabled` not true, Medium), CF-OS-002 (`NodeToNodeEncryptionOptions.Enabled` not true, Medium); both are off by default
- **Redshift**: CF-RS-001 (explicit `Encrypted: false`, Low). New provisioned clusters are encrypted by default since 2025, so an unset value is not reported
- **DocumentDB / Neptune**: CF-DOCDB-001, CF-NEP-001 (`StorageEncrypted` not true, Medium); a cluster restored from a snapshot or another cluster inherits its encryption and is not reported
- **MSK**: CF-MSK-001 (`EncryptionInTransit.ClientBroker` is `PLAINTEXT` or `TLS_PLAINTEXT`, or `InCluster` is false, Medium). Data at rest is always encrypted, and TLS / `InCluster: true` are the defaults, so an unset value is not reported
- **API Gateway**: CF-APIGW-001 (REST access logging), CF-APIGW-002 (REST X-Ray), CF-APIGW-V2-001 (HTTP API access logging), CF-APIGW-V2-002 (HTTP API X-Ray)
- **Auto Scaling**: CF-SUST-001 (no Spot / mixed instances)
- **ECS**: CF-SUST-002 (Fargate without FARGATE_SPOT)
- **EC2**: CF-EC2-001 (IMDSv2 not required on an instance or launch template: High when `HttpTokens: optional`, Medium when unset because the default then depends on the AMI), CF-PERF-004 (large instance right-sizing)
- **Launch Template**: CF-SUST-003 (no Spot when no ASG in template)
- **EKS**: CF-EKS-001 (control plane logging not enabled), CF-EKS-002 (API endpoint public to `0.0.0.0/0` or `::/0`; unset `EndpointPublicAccess` and `PublicAccessCidrs` count as public, the AWS default), CF-EKS-003 (no customer-managed KMS key for secrets: Medium below Kubernetes 1.28, Low from 1.28, where EKS already encrypts Kubernetes API data with an AWS-owned key)
- **Template-level**: CF-PERF-002 (consider caching when API/Lambda, no CloudFront/ElastiCache), CF-COST-002 (NAT Gateway cost hint)

## By pillar (AWS Well-Architected 6 pillars)

| Pillar | CF rule IDs |
|--------|-------------|
| Operational Excellence | CF-S3-004, CF-CT-001, CF-CT-002, CF-FL-001, CF-EKS-001 |
| Security | CF-S3-001, CF-S3-002, CF-S3-005, CF-RDS-001, CF-RDS-004, CF-CT-003, CF-KMS-001, CF-RP-001, CF-EC2-001, CF-EKS-002, CF-EKS-003, CF-IAM-001, CF-IAM-002, CF-IAM-003, CF-IAM-004, CF-IAM-005, CF-IAM-006, CF-IAM-007, CF-IAM-008, CF-SG-001, CF-CW-002, CF-SQS-001, CF-DDB-002, CF-LAM-003, CF-SNS-001, CF-EBS-001, CF-EFS-001, CF-KIN-001, CF-EC-001, CF-EC-002, CF-OS-001, CF-OS-002, CF-RS-001, CF-DOCDB-001, CF-NEP-001, CF-MSK-001, CF-CF-001, CF-CF-002, CF-CF-003, CF-CF-004, CF-WAF-001, CF-EC2-002, CF-EC2-003, CF-PAR-001, CF-PAR-002, CF-ECR-001, CF-ECR-002, CF-ECR-003, CF-ECS-001, CF-ECS-002, CF-ECS-003, CF-SM-001, CF-COG-001, CF-COG-002, CF-COG-003 |
| Reliability | CF-S3-003, CF-RDS-002, CF-RDS-003, CF-RDS-005, CF-LAM-001, CF-DDB-001, CF-SQS-002, CF-DEL-001 |
| Performance Efficiency | CF-PERF-001, CF-PERF-002, CF-PERF-003, CF-PERF-004 |
| Cost Optimization | CF-CW-001, CF-COST-002, CF-EBS-002, CF-EIP-001, CF-TAG-001, CF-ENV-001, CF-ENV-002, CF-ENV-003, CF-ENV-004, CF-ENV-005, CF-ENV-006 |
| Sustainability | CF-SUST-001, CF-SUST-002, CF-SUST-003 |
| Observability (reported under Operational Excellence) | CF-ALB-001, CF-LAM-002, CF-APIGW-001, CF-APIGW-002, CF-APIGW-V2-001, CF-APIGW-V2-002 |
| Best Practices | CF-VPC-001 |

## See also

- [REFERENCE.md](REFERENCE.md) — CLI options. Static and CloudFormation rule IDs are listed above.
- [CONFIG.md](CONFIG.md) — `templates` and `no_synth` config keys for V2.

## Cost estimates

Some findings carry `monthly_cost_usd`, `monthly_savings_usd` and an `estimate_basis` line, priced from the offline snapshot for `--region` (see [Prices](REFERENCE.md#prices)). Every report format labels them "estimate". A month is 730 hours. Only what the template states is priced. Data processed, requests and data transfer are never guessed, and the basis lists them as excluded. A saving is its own number and is never subtracted from the cost. A finding with too little to price (an instance type from a parameter, a volume sized by its snapshot, a type or region the snapshot lacks) has no number.

| Finding | Cost | Saving |
|---------|------|--------|
| CF-COST-002 | NAT gateway hours for every NAT gateway in the template | none: endpoints save data processing, which depends on traffic |
| CF-PERF-003 | the RDS instance's on-demand hours for its engine, class and Multi-AZ (Aurora is per instance) | the same instance one size smaller, when the snapshot prices it |
| CF-PERF-004 | the EC2 instance's Linux on-demand hours | one size smaller |
| CF-EBS-002 | Size × the gp2 price | Size × (gp2 − gp3), up to 1,000 GiB; above that gp2 has more baseline IOPS than gp3 includes, so no saving is estimated |
| CF-EIP-001 | the public IPv4 hour | the same: a released address is not billed |

CDK source rules (`COST-*`) cannot see sizes or counts and carry no estimates.

### Estimated monthly cost per stack

When templates are scanned (CloudFormation, `cdk synth` output, Terraform root modules), the report opens with an **Estimated Monthly Cost (estimate)** section. JSON has it as `context.notes.cost`. It prices every resource the snapshot covers, not only those with findings:

- EC2 instances (Linux, on-demand), RDS instances (engine, class, Multi-AZ), NAT gateways (hours), EBS volumes (size × type; gp2 by default), public IPv4 addresses, and DynamoDB provisioned capacity (RCU and WCU)
- the estimated monthly total for each template or root module, and overall
- the top 5 resources by cost, with the basis for each
- the possible savings: the sum of the findings' `monthly_savings_usd`, never subtracted from the total
- the resource types that cost money but were not priced, with counts. These are usage-based types (Lambda, S3, on-demand DynamoDB, ...), types not in the snapshot (load balancers, ...), and resources whose size comes from a parameter. Types that are free in themselves (IAM, security groups, subnets, routes, policies) are not listed.

Like Infracost's view, it is an approximation: on-demand prices, 730 hours a month, no data transfer, requests or storage growth. The region and AWS price list date are stated. A V1 scan of CDK source reads no templates and has no cost section; use `--mode v2`.

