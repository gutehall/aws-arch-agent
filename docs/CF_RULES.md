# AWS Arch Agent - Complete Rules Reference

This document provides a comprehensive list of all rules checked by AWS Arch Agent.

## Overview

AWS Arch Agent checks **372 static analysis rules** and **283 template checks** across all 6 AWS Well-Architected Framework pillars. 139 of the 372 CDK rules (37%) have a template check, so they also run for CloudFormation, Terraform and synthesised CDK. [COVERAGE.md](COVERAGE.md) gives the reason for each of the others.

## Static Analysis Rules (V1 & V2 Modes)

These rules run on your CDK TypeScript/Python code and execute in both V1 and V2 modes.

### Security (113 rules)

**Encryption & Data Protection:**
- SEC-006: S3 bucket encryption missing
- SEC-008: DynamoDB table encryption missing
- SEC-013: SQS queue encryption missing
- SEC-014: SNS topic encryption missing
- SEC-025: ElastiCache encryption missing
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

**Additional Security (SEC-057 to SEC-071):**
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
- SEC-069: IAM user has a console password (`iam.User` with `password`, `iam.CfnUser` with `loginProfile`)
- SEC-070: IAM access key is created in the code (`iam.AccessKey`, `iam.CfnAccessKey`)
- SEC-071: IAM user has policies attached directly (`managedPolicies` on `iam.User`, `policies` or `managedPolicyArns` on `iam.CfnUser`, `addManagedPolicy`, `addToPolicy`, `addToPrincipalPolicy` or `attachInlinePolicy` on a user variable, `users` on `iam.Policy`, `attachToUser`)

**Repo-level account guardrails** (read the IaC across the repo, so they run for CDK, CloudFormation and Terraform):
- REPO-004: No organization guardrails in the scanned IaC (org-level: runs with `rules.org` or `rules.include`)
- REPO-005: Account is defined without a security baseline
- REPO-006: Account baseline does not check root MFA or root access keys
- REPO-136: No Security Hub standard or Config conformance pack validates control objectives (org-level: runs with `rules.org` or `rules.include`)
- REPO-137: Security services are not centralized through a delegated administrator or controls (org-level: runs with `rules.org` or `rules.include`)
- REPO-138: No threat model is in the repo
- REPO-139: No IAM Access Analyzer, Inspector or dated security service review is in the repo
- REPO-007: No forensic capture is automated for security findings (org-level: runs with `rules.org` or `rules.include`)
- REPO-008: No containment control is deployed (org-level: runs with `rules.org` or `rules.include`)
- REPO-125: No Incident Manager contact or note names who responds to security incidents
- REPO-126: No security incident management plan is in the template or the repo
- REPO-127: No security incident response playbook is in the repo
- REPO-128: No incident response role is provisioned before an incident
- REPO-129: No simulation of an incident is defined
- REPO-130: No security post-incident template is in the repo
- REPO-009: The build does not scan dependencies
- REPO-010: Container or function artifacts are not scanned before deploy
- REPO-011: Packages are not pulled through a central repository
- REPO-117: No note records application security training
- REPO-118: No dated penetration test record is in the repo
- REPO-119: Nothing requires a code review before a change merges
- REPO-120: Software is not deployed programmatically
- REPO-121: No file names who owns security for the workload
- REPO-031: IAM roles have no permissions boundary or SCP to cap them
- REPO-032: No break-glass role kept apart from the workload's roles
- REPO-033: Security findings have no place to meet
- REPO-034: Traffic leaves the VPC with no inspection
- REPO-035: Network protection does not update itself
- REPO-036: A workload sits in a public subnet
- REPO-037: Deployed code and images are not signed
- REPO-038: A container image is referenced by a mutable tag
- REPO-039: Data stores carry no classification tag
- REPO-040: Data classified as sensitive has no customer managed key
- REPO-041: Nothing stops unencrypted storage from being created
- REPO-140: No permissions boundary, per-component roles or access requirements note define access
- REPO-141: No IAM Access Analyzer or dated access review reduces permissions over time
- REPO-142: The IaC creates a long-lived IAM user or access key
- REPO-143: A RAM resource share is not limited to the organization
- REPO-144: EC2 instances use an SSH key pair and no Session Manager access
- REPO-145: Compute protection is not automated with Inspector or an SSM association
- REPO-146: Data classified by tag has no lifecycle or retention rule
- REPO-151: Data stores carry no classification tag to drive retention and storage tiers

### Reliability (75 rules)

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

**Additional Reliability (REL-023 to REL-033):**
- REL-023: Blue-green deployment not configured for critical services
- REL-024: SQS visibility timeout may need review
- REL-025: DynamoDB global tables not configured for multi-region
- REL-026: S3 replication not configured for critical buckets
- REL-027: Lambda reserved concurrency not configured for critical functions
- REL-028: API Gateway request validation not configured
- REL-029: EventBridge rule retry policy not configured
- REL-030: RDS deletion protection not enabled
- REL-031: S3 bucket versioning not enabled
- REL-032: VPC uses one Availability Zone (`ec2.Vpc` with `maxAzs: 1` / `max_azs=1`, or one entry in `availabilityZones` / `availability_zones`)
- REL-033: Lambda function is granted direct invoke on another function (`callee.grantInvoke(fn)` / `grant_invoke`, where `fn` is a variable assigned a new `lambda.Function`, `NodejsFunction`, `PythonFunction`, `GoFunction` or `DockerImageFunction` in the same file and the callee has no `onFailure` / `onSuccess` destination; or `addToRolePolicy` / `addToPrincipalPolicy` on a function with `lambda:InvokeFunction`, `lambda:Invoke*` or `lambda:*`)

**Service quotas (repo-level, REL 1):**
- REPO-012: No Service Quotas usage alarm for the services the stack uses (org-level: runs with `rules.org` or `rules.include`)
- REPO-013: Limits the IaC sets leave no room for failover
- REPO-133: Service quotas are not managed as code across accounts and Regions (org-level: runs with `rules.org` or `rules.include`)
- REPO-134: No quota increase is requested by the template or by automation (org-level: runs with `rules.org` or `rules.include`)
- REPO-135: A fixed service quota is not designed around

**Network address plan (repo-level, REL 2):**
- REPO-014: VPC CIDR ranges overlap
- REPO-131: A public endpoint is an instance with a public IP, not a load balancer
- REPO-132: Only one link connects the VPC to the on-premises network

**Idempotent workers (repo-level, REL 4):**
- REPO-015: Queue and stream workers have no idempotency key or dedupe store

**Dependencies and constant work (repo-level, REL 4):**
- REPO-107: Code calls a hardcoded external URL
- REPO-108: Synchronous calls have no timeout, and no queue or schedule sits behind them

**Reliability testing (repo-level, REL 12):**
- REPO-016: No fault injection experiment targets the workload
- REPO-017: No load test runs in the pipeline
- REPO-122: No playbook is in the repo for investigating failures
- REPO-123: No post-incident template or record is in the repo
- REPO-124: No game day is recorded in the repo

**Change management (repo-level, REL 8):**
- REPO-023: Live instances are changed in place
- REPO-024: No functional test runs against the deployed change
- REPO-025: Infrastructure is not deployed by automation
- REPO-026: Deployments run no resiliency test

**Failure interactions (repo-level, REL 5):**
- REPO-042: Compute keeps state on local disk
- REPO-043: No emergency lever to shed load
- REPO-044: No fallback when a dependency fails

**Workload monitoring (repo-level, REL 6):**
- REPO-045: Alarms are not defined on workload metrics
- REPO-046: Logs are not analyzed for errors
- REPO-047: Alarms trigger no automated response
- REPO-048: Requests are not traced end to end

**Demand and impairment scaling (repo-level, REL 7):**
- REPO-049: A fleet has a fixed size
- REPO-050: Scaling reacts only to CPU or memory
- REPO-051: Backups are never restored to test them

**Disaster recovery (repo-level, REL 13):**
- REPO-052: Recovery objectives are not defined
- REPO-053: Replicated data has no automated failover
- REPO-054: Disaster recovery is never tested
- REPO-055: The DR Region can drift from the primary
- REPO-056: A standalone instance is not rebuilt when it fails

**Withstanding component failures (repo-level, REL 11):**
- REPO-057: Capacity has no headroom to survive a failure
- REPO-058: No availability target on the user-facing edge
- REPO-059: No one is notified when availability drops
- REPO-147: No dated review record lists the stateful resources and their alarms
- REPO-148: No load test shows that the workload adapts to changes in demand
- REPO-149: A lone EC2 instance has no data plane recovery
- REPO-188: One stack declares many compute services and data stores with no stack, module or API boundary

### Operational Excellence (67 rules)

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

**Additional OpsEx (OPS-021 to OPS-027):**
- OPS-021: CloudWatch dashboards not configured
- OPS-022: Resource tagging strategy may be incomplete
- OPS-023: SSM Parameter Store throughput setting may need review
- OPS-024: folded into REL-027; reserved concurrency is not reported twice
- OPS-025: S3 replication metrics not enabled
- OPS-026: EC2 instances have no patch baseline
- OPS-027: Alarms have no escalation path

**Repo-level** (read the repository tree, so they run for CDK, CloudFormation and Terraform):
- REPO-001: Repo has no automated tests
- REPO-002: No CI workflow or pipeline builds the workload
- REPO-003: Only one environment is defined

**Observability (repo-level, OPS 4):**
- REPO-018: No application KPI metric
- REPO-019: No user experience telemetry on the edge
- REPO-020: No telemetry on the datastores and queues the workload calls

**Deployment risk (repo-level, OPS 6):**
- REPO-021: A deploy runs with no test gate before it
- REPO-022: Deployments of the workload's compute have no automated rollback

**Telemetry analysis (repo-level, OPS 8):**
- REPO-027: Alarms watch only infrastructure metrics, not the workload's
- REPO-028: Workload logs are not analyzed
- REPO-029: Workload traces are not analyzed
- REPO-030: Dashboards show no workload metric

**Event management (repo-level, OPS 10):**
- REPO-109: Alarms and response plans carry no severity
- REPO-110: No customer communication channel is separate from the operator alarms
- REPO-111: No dashboard shows the state of the alarms
- REPO-112: Events start no automated response beyond a notification

**Change flow (repo-level, OPS 5):**
- REPO-113: The workload is not in version control
- REPO-114: Configuration is not kept in a configuration store or per-environment files
- REPO-115: No CI step lints, type-checks or sets a coverage gate
- REPO-116: Deployments have no rollback, blue/green or canary step
- REPO-157: No operations metric (deploys, alarms, error budget) is measured
- REPO-158: No dashboard or status topic shows operations status to operators
- REPO-159: No dated review of the operations metrics is in the repo
- REPO-161: No note names the external and internal customers the workload serves
- REPO-162: No conformance pack, Security Hub standard, SCP or compliance note names the controls
- REPO-163: Neither GuardDuty, Security Hub nor a threat model covers the threats to the workload
- REPO-164: No architecture decision record weighs a tradeoff
- REPO-165: No runbook, playbook or procedure names an owner
- REPO-166: No Incident Manager contact or note names who owns operations activities
- REPO-167: No CODEOWNERS file, escalation plan or ownership note says who owns what
- REPO-168: No pull request check, manual approval or request template shows how to ask for a change
- REPO-169: No escalation plan or note says who to turn to when the first responder cannot fix it
- REPO-170: No chat channel, subscription, on-call schedule or note tells operators what is wrong
- REPO-171: No ownership note says how the team is sponsored, empowered, trained and staffed
- REPO-172: No runbook is in the repo for deploying and operating the workload
- REPO-173: No playbook is in the repo for investigating issues in the workload
- REPO-174: No note or resource names the support plan for production
- REPO-175: No operational readiness checklist is in the repo
- REPO-176: No post-incident template or review records the lessons learned
- REPO-177: No issue template, pipeline notification or note records what a change did
- REPO-178: No improvement note names how the team improves, shares knowledge and finds time

### Performance Efficiency (33 rules)

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

**Compute selection and use (repo-level, PERF 2):**
- REPO-060: Compute utilization metrics are not collected
- REPO-061: Compute does not scale with demand
- REPO-062: Accelerator utilization is not watched

**Data management (repo-level, PERF 3):**
- REPO-063: Data lives on the instance, not in a purpose-built store

**Networking (repo-level, PERF 4):**
- REPO-064: Network latency at the edge is not watched
- REPO-065: Network configuration is not tuned on metrics
- REPO-066: Dedicated connectivity or VPN has no redundant link
- REPO-067: Traffic is not spread by a load balancer
- REPO-068: Edge uses an older network protocol
- REPO-183: No architecture decision record names the services considered, the cost, the tradeoff and the benchmark
- REPO-184: No alarm on latency or saturation has a numeric threshold
- REPO-185: Performance alarms trigger no automated remediation
- REPO-186: No load test shows how the workload performs under load
- REPO-187: No performance review note names how the team improves and reviews performance

### Cost Optimization (52 rules)

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

**Cost and usage monitoring (repo-level, COST 3):**
- REPO-069: No Cost and Usage Report or data export
- REPO-070: No cost attribution tag or cost category
- REPO-071: No unit-cost metric for the workload
- REPO-072: Costs are not allocated by workload metrics

**Cloud financial management (repo-level, COST 1):**
- REPO-073: Budget has no named owner
- REPO-074: Cost is only watched after the budget is spent
- REPO-075: Workload uses a previous-generation type or deprecated runtime
- REPO-076: Spend is not tied to a unit of business value
- REPO-077: No named cost owner links finance and engineering
- REPO-078: Cost is not part of the change process
- REPO-079: No cost guidance for the team

**Usage governance (repo-level, COST 2):**
- REPO-080: No policy governs what the organization may spend
- REPO-081: Nothing limits what the workload can spend
- REPO-082: Budget sets no target amount
- REPO-083: Production and non-production share an account
- REPO-084: Billing access is granted to an IAM user
- REPO-085: Temporary stacks have no end date

**Decommissioning (repo-level, COST 4):**
- REPO-086: Resources are not tagged with who created and owns them
- REPO-087: Nothing tears down temporary environments

**Resource type, size and number (repo-level, COST 6):**
- REPO-088: No cost estimate for the workload
- REPO-089: Workload creates its own network or cluster instead of sharing

**Pricing models (repo-level, COST 7):**
- REPO-090: No pricing model chosen for the compute fleet
- REPO-091: Higher-priced Region with no recorded reason
- REPO-092: Marketplace product with no recorded agreement term
- REPO-093: Organization tracks no shared Savings Plans or Reserved Instances

**Data transfer (repo-level, COST 8):**
- REPO-094: Data transfer between Availability Zones or Regions is not modeled
- REPO-095: Data movers pay for transfer they could avoid

**Demand management (repo-level, COST 9):**
- REPO-096: Workload demand is not analysed
- REPO-097: Demand has no buffer or throttle
- REPO-160: EC2 instances have no SSM association and no pipeline automates operations
- REPO-179: No budget or cost note states the cost requirements for peak and steady usage
- REPO-180: No cost estimate covers each component the workload declares
- REPO-181: A Marketplace image runs on a dedicated host with no licensing note
- REPO-182: No dated cost review or scheduled cost report is in the repo

### Best Practices (5 rules)

- BP-001: Standard tags missing (Environment, Owner, etc.)
- BP-002: Using environment variables instead of Secrets Manager
- BP-003: Resource naming convention may not be followed
- BP-004: CDK Aspects not used for policy enforcement
- BP-005: CDK context not used for environment-specific config

### Sustainability (27 rules)

- SUST-001: Spot instances not considered for batch/non-critical workloads
- SUST-002: Resource right-sizing opportunities detected
- SUST-003: Scheduled scaling not configured for predictable patterns
- SUST-004: Consider async processing for batch workloads
- SUST-005: Consider managed services over self-managed
- SUST-006: CloudFront compression not enabled
- SUST-007: Latest generation instance types not used

**Aligning resources to demand (repo-level, SUS 2):**
- REPO-098: Service levels are not aligned with sustainability goals
- REPO-099: Provisioned assets nothing uses
- REPO-100: CloudFront price class and stack Region disagree
- REPO-101: Team resources are not sized for the work
- REPO-102: Demand spikes reach the workload unflattened

**Software and architecture patterns (repo-level, SUS 3):**
- REPO-103: Workload components with no use
- REPO-104: Compute at its resource ceiling with no profile of the code
- REPO-105: Impact on end-user devices is not addressed
- REPO-106: Storage is not matched to the data access pattern

---
- REPO-150: Accelerator instances have no utilization alarm or batch window
- REPO-152: Instances keep their data on instance store with no durable store behind it
- REPO-153: A large EBS volume is a fixed size with nothing to grow it
- REPO-154: S3 buckets have no rule that deletes unneeded data
- REPO-155: Several EBS volumes hold data and no shared file system or bucket does
- REPO-156: A backup plan covers a cache or a temporary bucket
- REPO-189: A Terraform provider for an extra Region is declared and no resource uses it
- REPO-190: No sustainability note states the goals and the methods to reach them
- REPO-191: Nothing proposes updates to dependencies, runtimes and base images
- REPO-192: A dedicated always-on fleet runs builds
- REPO-193: A mobile app is built and no device farm tests it

## CloudFormation Template Rules

CloudFormation template rules run when the agent has access to template files. They produce findings with higher signal than code heuristics alone.

**When CF rules run:**

- In **V1** (the default) when the repo source is CloudFormation (`--iac auto` detects it, or `--iac cloudformation`). The agent discovers real templates (any `.json`, `.yaml`, `.yml`, or `.template` with `AWSTemplateFormatVersion` or an `AWS::` resource; `node_modules`, `cdk.out`, and dot dirs are skipped) and runs these rules instead of the CDK code heuristics. No synth, no `--mode v2`. YAML short tags (`!Ref`, `!Sub`, `!GetAtt`) are read as their long-form intrinsics.
- In **V1** on **Terraform** root modules (`*.tf`, `*.tf.json`; `--iac auto` detects them, or `--iac terraform`). `aws_*` resources map onto the same checks and ids; findings point at the HCL file and line. Values from `var.*` / `local.*` produce no finding. No `terraform init`; child and registry modules are not read.
- In **V2** after **`cdk synth`** — templates in `cdk.out/*.template.json` are analyzed.
- In **V2** with **`--templates`** — you provide a path to a directory or file; the agent discovers templates and skips synth. No Node.js or CDK required. You can omit `--repo` when using `--templates` (the templates path is used as the repo root).

**Template formats:** JSON (including `*.template.json`) and YAML (`*.yaml`, `*.yml`). With `--templates`, the agent discovers all of these under the given path.

**One finding per problem in V2:** when a template check reports a control that a CDK rule also checks, V2 keeps the template finding and drops the CDK one. The pairs are `CF_COVERS_STATIC` in `aws_arch_agent/rules/cf_template.py`. Some are named in the resource sections below. The others: CF-SQS-001/002 replace SEC-013 and REL-008, CF-SG-001 replaces SEC-003 and SEC-004, CF-DDB-001/002 replace REL-004 and SEC-008, CF-CW-001/002 replace COST-001 and SEC-062, CF-APIGW-001 and CF-APIGW-V2-001 replace OPS-005, CF-APIGW-002, CF-APIGW-V2-002 and CF-LAM-002 replace OPS-003, CF-LAM-001 replaces REL-003, CF-RDS-002/004/005 replace REL-002, SEC-064 and REL-030, CF-S3-003 replaces REL-031, CF-KMS-001 replaces SEC-007, CF-ALB-001 replaces OPS-006, and CF-COST-002 and CF-VPC-002/003 replace COST-006. The network checks below name their own. Some template checks cover only part of a CDK rule, so both are kept. For example, CF-RDS-003 checks DB instances but REL-001 also flags clusters. These are `CF_PARTLY_COVERS_STATIC`. [COVERAGE.md](COVERAGE.md) lists every CDK rule with its template check or the reason it has none.

## Rules (by resource)

- **S3**: CF-S3-001 (PublicAccessBlock), CF-S3-002 (encryption), CF-S3-003 (versioning), CF-S3-004 (server access logging), CF-S3-005 (no bucket policy in the template denies `s3:*` when `aws:SecureTransport` is false; Terraform reads `aws_s3_bucket_policy`, CDK `enforceSSL: true` clears it)
- **RDS**: CF-RDS-001 (StorageEncrypted), CF-RDS-002 (BackupRetentionPeriod), CF-RDS-003 (MultiAZ), CF-RDS-004 (PubliclyAccessible), CF-RDS-005 (DeletionProtection), CF-PERF-003 (large instance right-sizing)
- **RDS and Aurora settings** (`AWS::RDS::DBInstance`, `AWS::RDS::DBCluster`, their parameter groups; Terraform `aws_db_instance`, `aws_rds_cluster`, `aws_rds_cluster_instance`, `aws_db_parameter_group`, `aws_rds_cluster_parameter_group`). An Aurora member instance takes its engine settings from the cluster, so it is judged only for CF-RDS-007, CF-RDS-009 and CF-RDS-014. A database restored from a snapshot or a replica is not judged for its port or username. CF-RDS-006 (Medium): the linked parameter group does not set `rds.force_ssl` to 1 (PostgreSQL, SQL Server, Aurora PostgreSQL) or `require_secure_transport` to ON (MySQL, MariaDB, Aurora MySQL). No group, or a `default.*` group, does not enforce TLS, except on RDS for PostgreSQL 15 and later, whose defaults set `rds.force_ssl=1`. The major version comes from `EngineVersion` or the parameter group family; with neither, PostgreSQL is not judged, since AWS then picks the current default major. Oracle and Db2 set TLS in an option group, which is not read. A group the scan cannot read is not judged. CF-RDS-007 (Low, Security Hub RDS.6): `MonitoringInterval` unset or 0. CF-RDS-008 (Low, RDS.10 / RDS.12): IAM database authentication off, on MySQL, MariaDB, PostgreSQL and Aurora. CF-RDS-009 (Low, RDS.13): `AutoMinorVersionUpgrade: false`. CF-RDS-010 (Low, RDS.16 / RDS.17): `CopyTagsToSnapshot` not true. CF-RDS-011 (Low, RDS.9): no `EnableCloudwatchLogsExports`. CF-RDS-012 (Low, RDS.23): the engine's default port, set or by default. CF-RDS-013 (Low, RDS.24 / RDS.25): a literal default `MasterUsername` (`admin`, `postgres`, `root`, `sa`, ...); a username from a Secrets Manager reference is not read. CF-RDS-014 (Low): an x86 instance class on an engine with Graviton classes. In V2, CF-RDS-006, CF-RDS-007 and CF-RDS-014 replace SEC-021, OPS-009 and COST-010
- **ALB / NLB** (`AWS::ElasticLoadBalancingV2::LoadBalancer`, `Listener`, `TargetGroup`; Terraform `aws_lb`, `aws_lb_listener`, `aws_lb_target_group` and the `aws_alb*` aliases): CF-ALB-001 (access logs off, Low, Security Hub ELB.5), CF-ALB-002 (HTTP listener whose default action does not redirect to HTTPS, Medium, ELB.1), CF-ALB-003 (HTTPS or TLS listener with a policy that allows TLS 1.0 or 1.1, Medium; no `SslPolicy` counts, because CloudFormation, CDK and Terraform then use `ELBSecurityPolicy-2016-08`), CF-ALB-004 (ALB keeps invalid HTTP headers, Low, ELB.4), CF-ALB-005 (no deletion protection, Low, ELB.6), CF-ALB-006 (ALB desync mitigation mode `monitor`, Low, ELB.12), CF-NLB-001 (listener with `Protocol: TCP` on a literal port other than 443, 8443, 636, 465, 993, 995, 5671 or 9094, which are read as TLS passed through to the targets, Low), CF-ALB-007 (target group with health checks off, or an HTTP/HTTPS target group with no `HealthCheckPath`, Low; Lambda targets are skipped). An attribute or policy set from a parameter is not judged. In V2, CF-ALB-002, CF-ALB-003 and CF-ALB-007 replace SEC-011, SEC-012 and REL-007
- **Classic Load Balancer** (`AWS::ElasticLoadBalancing::LoadBalancer`, `aws_elb`): CF-CLB-001 (only HTTP or TCP listeners, Medium, ELB.3), CF-CLB-002 (an HTTPS or SSL listener with an IAM server certificate, not ACM, Low, ELB.2), CF-CLB-003 (access logs off, Low, ELB.5), CF-CLB-004 (cross-zone load balancing off, Low, ELB.9; off by default in CloudFormation, on by default in Terraform), CF-CLB-005 (connection draining off, Low, ELB.7)
- **CloudTrail**: CF-CT-001 (log file validation), CF-CT-002 (multi-region), CF-CT-003 (KMS encryption), CF-CT-004 (Low, Security Hub CloudTrail.5: no `CloudWatchLogsLogGroupArn`, Terraform `cloud_watch_logs_group_arn`; a value from a parameter or variable counts as set), CF-CT-005 (Low: the template holds a trail and an S3 bucket marked sensitive, and no trail has a data event selector that reaches it. Sensitive means the word `sensitive`, `pii`, `phi`, `confidential` or `secret` in a literal bucket name, logical id, tag value, or tag key with a true value; `non-sensitive` and `pii-free` do not count. A selector for all buckets counts, and so does one that cannot be read, a value from a parameter or variable, an advanced selector with an exclusion, or a literal ARN when the bucket's name is not known. A bucket a trail delivers its logs to is not judged)
- **CloudWatch alarms and dashboards** (`AWS::CloudWatch::Alarm`, `AWS::CloudWatch::CompositeAlarm`, `AWS::CloudWatch::Dashboard`; Terraform `aws_cloudwatch_metric_alarm`, `aws_cloudwatch_composite_alarm`, `aws_cloudwatch_dashboard`). All Low:
  - CF-ALARM-001: one finding per stack, at the first RDS, DynamoDB, Lambda, ECS service, ALB or SQS resource, when no metric alarm refers to any of them through `Dimensions` or `Metrics`. Composite alarms do not count. A dimension from a parameter or variable counts for all resources, and so does a literal for a resource whose name is not known, or a metric of that service with no dimension naming another resource. CDK's own helper functions, and load balancers not known to be ALBs, do not count as resources. Not judged when the stack has a nested stack, a remote Terraform module, or a local one that defines an alarm. Not reported in dev.
  - CF-ALARM-002: an alarm or composite alarm with no `AlarmActions`, and nothing in the template that reads it: a composite alarm, an EventBridge rule on alarm state, or another resource or module that refers to it. Any action counts, not only SNS: scaling, EC2, Systems Manager, Incident Manager and Lambda actions are real ones, and the CDK rule accepts them too. `ActionsEnabled: false` (Terraform `actions_enabled = false`) counts as no action. A value from a parameter or variable is not judged. Answers OPS10-BP02.
  - CF-ALARM-003: at least one alarm with an action, and no escalation after that first notification: no `AWS::SSMIncidents::ResponsePlan` with `Engagements` (Terraform `aws_ssmincidents_response_plan` `engagements`), no `AWS::SSMContacts::Contact` of `Type: ESCALATION` or with a `Plan` of two or more stages, no `AWS::SSMContacts::Plan` (Terraform `aws_ssmcontacts_plan`) of two or more stages, and no alarm action that targets a response plan (`arn:...:ssm-incidents::...:response-plan/...`, a `Ref` or `GetAtt` of one, or a CDK `Fn::Join` of that ARN). An action, engagement list or stage list the scan cannot read counts as an escalation, and so does a child stack or a module that may define one. Answers OPS10-BP01 and OPS10-BP04. In V2 it replaces OPS-027.
  - CF-DASH-001: a stack with more than `dashboards.min_resources` resources (default 20, see [CONFIG.md](CONFIG.md)) and no dashboard. Only resources the scan models count. Not judged when the stack has a nested stack, a remote Terraform module, or a local one that defines a dashboard. Not reported in dev.
- **Account baseline resources a repo defines** (`AWS::GuardDuty::Detector`, `AWS::SecurityHub::Hub`, `AWS::Config::ConfigurationRecorder`, `AWS::Macie::Session`, `AWS::Budgets::Budget`; Terraform `aws_guardduty_detector`, `aws_guardduty_detector_feature`, `aws_securityhub_account`, `aws_config_configuration_recorder`, `aws_macie2_account`, `aws_budgets_budget`). These run only when the resource is in the template, and never report a missing service. A value from a parameter or variable is not judged.
  - CF-GD-001 (Medium): `Enable` literally false (Security Hub GuardDuty.1), or S3 Protection (GuardDuty.10), EKS Audit Log Monitoring (GuardDuty.5) or Malware Protection for EC2 (GuardDuty.8) literally set off in `DataSources`, `Features` or a tied `aws_guardduty_detector_feature`. A feature left unset is not reported: it can be on by default for a new detector or an organization, and the template does not show it. A feature resource the scan cannot tie to a detector counts as on for all of them, and never as off. One that may turn the feature on wins over one that sets it off. Features are not judged when a child stack or module may define feature resources. Other features are not judged.
  - CF-SH-001 (Low): `EnableDefaultStandards` literally false (Terraform `enable_default_standards`) and no `AWS::SecurityHub::Standard` or `aws_securityhub_standards_subscription` for AWS Foundational Security Best Practices. Unset turns that standard on by default, so it is not reported. A `StandardsArn` that is not a plain literal counts as that standard. Not judged when the template has a Security Hub configuration policy, or a child stack or module may define a standard. `AWS::SecurityHub::HubV2` enables no standards and is not read.
  - CF-CFG-001 (Medium, Security Hub Config.1 in part): `RecordingGroup.AllSupported` literally false (Terraform `recording_group.all_supported`) with no `ResourceTypes`, `ExclusionByResourceTypes` or `RecordingStrategy`. `RecordingGroup` unset is not reported, nor is whether a list covers what the enabled controls need, whether the service-linked role is used, or whether the recorder is started.
  - CF-MACIE-001 (Low, Security Hub Macie.1): `Status` literally `PAUSED` (Terraform `aws_macie2_account.status`).
  - CF-BUDGET-001 (Low): no `NotificationsWithSubscribers` (Terraform `notification` block). Not judged for a dynamic block, or when the template has a budget action or a child stack or module may define one: an action has subscribers of its own.
- **KMS**: CF-KMS-001 (key policy allows Principal `*` with no condition that limits the caller; `kms:CallerAccount` and `kms:ViaService` count as limits. The standard root key policy with Resource `*` is not reported)
- **Resource policies**: CF-RP-001 (High): an Allow with Principal `*` or `{"AWS": "*"}` and no condition on `aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalOrgID`, `aws:SourceVpce` (or another caller key) on `AWS::SQS::QueuePolicy`, `AWS::SNS::TopicPolicy`, `AWS::S3::BucketPolicy`, `AWS::ECR::Repository` `RepositoryPolicyText`, `AWS::Events::EventBus` `Policy`, `AWS::Events::EventBusPolicy` (`Statement`, or the older `Principal` and `Condition`), `aws_cloudwatch_event_bus_policy` and `aws_cloudwatch_event_permission`; and `AWS::Lambda::Permission` with Principal `*` and no `SourceArn`, `SourceAccount` or `PrincipalOrgID` (a function URL with `FunctionUrlAuthType: AWS_IAM` is not reported). `aws:SourceIp` and `aws:SecureTransport` do not count as limits. Terraform: `aws_sqs_queue_policy`, `aws_sns_topic_policy`, `aws_s3_bucket_policy`, `aws_ecr_repository_policy`, `aws_lambda_permission`. The inline `policy` argument of `aws_sqs_queue` and `aws_sns_topic` is not read yet.
- **IAM**: CF-IAM-001 (Allow with Action `*`), CF-IAM-002 (Allow with `<service>:*`), CF-IAM-003 (Allow with write actions on Resource `*`). Read on: managed and inline policies, roles, users, and groups. Terraform: `jsonencode(...)`, heredoc JSON, JSON strings, and `data.aws_iam_policy_document`. Read-only actions and actions without resource-level permissions (X-Ray, `cloudwatch:PutMetricData`, Lambda VPC network interfaces) are not reported by CF-IAM-003. A field set from a variable or intrinsic is not guessed. Allow statements with `NotAction` or `NotResource` are not analyzed yet. In V2, CF-IAM-001/002 replace SEC-001 and CF-IAM-003 replaces SEC-002.
- **IAM admin access**: CF-IAM-008 (High, Security Hub IAM.1): a role, user, group or policy attachment with the AWS managed policy `AdministratorAccess`, or an Allow statement with Action `*` and Resource `*`. Read on CloudFormation `ManagedPolicyArns` (literal, `Fn::Join` or `Fn::Sub`, as CDK synth writes it; an ARN inside `Fn::If` is not guessed) and inline policies; Terraform `managed_policy_arns`, `aws_iam_role_policy_attachment`, `aws_iam_user_policy_attachment`, `aws_iam_group_policy_attachment`, `aws_iam_policy_attachment`, the role/user/group `*_policy_attachments_exclusive`, and `data.aws_iam_policy` looked up by name or ARN. Action `*` on Resource `*` is reported once, as CF-IAM-008, not also as CF-IAM-001. In V2, CF-IAM-008 replaces SEC-067, SEC-001 and SEC-002.
- **IAM users and credentials** (SEC 2):
  - CF-IAM-009 (Medium): an IAM user with a console password, `AWS::IAM::User` with `LoginProfile` (Terraform `aws_iam_user_login_profile`). People should sign in through IAM Identity Center or a federated identity provider. A repo with no IAM users passes, so does one with only Identity Center or a SAML or OIDC provider. Answers SEC02-BP04. In V2 it replaces SEC-069.
  - CF-IAM-010 (Medium): a long-lived access key, `AWS::IAM::AccessKey` (Terraform `aws_iam_access_key`). `Status: Inactive` is not reported, and a status from a parameter or variable is not judged. Answers SEC02-BP02. In V2 it replaces SEC-070.
  - CF-IAM-011 (Low, Security Hub IAM.2): a policy attached to an IAM user, not a group: `Policies` or `ManagedPolicyArns` on `AWS::IAM::User`, `AWS::IAM::UserPolicy`, `Users` on `AWS::IAM::Policy` or `AWS::IAM::ManagedPolicy`; Terraform `aws_iam_user_policy`, `aws_iam_user_policy_attachment`, `aws_iam_user_policy_attachments_exclusive`, and `aws_iam_policy_attachment` with `users`. Permissions through `Groups`, `AWS::IAM::UserToGroupAddition`, `aws_iam_group_membership` or `aws_iam_user_group_membership` pass. A user list from a variable is not judged. Answers SEC02-BP06. In V2 it replaces SEC-071.
- **IAM role trust** (`AssumeRolePolicyDocument`, Terraform `assume_role_policy`): CF-IAM-004 (any AWS account can assume the role: Principal `*` with no condition, High), CF-IAM-007 (GitHub Actions OIDC with no condition on `token.actions.githubusercontent.com:sub`, High), CF-IAM-005 (a literal account principal with no `sts:ExternalId`, Medium), CF-IAM-006 (a service that acts across accounts, such as Config, CloudTrail, SNS, EventBridge or S3, with no `aws:SourceAccount` or `aws:SourceArn`, Low; compute execution roles for Lambda, EC2 and ECS are not reported)
- **VPC**: CF-VPC-001 (no VPC endpoints), CF-FL-001 (no flow logs)
- **EC2 patching**: CF-PATCH-001 (EC2 instances, Auto Scaling groups or launch templates with no SSM patch baseline, AWS-RunPatchBaseline association or maintenance window task)
- **NAT traffic to S3 and DynamoDB**: CF-VPC-002 (S3) and CF-VPC-003 (DynamoDB), Low: a VPC with a public NAT gateway and no gateway VPC endpoint for that service, so private subnets reach it through the NAT gateway. Gateway endpoints for S3 and DynamoDB carry no hourly or data charge; the recommendation gives the NAT per-GB processing price from the snapshot. Only `VpcEndpointType: Gateway` clears it (the default when unset, in CloudFormation and Terraform); an Interface endpoint is billed. Terraform reads `aws_vpc_endpoint` and `aws_nat_gateway`. A NAT gateway and an endpoint are tied to their VPC through `SubnetId` and `VpcId`. A NAT gateway the scan cannot tie to a VPC is judged for the template, and an endpoint it cannot tie to a VPC counts for every VPC. A private NAT gateway (`ConnectivityType: private`) is skipped. An endpoint whose service or type comes from a parameter or variable may be the missing one, so its VPC is not judged
- **Parameters and variables**: CF-PAR-001 (a parameter named like a secret, such as `DbPassword`, `ApiKey` or `GithubToken`, without `NoEcho: true`, Medium), CF-PAR-002 (the same with a non-empty `Default`, so the secret is committed with the template, High; reported instead of CF-PAR-001, NoEcho or not). Names that point at a secret (`DbSecretArn`, `KeyName`, `PasswordLength`) and `AWS::SSM::Parameter::Value` types are not reported. Use a `{{resolve:secretsmanager:...}}` or `{{resolve:ssm-secure:...}}` dynamic reference instead. Terraform root-module `variable` blocks get the same checks with the same name rules: CF-PAR-001 for a secret-named variable without `sensitive = true` (its value shows in plan and apply output, Medium), CF-PAR-002 for one with a non-empty `default` (High, sensitive or not). The fix reads the secret with `data "aws_secretsmanager_secret_version"` or `data "aws_ssm_parameter"` instead. Variables in child modules are not read
- **Secrets Manager**: CF-SM-001 (Medium): an `AWS::SecretsManager::Secret` / `aws_secretsmanager_secret` that no `AWS::SecretsManager::RotationSchedule` / `aws_secretsmanager_secret_rotation` in this template points at, by `Ref`, Terraform address or the secret's literal name. A schedule the scan cannot tie to a secret counts for all of them. In V2 it replaces SEC-015
- **Cognito** (`AWS::Cognito::UserPool`, `aws_cognito_user_pool`): CF-COG-001 (`MfaConfiguration` unset or `OFF`, High; `OPTIONAL` is not reported), CF-COG-002 (password policy with `MinimumLength` below 12, or no character class required, Medium; no `PasswordPolicy` means the Cognito default of 8 characters), CF-COG-003 (`UserPoolAddOns.AdvancedSecurityMode` unset or `OFF`, Low; threat protection needs `UserPoolTier: PLUS`, and the recommendation says so when the pool is on another plan). In V2 they replace SEC-034, SEC-035 and SEC-036
- **ECR** (`AWS::ECR::Repository`, `aws_ecr_repository` with `aws_ecr_lifecycle_policy`): CF-ECR-001 (`ImageScanningConfiguration.ScanOnPush` not true, Low; registry-level enhanced scanning replaces it, so exclude the rule id where that is on), CF-ECR-002 (`ImageTagMutability` unset, `MUTABLE` or `MUTABLE_WITH_EXCLUSION`, Low), CF-ECR-003 (no `LifecyclePolicy` or linked `aws_ecr_lifecycle_policy`, Low; a Terraform lifecycle policy the scan cannot tie to a repository counts for all of them). In V2 they replace SEC-028, SEC-029 and SEC-030
- **ECS** (`AWS::ECS::TaskDefinition`, `aws_ecs_task_definition`): one finding per check per task definition, naming the containers. CF-ECS-001 (`Privileged` true, High), CF-ECS-002 (`ReadonlyRootFilesystem` not true, Low), CF-ECS-003 (`User` is `root` or `0`, with or without a group, Medium; `User` unset, so the image decides, Low). Terraform `container_definitions` is read from `jsonencode([...])`, a JSON string or a heredoc; `file()`, `templatefile()` and interpolated text are not read. Windows task definitions (`RuntimePlatform.OperatingSystemFamily`) are skipped for CF-ECS-002 and CF-ECS-003. In V2, CF-ECS-002 and CF-ECS-003 replace SEC-020 and SEC-058
- **ECS network, secrets, logging and sizing** (`AWS::ECS::TaskDefinition`, `AWS::ECS::Service`, `AWS::ECS::Cluster`; Terraform `aws_ecs_task_definition`, `aws_ecs_service`, `aws_ecs_cluster`): CF-ECS-004 (High): `NetworkMode: host` with a container that has `Privileged` true or `User` root or `0`; an unset `User` is not reported. CF-ECS-005 (Medium, Security Hub ECS.2): `AssignPublicIp: ENABLED` on a service; task sets are not read. CF-ECS-006 (High, Security Hub ECS.3): `PidMode: host`. CF-ECS-007 (High, Security Hub ECS.8): a container `Environment` variable named like a secret, or named `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` or `ECS_ENGINE_AUTH_DATA`, with a literal value; a reference is not reported. CF-ECS-008 (Medium, Security Hub ECS.9): a container with no `LogConfiguration` or `LogDriver`. CF-ECS-009 (Low, Security Hub ECS.10): a Fargate service, by `LaunchType` or capacity provider, with `PlatformVersion` below 1.4.0; `1.0.0` is not judged because it is the latest Windows version and the service does not state its OS. CF-ECS-010 (Low, Security Hub ECS.12): a cluster with `containerInsights` unset or `disabled`; `enabled` and `enhanced` pass, and an account default is not read, so exclude the rule id where that is on. CF-ECS-011 (Low): a task with `FARGATE` in `RequiresCompatibilities` whose `Cpu` and `Memory` numbers are not a pair in the published Fargate table; other task definitions and values such as `1 vCPU` are not judged. In V2, CF-ECS-010 and CF-ECS-011 replace OPS-008 and PERF-007
- **Public IPs**: CF-EC2-002 (`AWS::EC2::Subnet` / `aws_subnet` with `MapPublicIpOnLaunch` true, Medium; subnets that CDK `ec2.Vpc` creates, tagged `aws-cdk:subnet-type`, are not reported because CDK public subnets map public IPs by design), CF-EC2-003 (an instance or launch template network interface, or `aws_instance.associate_public_ip_address`, with `AssociatePublicIpAddress` true, Medium)
- **CloudFront** (`AWS::CloudFront::Distribution`, `aws_cloudfront_distribution`): CF-CF-001 (a cache behavior with `ViewerProtocolPolicy: allow-all`, Medium), CF-CF-002 (`ViewerCertificate.MinimumProtocolVersion` below `TLSv1.2_2021`, Medium; unset with your own certificate means `TLSv1`; the default `*.cloudfront.net` certificate is not reported because its minimum cannot be set), CF-CF-003 (no `WebACLId`, Low), CF-CF-004 (an S3 origin, by `S3OriginConfig` or an `*.s3[.region].amazonaws.com` / Terraform `bucket_regional_domain_name` domain, without `OriginAccessControlId`: Medium with neither OAC nor OAI, Low with only a legacy Origin Access Identity; S3 website endpoints are skipped because they cannot use OAC)
- **CloudFront settings** (`AWS::CloudFront::Distribution`, `aws_cloudfront_distribution`). A value from a parameter, a Terraform variable or a dynamic block is not judged, and one unknown value does not hide the others:
  - CF-CF-005 (Low, Security Hub CloudFront.5): no `Logging`, no `RealtimeLogConfigArn` on any behavior, and no v2 standard logging delivery (`AWS::Logs::DeliverySource`, `aws_cloudwatch_log_delivery_source`) naming the distribution. A delivery source the scan cannot tie to a resource counts for all distributions. The control itself reads only legacy `Logging`; this check also accepts the newer options, and so reports less than the control.
  - CF-CF-006 (Low): `PriceClass` unset, which means `PriceClass_All`, or literal `PriceClass_All`. A multi-tenant distribution is not judged: it has no price class.
  - CF-CF-007 (Low): `Compress` not true on the default or an ordered behavior, reported once per distribution with the paths. `Compress` defaults to false. A behavior using the managed `CachingDisabled` policy, or a cache policy the scan cannot read, is not judged: compression does not work without caching, and an unread policy may be that one.
  - CF-CF-008 (Low, Security Hub CloudFront.1): no `DefaultRootObject`, and the default behavior's target is an S3 origin, or an origin group of S3 origins. When the target cannot be tied, it reports only if every origin is an S3 origin. Not judged: a distribution whose default behavior goes to a custom origin, such as an API; an S3 website endpoint, which has its own index document; a default behavior with a viewer-request or origin-request function, which may rewrite the root URL.
  - CF-CF-009 (Low, Security Hub CloudFront.4): no origin group with two or more origins. This reports a distribution with one origin too, and many have one on purpose, so read it as advice.
  - CF-CF-010 (Medium, Security Hub CloudFront.9): a custom origin with `OriginProtocolPolicy: http-only`, or `match-viewer` behind a behavior with `ViewerProtocolPolicy: allow-all` that the scan can tie to the origin. An S3 origin (`S3OriginConfig`) and an S3 website endpoint, which supports only HTTP, are not judged.
  - CF-CF-011 (Medium, Security Hub CloudFront.10): a custom origin whose `OriginSSLProtocols` includes `SSLv3`. An S3 origin is not judged.
  - CF-CF-012 (Low, cost, Security Hub CloudFront.8): literal `SslSupportMethod: vip`. The control also fails on the default CloudFront certificate; this check does not report that.
  - CF-CF-013 (Low): the managed `CachingDisabled` policy id (`4135ea2d-6df8-44a3-9df3-4b5a84be39ad`) as a literal on a `PathPattern` with a static-looking form (`*.js`, `*.css`, `*.png`, `/static/*`, `/assets/*` and similar). This is narrower than PERF-006: a template does not show which other paths are static, so other behaviors and the default behavior are not judged.
- **WAF**: CF-WAF-001 (Low): an internet-facing Application Load Balancer or an API Gateway REST API stage that no `AWS::WAFv2::WebACLAssociation` / `aws_wafv2_web_acl_association` (or WAF Classic regional association) in this template points at. Network and Gateway Load Balancers and internal ALBs are not reported. An association the scan cannot tie to a resource counts for all of them
- **Lambda**: CF-LAM-001 (no DLQ), CF-LAM-002 (X-Ray not enabled), CF-LAM-003 (deprecated runtime, High; deprecated within 6 months, Low; container images skipped; dates in `rules/lambda_runtimes.py`), CF-PERF-001 (ARM64 not used)
- **Lambda access and limits** (`AWS::Lambda::Function`, `AWS::Lambda::Url`, `AWS::Lambda::EventSourceMapping`; Terraform `aws_lambda_function`, `aws_lambda_function_url`, `aws_lambda_event_source_mapping`): CF-LAM-004 (function URL with `AuthType: NONE`, High). CF-LAM-005 (High): an environment variable named like a secret (`DB_PASSWORD`, `API_KEY`, `GITHUB_TOKEN`) with a literal value. A reference, an ARN, a dynamic reference (`{{resolve:...}}`), a flag such as `true` or a number is not reported; the name rules are shared with CF-PAR-001 (`rules/secret_names.py`). CF-LAM-006 (Low): no `ReservedConcurrentExecutions`. CF-LAM-007 (Low): `Timeout` left at the 3 second default on a function an event source mapping polls for, or at 900 seconds on a function API Gateway invokes (read from an `AWS::Lambda::Permission` for `apigateway.amazonaws.com`). CF-LAM-008 (Medium, Security Hub Lambda.5): a VPC function whose subnets in this template are all in one AZ; a subnet the scan cannot place is not judged. In V2, CF-LAM-004..007 replace SEC-057, SEC-017, BP-002, REL-027 and REL-009
- **Lambda chains** (REL 4): CF-LAM-009 (Medium): a Lambda function whose role (its `Role`; Terraform `role`) has a policy that allows `lambda:InvokeFunction`, or a wildcard that covers it (`lambda:*`, `lambda:Invoke*`), on another function of the same template or module (`Ref`, `Fn::GetAtt`, `Fn::Sub`, a Terraform `aws_lambda_function.<name>.arn`). Policies are read inline on the role, from `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy` and `AWS::IAM::RolePolicy` naming the role or a managed policy the role lists, and from Terraform `inline_policy`, `aws_iam_role_policy`, and `aws_iam_policy` attached by `aws_iam_role_policy_attachment`. A callee with an `AWS::Lambda::EventInvokeConfig` (Terraform `aws_lambda_function_event_invoke_config`) that has an on-failure or on-success destination is taken as invoked asynchronously and passes. Step Functions and other service roles are not function roles, so orchestration does not fire; CDK's custom resource helpers and `cr.Provider` framework functions are skipped, and so are SAM `AWS::Serverless::Function` resources before transform. Answers REL04-BP02. In V2 it replaces REL-033
- **S3 ACLs, replication and Bucket Keys** (`AWS::S3::Bucket`; Terraform `aws_s3_bucket` with its inline `acl` and `replication_configuration`, `aws_s3_bucket_ownership_controls`, `aws_s3_bucket_acl`, `aws_s3_bucket_replication_configuration`, `aws_s3_bucket_server_side_encryption_configuration`):
  - CF-S3-008 (Medium, Security Hub S3.12): `OwnershipControls` literally `ObjectWriter` or `BucketOwnerPreferred`, or an explicit `AccessControl` other than `Private` (Terraform `acl`) with no ownership set. Unset ownership alone is not reported: new buckets have defaulted to `BucketOwnerEnforced` since April 2023. `LogDeliveryWrite` is not reported, since it grants the S3 log delivery group and not user access. A bucket that takes CloudFront standard logs is not reported, since those logs need ACLs. Terraform grants (`access_control_policy`, `grant`) are not read
  - CF-S3-009 (High, Security Hub S3.2 and S3.3): a literal `AccessControl` of `PublicRead` or `PublicReadWrite` (Terraform `public-read`, `public-read-write`). Not reported with `BucketOwnerEnforced`, or when `BlockPublicAcls` or `IgnorePublicAcls` is true, since the ACL then has no effect: such a bucket reports CF-S3-008 if it has no enforced ownership. CF-S3-009 replaces CF-S3-008 on the same bucket. CF-S3-001 reads Block Public Access and not the ACL, so it may report the same bucket
  - CF-S3-010 (Low, Security Hub S3.7): no `ReplicationConfiguration` on a bucket with the word `critical` in a literal name or tag value, a tag such as `Critical: true`, or any bucket in a prod stack. `non-critical`, `not critical` and free-text tags such as `Description` do not count. Not reported on a bucket that the template shows receiving replication or logs (`LoggingConfiguration` of another bucket, CloudFront, CloudTrail, `LogDeliveryWrite`). In a prod stack only, a bucket with `log`, `logs`, `logging`, `replica` or `replicas` as a word in its name is not reported either. Where the replica lives is not judged: same-Region replication counts
  - CF-S3-011 (Low): an enabled replication rule with `Destination.Metrics` or `Destination.ReplicationTime` unset or not `Enabled`. Both are asked for: a rule with metrics but no replication time control reports. A whole `Destination` from `Fn::If` is not judged. A `Destination.Bucket` from a parameter still reports, since the settings are read from the rule
  - CF-S3-012 (Low): a default encryption rule with `SSEAlgorithm` `aws:kms` and `BucketKeyEnabled` false or unset. `aws:kms:dsse` is not reported, since DSSE-KMS does not support Bucket Keys
  - For these checks, a value from a parameter or variable is not judged, and a Terraform part the scan cannot tie to a bucket counts for all buckets. S3 event notifications (Security Hub S3.11) have no check: most buckets have no reason to notify. Transfer Acceleration stays advice (PERF-014).
- **Storage and capacity**:
  - CF-S3-006 (an S3 bucket with no lifecycle rules, Low).
  - CF-S3-007 (a bucket whose lifecycle rules only expire objects, with no transition to a cheaper class and no Intelligent-Tiering configuration, Low). Terraform reads `aws_s3_bucket_lifecycle_configuration`, `aws_s3_bucket_intelligent_tiering_configuration` and the legacy inline `lifecycle_rule`.
  - CF-DDB-003 (a DynamoDB table with provisioned capacity that no `AWS::ApplicationAutoScaling::ScalableTarget` / `aws_appautoscaling_target` in the template scales, Medium, with the capacity cost). A target named by `Ref`, Terraform address or the table's literal name counts. One the scan cannot tie to a table counts for all of them. CF-DDB-003 is skipped in dev and staging, where CF-ENV-006 suggests on demand.
  - CF-EBS-002 also reports launch template block devices set to `gp2`. An unset type comes from the AMI, so it is not reported.
  - In V2 these replace COST-013, COST-007 and COST-003.
- **Previous-generation types**: CF-GEN-001 (Low): an EC2 instance, launch template, launch configuration, Auto Scaling group override, RDS instance, ElastiCache cluster or replication group, or OpenSearch domain on a previous-generation family (`t2`, `m4`, `c4`, `r4`, `db.m4`, `cache.t2`, `m4.large.search`, ...). It suggests the current x86 family and the Graviton family at the same size (`m4.large` to `m7i.large` or `m7g.large`), and says Graviton needs an arm64 build of the workload. For a single EC2 or RDS instance it adds the cost and the saving on the x86 successor (none when the successor costs more), with the Graviton price in the basis. Auto Scaling groups, launch templates and launch configurations run some number of instances, so they carry no number. ElastiCache and OpenSearch are not in the price snapshot. RDS for Oracle, SQL Server and Db2 get only the x86 class, since those engines have no Graviton classes. When CF-PERF-003/004 (one size smaller) also prices the same instance, only the CF-GEN-001 saving counts, because the two fixes do not add up. The family map is `aws_arch_agent/rules/data/instance_generations.json`. In V2 it replaces SUST-007
- **Non-production spend** (only in stacks that resolve to `dev` or `staging`, see `environments` in [CONFIG.md](CONFIG.md); Low): CF-ENV-001 (Multi-AZ RDS instance or ElastiCache replication group, with the single-AZ saving for RDS), CF-ENV-002 (Lambda provisioned concurrency on an alias or version, or `aws_lambda_provisioned_concurrency_config`), CF-ENV-003 (an EC2 or RDS instance above `nonprod.max_instance_size`, default `large`, with the saving at that size), CF-ENV-004 (more than one NAT gateway, with the saving from sharing one), CF-ENV-005 (log retention over 30 days, or never expiring), CF-ENV-006 (DynamoDB provisioned capacity, priced; on demand is suggested). The advice that says the opposite is prod-only. CF-RDS-003 (Multi-AZ), CF-DEL-001 (retain on delete) and CF-CW-001 (set a 30–365 day retention) are skipped in dev and staging. The CDK source rules REL-001, REL-016 (Multi-AZ) and COST-003 (DynamoDB autoscaling) are dropped when every stack in `cdk synth` output is dev or staging; with `--templates`, which may hold only some of the app's stacks, they stay. No stack gets both pieces of advice
- **Tag policy**: CF-TAG-001 (Medium): a taggable resource that misses a tag in config `tags.required`, or has a value `tags.allowed` does not list. Off without a policy. Stack-level tags (CDK `Tags.of(app)`, Terraform provider `default_tags`) count. See [CONFIG.md](CONFIG.md)
- **Cost** (with estimates): CF-EBS-002 (an `AWS::EC2::Volume` / `aws_ebs_volume` on gp2, set or by default, Low), CF-EIP-001 (an `AWS::EC2::EIP` / `aws_eip` that no NAT gateway, instance, network interface, association or load balancer in this template uses, Low; addresses from a BYOIP pool are not reported). In V2 they replace COST-008 and COST-012. CF-COST-002 (NAT gateway), CF-PERF-003 (large RDS instance) and CF-PERF-004 (large EC2 instance) also carry estimates. See [Cost estimates](#cost-estimates)
- **Data kept on delete**: CF-DEL-001 (Medium): an `AWS::RDS::DBInstance`, `AWS::RDS::DBCluster`, `AWS::DynamoDB::Table`, `AWS::S3::Bucket`, `AWS::EFS::FileSystem` or `AWS::Logs::LogGroup` whose `DeletionPolicy` or `UpdateReplacePolicy` is not `Retain`, `RetainExceptOnCreate` or (RDS only) `Snapshot`. No `DeletionPolicy` on an RDS cluster or standalone instance counts as `Snapshot`, the CloudFormation default; no `UpdateReplacePolicy` counts as `Delete` for every type. Aurora member instances (`DBClusterIdentifier`) are not reported, and a policy set with `Fn::If` is not judged (the other one still is). `RetainExceptOnCreate` counts only as a `DeletionPolicy`. On `cdk synth` output this is `removalPolicy: RemovalPolicy.DESTROY`, or an L1 construct with no removal policy. Terraform: the same types (`aws_db_instance`, `aws_rds_cluster`, `aws_dynamodb_table`, `aws_s3_bucket`, `aws_efs_file_system`, `aws_cloudwatch_log_group`) without `lifecycle { prevent_destroy = true }`. Dev stacks that are meant to be torn down can exclude the rule id
- **DynamoDB**: CF-DDB-001 (PITR not enabled), CF-DDB-002 (SSE not enabled), CF-DDB-004 (Low, Security Hub DynamoDB.6: `DeletionProtectionEnabled` not true; not reported in dev stacks), CF-DDB-005 (Low: no point-in-time recovery and no AWS Backup selection in the template that may select the table). In V2, CF-DDB-005 replaces REL-005
- **Security groups** (`AWS::EC2::SecurityGroup`, `AWS::EC2::SecurityGroupIngress`, `AWS::EC2::SecurityGroupEgress`; Terraform `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, `aws_vpc_security_group_egress_rule`): CF-SG-001 (High, Security Hub EC2.13, EC2.14, EC2.19): ingress from `0.0.0.0/0` or `::/0` on SSH, RDP, a database port, or a high-risk port (20, 21, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 4333, 5000, 5500, 5601, 8080, 8088, 8888, 9200, 9300). An unknown port counts. CF-SG-002 (High, Security Hub EC2.18): ingress from anywhere on every port (protocol `-1` or 0-65535), reported instead of CF-SG-001. CF-SG-003 (Low): egress to `0.0.0.0/0` or `::/0` on every port. A CloudFormation group created with no `SecurityGroupEgress` gets the AWS default rule, which allows all outbound traffic, so it is reported. A standalone `AWS::EC2::SecurityGroupEgress` is added after the group exists and does not remove that default. Terraform drops that default, so a group with no egress block is not. In V2, CF-SG-001 and CF-SG-002 replace SEC-003 and SEC-004, and CF-SG-003 replaces SEC-054
- **Network ACLs**: CF-NACL-001 (Medium, Security Hub EC2.21): an inbound allow entry (`AWS::EC2::NetworkAclEntry`, Terraform `aws_network_acl_rule` or an `aws_network_acl` ingress block) from `0.0.0.0/0` or `::/0` that covers port 22 or 3389, or every port. Rule order is not read, so a lower-numbered deny entry may still block the traffic
- **NAT gateway per AZ**: CF-NAT-001 (Medium): one NAT gateway that private subnets in more than one AZ route through. Routes come from `AWS::EC2::Route` (Terraform `aws_route` or `aws_route_table` route blocks) and subnets from the route table associations. A subnet whose AZ cannot be read is not counted. In V2 it replaces REL-012
- **Network topology** (REL 2):
  - CF-VPC-004 (Medium): a subnet tier of a VPC whose subnets are all in one Availability Zone. A subnet is public when it maps public IPs (`MapPublicIpOnLaunch`, Terraform `map_public_ip_on_launch`) or its route table has a route to an internet gateway in the template (`AWS::EC2::Route` `GatewayId`, Terraform `aws_route` or an `aws_route_table` route block, through `aws_route_table_association`); the other subnets are private. AZs are compared as written: a literal name or ID, or CDK's `Fn::Select` index into `Fn::GetAZs`. A VPC with a subnet whose AZ or public IP setting cannot be read is not judged, and a Terraform subnet whose VPC is not in the module is not grouped. Skipped in dev and staging. Answers REL02-BP03. In V2 it replaces REL-032.
  - CF-VPC-005 (Low): the literal subnet CIDRs of a VPC take every address of its literal IPv4 CIDR blocks (`CidrBlock` on the VPC and on `AWS::EC2::VPCCidrBlock`; Terraform `aws_vpc` and `aws_vpc_ipv4_cidr_block_association` `cidr_block`), so no subnet can be added. A block from a parameter, a variable or IPAM is not judged. A default CDK `ec2.Vpc` splits its CIDR among its subnets and so fires. Answers REL02-BP03.
  - CF-VPC-006 (Low): three or more VPC peering connections (`AWS::EC2::VPCPeeringConnection`, `aws_vpc_peering_connection`) and no transit gateway or Cloud WAN core network, or an attachment to one, in the template, a child stack or a module. Answers REL02-BP04.
- **Transit Gateway** (`AWS::EC2::TransitGateway`, `aws_ec2_transit_gateway`): CF-TGW-001 (Medium, Security Hub EC2.23): `AutoAcceptSharedAttachments: enable`. CF-TGW-002 (Low): no `AWS::EC2::FlowLog` / `aws_flow_log` on the gateway. A transit gateway flow log the scan cannot tie to a gateway counts for all of them. In V2, CF-TGW-002 replaces OPS-016
- **CloudWatch Logs**: CF-CW-001 (no retention), CF-CW-002 (no KMS)
- **SQS**: CF-SQS-001 (encryption not configured), CF-SQS-002 (no redrive/DLQ), CF-SQS-003 (Medium): `VisibilityTimeout` (default 30) shorter than the `Timeout` (default 3) of a Lambda that an event source mapping connects to the queue. The check asks for no more than the timeout; the recommendation gives the AWS advice of 6 times it
- **SNS**: CF-SNS-001 (no `KmsMasterKeyId`, Low: SNS still keeps its own disk encryption)
- **EBS**: CF-EBS-001 (`AWS::EC2::Volume` or a launch template EBS block device without `Encrypted: true`, Medium; a volume from a snapshot takes the snapshot's setting and is not reported. Account-level EBS encryption by default is not visible to the scan)
- **EFS** (`AWS::EFS::FileSystem`, `AWS::EFS::AccessPoint`; Terraform `aws_efs_file_system`, `aws_efs_backup_policy`, `aws_efs_access_point`): CF-EFS-001 (`Encrypted` not true, Medium), CF-EFS-002 (Low, Security Hub EFS.7: `BackupPolicy.Status` not `ENABLED`; unset on a One Zone file system is not reported, since backups then default to on), CF-EFS-003 (Low: no `LifecyclePolicies`), CF-EFS-004 (Medium, EFS.3: access point `RootDirectory.Path` is `/`, set or by default), CF-EFS-005 (Medium, EFS.4: access point with no `PosixUser`). Security Hub EFS.2, a file system in a backup plan, is CF-BAK-005. In V2, CF-EFS-002 and CF-EFS-003 replace REL-017 and REL-018
- **SageMaker** (`AWS::SageMaker::NotebookInstance`, `AWS::SageMaker::EndpointConfig`; Terraform `aws_sagemaker_notebook_instance`, `aws_sagemaker_endpoint_configuration`). A value from a parameter, a Terraform variable or a dynamic block is not judged:
  - CF-SAGE-001 (Medium, Security Hub SageMaker.1): notebook with `DirectInternetAccess` unset, which means `Enabled`, or literal `Enabled`.
  - CF-SAGE-002 (Medium, Security Hub SageMaker.2): notebook with no `SubnetId`. A notebook with neither setting gets both findings.
  - CF-SAGE-003 (Medium, Security Hub SageMaker.3): notebook with `RootAccess` unset, which means `Enabled`, or literal `Enabled`.
  - CF-SAGE-004 (Low): notebook, or endpoint config with an instance variant, with no `KmsKeyId` (Terraform `kms_key_id`, and `kms_key_arn` on the endpoint config). An endpoint config with only serverless variants has no volume and is not judged. Training jobs are not template resources, so they are not read. An instance type with local storage cannot take a key, and the check does not know which types those are: it can report them, and the recommendation says so.
  - CF-SAGE-005 (Low, Security Hub SageMaker.4): production variant with literal `InitialInstanceCount: 1`. A serverless variant and a shadow variant are not judged, and neither is an unset count. Not reported in dev or staging.
- **FSx** (`AWS::FSx::FileSystem`; Terraform `aws_fsx_lustre_file_system`, `aws_fsx_windows_file_system`, `aws_fsx_ontap_file_system`, `aws_fsx_openzfs_file_system`). A `FileSystemType` from a parameter is not judged, nor is a per-type block or a value the scan cannot read. Scratch Lustre, including an unset `DeploymentType`, or a type the scan cannot read, is not judged at all: it takes no key and has no backups. Lustre linked to S3 (`ImportPath`, `ExportPath`, or an `AWS::FSx::DataRepositoryAssociation` / `aws_fsx_data_repository_association` the scan ties to it or cannot tie to any file system) has no backups, so CF-FSX-002 and CF-FSX-003 skip it. On a file system restored from `BackupId`, an unset value is not judged, because the template does not show what it starts with:
  - CF-FSX-001 (Low): no `KmsKeyId`. FSx still encrypts with its service key, so this asks for a customer managed key, not for encryption.
  - CF-FSX-002 (Low, Security Hub FSx.2 on Lustre, FSx.1 on OpenZFS, none on Windows): `CopyTagsToBackups` unset or false. ONTAP has no such setting. FSx.1 also asks for `CopyTagsToVolumes`, which is not read.
  - CF-FSX-003 (Low): literal `AutomaticBackupRetentionDays: 0` on any type, or unset on persistent Lustre, where the default is 0. Unset on ONTAP, Windows and OpenZFS is not judged: CloudFormation documents a default of 30, and the Terraform provider's defaults differ.
- **AppSync** (`AWS::AppSync::GraphQLApi`, `AWS::AppSync::ApiCache`; Terraform `aws_appsync_graphql_api`, `aws_appsync_api_cache`). A value from a parameter, a Terraform variable or a dynamic block is not judged:
  - CF-APPSYNC-001 (Low, Security Hub AppSync.2): no `LogConfig`, or literal `FieldLogLevel: NONE`. `INFO` and `DEBUG` are not judged: the control's text fails only `NONE`, though it passes only `ERROR` and `ALL` by default.
  - CF-APPSYNC-002 (Medium, Security Hub AppSync.5): literal `AuthenticationType: API_KEY` with no other kind in `AdditionalAuthenticationProviders`. An API that also takes another kind is not reported, which is narrower than the control.
  - CF-APPSYNC-003 (Medium): no `AWS::WAFv2::WebACLAssociation` or `AWS::WAFRegional::WebACLAssociation` (Terraform `aws_wafv2_web_acl_association`, `aws_wafregional_web_acl_association`) in this scan points at the API. An association the scan cannot tie to an API, ALB or stage counts for all APIs. A `PRIVATE` or `MERGED` API is not judged. An association in another stack is not visible to the scan.
  - CF-APPSYNC-004 (Low, advice): no `ApiCache` in this scan has an `ApiId` that points at the API. A cache the scan cannot tie to an API counts for all APIs. A `MERGED` API is not judged.
- **Transfer Family** (`AWS::Transfer::Server`; Terraform `aws_transfer_server`):
  - CF-TRANSFER-001 (Medium, Security Hub Transfer.2): literal `FTP` in `Protocols`. Unset means `SFTP` and is not reported, and `FTPS` is not `FTP`.
  - CF-TRANSFER-002 (Low): no `LoggingRole` and no `StructuredLogDestinations`, or both empty. A value from a parameter or a variable counts as set. Security Hub Transfer.3 is about connectors, so it is not cited.
  - CF-TRANSFER-003 (Low): literal `EndpointType: PUBLIC`, or Terraform `endpoint_type` unset with no `endpoint_details`, which the provider documents as `PUBLIC`. Unset in CloudFormation is not judged: no default is documented.
- **Route 53** (`AWS::Route53::HostedZone`, `AWS::Route53::RecordSet`, `AWS::Route53::RecordSetGroup`, `AWS::Route53::DNSSEC`, `AWS::Route53::KeySigningKey`; Terraform `aws_route53_zone`, `aws_route53_record`, `aws_route53_query_log`, `aws_route53_hosted_zone_dnssec`, `aws_route53_key_signing_key`). A zone is public with no `VPCs` (Terraform no `vpc` block). A private zone, and an unknown `VPCs` or a dynamic `vpc` block, is not judged. A linked resource the scan cannot tie to a zone in this template counts for all zones.
  - CF-R53-001 (Low, Security Hub Route53.2): public zone with no `QueryLoggingConfig` and no `aws_route53_query_log` pointing at it.
  - CF-R53-002 (Low): public zone with no DNSSEC or key-signing key resource pointing at it. A key-signing key alone counts, and so does a `signing_status` of `NOT_SIGNING`: signing may be turned on outside the template.
  - CF-R53-003 (Medium): a `PRIMARY` failover record or a weighted record, including weight 0, with no `HealthCheckId`. In a `RecordSetGroup` each entry of `RecordSets` is read. An alias record with `EvaluateTargetHealth` true is not reported. A `SECONDARY` record is not reported: with no health check Route 53 answers with it whenever the primary is unhealthy, which is a documented design. A routing value from a parameter, a variable or a dynamic block is not judged, and neither is `SetIdentifier` alone.
- **ACM** (`AWS::CertificateManager::Certificate`; Terraform `aws_acm_certificate`). An imported certificate (Terraform `private_key` or `certificate_body`) is not judged. A private CA certificate (`CertificateAuthorityArn`) is judged only by CF-ACM-002.
  - CF-ACM-001 (Low): literal `ValidationMethod: EMAIL`, or unset in CloudFormation, which documents email as the default. Terraform requires the argument, so unset there is not reported. `DomainValidationOptions` does not change it.
  - CF-ACM-002 (Medium, Security Hub ACM.2): literal `KeyAlgorithm: RSA_1024`. `RSA_2048` and `EC_*` are not reported.
  - CF-ACM-003 (Low): literal `CertificateTransparencyLoggingPreference: DISABLED` (Terraform `options` block).
- **Global Accelerator** (`AWS::GlobalAccelerator::EndpointGroup`; Terraform `aws_globalaccelerator_endpoint_group`):
  - CF-GA-001 (Low): none of `HealthCheckProtocol`, `HealthCheckPath` or `HealthCheckPort` set on a group with an EC2 instance or Elastic IP endpoint. AWS has defaults, so this is advice. A group with only load balancers, or endpoints the scan cannot read, is not judged: a load balancer's own health checks decide.
- **App Runner** (`AWS::AppRunner::Service`; Terraform `aws_apprunner_service`):
  - CF-APPRUNNER-001 (Low): `ObservabilityConfiguration` unset, or `ObservabilityEnabled` literally false. A value from a parameter, a variable or a dynamic block is not judged.
- **Elastic Beanstalk** (`AWS::ElasticBeanstalk::Environment`, `AWS::ElasticBeanstalk::ConfigurationTemplate`; Terraform `aws_elastic_beanstalk_environment`, `aws_elastic_beanstalk_configuration_template`). Reads `OptionSettings` (Terraform `setting` blocks) over those of a configuration template in this scan that `TemplateName` (`template_name`) points at. An environment is not judged at all when its settings come from a parameter or a dynamic block, when an entry's namespace or name cannot be read, or when its template is outside the scan, cannot be read, or copies a `SourceConfiguration` or `EnvironmentId`. One option's unknown value leaves only that option unjudged. A value set in `.ebextensions` in the source bundle is not read, so an environment that sets one there is still reported:
  - CF-BEANSTALK-001 (Low, Security Hub ElasticBeanstalk.1): `SystemType` in `aws:elasticbeanstalk:healthreporting:system` not `enhanced`. Unset is reported: the documented default is `basic`.
  - CF-BEANSTALK-002 (Low, Security Hub ElasticBeanstalk.2): `ManagedActionsEnabled` in `aws:elasticbeanstalk:managedactions` unset, which means false, or false.
  - CF-BEANSTALK-003 (Low, Security Hub ElasticBeanstalk.3): `StreamLogs` in `aws:elasticbeanstalk:cloudwatch:logs` unset, which means false, or false.
- **Kinesis**: CF-KIN-001 (no `StreamEncryption`, Medium; Terraform `encryption_type` defaults to `NONE`)
- **ElastiCache** (`AWS::ElastiCache::ReplicationGroup`): CF-EC-001 (not encrypted at rest, Medium; Redis OSS defaults to off, Valkey to on, so an unset value on Valkey is not reported), CF-EC-002 (`TransitEncryptionEnabled` not true, Medium), CF-EC-003 (Medium, Security Hub ElastiCache.3: `AutomaticFailoverEnabled` or `MultiAZEnabled` not true; not reported in dev or staging stacks; in V2 it replaces REL-016), CF-EC-006 (Medium, ElastiCache.6: Redis OSS below 6 with no `AuthToken`; an unset `EngineVersion` is not judged). On replication groups and `AWS::ElastiCache::CacheCluster` (`aws_elasticache_cluster`): CF-EC-004 (Low, ElastiCache.1: Redis OSS or Valkey with `SnapshotRetentionLimit` 0 or unset), CF-EC-005 (Low, ElastiCache.2: Redis OSS or Valkey with `AutoMinorVersionUpgrade: false`), CF-EC-007 (Low, ElastiCache.7: `CacheSubnetGroupName` unset or `default`). A Terraform cluster in a replication group takes these from the group, and the template does not show what an existing `PrimaryClusterId` already has, so neither is judged for them or for CF-EC-006
- **OpenSearch** (`AWS::OpenSearchService::Domain`): CF-OS-001 (`EncryptionAtRestOptions.Enabled` not true, Medium), CF-OS-002 (`NodeToNodeEncryptionOptions.Enabled` not true, Medium); both are off by default
- **Redshift**: CF-RS-001 (explicit `Encrypted: false`, Low). New provisioned clusters are encrypted by default since 2025, so an unset value is not reported
- **DocumentDB / Neptune**: CF-DOCDB-001, CF-NEP-001 (`StorageEncrypted` not true, Medium); a cluster restored from a snapshot or another cluster inherits its encryption and is not reported
- **MSK**: CF-MSK-001 (`EncryptionInTransit.ClientBroker` is `PLAINTEXT` or `TLS_PLAINTEXT`, or `InCluster` is false, Medium). Data at rest is always encrypted, and TLS / `InCluster: true` are the defaults, so an unset value is not reported
- **API Gateway**: CF-APIGW-001 (REST access logging), CF-APIGW-002 (REST X-Ray), CF-APIGW-V2-001 (HTTP API access logging), CF-APIGW-V2-002 (HTTP API X-Ray)
- **API Gateway auth, TLS, throttling and caching** (`AWS::ApiGateway::RestApi`, `Method`, `Stage`, `DomainName`, `UsagePlan`, `AWS::ApiGatewayV2::Route`, `Stage`, `DomainName`; Terraform `aws_api_gateway_*` with `aws_api_gateway_method_settings` merged into its stage, and `aws_apigatewayv2_*`):
  - CF-APIGW-003 (High): a method other than `OPTIONS` with `AuthorizationType: NONE` (the default) and no API key required. CF-APIGW-V2-003 (High, Security Hub APIGateway.8): the same on an HTTP API route, or on a WebSocket `$connect` route; other WebSocket routes cannot have an authorizer. In V2 both replace SEC-009
  - CF-APIGW-004 (Medium): TLS 1.0 allowed. Regional and edge REST APIs default to `TLS_1_0` on their execute-api endpoint, so a REST API with no `SecurityPolicy` is reported unless it is private or its default endpoint is disabled; Terraform reports only an explicit `TLS_1_0`. Custom domains default to `TLS_1_2`, so only an explicit `TLS_1_0` is reported. In V2 it replaces SEC-010
  - CF-APIGW-005 (Low): a REST stage with no throttling in `MethodSettings` and no usage plan with a throttle; a usage plan the scan cannot tie to an API counts. CF-APIGW-V2-004 (Low): an HTTP or WebSocket stage with no `DefaultRouteSettings` throttling. In V2 both replace REL-006
  - CF-APIGW-006 (Low): a `POST`, `PUT`, `PATCH` or `ANY` method with no `RequestValidatorId`. In V2 it replaces REL-028
  - CF-APIGW-007 (Medium, Security Hub APIGateway.5): a method setting with caching on and `CacheDataEncrypted` not true
  - CF-APIGW-008 (Low): a stage with no cache cluster on an API that has `GET` methods. In V2 it replaces PERF-004
  - CF-APIGW-009 (Low, Security Hub APIGateway.2): a REST stage with no `ClientCertificateId`
  - Terraform method settings that point at no stage the scan can find make the stage checks that read them report nothing
- **CodeBuild** (`AWS::CodeBuild::Project`, `aws_codebuild_project`). Findings name a variable, never a value or a URL:
  - CF-CB-001 (High, Security Hub CodeBuild.2): a `PLAINTEXT` environment variable (the default type) with a secret-like name and a literal value, an AWS access key id as its value, or named `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY` whatever the value
  - CF-CB-002 (High, Security Hub CodeBuild.1): a primary or secondary source location with `user:secret@` or a bare token in its URL. The control names Bitbucket; this check reads any provider
  - CF-CB-003 (Medium): `PrivilegedMode: true`. Security Hub no longer lists a control for this. In V2 it replaces SEC-053
  - CF-CB-004 (Low, Security Hub CodeBuild.4): CloudWatch logs explicitly `DISABLED` and S3 logs not `ENABLED`. CloudWatch logs are on by default, so a project with no `LogsConfig` is not reported. In V2 it replaces OPS-020
  - CF-CB-005 (Low, Security Hub CodeBuild.3): S3 logs `ENABLED` with `EncryptionDisabled: true`
- **CodePipeline** (`AWS::CodePipeline::Pipeline`, `aws_codepipeline`):
  - CF-CP-001 (Low): an artifact store (`ArtifactStore` or an `ArtifactStores` entry) with no `EncryptionKey`. In V2 it replaces SEC-052
  - CF-CP-002 (Low): a `Deploy` action in a stage named for production with no `Approval` action in an earlier stage or `RunOrder`; in a pipeline named for production with no such stage, the last `Deploy` action. Production words are whole words (prod, production, prd, live), so `product-api` does not count. In V2 it replaces REL-021
  - CF-CP-003 (Low): no `AWS::CodeStarNotifications::NotificationRule` or EventBridge rule (`source: aws.codepipeline`) for the pipeline; a rule the scan cannot tie to a resource counts, unless it is for CodeBuild. In V2 it replaces OPS-017
- **KMS rotation and deletion window** (`AWS::KMS::Key`, `aws_kms_key`):
  - CF-KMS-002 (Medium, Security Hub KMS.4): `EnableKeyRotation` not true on a symmetric key with AWS KMS key material. Rotation does not exist for asymmetric, HMAC, `EXTERNAL` or custom key store keys, so they are not reported. In V2 it replaces SEC-023
  - CF-KMS-003 (Low): `PendingWindowInDays` (Terraform `deletion_window_in_days`) below 30 on a key that a data store or `SecureString` parameter in the same template refers to. A key used through an alias is not tied to its data store
- **SSM parameters** (`AWS::SSM::Parameter`, `aws_ssm_parameter`):
  - CF-SSM-001 (Medium): type `String` and a name that looks like a secret, read from the last part of `Name`, or the logical id or Terraform label when `Name` cannot be read. A value that cannot be the secret is not reported: an ARN, a flag, a number, or a reference to a resource in the template. A value from a template parameter or a Terraform variable is reported, because a `String` parameter stores it in plain text. Findings never quote the value. In V2 it replaces SEC-033
  - CF-SSM-002 (Low): `Tier: Advanced` with a literal value under 4 KB, no parameter policy, and a data type the standard tier supports. A parameter shared across accounts needs this tier, and the scan cannot see that, so the finding says so
- **OpenSearch access and resilience** (`AWS::OpenSearchService::Domain`, `aws_opensearch_domain`):
  - CF-OS-003 (Medium, Security Hub Opensearch.2): no `VPCOptions`. In V2 it replaces SEC-041
  - CF-OS-004 (Medium, Security Hub Opensearch.7): `AdvancedSecurityOptions.Enabled` not true. In V2 it replaces SEC-040
  - CF-OS-005 (Medium, Security Hub Opensearch.8): `EnforceHTTPS` not true, or a `TLSSecurityPolicy` that allows TLS 1.0. Security Hub also wants the latest policy, so `Policy-Min-TLS-1-2-2019-07` passes here and fails the control. An unset policy is not reported. In a Terraform `domain_endpoint_options` block `enforce_https` defaults to true
  - CF-OS-006 (Low, Security Hub Opensearch.4 and Opensearch.5): `ES_APPLICATION_LOGS` or `AUDIT_LOGS` not in `LogPublishingOptions`, or turned off
  - CF-OS-007 (Low, Security Hub Opensearch.6): fewer than three data nodes, or `ZoneAwarenessEnabled` not true. Not reported in dev or staging stacks
- **MSK access** (`AWS::MSK::Cluster`, `aws_msk_cluster`):
  - CF-MSK-002 (Medium, Security Hub MSK.6): `Unauthenticated` on, even alongside another method, or no method that identifies a client on, including no `ClientAuthentication` at all. In V2 it replaces SEC-045
  - CF-MSK-003 (High, Security Hub MSK.4): `PublicAccess.Type` is `SERVICE_PROVIDED_EIPS`
- **Kinesis retention** (`AWS::Kinesis::Stream`, `aws_kinesis_stream`): CF-KIN-002 (Low): 24-hour retention, the default, on a stream that a Lambda event source mapping, stream consumer, Firehose delivery stream or Managed Flink application in the same template refers to. In V2 it replaces REL-019
- **Redshift beyond encryption** (`AWS::Redshift::Cluster`, `aws_redshift_cluster`, `aws_redshift_logging`):
  - CF-RS-002 (High, Security Hub Redshift.1): `PubliclyAccessible: true`
  - CF-RS-003 (Medium, Security Hub Redshift.3): `AutomatedSnapshotRetentionPeriod` is 0. Security Hub also fails anything under 7 days, including the default of 1, which passes here
  - CF-RS-004 (Low, Security Hub Redshift.4): no `LoggingProperties` and no `aws_redshift_logging` for the cluster; one the scan cannot tie to a cluster counts
  - CF-RS-005 (Low, Security Hub Redshift.6): `AllowVersionUpgrade: false`. It is on by default
  - CF-RS-006 (Low, Security Hub Redshift.7): `EnhancedVpcRouting` not true
  - CF-RS-008 (Medium, Security Hub Redshift.2): no `ClusterParameterGroupName` (Terraform `cluster_parameter_group_name`), so the default parameter group applies and `require_ssl` is false. A named group is not read
  - CF-RS-007 (Low, Security Hub Redshift.8 for the admin user): admin user `awsuser` or database `dev`, which is also Terraform's default. A cluster restored from a snapshot is not reported
- **DocumentDB beyond encryption** (`AWS::DocDB::DBCluster`, `aws_docdb_cluster`): CF-DOCDB-002 (Low, Security Hub DocumentDB.2): `BackupRetentionPeriod` under 7; the default is 1, and an unset value on a restored cluster is not reported. CF-DOCDB-003 (Low, Security Hub DocumentDB.4): `audit` not in `EnableCloudwatchLogsExports`. CF-DOCDB-004 (Low, Security Hub DocumentDB.5): `DeletionProtection` not true; not reported in dev stacks
- **Neptune beyond encryption** (`AWS::Neptune::DBCluster`, `aws_neptune_cluster`): CF-NEP-002 (Low, Security Hub Neptune.2): `audit` not in `EnableCloudwatchLogsExports`. CF-NEP-003 (Low, Security Hub Neptune.4): `DeletionProtection` not true; not reported in dev stacks. CF-NEP-004 (Low, Security Hub Neptune.5): `BackupRetentionPeriod` under 7; the default is 1, and an unset value on a restored cluster is not reported. CF-NEP-005 (Low, Security Hub Neptune.7): `IamAuthEnabled` not true
- **AWS Backup** (`AWS::Backup::BackupVault`, `BackupPlan`, `BackupSelection`; Terraform `aws_backup_vault`, `aws_backup_vault_lock_configuration`, `aws_backup_plan`, `aws_backup_selection`). A value from a parameter or variable is not judged. In V2, CF-BAK-001, CF-BAK-002 and CF-BAK-005 replace SEC-063, REL-014 and REL-013:
  - CF-BAK-001 (Low): vault with no `EncryptionKeyArn`, so it uses the AWS managed key
  - CF-BAK-002 (Low): plan rule with no `CopyActions` to another Region. A copy to a vault in the same template, or to an ARN in the stack's Region, stays in the Region. A literal ARN is compared only when the scan knows the stack's Region, and a Terraform reference is not judged, because its provider may be in another Region
  - CF-BAK-003 (Low): plan rule with `Lifecycle.DeleteAfterDays` below 7. Unset keeps recovery points forever and is not reported
  - CF-BAK-004 (Low): vault with no `LockConfiguration` or `aws_backup_vault_lock_configuration` in a stack marked prod. A stack whose environment is unknown is not reported
  - CF-BAK-005 (Low): RDS, DynamoDB, EFS, EBS or FSx resource that no selection in the template selects, by ARN or tag. With no plan or selection in the template, one finding per stack. A selection is read for `Resources`, `ListOfTags` and `Conditions.StringEquals`. A wildcard or literal ARN of the resource's service, or a tag the scan cannot read, counts as selected. An Aurora member and a read replica are not reported
- **Step Functions** (`AWS::StepFunctions::StateMachine`, `aws_sfn_state_machine`):
  - CF-SFN-001 (Low): a `Task` state with no `Retry`, including inside `Parallel` and `Map` states, or a top-level last task with no `Catch` (it ends the workflow, or goes to a `Succeed` state). Read from `Definition`, `DefinitionString` (literal, `Fn::Sub` or `Fn::Join`, as CDK synth writes it) and `DefinitionS3Location` when it is a local path under the template's folder. Terraform: `jsonencode(...)`, JSON strings and heredocs. A definition in S3, or from `file()` or `templatefile()`, is not judged
  - CF-SFN-002 (Low): `TracingConfiguration.Enabled` not true
  - CF-SFN-003 (Medium, Security Hub StepFunctions.1): no `LoggingConfiguration`, or `Level: OFF`
- **EventBridge rule targets** (`AWS::Events::Rule` `Targets`, `aws_cloudwatch_event_target`): CF-EB-001 (Low): no `DeadLetterConfig`. CF-EB-002 (Low): no `RetryPolicy`, or `MaximumRetryAttempts` 0. A policy that sets only `MaximumEventAgeInSeconds` is not reported. Event bus policies open to anyone are CF-RP-001
- **Athena workgroups** (`AWS::Athena::WorkGroup`, `aws_athena_workgroup`):
  - CF-ATH-001 (Medium): no `ResultConfiguration.EncryptionConfiguration` in `WorkGroupConfiguration`. A value from a parameter or variable is not judged, and neither is a workgroup with the older `WorkGroupConfigurationUpdates`, Athena-managed query results, or a Spark engine. In V2 it replaces SEC-042
  - CF-ATH-002 (Low): `EnforceWorkGroupConfiguration` literally false. Unset is not reported
- **Glue jobs and security configurations** (`AWS::Glue::Job`, `AWS::Glue::SecurityConfiguration`; Terraform `aws_glue_job`, `aws_glue_security_configuration`):
  - CF-GLUE-001 (Medium): a job with no `SecurityConfiguration`, or a security configuration with S3, CloudWatch or bookmark encryption disabled or unset. It reports on the security configuration, so a job that names one is not reported, whether or not the scan can find it. In V2 it replaces SEC-043
  - CF-GLUE-002 (Low): a `glueetl` or `gluestreaming` job with no `--enable-metrics` in `DefaultArguments` or `NonOverridableArguments`. A map or job type from a parameter or variable is not judged, and neither is another job type, or a job with no `Command.Name` in CloudFormation. Arguments set when the job starts cannot be seen. In V2 it replaces OPS-015
  - CF-GLUE-003 (Low): a `glueetl` job with `--job-bookmark-option` literally `job-bookmark-disable`. A template does not show whether a job is incremental, and bookmarks are off by default, so unset is not reported and the finding is advice. Other job types are not reported, because streaming jobs use checkpoints and Python shell jobs have no bookmarks. In V2 it replaces OPS-019 when it reports; a job with the option unset keeps OPS-019
- **Firehose delivery streams** (`AWS::KinesisFirehose::DeliveryStream`, `aws_kinesis_firehose_delivery_stream`): CF-FH-001 (Medium, Security Hub DataFirehose.1): a direct-put stream, with `DeliveryStreamType` unset or `DirectPut`, and no `DeliveryStreamEncryptionConfigurationInput`, or `server_side_encryption` not enabled. A stream with a source takes its encryption from the source, so it is not judged, and neither is a value from a parameter or variable
- **EMR clusters and security configurations** (`AWS::EMR::Cluster`, `AWS::EMR::SecurityConfiguration`; Terraform `aws_emr_cluster`, `aws_emr_security_configuration`):
  - CF-EMR-001 (High, Security Hub EMR.1): `Instances.Ec2SubnetId` (Terraform `ec2_attributes.subnet_id`) names a subnet in this template with `MapPublicIpOnLaunch` (`map_public_ip_on_launch`) literally true. A template shows the subnet, not the node's address, so this is narrower than the control. A subnet from a parameter, a variable or outside the template is not judged, and neither is `Ec2SubnetIds`
  - CF-EMR-002 (Medium, Security Hub EMR.3): a security configuration with `EncryptionConfiguration.EnableAtRestEncryption` false or unset, or a cluster with no `SecurityConfiguration`. That cluster has no encryption in transit either, and is reported once, here. A cluster that names a configuration is not judged on it: each configuration is judged on itself. A document the scan cannot parse, such as one from `file()` or a variable, is not judged
  - CF-EMR-003 (Medium, Security Hub EMR.4): a security configuration with `EncryptionConfiguration.EnableInTransitEncryption` false or unset, with the same limits
- **DMS replication instances and endpoints** (`AWS::DMS::ReplicationInstance`, `AWS::DMS::Endpoint`; Terraform `aws_dms_replication_instance`, `aws_dms_endpoint`):
  - CF-DMS-001 (High, Security Hub DMS.1): `PubliclyAccessible` true. Unset also reports in CloudFormation, where the default is true, but not in Terraform, where the provider sends false
  - CF-DMS-002 (Low, Security Hub DMS.6): `AutoMinorVersionUpgrade` false. Unset also reports in Terraform, where the provider sends false, but not in CloudFormation, where the default is true
  - CF-DMS-003 (Medium, Security Hub DMS.9): `SslMode` none or unset on `aurora`, `aurora-postgresql`, `db2`, `docdb`, `mariadb`, `mysql`, `oracle`, `postgres` or `sqlserver`. Other engines are not judged, and neither is an engine from a parameter or variable. An unset mode is not judged when the endpoint has a Secrets Manager secret, a certificate, extra connection attributes or settings the scan cannot read
  - CF-DMS-004 (Low, Security Hub DMS.13): `MultiAZ` false or unset on an instance in a prod stack. Other environments are not reported. For these DMS checks, a value from a parameter or variable is not judged
- **Auto Scaling**: CF-SUST-001 (no Spot / mixed instances)
- **Auto Scaling groups and launch configurations** (`AWS::AutoScaling::AutoScalingGroup`, `LaunchConfiguration`, `ScalingPolicy`, `ScheduledAction`; Terraform `aws_autoscaling_group`, `aws_launch_configuration`, `aws_autoscaling_policy`, `aws_autoscaling_schedule`, `aws_autoscaling_attachment`):
  - CF-ASG-001 (Low, Security Hub AutoScaling.1): a group with `HealthCheckType` unset or without `ELB`, and a non-empty `TargetGroupARNs` or `LoadBalancerNames`, or an `aws_autoscaling_attachment` tied to it. A list from a parameter or variable is not judged, and neither is `TrafficSources` or an attachment that cannot be tied to the group
  - CF-ASG-002 (Medium, Security Hub AutoScaling.2): a group known to be in one AZ: one literal `AvailabilityZones` entry, `VPCZoneIdentifier` with one literal subnet or one reference to a subnet, or several subnets in this template that are all in one AZ. A list from a parameter or variable, and a single entry that may hold several (a parameter, a variable, an import, a join, a function call, a comma-separated literal), are not judged. Skipped in dev and staging
  - CF-ASG-003 (High, Security Hub AutoScaling.3): a launch configuration with `MetadataOptions.HttpTokens` unset or `optional`, read as CF-EC2-001 reads it. `HttpEndpoint: disabled` is not reported
  - CF-ASG-004 (Medium, Security Hub AutoScaling.5): a launch configuration with `AssociatePublicIpAddress: true`. Unset depends on the subnet, so it is not reported
  - CF-ASG-005 (Low, Security Hub AutoScaling.9): a group whose `LaunchConfigurationName` is a literal or a launch configuration in this template. A parameter or variable is not judged
  - CF-ASG-006 (Low): a group with `MinSize` equal to `MaxSize`, above 0, and no scaling policy or scheduled action. One that cannot be tied to a group counts for all of them. A fixed fleet can be intended, so the finding is advice. In V2 COST-002 stays, because it reports ECS services with no Auto Scaling at all
- **ECS**: CF-SUST-002 (Fargate without FARGATE_SPOT)
- **EC2**: CF-EC2-001 (IMDSv2 not required on an instance or launch template: High when `HttpTokens: optional`, Medium when unset because the default then depends on the AMI), CF-PERF-004 (large instance right-sizing)
- **Launch Template**: CF-SUST-003 (no Spot when no ASG in template)
- **EKS**: CF-EKS-001 (control plane logging not enabled), CF-EKS-002 (API endpoint public to `0.0.0.0/0` or `::/0`; unset `EndpointPublicAccess` and `PublicAccessCidrs` count as public, the AWS default), CF-EKS-003 (no customer-managed KMS key for secrets: Medium below Kubernetes 1.28, Low from 1.28, where EKS already encrypts Kubernetes API data with an AWS-owned key), CF-EKS-004 (Medium, Security Hub EKS.2: `Version` past the end of standard support; dates in `rules/data/eks_versions.json`; a version newer than the list, unset or not literal is not judged)
- **Template-level**: CF-PERF-002 (consider caching when API/Lambda, no CloudFront/ElastiCache), CF-COST-002 (NAT Gateway cost hint)

## By pillar (AWS Well-Architected 6 pillars)

| Pillar | CF rule IDs |
|--------|-------------|
| Operational Excellence | CF-CFG-001, CF-ALARM-001, CF-ALARM-002, CF-ALARM-003, CF-DASH-001, CF-CT-004, CF-S3-004, CF-RDS-007, CF-RDS-010, CF-RDS-011, CF-CT-001, CF-CT-002, CF-FL-001, CF-EKS-001, CF-TGW-002, CF-CB-004, CF-CP-003, CF-OS-006, CF-RS-004, CF-DOCDB-003, CF-NEP-002, CF-SFN-002, CF-SFN-003, CF-EB-001, CF-ECS-008, CF-ECS-010, CF-ASG-005, CF-GLUE-002, CF-GLUE-003, CF-S3-011, CF-CF-005, CF-FSX-002, CF-PATCH-001 |
| Security | CF-GD-001, CF-SH-001, CF-MACIE-001, CF-CT-005, CF-S3-001, CF-S3-002, CF-S3-005, CF-RDS-001, CF-RDS-004, CF-APIGW-003, CF-APIGW-004, CF-APIGW-007, CF-APIGW-009, CF-APIGW-V2-003, CF-LAM-004, CF-LAM-005, CF-RDS-006, CF-RDS-008, CF-RDS-009, CF-RDS-012, CF-RDS-013, CF-CT-003, CF-KMS-001, CF-RP-001, CF-EC2-001, CF-EKS-002, CF-EKS-003, CF-IAM-001, CF-IAM-002, CF-IAM-003, CF-IAM-004, CF-IAM-005, CF-IAM-006, CF-IAM-007, CF-IAM-008, CF-IAM-009, CF-IAM-010, CF-IAM-011, CF-ALB-002, CF-ALB-003, CF-NLB-001, CF-ALB-004, CF-ALB-006, CF-CLB-001, CF-CLB-002, CF-SG-001, CF-SG-002, CF-SG-003, CF-NACL-001, CF-TGW-001, CF-CW-002, CF-SQS-001, CF-DDB-002, CF-LAM-003, CF-SNS-001, CF-EBS-001, CF-EFS-001, CF-KIN-001, CF-EC-001, CF-EC-002, CF-OS-001, CF-OS-002, CF-RS-001, CF-DOCDB-001, CF-NEP-001, CF-MSK-001, CF-CF-001, CF-CF-002, CF-CF-003, CF-CF-004, CF-WAF-001, CF-EC2-002, CF-EC2-003, CF-PAR-001, CF-PAR-002, CF-ECR-001, CF-ECR-002, CF-ECR-003, CF-ECS-001, CF-ECS-002, CF-ECS-003, CF-SM-001, CF-COG-001, CF-COG-002, CF-COG-003, CF-CB-001, CF-CB-002, CF-CB-003, CF-CB-005, CF-CP-001, CF-KMS-002, CF-SSM-001, CF-OS-003, CF-OS-004, CF-OS-005, CF-MSK-002, CF-MSK-003, CF-RS-002, CF-RS-005, CF-RS-006, CF-RS-007, CF-RS-008, CF-NEP-005, CF-BAK-001, CF-EC-005, CF-EC-006, CF-EC-007, CF-EFS-004, CF-EFS-005, CF-ECS-004, CF-ECS-005, CF-ECS-006, CF-ECS-007, CF-ECS-009, CF-EKS-004, CF-ASG-003, CF-ASG-004, CF-ATH-001, CF-ATH-002, CF-GLUE-001, CF-FH-001, CF-EMR-001, CF-EMR-002, CF-EMR-003, CF-DMS-001, CF-DMS-002, CF-DMS-003, CF-S3-008, CF-S3-009, CF-CF-008, CF-CF-010, CF-CF-011, CF-SAGE-001, CF-SAGE-002, CF-SAGE-003, CF-SAGE-004, CF-FSX-001, CF-APPSYNC-001, CF-APPSYNC-002, CF-APPSYNC-003, CF-TRANSFER-001, CF-TRANSFER-002, CF-TRANSFER-003, CF-BEANSTALK-002, CF-R53-001, CF-R53-002, CF-ACM-002, CF-ACM-003 |
| Reliability | CF-S3-003, CF-RDS-002, CF-RDS-003, CF-RDS-005, CF-LAM-001, CF-LAM-006, CF-LAM-007, CF-LAM-008, CF-LAM-009, CF-APIGW-005, CF-APIGW-006, CF-APIGW-V2-004, CF-DDB-001, CF-SQS-002, CF-DEL-001, CF-NAT-001, CF-ALB-005, CF-ALB-007, CF-CLB-004, CF-CLB-005, CF-CP-002, CF-KMS-003, CF-OS-007, CF-KIN-002, CF-RS-003, CF-DOCDB-002, CF-DOCDB-004, CF-NEP-003, CF-NEP-004, CF-SFN-001, CF-EB-002, CF-SQS-003, CF-BAK-002, CF-BAK-003, CF-BAK-004, CF-BAK-005, CF-DDB-004, CF-DDB-005, CF-EC-003, CF-EC-004, CF-EFS-002, CF-ASG-001, CF-ASG-002, CF-DMS-004, CF-S3-010, CF-CF-009, CF-SAGE-005, CF-FSX-003, CF-R53-003, CF-ACM-001, CF-GA-001, CF-VPC-004, CF-VPC-005, CF-VPC-006 |
| Performance Efficiency | CF-APIGW-008, CF-PERF-001, CF-PERF-002, CF-PERF-003, CF-PERF-004, CF-ECS-011, CF-CF-013, CF-APPSYNC-004 |
| Cost Optimization | CF-BUDGET-001, CF-CW-001, CF-RDS-014, CF-COST-002, CF-EBS-002, CF-EIP-001, CF-TAG-001, CF-ENV-001, CF-ENV-002, CF-ENV-003, CF-ENV-004, CF-ENV-005, CF-ENV-006, CF-GEN-001, CF-S3-006, CF-S3-007, CF-DDB-003, CF-VPC-002, CF-VPC-003, CF-SSM-002, CF-EFS-003, CF-ASG-006, CF-S3-012, CF-CF-006, CF-CF-012 |
| Sustainability | CF-SUST-001, CF-SUST-002, CF-SUST-003, CF-CF-007 |
| Observability (reported under Operational Excellence) | CF-ALB-001, CF-CLB-003, CF-LAM-002, CF-APIGW-001, CF-APIGW-002, CF-APIGW-V2-001, CF-APIGW-V2-002, CF-APPRUNNER-001, CF-BEANSTALK-001, CF-BEANSTALK-003 |
| Best Practices | CF-VPC-001 |

## See also

- [REFERENCE.md](REFERENCE.md) — CLI options. Static and CloudFormation rule IDs are listed above.
- [CONFIG.md](CONFIG.md) — `templates` and `no_synth` config keys for V2.
- [COVERAGE.md](COVERAGE.md) — which CDK rules and FSBP controls have a template check.

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

## Themes

Every rule has one or more themes, which cut across pillars: `finops`, `security-baseline`, `identity`, `data-protection`, `network-exposure`, `resilience`, `observability`, `sustainability`. `--theme finops` (repeatable, or comma-separated; config `themes`) limits a scan to those themes. JSON findings carry `themes`. SARIF carries them as result `properties.themes` and rule `properties.tags`. `--group-by theme` (config `group_by`) groups Markdown findings by theme; a finding in two themes is listed under both. The HTML report has a theme filter next to the severity tabs, and the Markdown and JSON summary add one line per theme. CDK source rules declare their themes in their class; template checks declare them in `CF_THEMES` in `rules/cf_template.py`.

<!-- themes:start -->
| Rule | Themes |
|------|--------|
| CF-ACM-001 | resilience |
| CF-ACM-002 | data-protection |
| CF-ACM-003 | security-baseline |
| CF-ALARM-001 | observability |
| CF-ALARM-002 | observability |
| CF-ALARM-003 | observability |
| CF-ALB-001 | observability |
| CF-ALB-002 | data-protection, network-exposure |
| CF-ALB-003 | data-protection, network-exposure |
| CF-ALB-004 | network-exposure |
| CF-ALB-005 | resilience |
| CF-ALB-006 | network-exposure |
| CF-ALB-007 | resilience |
| CF-APIGW-001 | observability |
| CF-APIGW-002 | observability |
| CF-APIGW-003 | identity, network-exposure |
| CF-APIGW-004 | data-protection, network-exposure |
| CF-APIGW-005 | resilience |
| CF-APIGW-006 | resilience |
| CF-APIGW-007 | data-protection |
| CF-APIGW-008 | finops |
| CF-APIGW-009 | identity |
| CF-APIGW-V2-001 | observability |
| CF-APIGW-V2-002 | observability |
| CF-APIGW-V2-003 | identity, network-exposure |
| CF-APIGW-V2-004 | resilience |
| CF-APPRUNNER-001 | observability |
| CF-APPSYNC-001 | observability, security-baseline |
| CF-APPSYNC-002 | identity |
| CF-APPSYNC-003 | network-exposure |
| CF-APPSYNC-004 | resilience |
| CF-ASG-001 | resilience |
| CF-ASG-002 | resilience |
| CF-ASG-003 | security-baseline, identity |
| CF-ASG-004 | network-exposure |
| CF-ASG-005 | security-baseline |
| CF-ASG-006 | finops |
| CF-ATH-001 | data-protection |
| CF-ATH-002 | data-protection |
| CF-BAK-001 | data-protection |
| CF-BAK-002 | resilience, data-protection |
| CF-BAK-003 | resilience, data-protection |
| CF-BAK-004 | data-protection, resilience |
| CF-BAK-005 | resilience, data-protection |
| CF-BEANSTALK-001 | observability |
| CF-BEANSTALK-002 | security-baseline |
| CF-BEANSTALK-003 | observability |
| CF-BUDGET-001 | finops |
| CF-CB-001 | data-protection, identity |
| CF-CB-002 | data-protection, identity |
| CF-CB-003 | security-baseline |
| CF-CB-004 | observability |
| CF-CB-005 | observability, data-protection |
| CF-CF-001 | data-protection, network-exposure |
| CF-CF-002 | data-protection, network-exposure |
| CF-CF-003 | network-exposure |
| CF-CF-004 | network-exposure, identity |
| CF-CF-005 | observability |
| CF-CF-006 | finops |
| CF-CF-007 | sustainability, finops |
| CF-CF-008 | network-exposure |
| CF-CF-009 | resilience |
| CF-CF-010 | data-protection, network-exposure |
| CF-CF-011 | data-protection, network-exposure |
| CF-CF-012 | finops |
| CF-CF-013 | resilience |
| CF-CFG-001 | observability, security-baseline |
| CF-CLB-001 | data-protection, network-exposure |
| CF-CLB-002 | data-protection |
| CF-CLB-003 | observability |
| CF-CLB-004 | resilience |
| CF-CLB-005 | resilience |
| CF-COG-001 | identity |
| CF-COG-002 | identity |
| CF-COG-003 | identity |
| CF-COST-002 | finops |
| CF-CP-001 | data-protection |
| CF-CP-002 | resilience |
| CF-CP-003 | observability |
| CF-CT-001 | observability, security-baseline |
| CF-CT-002 | observability |
| CF-CT-003 | observability, data-protection |
| CF-CT-004 | observability, security-baseline |
| CF-CT-005 | observability, data-protection |
| CF-CW-001 | finops, data-protection |
| CF-CW-002 | data-protection |
| CF-DASH-001 | observability |
| CF-DDB-001 | resilience, data-protection |
| CF-DDB-002 | data-protection |
| CF-DDB-003 | finops, resilience |
| CF-DDB-004 | resilience, data-protection |
| CF-DDB-005 | resilience, data-protection |
| CF-DEL-001 | data-protection, resilience |
| CF-DMS-001 | network-exposure |
| CF-DMS-002 | security-baseline |
| CF-DMS-003 | data-protection |
| CF-DMS-004 | resilience |
| CF-DOCDB-001 | data-protection |
| CF-DOCDB-002 | resilience |
| CF-DOCDB-003 | observability |
| CF-DOCDB-004 | resilience, data-protection |
| CF-EB-001 | observability, resilience |
| CF-EB-002 | resilience |
| CF-EBS-001 | data-protection |
| CF-EBS-002 | finops |
| CF-EC-001 | data-protection |
| CF-EC-002 | data-protection |
| CF-EC-003 | resilience |
| CF-EC-004 | resilience, data-protection |
| CF-EC-005 | security-baseline |
| CF-EC-006 | identity |
| CF-EC-007 | network-exposure |
| CF-EC2-001 | security-baseline, identity |
| CF-EC2-002 | network-exposure |
| CF-EC2-003 | network-exposure |
| CF-ECR-001 | security-baseline |
| CF-ECR-002 | security-baseline |
| CF-ECR-003 | security-baseline, finops |
| CF-ECS-001 | security-baseline |
| CF-ECS-002 | security-baseline |
| CF-ECS-003 | security-baseline |
| CF-ECS-004 | security-baseline, network-exposure |
| CF-ECS-005 | network-exposure |
| CF-ECS-006 | security-baseline |
| CF-ECS-007 | data-protection, identity |
| CF-ECS-008 | observability |
| CF-ECS-009 | security-baseline |
| CF-ECS-010 | observability |
| CF-ECS-011 | finops |
| CF-EFS-001 | data-protection |
| CF-EFS-002 | resilience, data-protection |
| CF-EFS-003 | finops |
| CF-EFS-004 | data-protection, identity |
| CF-EFS-005 | identity |
| CF-EIP-001 | finops |
| CF-EKS-001 | observability |
| CF-EKS-002 | network-exposure |
| CF-EKS-003 | data-protection |
| CF-EKS-004 | security-baseline |
| CF-EMR-001 | network-exposure |
| CF-EMR-002 | data-protection |
| CF-EMR-003 | data-protection |
| CF-ENV-001 | finops |
| CF-ENV-002 | finops |
| CF-ENV-003 | finops |
| CF-ENV-004 | finops |
| CF-ENV-005 | finops |
| CF-ENV-006 | finops |
| CF-FH-001 | data-protection |
| CF-FL-001 | observability, network-exposure |
| CF-FSX-001 | data-protection |
| CF-FSX-002 | finops |
| CF-FSX-003 | resilience |
| CF-GA-001 | resilience |
| CF-GD-001 | security-baseline |
| CF-GEN-001 | finops, sustainability |
| CF-GLUE-001 | data-protection |
| CF-GLUE-002 | observability |
| CF-GLUE-003 | resilience |
| CF-IAM-001 | identity |
| CF-IAM-002 | identity |
| CF-IAM-003 | identity |
| CF-IAM-004 | identity |
| CF-IAM-005 | identity |
| CF-IAM-006 | identity |
| CF-IAM-007 | identity |
| CF-IAM-008 | identity |
| CF-IAM-009 | identity |
| CF-IAM-010 | identity |
| CF-IAM-011 | identity |
| CF-KIN-001 | data-protection |
| CF-KIN-002 | resilience |
| CF-KMS-001 | identity, data-protection |
| CF-KMS-002 | data-protection |
| CF-KMS-003 | resilience |
| CF-LAM-001 | resilience |
| CF-LAM-002 | observability |
| CF-LAM-003 | security-baseline |
| CF-LAM-004 | identity, network-exposure |
| CF-LAM-005 | data-protection, identity |
| CF-LAM-006 | resilience |
| CF-LAM-007 | resilience |
| CF-LAM-008 | resilience |
| CF-LAM-009 | resilience |
| CF-MACIE-001 | data-protection, security-baseline |
| CF-MSK-001 | data-protection |
| CF-MSK-002 | identity |
| CF-MSK-003 | network-exposure |
| CF-NACL-001 | network-exposure |
| CF-NAT-001 | resilience |
| CF-NEP-001 | data-protection |
| CF-NEP-002 | observability |
| CF-NEP-003 | resilience, data-protection |
| CF-NEP-004 | resilience |
| CF-NEP-005 | identity |
| CF-NLB-001 | data-protection, network-exposure |
| CF-OS-001 | data-protection |
| CF-OS-002 | data-protection |
| CF-OS-003 | network-exposure |
| CF-OS-004 | identity |
| CF-OS-005 | data-protection, network-exposure |
| CF-OS-006 | observability |
| CF-OS-007 | resilience |
| CF-PAR-001 | data-protection, identity |
| CF-PAR-002 | data-protection, identity |
| CF-PATCH-001 | security-baseline |
| CF-PERF-001 | finops, sustainability |
| CF-PERF-002 | resilience |
| CF-PERF-003 | finops |
| CF-PERF-004 | finops |
| CF-R53-001 | observability, security-baseline |
| CF-R53-002 | security-baseline |
| CF-R53-003 | resilience |
| CF-RDS-001 | data-protection |
| CF-RDS-002 | resilience, data-protection |
| CF-RDS-003 | resilience |
| CF-RDS-004 | network-exposure |
| CF-RDS-005 | resilience, data-protection |
| CF-RDS-006 | data-protection, network-exposure |
| CF-RDS-007 | observability |
| CF-RDS-008 | identity |
| CF-RDS-009 | security-baseline |
| CF-RDS-010 | finops |
| CF-RDS-011 | observability |
| CF-RDS-012 | network-exposure |
| CF-RDS-013 | identity |
| CF-RDS-014 | finops, sustainability |
| CF-RP-001 | identity, network-exposure |
| CF-RS-001 | data-protection |
| CF-RS-002 | network-exposure |
| CF-RS-003 | resilience |
| CF-RS-004 | observability |
| CF-RS-005 | security-baseline |
| CF-RS-006 | network-exposure |
| CF-RS-007 | security-baseline |
| CF-RS-008 | data-protection, network-exposure |
| CF-S3-001 | network-exposure, data-protection |
| CF-S3-002 | data-protection |
| CF-S3-003 | resilience, data-protection |
| CF-S3-004 | observability |
| CF-S3-005 | data-protection, network-exposure |
| CF-S3-006 | finops, data-protection |
| CF-S3-007 | finops |
| CF-S3-008 | data-protection |
| CF-S3-009 | network-exposure, data-protection |
| CF-S3-010 | resilience, data-protection |
| CF-S3-011 | observability, data-protection |
| CF-S3-012 | finops |
| CF-SAGE-001 | network-exposure |
| CF-SAGE-002 | network-exposure |
| CF-SAGE-003 | security-baseline, identity |
| CF-SAGE-004 | data-protection |
| CF-SAGE-005 | resilience |
| CF-SFN-001 | resilience |
| CF-SFN-002 | observability |
| CF-SFN-003 | observability |
| CF-SG-001 | network-exposure |
| CF-SG-002 | network-exposure |
| CF-SG-003 | network-exposure |
| CF-SH-001 | security-baseline |
| CF-SM-001 | data-protection, identity |
| CF-SNS-001 | data-protection |
| CF-SQS-001 | data-protection |
| CF-SQS-002 | resilience |
| CF-SQS-003 | resilience |
| CF-SSM-001 | data-protection |
| CF-SSM-002 | finops |
| CF-SUST-001 | sustainability, finops |
| CF-SUST-002 | sustainability, finops |
| CF-SUST-003 | sustainability, finops |
| CF-TAG-001 | finops |
| CF-TGW-001 | network-exposure, identity |
| CF-TGW-002 | observability, network-exposure |
| CF-TRANSFER-001 | data-protection |
| CF-TRANSFER-002 | observability, security-baseline |
| CF-TRANSFER-003 | network-exposure |
| CF-VPC-001 | network-exposure, finops |
| CF-VPC-002 | finops |
| CF-VPC-003 | finops |
| CF-VPC-004 | resilience |
| CF-VPC-005 | resilience |
| CF-VPC-006 | resilience |
| CF-WAF-001 | network-exposure |
| BP-001 | finops |
| BP-002 | data-protection, identity |
| BP-003 | observability |
| BP-004 | security-baseline |
| BP-005 | resilience |
| COST-001 | finops, data-protection |
| COST-002 | finops |
| COST-003 | finops |
| COST-004 | finops |
| COST-005 | finops |
| COST-006 | finops |
| COST-007 | finops |
| COST-008 | finops |
| COST-009 | finops |
| COST-010 | finops |
| COST-011 | finops |
| COST-012 | finops |
| COST-013 | finops |
| COST-014 | finops |
| COST-015 | finops |
| COST-016 | finops |
| COST-017 | finops |
| COST-018 | finops |
| OPS-001 | observability |
| OPS-002 | observability, network-exposure |
| OPS-003 | observability |
| OPS-004 | resilience |
| OPS-005 | observability |
| OPS-006 | observability |
| OPS-007 | observability |
| OPS-008 | observability |
| OPS-009 | observability |
| OPS-010 | observability |
| OPS-011 | observability |
| OPS-012 | observability |
| OPS-013 | observability, resilience |
| OPS-014 | observability |
| OPS-015 | observability |
| OPS-016 | observability |
| OPS-017 | observability |
| OPS-018 | observability |
| OPS-019 | resilience |
| OPS-020 | observability |
| OPS-021 | observability |
| OPS-022 | finops, observability |
| OPS-023 | resilience |
| OPS-025 | observability, data-protection |
| OPS-026 | security-baseline |
| OPS-027 | observability |
| PERF-001 | finops |
| PERF-002 | resilience |
| PERF-003 | finops |
| PERF-004 | resilience |
| PERF-005 | finops |
| PERF-006 | resilience |
| PERF-007 | finops |
| PERF-008 | finops |
| PERF-009 | resilience |
| PERF-010 | finops |
| PERF-011 | resilience |
| PERF-012 | resilience |
| PERF-013 | resilience |
| PERF-014 | resilience |
| PERF-015 | resilience |
| PERF-016 | finops |
| PERF-017 | resilience |
| PERF-018 | observability |
| PERF-019 | resilience |
| REL-001 | resilience |
| REL-002 | resilience, data-protection |
| REL-003 | resilience |
| REL-004 | resilience, data-protection |
| REL-005 | resilience, data-protection |
| REL-006 | resilience |
| REL-007 | resilience |
| REL-008 | resilience |
| REL-009 | resilience |
| REL-010 | resilience, network-exposure |
| REL-011 | resilience |
| REL-012 | resilience |
| REL-013 | resilience, data-protection |
| REL-014 | resilience, data-protection |
| REL-015 | resilience |
| REL-016 | resilience |
| REL-017 | resilience, data-protection |
| REL-018 | finops |
| REL-019 | resilience, data-protection |
| REL-020 | resilience |
| REL-021 | resilience |
| REL-022 | resilience |
| REL-023 | resilience |
| REL-024 | resilience |
| REL-025 | resilience |
| REL-026 | resilience, data-protection |
| REL-027 | resilience |
| REL-028 | resilience, security-baseline |
| REL-029 | resilience |
| REL-030 | resilience, data-protection |
| REL-031 | resilience, data-protection |
| REL-032 | resilience |
| REL-033 | resilience |
| REPO-001 | resilience |
| REPO-002 | resilience |
| REPO-003 | resilience |
| REPO-004 | security-baseline |
| REPO-005 | security-baseline |
| REPO-006 | security-baseline, identity |
| REPO-007 | security-baseline |
| REPO-008 | security-baseline |
| REPO-009 | security-baseline |
| REPO-010 | security-baseline |
| REPO-011 | security-baseline |
| REPO-012 | resilience |
| REPO-013 | resilience |
| REPO-014 | resilience |
| REPO-015 | resilience |
| REPO-016 | resilience |
| REPO-017 | resilience |
| REPO-018 | observability |
| REPO-019 | observability |
| REPO-020 | observability |
| REPO-021 | resilience |
| REPO-022 | resilience |
| REPO-023 | resilience |
| REPO-024 | resilience |
| REPO-025 | resilience |
| REPO-026 | resilience |
| REPO-027 | observability |
| REPO-028 | observability |
| REPO-029 | observability |
| REPO-030 | observability |
| REPO-031 | identity |
| REPO-032 | identity |
| REPO-033 | security-baseline |
| REPO-034 | network-exposure |
| REPO-035 | network-exposure |
| REPO-036 | network-exposure |
| REPO-037 | security-baseline |
| REPO-038 | security-baseline |
| REPO-039 | data-protection |
| REPO-040 | data-protection |
| REPO-041 | data-protection |
| REPO-042 | resilience |
| REPO-043 | resilience |
| REPO-044 | resilience |
| REPO-045 | observability |
| REPO-046 | observability |
| REPO-047 | observability |
| REPO-048 | observability |
| REPO-049 | resilience |
| REPO-050 | resilience |
| REPO-051 | resilience |
| REPO-052 | resilience |
| REPO-053 | resilience |
| REPO-054 | resilience |
| REPO-055 | resilience |
| REPO-056 | resilience |
| REPO-057 | resilience |
| REPO-058 | resilience |
| REPO-059 | observability |
| REPO-060 | observability |
| REPO-061 | finops |
| REPO-062 | finops |
| REPO-063 | resilience |
| REPO-064 | observability |
| REPO-065 | observability |
| REPO-066 | resilience |
| REPO-067 | resilience |
| REPO-068 | network-exposure |
| REPO-069 | finops |
| REPO-070 | finops |
| REPO-071 | finops |
| REPO-072 | finops |
| REPO-073 | finops |
| REPO-074 | finops |
| REPO-075 | finops |
| REPO-076 | finops |
| REPO-077 | finops |
| REPO-078 | finops |
| REPO-079 | finops |
| REPO-080 | finops |
| REPO-081 | finops |
| REPO-082 | finops |
| REPO-083 | finops |
| REPO-084 | identity |
| REPO-085 | finops |
| REPO-086 | finops |
| REPO-087 | finops |
| REPO-088 | finops |
| REPO-089 | finops |
| REPO-090 | finops |
| REPO-091 | finops |
| REPO-092 | finops |
| REPO-093 | finops |
| REPO-094 | finops |
| REPO-095 | finops |
| REPO-096 | finops |
| REPO-097 | finops |
| REPO-098 | sustainability, finops |
| REPO-099 | sustainability, finops |
| REPO-100 | sustainability, finops |
| REPO-101 | sustainability, finops |
| REPO-102 | sustainability, finops |
| REPO-103 | sustainability, finops |
| REPO-104 | sustainability, finops |
| REPO-105 | sustainability, finops |
| REPO-106 | sustainability, finops |
| REPO-107 | resilience |
| REPO-108 | resilience |
| REPO-109 | observability |
| REPO-110 | observability |
| REPO-111 | observability |
| REPO-112 | observability |
| REPO-113 | resilience |
| REPO-114 | resilience |
| REPO-115 | resilience |
| REPO-116 | resilience |
| REPO-117 | security-baseline |
| REPO-118 | security-baseline |
| REPO-119 | security-baseline |
| REPO-120 | security-baseline |
| REPO-121 | security-baseline |
| REPO-122 | resilience |
| REPO-123 | resilience |
| REPO-124 | resilience |
| REPO-125 | security-baseline |
| REPO-126 | security-baseline |
| REPO-127 | security-baseline |
| REPO-128 | security-baseline |
| REPO-129 | security-baseline |
| REPO-130 | security-baseline |
| REPO-131 | resilience |
| REPO-132 | resilience |
| REPO-133 | resilience |
| REPO-134 | resilience |
| REPO-135 | resilience |
| REPO-136 | security-baseline |
| REPO-137 | security-baseline |
| REPO-138 | security-baseline |
| REPO-139 | security-baseline |
| REPO-140 | identity |
| REPO-141 | identity |
| REPO-142 | identity |
| REPO-143 | identity |
| REPO-144 | identity, network-exposure |
| REPO-145 | security-baseline |
| REPO-146 | data-protection |
| REPO-147 | observability |
| REPO-148 | resilience |
| REPO-149 | resilience |
| REPO-150 | sustainability, finops |
| REPO-151 | sustainability |
| REPO-152 | sustainability, resilience |
| REPO-153 | sustainability, finops |
| REPO-154 | sustainability, finops |
| REPO-155 | sustainability, finops |
| REPO-156 | sustainability, finops |
| REPO-157 | observability |
| REPO-158 | observability |
| REPO-159 | observability |
| REPO-160 | finops |
| REPO-161 | observability |
| REPO-162 | observability |
| REPO-163 | security-baseline |
| REPO-164 | observability |
| REPO-165 | observability |
| REPO-166 | observability |
| REPO-167 | observability |
| REPO-168 | observability |
| REPO-169 | observability |
| REPO-170 | observability |
| REPO-171 | observability |
| REPO-172 | observability |
| REPO-173 | observability |
| REPO-174 | observability |
| REPO-175 | observability |
| REPO-176 | observability |
| REPO-177 | observability |
| REPO-178 | observability |
| REPO-179 | finops |
| REPO-180 | finops |
| REPO-181 | finops |
| REPO-182 | finops |
| REPO-183 | observability |
| REPO-184 | observability |
| REPO-185 | observability |
| REPO-186 | observability |
| REPO-187 | observability |
| REPO-188 | resilience |
| REPO-189 | sustainability, finops |
| REPO-190 | sustainability |
| REPO-191 | sustainability |
| REPO-192 | sustainability, finops |
| REPO-193 | sustainability |
| SEC-001 | identity |
| SEC-002 | identity |
| SEC-003 | network-exposure |
| SEC-004 | network-exposure |
| SEC-005 | network-exposure |
| SEC-006 | data-protection |
| SEC-007 | identity, data-protection |
| SEC-008 | data-protection |
| SEC-009 | identity, network-exposure |
| SEC-010 | data-protection, network-exposure |
| SEC-011 | data-protection |
| SEC-012 | data-protection, network-exposure |
| SEC-013 | data-protection |
| SEC-014 | data-protection |
| SEC-015 | data-protection |
| SEC-016 | identity, data-protection |
| SEC-017 | data-protection |
| SEC-018 | data-protection, network-exposure |
| SEC-019 | data-protection, network-exposure |
| SEC-020 | security-baseline |
| SEC-021 | data-protection |
| SEC-022 | network-exposure, finops |
| SEC-023 | data-protection |
| SEC-024 | network-exposure |
| SEC-025 | data-protection |
| SEC-026 | security-baseline |
| SEC-027 | observability, security-baseline |
| SEC-028 | security-baseline |
| SEC-029 | security-baseline |
| SEC-030 | security-baseline, finops |
| SEC-031 | resilience |
| SEC-032 | security-baseline |
| SEC-033 | data-protection |
| SEC-034 | identity |
| SEC-035 | identity |
| SEC-036 | identity |
| SEC-037 | data-protection |
| SEC-038 | data-protection |
| SEC-039 | data-protection, network-exposure |
| SEC-040 | identity |
| SEC-041 | network-exposure |
| SEC-042 | data-protection |
| SEC-043 | data-protection |
| SEC-044 | data-protection |
| SEC-045 | identity |
| SEC-046 | network-exposure |
| SEC-047 | data-protection |
| SEC-048 | observability, security-baseline |
| SEC-049 | network-exposure |
| SEC-050 | data-protection |
| SEC-051 | observability, security-baseline |
| SEC-052 | data-protection |
| SEC-053 | security-baseline |
| SEC-054 | network-exposure |
| SEC-055 | network-exposure |
| SEC-056 | resilience, data-protection |
| SEC-057 | identity, network-exposure |
| SEC-058 | security-baseline |
| SEC-059 | data-protection |
| SEC-060 | data-protection |
| SEC-061 | data-protection |
| SEC-062 | data-protection, observability |
| SEC-063 | data-protection, resilience |
| SEC-064 | network-exposure |
| SEC-065 | data-protection |
| SEC-066 | security-baseline |
| SEC-067 | identity |
| SEC-068 | security-baseline |
| SEC-069 | identity |
| SEC-070 | identity |
| SEC-071 | identity |
| SUST-001 | sustainability, finops |
| SUST-002 | sustainability, finops |
| SUST-003 | sustainability |
| SUST-004 | sustainability |
| SUST-005 | sustainability |
| SUST-006 | sustainability, finops |
| SUST-007 | sustainability, finops |
<!-- themes:end -->
