# Rule coverage

Which CDK rules have a template check, and which AWS Foundational Security Best Practices (FSBP) controls a template check covers. `tests/test_coverage_doc.py` keeps both tables in sync with the code.

## Status

| Status | Meaning |
| -- | -- |
| `covered` | A template check covers the whole CDK rule. In V2 the CDK finding is dropped when the template check reports (`CF_COVERS_STATIC`, or the tag policy for BP-001 and COST-015). |
| `partial` | A template check covers part of the CDK rule, so V2 keeps both (`CF_PARTLY_COVERS_STATIC`). |
| `account` | Needs a live account. A scan of templates cannot see it. |
| `cdk-only` | Reads the CDK code itself, not a resource property. |
| `advice` | No property to read. The answer depends on traffic, usage or design. |
| `repo` | Reads the repository tree (tests, CI config, environments, account guardrails), not one IaC file. Runs for every source. |

## CDK rules

268 rules: 132 covered, 7 partial, 10 account, 5 cdk-only, 25 advice, 89 repo.

| Rule | Title | Template check | Status | Note |
| -- | -- | -- | -- | -- |
| SEC-001 | IAM policy uses wildcard actions | `CF-IAM-001`, `CF-IAM-002`, `CF-IAM-008` | `covered` |  |
| SEC-002 | IAM policy uses wildcard resources | `CF-IAM-003`, `CF-IAM-008` | `covered` |  |
| SEC-003 | Security Group allows SSH from 0.0.0.0/0 | `CF-SG-001`, `CF-SG-002` | `covered` |  |
| SEC-004 | Security Group exposes common DB ports to 0.0.0.0/0 | `CF-SG-001`, `CF-SG-002` | `covered` |  |
| SEC-005 | S3 bucket may miss Block Public Access | `CF-S3-001` | `covered` |  |
| SEC-006 | S3 bucket encryption explicitly disabled | `CF-S3-002` | `covered` |  |
| SEC-007 | KMS key policy may use wildcard principal | `CF-KMS-001` | `covered` |  |
| SEC-008 | DynamoDB table may miss encryption | `CF-DDB-002` | `covered` |  |
| SEC-009 | API Gateway missing authentication | `CF-APIGW-003`, `CF-APIGW-V2-003` | `covered` |  |
| SEC-010 | API Gateway may not enforce TLS 1.2+ | `CF-APIGW-004` | `covered` |  |
| SEC-011 | ALB/NLB not enforcing HTTPS redirect | `CF-ALB-002` | `covered` |  |
| SEC-012 | ALB using insecure SSL/TLS policy | `CF-ALB-003` | `covered` |  |
| SEC-013 | SQS queue not encrypted | `CF-SQS-001` | `covered` |  |
| SEC-014 | SNS topic not encrypted | `CF-SNS-001` | `covered` |  |
| SEC-015 | Secrets Manager rotation not enabled | `CF-SM-001` | `covered` |  |
| SEC-016 | Potential hardcoded credentials/secrets in code |  | `cdk-only` | Scans source for secret-looking literals. CF-PAR-001/002 check template parameters. |
| SEC-017 | Lambda environment variables may contain secrets | `CF-LAM-005` | `covered` |  |
| SEC-018 | CloudFront not enforcing HTTPS | `CF-CF-001` | `covered` |  |
| SEC-019 | CloudFront using legacy SSL/TLS | `CF-CF-002` | `covered` |  |
| SEC-020 | ECS task definition not using read-only root filesystem | `CF-ECS-002` | `covered` |  |
| SEC-021 | RDS not enforcing SSL/TLS connections | `CF-RDS-006` | `covered` |  |
| SEC-022 | VPC endpoints missing (security & cost improvement) | `CF-VPC-001` | `covered` |  |
| SEC-023 | KMS key rotation not enabled | `CF-KMS-002` | `covered` |  |
| SEC-024 | WAF not enabled on ALB/API Gateway/CloudFront | `CF-CF-003`, `CF-WAF-001` | `covered` |  |
| SEC-025 | ElastiCache not using encryption in-transit/at-rest | `CF-EC-001`, `CF-EC-002` | `covered` |  |
| SEC-026 | Security Hub not enabled |  | `account` | Security Hub is an account service. `CF-SH-001` checks a hub the repo defines. |
| SEC-027 | GuardDuty not enabled |  | `account` | GuardDuty is an account service. `CF-GD-001` checks a detector the repo defines. |
| SEC-028 | ECR repository image scanning not enabled | `CF-ECR-001` | `covered` |  |
| SEC-029 | ECR image tag immutability not configured | `CF-ECR-002` | `covered` |  |
| SEC-030 | ECR repository lifecycle policy missing | `CF-ECR-003` | `covered` |  |
| SEC-031 | Route 53 health checks not configured | `CF-R53-003` | `covered` | Primary failover and weighted records. A secondary record is not judged. |
| SEC-032 | Route 53 DNSSEC not enabled | `CF-R53-002` | `covered` | Public zones. A private zone is not judged. |
| SEC-033 | SSM Parameter Store not using SecureString | `CF-SSM-001` | `covered` |  |
| SEC-034 | Cognito User Pool MFA not required | `CF-COG-001` | `covered` |  |
| SEC-035 | Cognito User Pool password policy may be weak | `CF-COG-002` | `covered` |  |
| SEC-036 | Cognito advanced security features not enabled | `CF-COG-003` | `covered` |  |
| SEC-037 | EFS encryption not enabled | `CF-EFS-001` | `covered` |  |
| SEC-038 | Kinesis stream encryption not enabled | `CF-KIN-001` | `covered` |  |
| SEC-039 | OpenSearch domain encryption not enabled | `CF-OS-001`, `CF-OS-002` | `covered` |  |
| SEC-040 | OpenSearch fine-grained access control not enabled | `CF-OS-004` | `covered` |  |
| SEC-041 | OpenSearch domain not in VPC | `CF-OS-003` | `covered` |  |
| SEC-042 | Athena query result encryption not enabled | `CF-ATH-001` | `covered` |  |
| SEC-043 | Glue job encryption not configured | `CF-GLUE-001` | `covered` |  |
| SEC-044 | MSK cluster encryption not configured | `CF-MSK-001` | `covered` |  |
| SEC-045 | MSK cluster client authentication not configured | `CF-MSK-002` | `covered` |  |
| SEC-046 | SageMaker notebook instance not in VPC | `CF-SAGE-002` | `covered` |  |
| SEC-047 | SageMaker encryption not enabled | `CF-SAGE-004` | `covered` | Notebooks and endpoint configs: a training job is not a template resource. |
| SEC-048 | AppSync API logging not enabled | `CF-APPSYNC-001` | `covered` |  |
| SEC-049 | AppSync API not protected by WAF | `CF-APPSYNC-003` | `covered` | Public standard APIs. A private or merged API is not judged. |
| SEC-050 | FSx file system encryption not enabled | `CF-FSX-001` | `covered` | FSx always encrypts: CF-FSX-001 asks for a customer managed key. |
| SEC-051 | Transfer Family server logging not enabled | `CF-TRANSFER-002` | `covered` |  |
| SEC-052 | CodePipeline artifact encryption not enabled | `CF-CP-001` | `covered` |  |
| SEC-053 | CodeBuild project using privileged mode | `CF-CB-003` | `covered` |  |
| SEC-054 | Security Group egress too permissive (0.0.0.0/0) | `CF-SG-003` | `covered` |  |
| SEC-055 | Network ACLs not configured | `CF-NACL-001` | `partial` | CF-NACL-001 checks entries that open 22 or 3389; SEC-055 reports a VPC with no custom network ACL. |
| SEC-056 | Stack termination protection not enabled |  | `cdk-only` | Termination protection is a stack setting, not in the template. |
| SEC-057 | Lambda function URL without authentication | `CF-LAM-004` | `covered` |  |
| SEC-058 | ECS task may run as root user | `CF-ECS-003` | `covered` |  |
| SEC-059 | Redshift cluster encryption not enabled | `CF-RS-001` | `covered` |  |
| SEC-060 | DocumentDB cluster encryption not enabled | `CF-DOCDB-001` | `covered` |  |
| SEC-061 | Neptune database encryption not enabled | `CF-NEP-001` | `covered` |  |
| SEC-062 | CloudWatch Logs not encrypted with KMS | `CF-CW-002` | `covered` |  |
| SEC-063 | Backup vault encryption not configured | `CF-BAK-001` | `covered` |  |
| SEC-064 | RDS instance may be publicly accessible | `CF-RDS-004` | `covered` |  |
| SEC-065 | Amazon Macie not enabled for sensitive data discovery |  | `account` | Macie is an account service. `CF-MACIE-001` checks a session the repo defines. |
| SEC-066 | EC2 instance may not require IMDSv2 | `CF-EC2-001` | `covered` |  |
| SEC-067 | IAM principal has full admin access | `CF-IAM-008` | `covered` |  |
| SEC-068 | Lambda function uses a deprecated runtime | `CF-LAM-003` | `covered` |  |
| SEC-069 | IAM user has a console password | `CF-IAM-009` | `covered` |  |
| SEC-070 | IAM access key is created in the code | `CF-IAM-010` | `covered` | The template check passes on a key with `Status: Inactive`. |
| SEC-071 | IAM user has policies attached directly | `CF-IAM-011` | `covered` |  |
| REL-001 | RDS may miss Multi-AZ | `CF-RDS-003` | `partial` | Checks DB instances only; REL-001 also flags DatabaseCluster. |
| REL-002 | RDS may miss backup retention | `CF-RDS-002` | `covered` |  |
| REL-003 | Lambda may miss DLQ / on-failure destination | `CF-LAM-001` | `covered` |  |
| REL-004 | DynamoDB may miss point-in-time recovery | `CF-DDB-001` | `covered` |  |
| REL-005 | DynamoDB may miss automated backups | `CF-DDB-005` | `covered` |  |
| REL-006 | API Gateway throttling not configured | `CF-APIGW-005`, `CF-APIGW-V2-004` | `covered` |  |
| REL-007 | ALB health check configuration missing | `CF-ALB-007` | `covered` |  |
| REL-008 | SQS missing dead-letter queue configuration | `CF-SQS-002` | `covered` |  |
| REL-009 | Lambda timeout may be too low or too high | `CF-LAM-007` | `covered` |  |
| REL-010 | Lambda not in VPC when accessing RDS/ElastiCache |  | `advice` | Whether a function needs the VPC depends on what it calls. |
| REL-011 | RDS read replicas missing for read-heavy workloads |  | `advice` | Read replicas depend on read load. |
| REL-012 | NAT Gateway single point of failure (need multi-AZ) | `CF-NAT-001` | `covered` |  |
| REL-013 | AWS Backup vault not configured | `CF-BAK-005` | `covered` |  |
| REL-014 | Cross-region backup replication missing | `CF-BAK-002` | `covered` |  |
| REL-015 | Step Functions retry/catch not configured | `CF-SFN-001` | `covered` |  |
| REL-016 | ElastiCache not using multi-AZ | `CF-EC-003` | `covered` | Reads replication groups. A cache cluster has no failover setting, so a scan where CF-EC-003 does not report keeps the CDK finding. |
| REL-017 | EFS backup policy not configured | `CF-EFS-002` | `covered` |  |
| REL-018 | EFS lifecycle policy not configured | `CF-EFS-003` | `covered` |  |
| REL-019 | Kinesis stream retention period too short | `CF-KIN-002` | `covered` |  |
| REL-020 | Global Accelerator health checks not configured | `CF-GA-001` | `covered` | Advice: EC2 and Elastic IP endpoints. A load balancer's own health checks decide. |
| REL-021 | CodePipeline missing manual approval for production | `CF-CP-002` | `covered` |  |
| REL-022 | ACM certificate validation method not specified | `CF-ACM-001` | `covered` | An imported or private CA certificate is not judged. |
| REL-023 | Blue-green deployment not configured for critical services |  | `advice` | Deployment strategy, not a resource property. |
| REL-024 | SQS visibility timeout may need review | `CF-SQS-003` | `covered` |  |
| REL-025 | DynamoDB global tables not configured for multi-region |  | `advice` | Global tables depend on multi-Region needs. |
| REL-026 | S3 replication not configured for critical buckets | `CF-S3-010` | `covered` |  |
| REL-027 | Lambda reserved concurrency not configured for critical functions | `CF-LAM-006` | `covered` |  |
| REL-028 | API Gateway request validation not configured | `CF-APIGW-006` | `covered` |  |
| REL-029 | EventBridge rule retry policy not configured | `CF-EB-002` | `covered` |  |
| REL-030 | RDS deletion protection not enabled | `CF-RDS-005` | `covered` |  |
| REL-031 | S3 bucket versioning not enabled | `CF-S3-003` | `covered` |  |
| REL-032 | VPC uses one Availability Zone | `CF-VPC-004` | `covered` | The template check reads each subnet tier (public, private) of the synthesised VPC. |
| REL-033 | Lambda function is granted direct invoke on another function | `CF-LAM-009` | `covered` | The template check reads the caller's role policies and the callee's event invoke config. |
| COST-001 | Log retention may be infinite (cost risk) | `CF-CW-001` | `covered` |  |
| COST-002 | Compute resources may miss autoscaling | `CF-ASG-006` | `partial` | CF-ASG-006 checks Auto Scaling groups of fixed size; COST-002 reports ECS services in code with no Auto Scaling at all. |
| COST-003 | DynamoDB provisioned capacity may miss autoscaling | `CF-DDB-003` | `covered` |  |
| COST-004 | Lambda provisioned concurrency may be overprovisioned |  | `advice` | Provisioned concurrency sizing needs traffic data. |
| COST-005 | RDS not using Reserved Instances (savings opportunity) |  | `account` | Reserved Instances are bought for the account. |
| COST-006 | NAT Gateway incurs data processing costs | `CF-COST-002`, `CF-VPC-002`, `CF-VPC-003` | `covered` |  |
| COST-007 | S3 Intelligent-Tiering not enabled | `CF-S3-007` | `covered` |  |
| COST-008 | EBS volumes using gp2 instead of gp3 | `CF-EBS-002` | `covered` |  |
| COST-009 | ElastiCache may benefit from reserved nodes |  | `account` | Reserved nodes are bought for the account. |
| COST-010 | RDS not using Graviton instances | `CF-RDS-014` | `covered` |  |
| COST-011 | CloudFront using all edge locations (Price Class All) | `CF-CF-006` | `covered` |  |
| COST-012 | Elastic IP allocated but may not be used | `CF-EIP-001` | `covered` |  |
| COST-013 | S3 lifecycle policy not configured for cost optimization | `CF-S3-006` | `covered` |  |
| COST-014 | AWS Budgets not configured |  | `account` | Budgets are account-level. `CF-BUDGET-001` checks a budget the repo defines. |
| COST-015 | Cost allocation tags may not be configured | `CF-TAG-001` | `covered` |  |
| COST-016 | Savings Plans opportunity for compute workloads |  | `account` | Savings Plans are bought for the account. |
| COST-017 | Lambda memory/CPU may not be optimized |  | `advice` | Memory tuning needs invocation data. |
| COST-018 | S3 Storage Lens not enabled |  | `account` | Storage Lens is configured for the account or organization. |
| BP-001 | Standard tags may be missing | `CF-TAG-001` | `covered` |  |
| BP-002 | Using environment variables instead of Secrets Manager | `CF-LAM-005` | `covered` |  |
| BP-003 | Resource naming convention may not be followed |  | `cdk-only` | Reads construct and resource names in code. |
| BP-004 | CDK Aspects not used for policy enforcement |  | `cdk-only` | Reads CDK Aspects. |
| BP-005 | CDK context not used for environment-specific config |  | `cdk-only` | Reads CDK context. |
| OPS-001 | CloudTrail / audit trail may be missing |  | `account` | A trail is usually an organization or account trail outside the app. CF-CT-001 to CF-CT-005 check a trail the template defines. |
| OPS-002 | VPC Flow Logs may be missing | `CF-FL-001` | `covered` |  |
| OPS-003 | X-Ray / distributed tracing may be missing | `CF-APIGW-002`, `CF-APIGW-V2-002`, `CF-LAM-002` | `covered` |  |
| OPS-004 | DynamoDB table may benefit from streams for event-driven patterns |  | `advice` | Streams depend on the event design. |
| OPS-005 | API Gateway access logging not enabled | `CF-APIGW-001`, `CF-APIGW-V2-001` | `covered` |  |
| OPS-006 | ALB/NLB access logs not enabled | `CF-ALB-001` | `covered` |  |
| OPS-007 | CloudFront access logging not enabled | `CF-CF-005` | `covered` |  |
| OPS-008 | ECS container insights not enabled | `CF-ECS-010` | `covered` |  |
| OPS-009 | RDS enhanced monitoring not enabled | `CF-RDS-007` | `covered` |  |
| OPS-010 | CloudWatch alarms not configured for critical resources | `CF-ALARM-001` | `covered` | Not reported in dev. A child stack or module that may hold alarms is not judged. |
| OPS-011 | No SNS topics for alarm notifications | `CF-ALARM-002` | `covered` | Like the CDK rule, any alarm action passes, not only SNS. An alarm something else reads is not reported. |
| OPS-012 | Step Functions not using X-Ray tracing | `CF-SFN-002` | `covered` |  |
| OPS-013 | EventBridge rules not using DLQ | `CF-EB-001` | `covered` |  |
| OPS-014 | AWS Config not enabled |  | `account` | AWS Config is an account service. `CF-CFG-001` checks a recorder the repo defines. |
| OPS-015 | Glue job CloudWatch metrics not enabled | `CF-GLUE-002` | `covered` |  |
| OPS-016 | Transit Gateway flow logs not enabled | `CF-TGW-002` | `covered` |  |
| OPS-017 | CodePipeline notifications not configured | `CF-CP-003` | `covered` |  |
| OPS-018 | App Runner observability not configured | `CF-APPRUNNER-001` | `covered` |  |
| OPS-019 | Glue job bookmarks not enabled | `CF-GLUE-003` | `covered` | CF-GLUE-003 reports a literal job-bookmark-disable; a job with the option unset keeps OPS-019. |
| OPS-020 | CodeBuild project logging not configured | `CF-CB-004` | `covered` |  |
| OPS-021 | CloudWatch dashboards not configured | `CF-DASH-001` | `covered` | Stacks with more than `dashboards.min_resources` resources (default 20). Not reported in dev. |
| OPS-022 | Resource tagging strategy may be incomplete |  | `advice` | Tag choice. CF-TAG-001 checks a configured tag policy. |
| OPS-023 | SSM Parameter Store throughput setting may need review |  | `advice` | Restated: it used to recommend the advanced tier for throughput, but AWS sets throughput per account and Region, whatever the tier. Throughput needs traffic data. `CF-SSM-002` reports the separate cost of an advanced parameter that does not need that tier. |
| OPS-025 | S3 replication metrics not enabled | `CF-S3-011` | `covered` |  |
| OPS-026 | EC2 instances have no patch baseline | `CF-PATCH-001` | `covered` |  |
| OPS-027 | Alarms have no escalation path | `CF-ALARM-003` | `covered` | The template check also passes on an alarm action that targets a response plan ARN, and needs an alarm with an action. |
| PERF-001 | Compute may not use Graviton/ARM (cost and performance) | `CF-PERF-001` | `partial` | Checks Lambda only; PERF-001 also flags EC2 and ECS. |
| PERF-002 | No caching layer detected (performance) | `CF-PERF-002` | `partial` | API Gateway and Lambda only; PERF-002 also counts load balancers, API caches and DAX. |
| PERF-003 | DynamoDB table may use provisioned capacity (consider on-demand) |  | `advice` | On-demand versus provisioned depends on traffic. |
| PERF-004 | API Gateway caching not enabled | `CF-APIGW-008` | `covered` |  |
| PERF-005 | Lambda memory not optimized (too low/high) |  | `advice` | Memory tuning needs invocation data. |
| PERF-006 | CloudFront caching strategy not optimized | `CF-CF-013` | `covered` | Narrowed: CF-CF-013 reports only the managed CachingDisabled policy on a static-looking path, because a template does not show other caching gaps. |
| PERF-007 | ECS task sizing (CPU/memory) may need review | `CF-ECS-011` | `covered` |  |
| PERF-008 | RDS instance class may be oversized | `CF-PERF-003`, `CF-PERF-004` | `partial` | CF-PERF-003 checks RDS and CF-PERF-004 checks EC2; PERF-008 matches any large instanceType. |
| PERF-009 | Kinesis enhanced fan-out not used |  | `advice` | Enhanced fan-out depends on consumer count. |
| PERF-010 | OpenSearch instance types not optimized |  | `advice` | Instance choice depends on the workload. |
| PERF-011 | Global Accelerator not used for global traffic |  | `advice` | Global Accelerator depends on where users are. |
| PERF-012 | EFS performance mode not configured |  | `advice` | Performance mode depends on the workload. |
| PERF-013 | AppSync API caching not enabled | `CF-APPSYNC-004` | `covered` | Advice: a cache suits repeated reads. A merged API is not judged. |
| PERF-014 | S3 Transfer Acceleration not enabled for global uploads |  | `advice` | Transfer Acceleration depends on where uploads come from. |
| PERF-015 | Lambda SnapStart not enabled for Java functions |  | `advice` | SnapStart depends on cold-start needs. |
| PERF-016 | Aurora not using I/O-Optimized for high I/O workloads |  | `advice` | I/O-Optimized depends on I/O spend. |
| PERF-017 | EBS io2 Block Express not used for high IOPS |  | `advice` | io2 Block Express depends on IOPS needs. |
| PERF-018 | CloudWatch Contributor Insights not enabled |  | `advice` | Contributor Insights depends on access patterns. |
| PERF-019 | RDS Proxy not used for connection pooling |  | `advice` | RDS Proxy depends on connection patterns. |
| SUST-001 | Fleet may not use Spot for interruptible workloads | `CF-SUST-001`, `CF-SUST-002`, `CF-SUST-003` | `partial` | CF-SUST-001 checks Auto Scaling groups, CF-SUST-002 Fargate and CF-SUST-003 launch templates; SUST-001 also flags EC2 instances and ECS on EC2. |
| SUST-002 | Right-sizing and efficiency review recommended |  | `advice` | Right-sizing needs usage data. CF-PERF-003/004 flag large instances. |
| SUST-003 | Scheduled scaling not configured for predictable patterns |  | `advice` | Scheduled scaling depends on traffic patterns. |
| SUST-004 | Consider async processing for batch workloads |  | `advice` | Architecture advice. |
| SUST-005 | Consider managed services over self-managed |  | `advice` | Architecture advice. |
| SUST-006 | CloudFront compression not enabled | `CF-CF-007` | `covered` |  |
| SUST-007 | Latest generation instance types not used | `CF-GEN-001` | `covered` |  |
| REPO-001 | Repo has no automated tests |  | `repo` | Looks for test directories and test file names. |
| REPO-002 | No CI workflow or pipeline builds the workload |  | `repo` | Looks for CI config files or a CodePipeline in the IaC. |
| REPO-003 | Only one environment is defined |  | `repo` | Looks for environment names in IaC paths, CDK stack ids and cdk.json context. |
| REPO-004 | No organization guardrails in the scanned IaC |  | `repo` | Looks for SCPs, Control Tower controls, an organization trail, or Organizations accounts and OUs. Org-level: off unless `rules.org`. |
| REPO-005 | Account is defined without a security baseline |  | `repo` | When the IaC defines an account, looks for CloudTrail, Config, GuardDuty, Security Hub and IAM Access Analyzer. |
| REPO-006 | Account baseline does not check root MFA or root access keys |  | `repo` | When the IaC defines an account, looks for the Config rules for root MFA and root access keys, a conformance pack, the Security Hub CIS or FSBP standard, or an SCP that denies the root user. |
| REPO-007 | No forensic capture is automated for security findings |  | `repo` | Looks for an EventBridge rule on GuardDuty, Security Hub, Inspector or Macie findings and an EBS snapshot or SSM capture runbook, or Amazon Detective. Org-level: off unless `rules.org`. |
| REPO-008 | No containment control is deployed |  | `repo` | Looks for a quarantine or isolation security group, an SSM containment runbook, or credential revocation automation. Org-level: off unless `rules.org`. |
| REPO-009 | The build does not scan dependencies |  | `repo` | Looks in the CI configs, CodeBuild buildspecs inline in the IaC, and the package.json scripts they run for a dependency scan (npm audit, pip-audit, osv-scanner, snyk, trivy, Amazon Inspector) that can fail the build. |
| REPO-010 | Container or function artifacts are not scanned before deploy |  | `repo` | When the repo builds images or deploys Lambda functions, looks for ECR scan on push or registry scanning, Amazon Inspector for ECR or Lambda, or a CI scan. |
| REPO-011 | Packages are not pulled through a central repository |  | `repo` | When the repo has a package manifest, looks for CodeArtifact, `aws codeartifact login`, or a private registry in .npmrc, pip.conf, poetry, Maven or Gradle. |
| REPO-012 | No Service Quotas usage alarm for the services the stack uses |  | `repo` | When the IaC uses Lambda, Elastic IPs, NAT gateways or load balancers, looks for a CloudWatch alarm on the AWS/Usage namespace, SERVICE_QUOTA metric math, Quota Monitor for AWS, or Trusted Advisor service limit events. Org-level: off unless `rules.org`. |
| REPO-013 | Limits the IaC sets leave no room for failover |  | `repo` | Sums literal Lambda reserved concurrency and Elastic IPs (with CDK NAT gateways) across the repo against the default quotas; over half fires. |
| REPO-014 | VPC CIDR ranges overlap |  | `repo` | Compares the literal VPC CIDRs of CloudFormation, Terraform and CDK across the repo; files for different environments (dev and prod) are not compared. |
| REPO-015 | Queue and stream workers have no idempotency key or dedupe store |  | `repo` | When the IaC has a Lambda queue or stream event source, looks for Powertools idempotency, SQS FIFO deduplication, or a conditional write in the IaC and function code. |
| REPO-016 | No fault injection experiment targets the workload |  | `repo` | Looks for an AWS FIS experiment template in the IaC, or aws fis start-experiment or a chaos tool (Litmus, Chaos Mesh, Gremlin, Chaos Toolkit) in a build. |
| REPO-017 | No load test runs in the pipeline |  | `repo` | Looks for a load test tool (k6, Artillery, Locust, JMeter, Gatling, Vegeta, hey, ab, Taurus, Distributed Load Testing on AWS) run by a CI config, an inline buildspec, or a package.json script a build runs. |
| REPO-018 | No application KPI metric |  | `repo` | When the IaC runs compute, looks for a CloudWatch alarm, metric or metric filter in a namespace outside AWS/, or embedded metric format, PutMetricData or Powertools Metrics in function code. |
| REPO-019 | No user experience telemetry on the edge |  | `repo` | When the IaC has an API Gateway, load balancer or CloudFront distribution, looks for a Synthetics canary, a RUM app monitor, a Route 53 health check, or an alarm on an edge latency or 5xx metric. |
| REPO-020 | No telemetry on the datastores and queues the workload calls |  | `repo` | When the IaC has a datastore or queue, looks for AWS SDK tracing in function code (X-Ray, Powertools Tracer, OpenTelemetry), the ADOT Lambda layer or Application Signals, or an alarm on a datastore or queue metric. |
| REPO-021 | A deploy runs with no test gate before it |  | `repo` | Looks in each build config that deploys (cdk deploy, terraform apply, aws cloudformation deploy, sam deploy, a CodePipeline deploy action, a CDK pipelines stage) for a test that can fail before its last deploy, including package.json scripts the build runs. |
| REPO-022 | Deployments of the workload's compute have no automated rollback |  | `repo` | When the IaC runs compute, looks for an ECS circuit breaker or deployment alarms with rollback, CodeDeploy automatic rollback, a SAM deployment preference, CloudFormation rollback triggers, a CodePipeline stage that rolls back, an Auto Scaling rollback, or Argo Rollouts or Flagger. |
| REPO-023 | Live instances are changed in place |  | `repo` | Looks for builds that ssh, scp or rsync to a host, run ansible-playbook, SSM Run Command or an in-place CodeDeploy deployment, and in the IaC for in-place CodeDeploy deployment groups, SSM associations that run shell scripts or Ansible, and cfn-hup. |
| REPO-024 | No functional test runs against the deployed change |  | `repo` | Looks in each build config that deploys for a test that can fail after a deploy (and before the last one when it deploys more than once): the REPO-021 tests, a curl that fails on an HTTP error, Playwright, Cypress, Newman, integ, e2e or smoke scripts, integ-runner, a CodePipeline test action, a CDK pipelines post step. |
| REPO-025 | Infrastructure is not deployed by automation |  | `repo` | When the repo holds CDK, CloudFormation or Terraform, looks for a build config that deploys it, or a CodePipeline or CDK pipelines in the IaC. |
| REPO-026 | Deployments run no resiliency test |  | `repo` | When a build deploys, looks in the deploying builds for a started AWS FIS experiment or a chaos tool, and in the IaC for a Step Functions task that starts an FIS experiment. |
| REPO-027 | Alarms watch only infrastructure metrics, not the workload's |  | `repo` | When the IaC runs compute, looks for an alarm on a metric outside AWS/, an edge latency or 5xx metric, a datastore or queue metric, or with anomaly detection. |
| REPO-028 | Workload logs are not analyzed |  | `repo` | When the IaC runs compute, looks for a CloudWatch Logs metric filter, Contributor Insights rule, Logs Insights saved query, log anomaly detector or subscription filter. |
| REPO-029 | Workload traces are not analyzed |  | `repo` | When the IaC runs compute, looks for an X-Ray group or sampling rule, CloudWatch Application Signals, or an alarm on an Application Signals or X-Ray metric. |
| REPO-030 | Dashboards show no workload metric |  | `repo` | When the IaC declares a CloudWatch dashboard, looks in the dashboards for a metric outside AWS/, an edge latency or 5xx metric, a datastore or queue metric, or Application Signals. |
| REPO-031 | IAM roles have no permissions boundary or SCP to cap them |  | `repo` | When the IaC declares an IAM role or user, looks for a permissions boundary (CloudFormation, Terraform, CDK or the cdk.json context) or a service control policy. |
| REPO-032 | No break-glass role kept apart from the workload's roles |  | `repo` | Looks for an IAM role or Identity Center permission set named for break-glass or emergency access, and for a workload resource that uses it as its role. Org-level: off unless `rules.org`. |
| REPO-033 | Security findings have no place to meet |  | `repo` | When the IaC turns on GuardDuty, Config, Inspector, Macie or Access Analyzer, looks for Security Hub, Security Lake, or an EventBridge rule with a target on each detector's event source. |
| REPO-034 | Traffic leaves the VPC with no inspection |  | `repo` | When the IaC declares a NAT gateway, an internet gateway, or a CDK VPC with its default NAT, looks for Network Firewall, a DNS Firewall association, or a Gateway Load Balancer endpoint. |
| REPO-035 | Network protection does not update itself |  | `repo` | When the IaC has an edge or an egress path, looks for a WAF AWS managed rule group, Shield Advanced, a Firewall Manager policy, or AWS managed Network Firewall or DNS Firewall lists. |
| REPO-036 | A workload sits in a public subnet |  | `repo` | Looks for CDK constructs placed with SubnetType.PUBLIC, and Terraform or CloudFormation resources that name a subnet that maps public IPs, other than load balancers, NAT and endpoints. |
| REPO-037 | Deployed code and images are not signed |  | `repo` | When the IaC deploys Lambda functions, looks for a code signing config; when it deploys container images, for an AWS Signer Notation profile or notation or cosign signing in a build. |
| REPO-038 | A container image is referenced by a mutable tag |  | `repo` | Looks for container images in task definitions, Lambda image functions and CDK container images referenced with no tag or :latest, and no digest. |
| REPO-039 | Data stores carry no classification tag |  | `repo` | Looks in each IaC file that declares a data store for a classification tag key, or for an app-wide CDK tag or Terraform default_tags holding one. |
| REPO-040 | Data classified as sensitive has no customer managed key |  | `repo` | Looks in each IaC file whose data stores are tagged confidential, restricted, secret, sensitive, PII, PHI or PCI for a customer managed KMS key. |
| REPO-041 | Nothing stops unencrypted storage from being created |  | `repo` | When the IaC declares a data store or EBS volume, looks for EBS encryption by default, a deny on an encryption condition key, an AWS Config encryption rule, CDK Nag, or checkov, tfsec, trivy config, cfn-guard or KICS in a build. |
| REPO-042 | Compute keeps state on local disk |  | `repo` | When the IaC runs compute, looks for an attached EBS data volume, a non-root block device, an ECS host volume, an autoprovisioned shared Docker volume or a Kubernetes hostPath. |
| REPO-043 | No emergency lever to shed load |  | `repo` | When the IaC runs compute, looks for Lambda reserved concurrency, an API Gateway throttle or usage plan, a WAF rate-based rule, AppConfig feature flags, or a feature flag SDK in the function code. |
| REPO-044 | No fallback when a dependency fails |  | `repo` | When compute has a dependency or an edge, looks for an SQS buffer, an on-failure destination, a Step Functions catch, origin or DNS failover, a fixed or mock response, or a circuit breaker library. |
| REPO-045 | Alarms are not defined on workload metrics |  | `repo` | When the IaC runs compute, looks for CloudFormation and Terraform alarms with no metric or no threshold, then for alarms that watch only host metrics. |
| REPO-046 | Logs are not analyzed for errors |  | `repo` | When the IaC runs compute, looks for a CloudWatch Logs metric filter on errors, a log anomaly detector, a Logs Insights saved query or a subscription filter. |
| REPO-047 | Alarms trigger no automated response |  | `repo` | When the IaC runs compute, looks for an Auto Scaling or Application Auto Scaling policy, an alarm action that runs automation or a Lambda function, or an EventBridge rule on alarm state changes. |
| REPO-048 | Requests are not traced end to end |  | `repo` | When the IaC runs compute, looks for Lambda active tracing, an X-Ray or ADOT collector, Application Signals or a tracing SDK in the code, and for X-Ray tracing on API Gateway REST API stages. |
| REPO-049 | A fleet has a fixed size |  | `repo` | Names each ECS service with no Application Auto Scaling target on its task count, Auto Scaling group whose minimum equals its maximum or with no scaling policy in the repo, and provisioned DynamoDB table with no auto scaling. |
| REPO-050 | Scaling reacts only to CPU or memory |  | `repo` | When the repo has scaling policies, fires if every one tracks CPU or memory and none scales on queue depth, request count, latency, errors, another custom metric or a forecast. |
| REPO-051 | Backups are never restored to test them |  | `repo` | When the IaC backs data up (AWS Backup plan, DynamoDB point-in-time recovery, RDS or Aurora), looks for an AWS Backup restore testing plan, a schedule that calls a restore API, or a restore command in a build. |
| REPO-052 | Recovery objectives are not defined |  | `repo` | When the IaC holds a data store or compute, looks for a Resilience Hub resiliency policy or an RTO or RPO tag or context key. |
| REPO-053 | Replicated data has no automated failover |  | `repo` | When data is copied to another Region, looks for DNS failover or health checks, origin failover, Application Recovery Controller, Global Accelerator in two Regions, a global table, Elastic Disaster Recovery, or a tested restore. |
| REPO-054 | Disaster recovery is never tested |  | `repo` | When data is copied to another Region, looks for a fault injection experiment, a failover or recovery drill in a build, a readiness check, or a scheduled restore test. |
| REPO-055 | The DR Region can drift from the primary |  | `repo` | When data is copied to another Region, looks for StackSets, a readiness check or resource set, a Config aggregator, drift detection in a build, or one stack or module deployed to two Regions. |
| REPO-056 | A standalone instance is not rebuilt when it fails |  | `repo` | When the IaC runs a standalone EC2 instance, looks for an Auto Scaling group, an alarm that recovers or reboots the instance, an AWS Backup plan, or a restore test; an instance with automatic recovery turned off always fires. |
| REPO-057 | Capacity has no headroom to survive a failure |  | `repo` | Fires on a production Auto Scaling group or ECS scaling target whose literal minimum is 1 (CDK default included), or an ECS service with a desired count of 1 and no scaling target; dev and staging paths are skipped. |
| REPO-058 | No availability target on the user-facing edge |  | `repo` | When the IaC declares an API, load balancer or CloudFront distribution, looks for an alarm on an edge error or latency metric or an Application Signals service level objective; canaries and health checks do not count. |
| REPO-059 | No one is notified when availability drops |  | `repo` | When compute runs, looks for an alarm that notifies an SNS topic, an Incident Manager response plan, an AWS Chatbot configuration, or an EventBridge rule on AWS Health events with a target. |
| REPO-060 | Compute utilization metrics are not collected |  | `repo` | When production IaC runs compute, looks for an alarm on a CPU, memory, duration or concurrency metric, ECS Container Insights, the EKS CloudWatch observability add-on, or the CloudWatch agent; dev and staging paths are skipped. |
| REPO-061 | Compute does not scale with demand |  | `repo` | Fires on a production ECS service when the repo has no ECS scaling target with a scaling policy, and on an Auto Scaling group with a fixed size or no scaling policy; a schedule alone does not count, and serverless-only stacks pass. |
| REPO-062 | Accelerator utilization is not watched |  | `repo` | When a GPU, Inferentia, Trainium or other accelerated instance type sits on an instance, launch template, Auto Scaling group, EKS node group, Batch or SageMaker resource, looks for an alarm on a GPU or Neuron core utilization metric. |
| REPO-063 | Data lives on the instance, not in a purpose-built store |  | `repo` | Fires when production IaC keeps data on an EBS data volume, a non-root or instance store block device, or a database engine installed or run by user data or an SSM document, and the repo declares no managed data store (S3, DynamoDB, RDS or Aurora, ElastiCache, MemoryDB, DocumentDB, Neptune, Keyspaces, OpenSearch Service, Timestream, Redshift, EFS, FSx); dev and staging paths are skipped. |
| REPO-064 | Network latency at the edge is not watched |  | `repo` | When production IaC declares a load balancer, API Gateway or CloudFront distribution, looks for an alarm on TargetResponseTime, Latency, IntegrationLatency or OriginLatency; error and 5xx alarms do not count. |
| REPO-065 | Network configuration is not tuned on metrics |  | `repo` | When production IaC declares an edge, looks for VPC Flow Logs or a latency alarm with a literal numeric threshold; a parameter, variable or anomaly band does not count. |
| REPO-066 | Dedicated connectivity or VPN has no redundant link |  | `repo` | Fires on exactly one Direct Connect connection or virtual interface with no second one, LAG or VPN backup, and on exactly one VPN connection with one customer gateway and no Direct Connect; no hybrid link passes. |
| REPO-067 | Traffic is not spread by a load balancer |  | `repo` | Fires on a production EC2 instance with a public IP or Elastic IP when the repo declares no load balancer, and on a target group with exactly one literal target and no Auto Scaling group or ECS service registered. |
| REPO-068 | Edge uses an older network protocol |  | `repo` | Fires on explicit CloudFront http1.1, a CloudFront viewer minimum below TLSv1.2, a load balancer TLS policy that allows TLS 1.0 or 1.1, an API Gateway domain on TLS_1_0, or an internet-facing HTTP listener that forwards instead of redirecting; dev and staging paths are skipped. |
| REPO-069 | No Cost and Usage Report or data export |  | `repo` | Fires when production IaC declares compute, a data store or an edge and the repo has no Cost and Usage Report or AWS Data Exports export. Org-level: off unless `rules.org`. |
| REPO-070 | No cost attribution tag or cost category |  | `repo` | Fires when production IaC declares compute, a data store or an edge and no tag is keyed CostCenter, BusinessUnit, Project, Product or CostCategory (any case) and no Cost Categories rule exists; Owner, Environment and Name keys do not count. |
| REPO-071 | No unit-cost metric for the workload |  | `repo` | When production IaC runs compute, looks for a metric named like CostPerRequest or UnitCost in a metric-name position (metric name, metric filter, metric math label or id, Powertools or embedded metric format); comments and README text do not count. |
| REPO-072 | Costs are not allocated by workload metrics |  | `repo` | When production IaC runs compute, looks for metric math on an alarm or dashboard (or a CDK MathExpression) that reads EstimatedCharges or a unit-cost metric and at least one other metric. |
| REPO-073 | Budget has no named owner |  | `repo` | Fires on a budget the IaC declares with no Owner, CostOwner or Team tag and no notification subscriber; a repo with no budget passes (COST-014 is the account-level check). |
| REPO-074 | Cost is only watched after the budget is spent |  | `repo` | Fires when every declared budget notifies only at 100 percent or more of actual spend (no FORECASTED notification, no threshold below 100) and there is no Cost Anomaly Detection monitor or subscription; a repo with no budget passes. |
| REPO-075 | Workload uses a previous-generation type or deprecated runtime |  | `repo` | Fires on previous-generation EC2, RDS and ElastiCache types SUST-007 does not report, and on deprecated Lambda runtimes set literally, in production IaC; a dated service or architecture review note passes. |
| REPO-076 | Spend is not tied to a unit of business value |  | `repo` | Fires when production IaC runs compute and there is no unit-cost metric (as REPO-071) and no budget named per request, tenant, order, user or transaction. |
| REPO-077 | No named cost owner links finance and engineering |  | `repo` | Fires when production IaC declares compute, a data store or an edge and no cost note (COST.md, FINOPS.md, docs/cost*.md, or a README or docs section headed Cost, FinOps or Cost ownership) names an owner. |
| REPO-078 | Cost is not part of the change process |  | `repo` | As REPO-077; a pull or merge request template with a cost checklist item also passes. |
| REPO-079 | No cost guidance for the team |  | `repo` | As REPO-077: production workload resources and no cost note that names an owner. |
| REPO-080 | No policy governs what the organization may spend |  | `repo` | Fires when production IaC declares compute, a data store or an edge and there is no service control policy and no policy that Denies ec2:RunInstances or sagemaker:Create* or sets a condition on ec2:InstanceType, sagemaker:InstanceTypes, rds:DatabaseClass or aws:RequestedRegion. Org-level: off unless `rules.org`. |
| REPO-081 | Nothing limits what the workload can spend |  | `repo` | Fires when production IaC declares compute, a data store or an edge and there is no cost policy (as REPO-080), no permissions boundary and no AWS Budgets action. |
| REPO-082 | Budget sets no target amount |  | `repo` | Fires when the IaC declares budgets and none sets a limit amount or a limit per period; a repo with no budget passes (COST-014 is the account-level check). |
| REPO-083 | Production and non-production share an account |  | `repo` | Fires when the repo declares compute, a data store or an edge, deploys production and dev or staging, and has no Organizations account or OU, no StackSets deployment targets and fewer than two distinct literal account ids. |
| REPO-084 | Billing access is granted to an IAM user |  | `repo` | Fires when billing actions (aws-portal, billing, ce, budgets, cur) or a Billing managed policy are granted to an IAM user directly; a group or role passes. |
| REPO-085 | Temporary stacks have no end date |  | `repo` | Fires on a temporary stack (path or stack id reads as sandbox, test, preview, ephemeral, feature, demo, poc or pr-<n>; long-lived dev and staging are not) with no end-date tag or no environment tag in its file or directory. |
| REPO-086 | Resources are not tagged with who created and owns them |  | `repo` | Fires when production IaC declares compute, a data store or an edge and no IaC file tags with a created-by key (CreatedBy, ManagedBy, Creator, Source, Repository, Repo, IaC) or no IaC file tags with an owner key (Owner, CostOwner, Team). |
| REPO-087 | Nothing tears down temporary environments |  | `repo` | Fires when the repo creates temporary environments (a temporary stack as REPO-085, a GitHub workflow that deploys on pull requests, a GitLab review/ environment) and has no destroy step or GitLab on_stop job in CI, no scheduled cleanup in IaC, no aws-nuke config and no decommissioning note. |
| REPO-088 | No cost estimate for the workload |  | `repo` | Fires when production IaC declares compute, a data store or an edge and the repo has no Infracost config or CI step (infracost breakdown, diff or comment), no cost-estimate tool config, and no note named or headed cost estimate, cost model, estimated cost or pricing that gives an amount or an AWS Pricing Calculator link. |
| REPO-089 | Workload creates its own network or cluster instead of sharing |  | `repo` | Fires when production IaC creates its own VPC or ECS or EKS cluster and the IaC looks up or imports no shared VPC, subnet, cluster or bucket, has no AWS RAM share, and has no Tenancy tag of single or dedicated or single-tenant comment. |

## FSBP controls

Controls a template can show. Account-level controls (for example S3.1, EC2.7 and IAM password policy controls) are not listed.

| Control | Check | Resource type |
| -- | -- | -- |
| ACM.2 | `CF-ACM-002` | `AWS::CertificateManager::Certificate` |
| APIGateway.2 | `CF-APIGW-009` | `AWS::ApiGateway::Stage` |
| APIGateway.3 | `CF-APIGW-002` | `AWS::ApiGateway::Stage` |
| APIGateway.5 | `CF-APIGW-007` | `AWS::ApiGateway::Stage` |
| APIGateway.8 | `CF-APIGW-V2-003` | `AWS::ApiGatewayV2::Route` |
| APIGateway.9 | `CF-APIGW-V2-001` | `AWS::ApiGatewayV2::Stage` |
| AppSync.2 | `CF-APPSYNC-001` | `AWS::AppSync::GraphQLApi` |
| AppSync.5 | `CF-APPSYNC-002` | `AWS::AppSync::GraphQLApi` |
| AutoScaling.1 | `CF-ASG-001` | `AWS::AutoScaling::AutoScalingGroup` |
| AutoScaling.2 | `CF-ASG-002` | `AWS::AutoScaling::AutoScalingGroup` |
| AutoScaling.3 | `CF-ASG-003` | `AWS::AutoScaling::LaunchConfiguration` |
| AutoScaling.5 | `CF-ASG-004` | `AWS::AutoScaling::LaunchConfiguration` |
| AutoScaling.9 | `CF-ASG-005` | `AWS::AutoScaling::AutoScalingGroup` |
| CloudFront.1 | `CF-CF-008` | `AWS::CloudFront::Distribution` |
| CloudFront.3 | `CF-CF-001` | `AWS::CloudFront::Distribution` |
| CloudFront.4 | `CF-CF-009` | `AWS::CloudFront::Distribution` |
| CloudFront.5 | `CF-CF-005` | `AWS::CloudFront::Distribution` |
| CloudFront.6 | `CF-CF-003` | `AWS::CloudFront::Distribution` |
| CloudFront.8 | `CF-CF-012` | `AWS::CloudFront::Distribution` |
| CloudFront.9 | `CF-CF-010` | `AWS::CloudFront::Distribution` |
| CloudFront.10 | `CF-CF-011` | `AWS::CloudFront::Distribution` |
| CloudFront.13 | `CF-CF-004` | `AWS::CloudFront::Distribution` |
| CloudFront.15 | `CF-CF-002` | `AWS::CloudFront::Distribution` |
| CloudTrail.1 | `CF-CT-002` | `AWS::CloudTrail::Trail` |
| CloudTrail.2 | `CF-CT-003` | `AWS::CloudTrail::Trail` |
| CloudTrail.4 | `CF-CT-001` | `AWS::CloudTrail::Trail` |
| CloudTrail.5 | `CF-CT-004` | `AWS::CloudTrail::Trail` |
| CodeBuild.1 | `CF-CB-002` | `AWS::CodeBuild::Project` |
| CodeBuild.2 | `CF-CB-001` | `AWS::CodeBuild::Project` |
| CodeBuild.3 | `CF-CB-005` | `AWS::CodeBuild::Project` |
| CodeBuild.4 | `CF-CB-004` | `AWS::CodeBuild::Project` |
| Cognito.1 | `CF-COG-003` | `AWS::Cognito::UserPool` |
| Config.1 | `CF-CFG-001` | `AWS::Config::ConfigurationRecorder` |
| DataFirehose.1 | `CF-FH-001` | `AWS::KinesisFirehose::DeliveryStream` |
| DMS.1 | `CF-DMS-001` | `AWS::DMS::ReplicationInstance` |
| DMS.6 | `CF-DMS-002` | `AWS::DMS::ReplicationInstance` |
| DMS.9 | `CF-DMS-003` | `AWS::DMS::Endpoint` |
| DMS.13 | `CF-DMS-004` | `AWS::DMS::ReplicationInstance` |
| DocumentDB.1 | `CF-DOCDB-001` | `AWS::DocDB::DBCluster` |
| DocumentDB.2 | `CF-DOCDB-002` | `AWS::DocDB::DBCluster` |
| DocumentDB.4 | `CF-DOCDB-003` | `AWS::DocDB::DBCluster` |
| DocumentDB.5 | `CF-DOCDB-004` | `AWS::DocDB::DBCluster` |
| DynamoDB.1 | `CF-DDB-003` | `AWS::DynamoDB::Table` |
| DynamoDB.2 | `CF-DDB-001` | `AWS::DynamoDB::Table` |
| DynamoDB.6 | `CF-DDB-004` | `AWS::DynamoDB::Table` |
| EC2.3 | `CF-EBS-001` | `AWS::EC2::Volume` |
| EC2.6 | `CF-FL-001` | `AWS::EC2::VPC` |
| EC2.8 | `CF-EC2-001` | `AWS::EC2::Instance`, `AWS::EC2::LaunchTemplate` |
| EC2.9 | `CF-EC2-003` | `AWS::EC2::Instance` |
| EC2.13 | `CF-SG-001` | `AWS::EC2::SecurityGroup` |
| EC2.14 | `CF-SG-001` | `AWS::EC2::SecurityGroup` |
| EC2.15 | `CF-EC2-002` | `AWS::EC2::Subnet` |
| EC2.18 | `CF-SG-002` | `AWS::EC2::SecurityGroup` |
| EC2.19 | `CF-SG-001` | `AWS::EC2::SecurityGroup` |
| EC2.21 | `CF-NACL-001` | `AWS::EC2::NetworkAclEntry` |
| EC2.23 | `CF-TGW-001` | `AWS::EC2::TransitGateway` |
| ECR.1 | `CF-ECR-001` | `AWS::ECR::Repository` |
| ECR.2 | `CF-ECR-002` | `AWS::ECR::Repository` |
| ECR.3 | `CF-ECR-003` | `AWS::ECR::Repository` |
| ECS.1 | `CF-ECS-004` | `AWS::ECS::TaskDefinition` |
| ECS.2 | `CF-ECS-005` | `AWS::ECS::Service` |
| ECS.3 | `CF-ECS-006` | `AWS::ECS::TaskDefinition` |
| ECS.4 | `CF-ECS-001` | `AWS::ECS::TaskDefinition` |
| ECS.5 | `CF-ECS-002` | `AWS::ECS::TaskDefinition` |
| ECS.8 | `CF-ECS-007` | `AWS::ECS::TaskDefinition` |
| ECS.9 | `CF-ECS-008` | `AWS::ECS::TaskDefinition` |
| ECS.10 | `CF-ECS-009` | `AWS::ECS::Service` |
| ECS.12 | `CF-ECS-010` | `AWS::ECS::Cluster` |
| EFS.1 | `CF-EFS-001` | `AWS::EFS::FileSystem` |
| EFS.2 | `CF-BAK-005` | `AWS::EFS::FileSystem` |
| EFS.3 | `CF-EFS-004` | `AWS::EFS::AccessPoint` |
| EFS.4 | `CF-EFS-005` | `AWS::EFS::AccessPoint` |
| EFS.7 | `CF-EFS-002` | `AWS::EFS::FileSystem` |
| EKS.1 | `CF-EKS-002` | `AWS::EKS::Cluster` |
| EKS.2 | `CF-EKS-004` | `AWS::EKS::Cluster` |
| EKS.3 | `CF-EKS-003` | `AWS::EKS::Cluster` |
| EKS.8 | `CF-EKS-001` | `AWS::EKS::Cluster` |
| ElastiCache.1 | `CF-EC-004` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.2 | `CF-EC-005` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.3 | `CF-EC-003` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.4 | `CF-EC-001` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.5 | `CF-EC-002` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.6 | `CF-EC-006` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.7 | `CF-EC-007` | `AWS::ElastiCache::ReplicationGroup` |
| ElasticBeanstalk.1 | `CF-BEANSTALK-001` | `AWS::ElasticBeanstalk::Environment` |
| ElasticBeanstalk.2 | `CF-BEANSTALK-002` | `AWS::ElasticBeanstalk::Environment` |
| ElasticBeanstalk.3 | `CF-BEANSTALK-003` | `AWS::ElasticBeanstalk::Environment` |
| ELB.1 | `CF-ALB-002` | `AWS::ElasticLoadBalancingV2::Listener` |
| ELB.2 | `CF-CLB-002` | `AWS::ElasticLoadBalancing::LoadBalancer` |
| ELB.3 | `CF-CLB-001` | `AWS::ElasticLoadBalancing::LoadBalancer` |
| ELB.4 | `CF-ALB-004` | `AWS::ElasticLoadBalancingV2::LoadBalancer` |
| ELB.5 | `CF-ALB-001` | `AWS::ElasticLoadBalancingV2::LoadBalancer` (CF-CLB-003 for `AWS::ElasticLoadBalancing::LoadBalancer`) |
| ELB.6 | `CF-ALB-005` | `AWS::ElasticLoadBalancingV2::LoadBalancer` |
| ELB.7 | `CF-CLB-005` | `AWS::ElasticLoadBalancing::LoadBalancer` |
| ELB.9 | `CF-CLB-004` | `AWS::ElasticLoadBalancing::LoadBalancer` |
| ELB.12 | `CF-ALB-006` | `AWS::ElasticLoadBalancingV2::LoadBalancer` |
| EMR.1 | `CF-EMR-001` | `AWS::EMR::Cluster` |
| EMR.3 | `CF-EMR-002` | `AWS::EMR::SecurityConfiguration` |
| EMR.4 | `CF-EMR-003` | `AWS::EMR::SecurityConfiguration` |
| FSx.1 | `CF-FSX-002` | `AWS::FSx::FileSystem` |
| FSx.2 | `CF-FSX-002` | `AWS::FSx::FileSystem` |
| IAM.1 | `CF-IAM-008` | `AWS::IAM::Role`, `AWS::IAM::User`, `AWS::IAM::Group`, `AWS::IAM::ManagedPolicy` |
| IAM.21 | `CF-IAM-002` | `AWS::IAM::ManagedPolicy`, `AWS::IAM::Policy` |
| Kinesis.1 | `CF-KIN-001` | `AWS::Kinesis::Stream` |
| KMS.4 | `CF-KMS-002` | `AWS::KMS::Key` |
| Lambda.1 | `CF-RP-001` | `AWS::Lambda::Permission` |
| Lambda.2 | `CF-LAM-003` | `AWS::Lambda::Function` |
| Lambda.5 | `CF-LAM-008` | `AWS::Lambda::Function` |
| MSK.1 | `CF-MSK-001` | `AWS::MSK::Cluster` |
| MSK.4 | `CF-MSK-003` | `AWS::MSK::Cluster` |
| MSK.6 | `CF-MSK-002` | `AWS::MSK::Cluster` |
| Neptune.1 | `CF-NEP-001` | `AWS::Neptune::DBCluster` |
| Neptune.2 | `CF-NEP-002` | `AWS::Neptune::DBCluster` |
| Neptune.4 | `CF-NEP-003` | `AWS::Neptune::DBCluster` |
| Neptune.5 | `CF-NEP-004` | `AWS::Neptune::DBCluster` |
| Neptune.7 | `CF-NEP-005` | `AWS::Neptune::DBCluster` |
| Opensearch.1 | `CF-OS-001` | `AWS::OpenSearchService::Domain` |
| Opensearch.2 | `CF-OS-003` | `AWS::OpenSearchService::Domain` |
| Opensearch.3 | `CF-OS-002` | `AWS::OpenSearchService::Domain` |
| Opensearch.4 | `CF-OS-006` | `AWS::OpenSearchService::Domain` |
| Opensearch.5 | `CF-OS-006` | `AWS::OpenSearchService::Domain` |
| Opensearch.6 | `CF-OS-007` | `AWS::OpenSearchService::Domain` |
| Opensearch.7 | `CF-OS-004` | `AWS::OpenSearchService::Domain` |
| Opensearch.8 | `CF-OS-005` | `AWS::OpenSearchService::Domain` |
| RDS.2 | `CF-RDS-004` | `AWS::RDS::DBInstance` |
| RDS.3 | `CF-RDS-001` | `AWS::RDS::DBInstance` |
| RDS.5 | `CF-RDS-003` | `AWS::RDS::DBInstance` |
| RDS.6 | `CF-RDS-007` | `AWS::RDS::DBInstance` |
| RDS.7 | `CF-RDS-005` | `AWS::RDS::DBCluster` |
| RDS.8 | `CF-RDS-005` | `AWS::RDS::DBInstance` |
| RDS.9 | `CF-RDS-011` | `AWS::RDS::DBInstance` |
| RDS.10 | `CF-RDS-008` | `AWS::RDS::DBInstance` |
| RDS.11 | `CF-RDS-002` | `AWS::RDS::DBInstance` |
| RDS.12 | `CF-RDS-008` | `AWS::RDS::DBCluster` |
| RDS.13 | `CF-RDS-009` | `AWS::RDS::DBInstance` |
| RDS.16 | `CF-RDS-010` | `AWS::RDS::DBCluster` |
| RDS.17 | `CF-RDS-010` | `AWS::RDS::DBInstance` |
| RDS.23 | `CF-RDS-012` | `AWS::RDS::DBInstance`, `AWS::RDS::DBCluster` |
| RDS.24 | `CF-RDS-013` | `AWS::RDS::DBCluster` |
| RDS.25 | `CF-RDS-013` | `AWS::RDS::DBInstance` |
| RDS.27 | `CF-RDS-001` | `AWS::RDS::DBCluster` |
| Redshift.1 | `CF-RS-002` | `AWS::Redshift::Cluster` |
| Redshift.3 | `CF-RS-003` | `AWS::Redshift::Cluster` |
| Redshift.4 | `CF-RS-004` | `AWS::Redshift::Cluster` |
| Redshift.6 | `CF-RS-005` | `AWS::Redshift::Cluster` |
| Redshift.7 | `CF-RS-006` | `AWS::Redshift::Cluster` |
| Redshift.8 | `CF-RS-007` | `AWS::Redshift::Cluster` |
| Redshift.10 | `CF-RS-001` | `AWS::Redshift::Cluster` |
| Route53.2 | `CF-R53-001` | `AWS::Route53::HostedZone` |
| S3.5 | `CF-S3-005` | `AWS::S3::BucketPolicy` |
| S3.7 | `CF-S3-010` | `AWS::S3::Bucket` |
| S3.8 | `CF-S3-001` | `AWS::S3::Bucket` |
| S3.9 | `CF-S3-004` | `AWS::S3::Bucket` |
| S3.12 | `CF-S3-008` | `AWS::S3::Bucket` |
| S3.14 | `CF-S3-003` | `AWS::S3::Bucket` |
| SageMaker.1 | `CF-SAGE-001` | `AWS::SageMaker::NotebookInstance` |
| SageMaker.2 | `CF-SAGE-002` | `AWS::SageMaker::NotebookInstance` |
| SageMaker.3 | `CF-SAGE-003` | `AWS::SageMaker::NotebookInstance` |
| SageMaker.4 | `CF-SAGE-005` | `AWS::SageMaker::EndpointConfig` |
| SecretsManager.1 | `CF-SM-001` | `AWS::SecretsManager::Secret` |
| SNS.1 | `CF-SNS-001` | `AWS::SNS::Topic` |
| SQS.1 | `CF-SQS-001` | `AWS::SQS::Queue` |
| StepFunctions.1 | `CF-SFN-003` | `AWS::StepFunctions::StateMachine` |
| Transfer.2 | `CF-TRANSFER-001` | `AWS::Transfer::Server` |
