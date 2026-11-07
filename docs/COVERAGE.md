# Rule coverage

Which CDK rules have a template check, and which AWS Foundational Security Best Practices (FSBP) controls a template check covers. `tests/test_coverage_doc.py` keeps both tables in sync with the code.

## Status

| Status | Meaning |
| -- | -- |
| `covered` | A template check covers the whole CDK rule. In V2 the CDK finding is dropped when the template check reports (`CF_COVERS_STATIC`, or the tag policy for BP-001 and COST-015). |
| `partial` | A template check covers part of the CDK rule, so V2 keeps both (`CF_PARTLY_COVERS_STATIC`). |
| `planned: <work>` | Planned work, listed below, will add the template check. |
| `account` | Needs a live account. A scan of templates cannot see it. |
| `cdk-only` | Reads the CDK code itself, not a resource property. |
| `advice` | No property to read. The answer depends on traffic, usage or design. |

## Planned work

| Work | Adds template checks for |
| -- | -- |
| `network` | Security groups, network ACLs, NAT and Transit Gateway |
| `load-balancers` | Load balancers (ALB, NLB, Classic) |
| `rds` | More RDS and Aurora settings |
| `lambda` | Lambda access, secrets and limits |
| `api-gateway` | API Gateway auth, TLS, throttling and caching |
| `ci-cd` | CodeBuild and CodePipeline |
| `kms-ssm` | KMS key rotation and SSM parameters |
| `search-streaming` | OpenSearch, MSK and Kinesis access and resilience |
| `data-resilience` | DynamoDB, ElastiCache and EFS resilience |
| `warehouses` | Redshift, DocumentDB and Neptune beyond encryption |
| `error-handling` | Step Functions, EventBridge and SQS error handling |
| `backup` | AWS Backup plans, vaults and coverage |
| `containers` | More ECS and EKS settings |
| `auto-scaling` | Auto Scaling groups and launch configurations |
| `analytics` | Athena, Glue and Firehose |
| `emr-dms` | EMR and DMS |
| `s3` | S3 replication, ownership and notifications |
| `cloudfront` | More CloudFront settings |
| `sagemaker-fsx` | SageMaker and FSx |
| `app-services` | AppSync, Transfer Family, App Runner and Elastic Beanstalk |
| `dns-certs` | Route 53, ACM and Global Accelerator |
| `alarms` | Alarms, dashboards and trail integration |
| `account-baseline` | Account baseline resources a repo defines |

## CDK rules

172 rules: 56 covered, 5 partial, 72 planned, 10 account, 5 cdk-only, 24 advice.

| Rule | Title | Template check | Status | Note |
| -- | -- | -- | -- | -- |
| SEC-001 | IAM policy uses wildcard actions | `CF-IAM-001`, `CF-IAM-002`, `CF-IAM-008` | `covered` |  |
| SEC-002 | IAM policy uses wildcard resources | `CF-IAM-003`, `CF-IAM-008` | `covered` |  |
| SEC-003 | Security Group allows SSH from 0.0.0.0/0 | `CF-SG-001` | `covered` |  |
| SEC-004 | Security Group exposes common DB ports to 0.0.0.0/0 | `CF-SG-001` | `covered` |  |
| SEC-005 | S3 bucket may miss Block Public Access | `CF-S3-001` | `covered` |  |
| SEC-006 | S3 bucket encryption explicitly disabled | `CF-S3-002` | `covered` |  |
| SEC-007 | KMS key policy may use wildcard principal | `CF-KMS-001` | `covered` |  |
| SEC-008 | DynamoDB table may miss encryption | `CF-DDB-002` | `covered` |  |
| SEC-009 | API Gateway missing authentication |  | `planned: api-gateway` |  |
| SEC-010 | API Gateway may not enforce TLS 1.2+ |  | `planned: api-gateway` |  |
| SEC-011 | ALB/NLB not enforcing HTTPS redirect |  | `planned: load-balancers` |  |
| SEC-012 | ALB using insecure SSL/TLS policy |  | `planned: load-balancers` |  |
| SEC-013 | SQS queue not encrypted | `CF-SQS-001` | `covered` |  |
| SEC-014 | SNS topic not encrypted | `CF-SNS-001` | `covered` |  |
| SEC-015 | Secrets Manager rotation not enabled | `CF-SM-001` | `covered` |  |
| SEC-016 | Potential hardcoded credentials/secrets in code |  | `cdk-only` | Scans source for secret-looking literals. CF-PAR-001/002 check template parameters. |
| SEC-017 | Lambda environment variables may contain secrets |  | `planned: lambda` |  |
| SEC-018 | CloudFront not enforcing HTTPS | `CF-CF-001` | `covered` |  |
| SEC-019 | CloudFront using legacy SSL/TLS | `CF-CF-002` | `covered` |  |
| SEC-020 | ECS task definition not using read-only root filesystem | `CF-ECS-002` | `covered` |  |
| SEC-021 | RDS not enforcing SSL/TLS connections |  | `planned: rds` |  |
| SEC-022 | VPC endpoints missing (security & cost improvement) | `CF-VPC-001` | `covered` |  |
| SEC-023 | KMS key rotation not enabled |  | `planned: kms-ssm` |  |
| SEC-024 | WAF not enabled on ALB/API Gateway/CloudFront | `CF-CF-003`, `CF-WAF-001` | `covered` |  |
| SEC-025 | ElastiCache not using encryption in-transit/at-rest | `CF-EC-001`, `CF-EC-002` | `covered` |  |
| SEC-026 | Security Hub not enabled |  | `account` | Security Hub is an account service. account-baseline checks a hub the repo defines. |
| SEC-027 | GuardDuty not enabled |  | `account` | GuardDuty is an account service. account-baseline checks a detector the repo defines. |
| SEC-028 | ECR repository image scanning not enabled | `CF-ECR-001` | `covered` |  |
| SEC-029 | ECR image tag immutability not configured | `CF-ECR-002` | `covered` |  |
| SEC-030 | ECR repository lifecycle policy missing | `CF-ECR-003` | `covered` |  |
| SEC-031 | Route 53 health checks not configured |  | `planned: dns-certs` |  |
| SEC-032 | Route 53 DNSSEC not enabled |  | `planned: dns-certs` |  |
| SEC-033 | SSM Parameter Store not using SecureString |  | `planned: kms-ssm` |  |
| SEC-034 | Cognito User Pool MFA not required | `CF-COG-001` | `covered` |  |
| SEC-035 | Cognito User Pool password policy may be weak | `CF-COG-002` | `covered` |  |
| SEC-036 | Cognito advanced security features not enabled | `CF-COG-003` | `covered` |  |
| SEC-037 | EFS encryption not enabled | `CF-EFS-001` | `covered` |  |
| SEC-038 | Kinesis stream encryption not enabled | `CF-KIN-001` | `covered` |  |
| SEC-039 | OpenSearch domain encryption not enabled | `CF-OS-001`, `CF-OS-002` | `covered` |  |
| SEC-040 | OpenSearch fine-grained access control not enabled |  | `planned: search-streaming` |  |
| SEC-041 | OpenSearch domain not in VPC |  | `planned: search-streaming` |  |
| SEC-042 | Athena query result encryption not enabled |  | `planned: analytics` |  |
| SEC-043 | Glue job encryption not configured |  | `planned: analytics` |  |
| SEC-044 | MSK cluster encryption not configured | `CF-MSK-001` | `covered` |  |
| SEC-045 | MSK cluster client authentication not configured |  | `planned: search-streaming` |  |
| SEC-046 | SageMaker notebook instance not in VPC |  | `planned: sagemaker-fsx` |  |
| SEC-047 | SageMaker encryption not enabled |  | `planned: sagemaker-fsx` |  |
| SEC-048 | AppSync API logging not enabled |  | `planned: app-services` |  |
| SEC-049 | AppSync API not protected by WAF |  | `planned: app-services` |  |
| SEC-050 | FSx file system encryption not enabled |  | `planned: sagemaker-fsx` |  |
| SEC-051 | Transfer Family server logging not enabled |  | `planned: app-services` |  |
| SEC-052 | CodePipeline artifact encryption not enabled |  | `planned: ci-cd` |  |
| SEC-053 | CodeBuild project using privileged mode |  | `planned: ci-cd` |  |
| SEC-054 | Security Group egress too permissive (0.0.0.0/0) |  | `planned: network` |  |
| SEC-055 | Network ACLs not configured |  | `planned: network` |  |
| SEC-056 | Stack termination protection not enabled |  | `cdk-only` | Termination protection is a stack setting, not in the template. |
| SEC-057 | Lambda function URL without authentication |  | `planned: lambda` |  |
| SEC-058 | ECS task may run as root user | `CF-ECS-003` | `covered` |  |
| SEC-059 | Redshift cluster encryption not enabled | `CF-RS-001` | `covered` |  |
| SEC-060 | DocumentDB cluster encryption not enabled | `CF-DOCDB-001` | `covered` |  |
| SEC-061 | Neptune database encryption not enabled | `CF-NEP-001` | `covered` |  |
| SEC-062 | CloudWatch Logs not encrypted with KMS | `CF-CW-002` | `covered` |  |
| SEC-063 | Backup vault encryption not configured |  | `planned: backup` |  |
| SEC-064 | RDS instance may be publicly accessible | `CF-RDS-004` | `covered` |  |
| SEC-065 | Amazon Macie not enabled for sensitive data discovery |  | `account` | Macie is an account service. account-baseline checks a session the repo defines. |
| SEC-066 | EC2 instance may not require IMDSv2 | `CF-EC2-001` | `covered` |  |
| SEC-067 | IAM principal has full admin access | `CF-IAM-008` | `covered` |  |
| SEC-068 | Lambda function uses a deprecated runtime | `CF-LAM-003` | `covered` |  |
| REL-001 | RDS may miss Multi-AZ | `CF-RDS-003` | `partial` | Checks DB instances only; REL-001 also flags DatabaseCluster. |
| REL-002 | RDS may miss backup retention | `CF-RDS-002` | `covered` |  |
| REL-003 | Lambda may miss DLQ / on-failure destination | `CF-LAM-001` | `covered` |  |
| REL-004 | DynamoDB may miss point-in-time recovery | `CF-DDB-001` | `covered` |  |
| REL-005 | DynamoDB may miss automated backups |  | `planned: data-resilience` |  |
| REL-006 | API Gateway throttling not configured |  | `planned: api-gateway` |  |
| REL-007 | ALB health check configuration missing |  | `planned: load-balancers` |  |
| REL-008 | SQS missing dead-letter queue configuration | `CF-SQS-002` | `covered` |  |
| REL-009 | Lambda timeout may be too low or too high |  | `planned: lambda` |  |
| REL-010 | Lambda not in VPC when accessing RDS/ElastiCache |  | `advice` | Whether a function needs the VPC depends on what it calls. |
| REL-011 | RDS read replicas missing for read-heavy workloads |  | `advice` | Read replicas depend on read load. |
| REL-012 | NAT Gateway single point of failure (need multi-AZ) |  | `planned: network` |  |
| REL-013 | AWS Backup vault not configured |  | `planned: backup` |  |
| REL-014 | Cross-region backup replication missing |  | `planned: backup` |  |
| REL-015 | Step Functions retry/catch not configured |  | `planned: error-handling` |  |
| REL-016 | ElastiCache not using multi-AZ |  | `planned: data-resilience` |  |
| REL-017 | EFS backup policy not configured |  | `planned: data-resilience` |  |
| REL-018 | EFS lifecycle policy not configured |  | `planned: data-resilience` |  |
| REL-019 | Kinesis stream retention period too short |  | `planned: search-streaming` |  |
| REL-020 | Global Accelerator health checks not configured |  | `planned: dns-certs` |  |
| REL-021 | CodePipeline missing manual approval for production |  | `planned: ci-cd` |  |
| REL-022 | ACM certificate validation method not specified |  | `planned: dns-certs` |  |
| REL-023 | Blue-green deployment not configured for critical services |  | `advice` | Deployment strategy, not a resource property. |
| REL-024 | SQS visibility timeout may need review |  | `planned: error-handling` |  |
| REL-025 | DynamoDB global tables not configured for multi-region |  | `advice` | Global tables depend on multi-Region needs. |
| REL-026 | S3 replication not configured for critical buckets |  | `planned: s3` |  |
| REL-027 | Lambda reserved concurrency not configured for critical functions |  | `planned: lambda` |  |
| REL-028 | API Gateway request validation not configured |  | `planned: api-gateway` |  |
| REL-029 | EventBridge rule retry policy not configured |  | `planned: error-handling` |  |
| REL-030 | RDS deletion protection not enabled | `CF-RDS-005` | `covered` |  |
| REL-031 | S3 bucket versioning not enabled | `CF-S3-003` | `covered` |  |
| COST-001 | Log retention may be infinite (cost risk) | `CF-CW-001` | `covered` |  |
| COST-002 | Compute resources may miss autoscaling |  | `planned: auto-scaling` |  |
| COST-003 | DynamoDB provisioned capacity may miss autoscaling | `CF-DDB-003` | `covered` |  |
| COST-004 | Lambda provisioned concurrency may be overprovisioned |  | `advice` | Provisioned concurrency sizing needs traffic data. |
| COST-005 | RDS not using Reserved Instances (savings opportunity) |  | `account` | Reserved Instances are bought for the account. |
| COST-006 | NAT Gateway incurs data processing costs | `CF-COST-002`, `CF-VPC-002`, `CF-VPC-003` | `covered` |  |
| COST-007 | S3 Intelligent-Tiering not enabled | `CF-S3-007` | `covered` |  |
| COST-008 | EBS volumes using gp2 instead of gp3 | `CF-EBS-002` | `covered` |  |
| COST-009 | ElastiCache may benefit from reserved nodes |  | `account` | Reserved nodes are bought for the account. |
| COST-010 | RDS not using Graviton instances |  | `planned: rds` |  |
| COST-011 | CloudFront using all edge locations (Price Class All) |  | `planned: cloudfront` |  |
| COST-012 | Elastic IP allocated but may not be used | `CF-EIP-001` | `covered` |  |
| COST-013 | S3 lifecycle policy not configured for cost optimization | `CF-S3-006` | `covered` |  |
| COST-014 | AWS Budgets not configured |  | `account` | Budgets are account-level. account-baseline checks a budget the repo defines. |
| COST-015 | Cost allocation tags may not be configured | `CF-TAG-001` | `covered` |  |
| COST-016 | Savings Plans opportunity for compute workloads |  | `account` | Savings Plans are bought for the account. |
| COST-017 | Lambda memory/CPU may not be optimized |  | `advice` | Memory tuning needs invocation data. |
| COST-018 | S3 Storage Lens not enabled |  | `account` | Storage Lens is configured for the account or organization. |
| BP-001 | Standard tags may be missing | `CF-TAG-001` | `covered` |  |
| BP-002 | Using environment variables instead of Secrets Manager |  | `planned: lambda` |  |
| BP-003 | Resource naming convention may not be followed |  | `cdk-only` | Reads construct and resource names in code. |
| BP-004 | CDK Aspects not used for policy enforcement |  | `cdk-only` | Reads CDK Aspects. |
| BP-005 | CDK context not used for environment-specific config |  | `cdk-only` | Reads CDK context. |
| OPS-001 | CloudTrail / audit trail may be missing |  | `account` | A trail is usually an organization or account trail outside the app. CF-CT-001/002/003 check a trail the template defines. |
| OPS-002 | VPC Flow Logs may be missing | `CF-FL-001` | `covered` |  |
| OPS-003 | X-Ray / distributed tracing may be missing | `CF-APIGW-002`, `CF-APIGW-V2-002`, `CF-LAM-002` | `covered` |  |
| OPS-004 | DynamoDB table may benefit from streams for event-driven patterns |  | `advice` | Streams depend on the event design. |
| OPS-005 | API Gateway access logging not enabled | `CF-APIGW-001`, `CF-APIGW-V2-001` | `covered` |  |
| OPS-006 | ALB/NLB access logs not enabled | `CF-ALB-001` | `covered` |  |
| OPS-007 | CloudFront access logging not enabled |  | `planned: cloudfront` |  |
| OPS-008 | ECS container insights not enabled |  | `planned: containers` |  |
| OPS-009 | RDS enhanced monitoring not enabled |  | `planned: rds` |  |
| OPS-010 | CloudWatch alarms not configured for critical resources |  | `planned: alarms` |  |
| OPS-011 | No SNS topics for alarm notifications |  | `planned: alarms` |  |
| OPS-012 | Step Functions not using X-Ray tracing |  | `planned: error-handling` |  |
| OPS-013 | EventBridge rules not using DLQ |  | `planned: error-handling` |  |
| OPS-014 | AWS Config not enabled |  | `account` | AWS Config is an account service. account-baseline checks a recorder the repo defines. |
| OPS-015 | Glue job CloudWatch metrics not enabled |  | `planned: analytics` |  |
| OPS-016 | Transit Gateway flow logs not enabled |  | `planned: network` |  |
| OPS-017 | CodePipeline notifications not configured |  | `planned: ci-cd` |  |
| OPS-018 | App Runner observability not configured |  | `planned: app-services` |  |
| OPS-019 | Glue job bookmarks not enabled |  | `planned: analytics` |  |
| OPS-020 | CodeBuild project logging not configured |  | `planned: ci-cd` |  |
| OPS-021 | CloudWatch dashboards not configured |  | `planned: alarms` |  |
| OPS-022 | Resource tagging strategy may be incomplete |  | `advice` | Tag choice. CF-TAG-001 checks a configured tag policy. |
| OPS-023 | SSM Parameter Store not using advanced tier for high throughput |  | `planned: kms-ssm` |  |
| OPS-025 | S3 replication metrics not enabled |  | `planned: s3` |  |
| PERF-001 | Compute may not use Graviton/ARM (cost and performance) | `CF-PERF-001` | `partial` | Checks Lambda only; PERF-001 also flags EC2 and ECS. |
| PERF-002 | No caching layer detected (performance) | `CF-PERF-002` | `partial` | API Gateway and Lambda only; PERF-002 also counts load balancers, API caches and DAX. |
| PERF-003 | DynamoDB table may use provisioned capacity (consider on-demand) |  | `advice` | On-demand versus provisioned depends on traffic. |
| PERF-004 | API Gateway caching not enabled |  | `planned: api-gateway` |  |
| PERF-005 | Lambda memory not optimized (too low/high) |  | `advice` | Memory tuning needs invocation data. |
| PERF-006 | CloudFront caching strategy not optimized |  | `planned: cloudfront` |  |
| PERF-007 | ECS task sizing (CPU/memory) may need review |  | `planned: containers` |  |
| PERF-008 | RDS instance class may be oversized | `CF-PERF-003`, `CF-PERF-004` | `partial` | CF-PERF-003 checks RDS and CF-PERF-004 checks EC2; PERF-008 matches any large instanceType. |
| PERF-009 | Kinesis enhanced fan-out not used |  | `advice` | Enhanced fan-out depends on consumer count. |
| PERF-010 | OpenSearch instance types not optimized |  | `advice` | Instance choice depends on the workload. |
| PERF-011 | Global Accelerator not used for global traffic |  | `advice` | Global Accelerator depends on where users are. |
| PERF-012 | EFS performance mode not configured |  | `advice` | Performance mode depends on the workload. |
| PERF-013 | AppSync API caching not enabled |  | `planned: app-services` |  |
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
| SUST-006 | CloudFront compression not enabled |  | `planned: cloudfront` |  |
| SUST-007 | Latest generation instance types not used | `CF-GEN-001` | `covered` |  |

## FSBP controls

Controls a template can show. Account-level controls (for example S3.1, EC2.7 and IAM password policy controls) are not listed.

| Control | Check | Resource type |
| -- | -- | -- |
| ACM.2 | `planned: dns-certs` | `AWS::CertificateManager::Certificate` |
| APIGateway.2 | `planned: api-gateway` | `AWS::ApiGateway::Stage` |
| APIGateway.3 | `CF-APIGW-002` | `AWS::ApiGateway::Stage` |
| APIGateway.5 | `planned: api-gateway` | `AWS::ApiGateway::Stage` |
| APIGateway.8 | `planned: api-gateway` | `AWS::ApiGatewayV2::Route` |
| APIGateway.9 | `CF-APIGW-V2-001` | `AWS::ApiGatewayV2::Stage` |
| AppSync.2 | `planned: app-services` | `AWS::AppSync::GraphQLApi` |
| AppSync.5 | `planned: app-services` | `AWS::AppSync::GraphQLApi` |
| AutoScaling.1 | `planned: auto-scaling` | `AWS::AutoScaling::AutoScalingGroup` |
| AutoScaling.2 | `planned: auto-scaling` | `AWS::AutoScaling::AutoScalingGroup` |
| AutoScaling.3 | `planned: auto-scaling` | `AWS::AutoScaling::LaunchConfiguration` |
| AutoScaling.5 | `planned: auto-scaling` | `AWS::AutoScaling::LaunchConfiguration` |
| AutoScaling.9 | `planned: auto-scaling` | `AWS::AutoScaling::AutoScalingGroup` |
| CloudFront.1 | `planned: cloudfront` | `AWS::CloudFront::Distribution` |
| CloudFront.3 | `CF-CF-001` | `AWS::CloudFront::Distribution` |
| CloudFront.4 | `planned: cloudfront` | `AWS::CloudFront::Distribution` |
| CloudFront.5 | `planned: cloudfront` | `AWS::CloudFront::Distribution` |
| CloudFront.6 | `CF-CF-003` | `AWS::CloudFront::Distribution` |
| CloudFront.8 | `planned: cloudfront` | `AWS::CloudFront::Distribution` |
| CloudFront.9 | `planned: cloudfront` | `AWS::CloudFront::Distribution` |
| CloudFront.10 | `planned: cloudfront` | `AWS::CloudFront::Distribution` |
| CloudFront.13 | `CF-CF-004` | `AWS::CloudFront::Distribution` |
| CloudFront.15 | `CF-CF-002` | `AWS::CloudFront::Distribution` |
| CloudTrail.1 | `CF-CT-002` | `AWS::CloudTrail::Trail` |
| CloudTrail.2 | `CF-CT-003` | `AWS::CloudTrail::Trail` |
| CloudTrail.4 | `CF-CT-001` | `AWS::CloudTrail::Trail` |
| CloudTrail.5 | `planned: alarms` | `AWS::CloudTrail::Trail` |
| CodeBuild.1 | `planned: ci-cd` | `AWS::CodeBuild::Project` |
| CodeBuild.2 | `planned: ci-cd` | `AWS::CodeBuild::Project` |
| CodeBuild.3 | `planned: ci-cd` | `AWS::CodeBuild::Project` |
| CodeBuild.4 | `planned: ci-cd` | `AWS::CodeBuild::Project` |
| CodeBuild.5 | `planned: ci-cd` | `AWS::CodeBuild::Project` |
| Cognito.1 | `CF-COG-003` | `AWS::Cognito::UserPool` |
| Config.1 | `planned: account-baseline` | `AWS::Config::ConfigurationRecorder` |
| DataFirehose.1 | `planned: analytics` | `AWS::KinesisFirehose::DeliveryStream` |
| DMS.1 | `planned: emr-dms` | `AWS::DMS::ReplicationInstance` |
| DMS.6 | `planned: emr-dms` | `AWS::DMS::ReplicationInstance` |
| DMS.9 | `planned: emr-dms` | `AWS::DMS::Endpoint` |
| DocumentDB.1 | `CF-DOCDB-001` | `AWS::DocDB::DBCluster` |
| DocumentDB.2 | `planned: warehouses` | `AWS::DocDB::DBCluster` |
| DocumentDB.4 | `planned: warehouses` | `AWS::DocDB::DBCluster` |
| DocumentDB.5 | `planned: warehouses` | `AWS::DocDB::DBCluster` |
| DynamoDB.1 | `CF-DDB-003` | `AWS::DynamoDB::Table` |
| DynamoDB.2 | `CF-DDB-001` | `AWS::DynamoDB::Table` |
| DynamoDB.6 | `planned: data-resilience` | `AWS::DynamoDB::Table` |
| EC2.3 | `CF-EBS-001` | `AWS::EC2::Volume` |
| EC2.6 | `CF-FL-001` | `AWS::EC2::VPC` |
| EC2.8 | `CF-EC2-001` | `AWS::EC2::Instance`, `AWS::EC2::LaunchTemplate` |
| EC2.9 | `CF-EC2-003` | `AWS::EC2::Instance` |
| EC2.13 | `CF-SG-001` | `AWS::EC2::SecurityGroup` |
| EC2.14 | `CF-SG-001` | `AWS::EC2::SecurityGroup` |
| EC2.15 | `CF-EC2-002` | `AWS::EC2::Subnet` |
| EC2.18 | `planned: network` | `AWS::EC2::SecurityGroup` |
| EC2.19 | `planned: network` | `AWS::EC2::SecurityGroup` |
| EC2.21 | `planned: network` | `AWS::EC2::NetworkAclEntry` |
| EC2.23 | `planned: network` | `AWS::EC2::TransitGateway` |
| ECR.1 | `CF-ECR-001` | `AWS::ECR::Repository` |
| ECR.2 | `CF-ECR-002` | `AWS::ECR::Repository` |
| ECR.3 | `CF-ECR-003` | `AWS::ECR::Repository` |
| ECS.1 | `planned: containers` | `AWS::ECS::TaskDefinition` |
| ECS.2 | `planned: containers` | `AWS::ECS::Service` |
| ECS.3 | `planned: containers` | `AWS::ECS::TaskDefinition` |
| ECS.4 | `CF-ECS-001` | `AWS::ECS::TaskDefinition` |
| ECS.5 | `CF-ECS-002` | `AWS::ECS::TaskDefinition` |
| ECS.8 | `planned: containers` | `AWS::ECS::TaskDefinition` |
| ECS.9 | `planned: containers` | `AWS::ECS::TaskDefinition` |
| ECS.10 | `planned: containers` | `AWS::ECS::Service` |
| ECS.12 | `planned: containers` | `AWS::ECS::Cluster` |
| EFS.1 | `CF-EFS-001` | `AWS::EFS::FileSystem` |
| EFS.2 | `planned: data-resilience` | `AWS::EFS::FileSystem` |
| EFS.3 | `planned: data-resilience` | `AWS::EFS::AccessPoint` |
| EFS.4 | `planned: data-resilience` | `AWS::EFS::AccessPoint` |
| EKS.1 | `CF-EKS-002` | `AWS::EKS::Cluster` |
| EKS.2 | `planned: containers` | `AWS::EKS::Cluster` |
| EKS.3 | `CF-EKS-003` | `AWS::EKS::Cluster` |
| EKS.8 | `CF-EKS-001` | `AWS::EKS::Cluster` |
| ElastiCache.1 | `planned: data-resilience` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.2 | `planned: data-resilience` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.3 | `planned: data-resilience` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.4 | `CF-EC-001` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.5 | `CF-EC-002` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.6 | `planned: data-resilience` | `AWS::ElastiCache::ReplicationGroup` |
| ElastiCache.7 | `planned: data-resilience` | `AWS::ElastiCache::ReplicationGroup` |
| ElasticBeanstalk.1 | `planned: app-services` | `AWS::ElasticBeanstalk::Environment` |
| ElasticBeanstalk.2 | `planned: app-services` | `AWS::ElasticBeanstalk::Environment` |
| ElasticBeanstalk.3 | `planned: app-services` | `AWS::ElasticBeanstalk::Environment` |
| ELB.1 | `planned: load-balancers` | `AWS::ElasticLoadBalancingV2::Listener` |
| ELB.2 | `planned: load-balancers` | `AWS::ElasticLoadBalancing::LoadBalancer` |
| ELB.3 | `planned: load-balancers` | `AWS::ElasticLoadBalancing::LoadBalancer` |
| ELB.4 | `planned: load-balancers` | `AWS::ElasticLoadBalancingV2::LoadBalancer` |
| ELB.5 | `CF-ALB-001` | `AWS::ElasticLoadBalancingV2::LoadBalancer` |
| ELB.6 | `planned: load-balancers` | `AWS::ElasticLoadBalancingV2::LoadBalancer` |
| ELB.7 | `planned: load-balancers` | `AWS::ElasticLoadBalancing::LoadBalancer` |
| ELB.9 | `planned: load-balancers` | `AWS::ElasticLoadBalancing::LoadBalancer` |
| ELB.12 | `planned: load-balancers` | `AWS::ElasticLoadBalancingV2::LoadBalancer` |
| EMR.1 | `planned: emr-dms` | `AWS::EMR::Cluster` |
| EMR.3 | `planned: emr-dms` | `AWS::EMR::SecurityConfiguration` |
| EMR.4 | `planned: emr-dms` | `AWS::EMR::SecurityConfiguration` |
| FSx.1 | `planned: sagemaker-fsx` | `AWS::FSx::FileSystem` |
| IAM.1 | `CF-IAM-008` | `AWS::IAM::Role`, `AWS::IAM::User`, `AWS::IAM::Group`, `AWS::IAM::ManagedPolicy` |
| IAM.21 | `CF-IAM-002` | `AWS::IAM::ManagedPolicy`, `AWS::IAM::Policy` |
| Kinesis.1 | `CF-KIN-001` | `AWS::Kinesis::Stream` |
| KMS.4 | `planned: kms-ssm` | `AWS::KMS::Key` |
| Lambda.1 | `CF-RP-001` | `AWS::Lambda::Permission` |
| Lambda.2 | `CF-LAM-003` | `AWS::Lambda::Function` |
| Lambda.5 | `planned: lambda` | `AWS::Lambda::Function` |
| MSK.1 | `CF-MSK-001` | `AWS::MSK::Cluster` |
| MSK.4 | `planned: search-streaming` | `AWS::MSK::Cluster` |
| Neptune.1 | `CF-NEP-001` | `AWS::Neptune::DBCluster` |
| Neptune.2 | `planned: warehouses` | `AWS::Neptune::DBCluster` |
| Neptune.4 | `planned: warehouses` | `AWS::Neptune::DBCluster` |
| Neptune.5 | `planned: warehouses` | `AWS::Neptune::DBCluster` |
| Neptune.7 | `planned: warehouses` | `AWS::Neptune::DBCluster` |
| Opensearch.1 | `CF-OS-001` | `AWS::OpenSearchService::Domain` |
| Opensearch.2 | `planned: search-streaming` | `AWS::OpenSearchService::Domain` |
| Opensearch.3 | `CF-OS-002` | `AWS::OpenSearchService::Domain` |
| Opensearch.4 | `planned: search-streaming` | `AWS::OpenSearchService::Domain` |
| Opensearch.5 | `planned: search-streaming` | `AWS::OpenSearchService::Domain` |
| Opensearch.6 | `planned: search-streaming` | `AWS::OpenSearchService::Domain` |
| Opensearch.7 | `planned: search-streaming` | `AWS::OpenSearchService::Domain` |
| Opensearch.8 | `planned: search-streaming` | `AWS::OpenSearchService::Domain` |
| RDS.2 | `CF-RDS-004` | `AWS::RDS::DBInstance` |
| RDS.3 | `CF-RDS-001` | `AWS::RDS::DBInstance` |
| RDS.5 | `CF-RDS-003` | `AWS::RDS::DBInstance` |
| RDS.6 | `planned: rds` | `AWS::RDS::DBInstance` |
| RDS.7 | `CF-RDS-005` | `AWS::RDS::DBCluster` |
| RDS.8 | `CF-RDS-005` | `AWS::RDS::DBInstance` |
| RDS.9 | `planned: rds` | `AWS::RDS::DBInstance` |
| RDS.10 | `planned: rds` | `AWS::RDS::DBInstance` |
| RDS.11 | `CF-RDS-002` | `AWS::RDS::DBInstance` |
| RDS.12 | `planned: rds` | `AWS::RDS::DBCluster` |
| RDS.13 | `planned: rds` | `AWS::RDS::DBInstance` |
| RDS.16 | `planned: rds` | `AWS::RDS::DBCluster` |
| RDS.17 | `planned: rds` | `AWS::RDS::DBInstance` |
| RDS.23 | `planned: rds` | `AWS::RDS::DBInstance`, `AWS::RDS::DBCluster` |
| RDS.24 | `planned: rds` | `AWS::RDS::DBCluster` |
| RDS.25 | `planned: rds` | `AWS::RDS::DBInstance` |
| RDS.27 | `CF-RDS-001` | `AWS::RDS::DBCluster` |
| Redshift.1 | `planned: warehouses` | `AWS::Redshift::Cluster` |
| Redshift.3 | `planned: warehouses` | `AWS::Redshift::Cluster` |
| Redshift.4 | `planned: warehouses` | `AWS::Redshift::Cluster` |
| Redshift.6 | `planned: warehouses` | `AWS::Redshift::Cluster` |
| Redshift.7 | `planned: warehouses` | `AWS::Redshift::Cluster` |
| Redshift.8 | `planned: warehouses` | `AWS::Redshift::Cluster` |
| Redshift.9 | `planned: warehouses` | `AWS::Redshift::Cluster` |
| Redshift.10 | `CF-RS-001` | `AWS::Redshift::Cluster` |
| Route53.2 | `planned: dns-certs` | `AWS::Route53::HostedZone` |
| S3.5 | `CF-S3-005` | `AWS::S3::BucketPolicy` |
| S3.7 | planned: s3 | `AWS::S3::Bucket` |
| S3.8 | `CF-S3-001` | `AWS::S3::Bucket` |
| S3.9 | `CF-S3-004` | `AWS::S3::Bucket` |
| S3.11 | planned: s3 | `AWS::S3::Bucket` |
| S3.12 | planned: s3 | `AWS::S3::Bucket` |
| S3.14 | `CF-S3-003` | `AWS::S3::Bucket` |
| SageMaker.1 | `planned: sagemaker-fsx` | `AWS::SageMaker::NotebookInstance` |
| SageMaker.2 | `planned: sagemaker-fsx` | `AWS::SageMaker::NotebookInstance` |
| SageMaker.3 | `planned: sagemaker-fsx` | `AWS::SageMaker::NotebookInstance` |
| SageMaker.4 | `planned: sagemaker-fsx` | `AWS::SageMaker::EndpointConfig` |
| SecretsManager.1 | `CF-SM-001` | `AWS::SecretsManager::Secret` |
| SNS.1 | `CF-SNS-001` | `AWS::SNS::Topic` |
| SQS.1 | `CF-SQS-001` | `AWS::SQS::Queue` |
| StepFunctions.1 | `planned: error-handling` | `AWS::StepFunctions::StateMachine` |
| Transfer.2 | `planned: app-services` | `AWS::Transfer::Server` |
