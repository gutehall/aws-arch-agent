"""Repo-level checks: tests, a pipeline, environments (OPS 5), account guardrails (SEC 1),
incident response (SEC 10), application security (SEC 11), service quotas (REL 1),
VPC address plan (REL 2), idempotent workers (REL 4), reliability testing (REL 12),
observability (OPS 4), deployment risk (OPS 6), change management (REL 8), workload
monitoring (REL 6), demand and impairment scaling (REL 7), backup recovery (REL 9) and
disaster recovery (REL 13).

REPO-006 (the account root user) answers SEC01-BP02 in SEC 1, though it was added with the
SEC 2 checks.

These rules read the repository tree, not one IaC file, so they run the same for CDK,
CloudFormation, and Terraform scans. They walk the whole repo (test directories included,
since tests are what REPO-001 looks for) and skip dependency and build output:
node_modules, cdk.out, .git, dist, build, .venv, venv, .terraform and caches.

Heuristics, kept simple on purpose:

- REPO-001 tests: a code file under a test/, tests/, __tests__/ or spec/ directory, or a
  file named like a test (*.test.ts, *.spec.js, test_*.py, *_test.py, *_test.go,
  *.tftest.hcl), a taskcat config, or cfn-guard rule tests (*_tests.yaml next to *.guard).
- REPO-002 pipeline: a CI config file (GitHub Actions, GitLab CI, CodeBuild buildspec,
  Jenkinsfile, Azure Pipelines, Bitbucket Pipelines, CircleCI, Buildkite, Travis), or a
  CodePipeline declared in the IaC (AWS::CodePipeline::Pipeline, aws_codepipeline,
  codepipeline.Pipeline, pipelines.CodePipeline).
- REPO-003 environments: environment words (rules/environments.py: prod, staging, dev and
  their synonyms) in the paths of IaC files (Terraform, tfvars, CloudFormation templates,
  parameter files), in CDK stack and stage ids, and in cdk.json context keys. Two distinct
  environments pass. Environments built in a loop or from a variable are not seen.
- REPO-004 organization guardrails (an org-level rule, off unless rules.org or
  rules.include): the IaC declares an SCP (AWS::Organizations::Policy,
  aws_organizations_policy, organizations.CfnPolicy, with SERVICE_CONTROL_POLICY named in
  the file or no other policy type named), a Control Tower control or landing zone, an
  organization trail (IsOrganizationTrail / is_organization_trail / isOrganizationTrail
  true), or Organizations accounts or OUs.
- REPO-005 account baseline: when the IaC defines an account (Organizations account,
  Control Tower Account Factory provisioned product, or an AFT aft-account-request module),
  it must also declare a CloudTrail trail, a Config recorder, a GuardDuty detector, a
  Security Hub hub and an IAM Access Analyzer. No account defined, no finding.
- REPO-006 root user: when the IaC defines an account (as for REPO-005), it must also check
  root MFA and root access keys: the AWS Config managed rules ROOT_ACCOUNT_MFA_ENABLED (or
  ROOT_ACCOUNT_HARDWARE_MFA_ENABLED) and IAM_ROOT_ACCESS_KEY_CHECK, a Config conformance
  pack, Security Hub with the CIS or FSBP standard (a hub with default standards on counts,
  as they include both), or an SCP that denies the root user (aws:PrincipalArn
  arn:aws:iam::*:root). No account defined, no finding.

- REPO-007 forensics (org-level): an EventBridge rule (AWS::Events::Rule,
  aws_cloudwatch_event_rule, events.Rule, events.CfnRule) whose file names a security finding
  source (aws.guardduty, aws.securityhub, aws.inspector2, aws.macie, "GuardDuty Finding",
  "Security Hub Findings - Imported"), and a capture action anywhere in the IaC or code:
  CreateSnapshot(s), createSnapshot(s) or create_snapshot(s), or the SSM documents
  AWS-CreateSnapshot, AWS-CreateImage, AWSSupport-CollectEC2* or
  AWSSupport-ContainEC2Instance. The rule and the
  capture are not linked target by target: a Lambda that snapshots for backups counts.
  Amazon Detective (a behavior graph) passes on its own.
- REPO-008 containment (org-level): a security group whose logical id, name, description or
  tags (within a few hundred characters of the declaration) say quarantine, isolation,
  isolate, forensic or containment; or an SSM document or code that contains or revokes:
  AWSSupport-ContainEC2Instance, AWS-DisablePublicAccessForSecurityGroup, an AWS*-Revoke*
  runbook, AWSRevokeOlderSessions or an aws:TokenIssueTime deny, DeleteLoginProfile, or
  UpdateAccessKey with Inactive in the same file.

REPO-004 to REPO-008 match text in IaC files (CDK TypeScript/JavaScript/Python,
CloudFormation JSON/YAML, Terraform), less test files. A resource built from a variable
type, or in a module the repo does not hold, is not seen.

Application security in the pipeline (SEC 11) runs by default:

- REPO-009 dependency scan: the build configs (the CI files REPO-002 knows, CodeBuild
  buildspecs and CDK pipeline steps inline in the IaC, and the package.json scripts those
  run) hold a dependency scan: npm/yarn/pnpm audit, pip-audit, safety, osv-scanner, snyk
  test, trivy fs or repo (with a non-zero --exit-code), grype on a directory (with
  --fail-on), OWASP dependency-check (with a failing CVSS score), cargo audit,
  govulncheck, bundler-audit, the dependency review action, or Amazon Inspector (the scan
  action with a vulnerability_threshold_exceeded gate, or inspector-sbomgen and
  inspector-scan). A scan that cannot fail the build does not count: `|| true`,
  `|| exit 0`, or a continue-on-error, allow_failure, ignore-errors or on-failure: CONTINUE
  key beside the step or a block it sits in. No build config at all also fires.
- REPO-010 artifact scan: when the repo builds container images (a Dockerfile, an ECR
  repository, a CDK image asset, a docker build in CI) they need ECR scan on push, ECR
  registry scanning, Amazon Inspector with ECR, or a CI image scan that can fail; when it
  deploys Lambda functions they need Amazon Inspector with LAMBDA or LAMBDA_CODE, or a
  REPO-009 dependency scan. Neither kind present, no finding.
- REPO-011 central package repository: when the repo has a package manifest, it needs AWS
  CodeArtifact in the IaC, `aws codeartifact login` in a build, or a registry other than
  the public default in .npmrc, .yarnrc(.yml), pip.conf/pip.ini, a requirements index-url,
  a poetry or uv source, Maven or Gradle repositories, or GOPROXY.

Service quotas (REL 1), which are per account and Region:

- REPO-012 quota alarms (org-level, off unless rules.org or rules.include): when the IaC
  uses Lambda functions, Elastic IPs, NAT gateways (resources, or a CDK natGateways of one
  or more) or load balancers, it needs a CloudWatch alarm in a file that names the
  AWS/Usage namespace, SERVICE_QUOTA() metric math, the Quota Monitor for AWS solution, or
  an EventBridge rule on aws.trustedadvisor events. A CDK Vpc that takes the default NAT
  gateways, with no natGateways set, is not seen as using NAT.
- REPO-013 failover headroom: sums the literal limits the IaC declares across the repo
  against the default quotas in DEFAULT_QUOTAS. Lambda reserved concurrency over half of
  the 900 that can be reserved fires, as do Elastic IPs (EIP resources plus a CDK VPC's
  natGateways, which allocate one each) over half of 5. Values from variables, parameters,
  count or for_each, or loops are not summed: each literal counts once where it is written.
  NAT gateways per Availability Zone (quota 5) are not checked: the zone of a NAT gateway
  comes from a subnet reference or from maxAzs and the environment, which a text scan does
  not resolve, and a stack rarely needs more than one per zone.

Network address plan (REL 2):

- REPO-014 overlapping VPC CIDRs: the literal IPv4 CIDRs of VPCs across the repo
  (CloudFormation AWS::EC2::VPC and AWS::EC2::VPCCidrBlock CidrBlock; Terraform aws_vpc
  and aws_vpc_ipv4_cidr_block_association cidr_block, and the cidr of a
  terraform-aws-modules/vpc module; CDK ec2.IpAddresses.cidr(), cidr on ec2.Vpc, and
  cidrBlock on CfnVPC and CfnVPCCidrBlock). Any two declarations whose ranges overlap fire,
  in one file or across stacks and modules, naming both. Files for different environments
  (rules/environments.py words in the path, such as dev and prod) are not compared: those
  networks are not connected. A compiled .js next to its .ts source counts once, and
  cdk.out is not walked. CIDRs from variables, parameters, tfvars or IPAM are not seen.

Idempotent workers (REL 4) runs by default:

- REPO-015 idempotency: when the IaC gives a Lambda function a queue or stream event source
  (AWS::Lambda::EventSourceMapping, aws_lambda_event_source_mapping, CDK SqsEventSource,
  KinesisEventSource, DynamoEventSource, ManagedKafkaEventSource, CfnEventSourceMapping or
  addEventSourceMapping, or a SAM SQS, Kinesis, DynamoDB, MSK or MQ event), the IaC or the
  function code (Python, TypeScript, JavaScript, Java, Kotlin, C#, Go; tests excluded) needs
  one of: Powertools idempotency (Python utilities.idempotency, @idempotent,
  idempotent_function; TypeScript @aws-lambda-powertools/idempotency, makeIdempotent; the
  Java and .NET packages, @Idempotent, [Idempotent]), SQS FIFO content-based deduplication
  or a MessageDeduplicationId, or a conditional write (attribute_not_exists in a file with
  a ConditionExpression). It is repo-wide: one control anywhere passes every worker, and
  function code outside the repo is not seen.

Reliability testing (REL 12) runs by default and reads the IaC and the builds REPO-009 reads
(CI configs, inline buildspecs, CodeBuild projects and pipelines in the IaC, and the
package.json scripts they run):

- REPO-016 fault injection: an AWS FIS experiment template in the IaC
  (AWS::FIS::ExperimentTemplate, aws_fis_experiment_template, fis.CfnExperimentTemplate),
  or a build that starts an experiment (aws fis start-experiment) or runs a chaos tool
  (Litmus, Chaos Mesh, Gremlin, Chaos Toolkit). What the template targets is not read.
- REPO-017 load test: a build runs a load test tool (k6 run, artillery run, locust
  --headless, jmeter -n, Gatling, vegeta attack, hey or ab with a request count, Taurus, or
  Distributed Load Testing on AWS). A load test script or config (a k6 script,
  artillery.yml, locustfile.py) that no build runs does not count.

Observability (OPS 4) runs by default and reads the IaC and the function code outside tests:

- REPO-018 application KPI: when the IaC runs compute (Lambda, ECS service, EKS, EC2 or
  Auto Scaling, App Runner), a CloudWatch alarm, metric or metric filter in a namespace
  outside AWS/, or embedded metric format, PutMetricData or Powertools Metrics in the code.
- REPO-019 user experience: when the IaC has an edge (API Gateway, load balancer,
  CloudFront), a Synthetics canary, a RUM app monitor, a Route 53 health check, or an alarm
  on an edge latency or 5xx metric.
- REPO-020 dependency telemetry: when the IaC has a datastore or queue (DynamoDB, RDS,
  ElastiCache, SQS, SNS, Kinesis, OpenSearch), AWS SDK tracing in the code (X-Ray, Powertools
  Tracer, OpenTelemetry), the ADOT Lambda layer or Application Signals, or an alarm on a
  datastore or queue metric. Which dependency an alarm or trace covers is not matched.

Deployment risk (OPS 6) runs by default and reads the builds REPO-009 reads and the IaC:

- REPO-021 test gate: each build config that deploys (cdk deploy, terraform apply, aws
  cloudformation deploy or a stack or change set call, sam, serverless or copilot deploy, an
  ECS service or Lambda code update, a CodePipeline deploy action, a CDK pipelines stage)
  runs a test that can fail (npm test, jest, vitest, pytest, tox, go test, terraform test,
  taskcat, cfn-guard, mvn, gradle, dotnet, cargo or make test, a CodePipeline test action)
  before its last deploy, so a test between a staging and a production deploy gates the
  promotion. A package.json script a build runs counts at the place it is run. A test whose
  failure is swallowed (|| true, continue-on-error, allow_failure) is not a gate. A test in
  a separate workflow from the deploy is not seen as a gate.
- REPO-022 automated rollback: when the IaC runs compute (as REPO-018), an ECS deployment
  circuit breaker or deployment alarms with rollback, CodeDeploy automatic rollback (CDK
  deployment groups roll back by default), a SAM deployment preference, CloudFormation
  rollback triggers, a CodePipeline stage that rolls back on failure, an Auto Scaling
  instance refresh or rolling update that rolls back, or an Argo Rollouts Rollout or Flagger
  Canary manifest. It is repo-wide: one control passes every compute resource. A
  CloudFormation stack's own rollback on a failed resource does not count.

Change management (REL 8) runs by default and reads the builds REPO-009 reads and the IaC:

- REPO-023 in-place change: fires only when the repo changes running instances instead of
  replacing them: a build (or a package.json script it runs) that runs ssh, scp or rsync to
  a user@host, ansible-playbook, aws ssm send-command, or aws deploy create-deployment when
  the IaC declares no blue/green, ECS or Lambda CodeDeploy group; a CodeDeploy deployment
  group that deploys in place (DeploymentType IN_PLACE, or no deployment style on the Server
  platform; a CDK ServerDeploymentGroup); an SSM association that runs AWS-RunShellScript,
  AWS-RunPowerShellScript or AWS-ApplyAnsiblePlaybooks; or cfn-hup. Lambda versions, ECS
  task definitions and launch templates replace and never fire.
- REPO-024 functional test: each build config that deploys (as REPO-021) runs a test that
  can fail after a deploy, and before the last deploy when it deploys more than once
  (staging, test, production): the REPO-021 tests, curl with a fail flag against a URL,
  newman run, playwright test, cypress run, an integ, e2e or smoke package script,
  integ-runner, a CodePipeline test action after the deploy, or a CDK pipelines post step.
- REPO-025 automated deploy: when the repo holds IaC (Terraform, CloudFormation templates,
  CDK code or cdk.json), a build config deploys it (the REPO-021 deploy commands, in the
  build or the package.json scripts it runs) or the IaC declares a CodePipeline or CDK
  pipelines. A pipeline is the automated runbook for a deploy.
- REPO-026 resiliency test: when a build deploys, a deploying build (or the package.json
  scripts it runs) starts an AWS FIS experiment or runs a chaos tool (as REPO-016), or the
  IaC has a Step Functions task that starts an FIS experiment. An experiment template that
  no build starts does not count.

Telemetry analysis (OPS 8) runs by default and reads the IaC with the OPS 4 telemetry model:

- REPO-027 workload alarms: when the IaC runs compute (as REPO-018), a CloudWatch alarm on a
  workload metric: a namespace outside AWS/ (a KPI), an edge latency or 5xx metric, a
  datastore or queue metric (as REPO-019 and REPO-020), or a CloudWatch anomaly detector or
  anomaly detection band alarm. Alarms only on host metrics (CPU, memory, network, disk) or
  no alarm at all fire; the evidence says which.
- REPO-028 log analysis: when the IaC runs compute, a CloudWatch Logs metric filter, a
  Contributor Insights rule, a Logs Insights saved query, a log anomaly detector, or a
  subscription filter that ships the logs to analysis.
- REPO-029 trace analysis: when the IaC runs compute, an X-Ray group or sampling rule,
  CloudWatch Application Signals (a service level objective or discovery), or an alarm on an
  Application Signals or X-Ray metric. Active tracing alone collects traces; it does not
  analyze them.
- REPO-030 dashboard content: only when the IaC declares a CloudWatch dashboard. It fires
  when the dashboards show host metrics (CPU, memory, network, disk) and no dashboard shows a
  workload metric (a namespace outside AWS/, an edge latency or 5xx metric, a datastore or
  queue metric, Application Signals or X-Ray). A dashboard whose metrics are not readable in
  the IaC is not judged. No dashboard at all is OPS-021 and CF-DASH-001.

Permission guardrails and emergency access (SEC 3). Principal `*` on a resource policy is
CF-RP-001 and CF-KMS-001; these two read the rest:

- REPO-031 permission boundary: when the IaC declares an IAM role or user (CloudFormation
  `Type: AWS::IAM::Role` or `AWS::IAM::User`, Terraform aws_iam_role or aws_iam_user, CDK
  iam.Role or iam.User), it needs a permissions boundary somewhere in the repo
  (PermissionsBoundary on a role or user, permissions_boundary in Terraform, CDK
  permissionsBoundary or PermissionsBoundary.of(), the @aws-cdk/core:permissionsBoundary
  context in cdk.json), or a service control policy (as REPO-004 finds it). One boundary
  anywhere passes every role: which role it sits on is not matched.
- REPO-032 break-glass role (an org-level rule, off unless rules.org or rules.include): an
  IAM role or IAM Identity Center permission set whose logical id, resource name or name
  (within a few hundred characters of the declaration) says break-glass or emergency access.
  It also fires when a workload resource uses that role every day: a Role, Roles,
  ExecutionRoleArn, TaskRoleArn or ServiceRoleArn property (role, role_arn,
  execution_role_arn, task_role_arn, executionRole, taskRole in Terraform and CDK) that
  names it.

Correlated security findings (SEC 4):

- REPO-033 finding destination: when the IaC turns on a detector (a GuardDuty detector, an
  AWS Config recorder or rule, Amazon Inspector, Amazon Macie, or IAM Access Analyzer), the
  findings need one place to meet: Security Hub or Amazon Security Lake in the IaC, or an
  EventBridge rule with a target in a file that names the detector's event source
  (aws.guardduty, aws.config, aws.inspector2, aws.macie, aws.access-analyzer). It names each
  detector whose findings go nowhere. Security Hub off by itself, with no detector in the
  repo, is SEC-026 (an org-level rule).

Network protection (SEC 5):

- REPO-034 egress inspection: when the IaC gives a VPC a path out to the internet (a NAT
  gateway, an internet gateway, or a CDK ec2.Vpc that keeps its default NAT gateways), it
  needs inspection: AWS Network Firewall, a Route 53 Resolver DNS Firewall rule group
  association, or a Gateway Load Balancer endpoint for third-party appliances.
- REPO-035 automated protection: when the IaC has an edge (as REPO-019) or an egress path
  (as REPO-034), it needs protection that updates itself: a WAF rule using an AWS managed
  rule group, Shield Advanced protection, a Firewall Manager policy, AWS managed threat
  signatures in Network Firewall, or AWS managed domain lists in DNS Firewall.
- REPO-036 workloads in public subnets: a workload placed in a public subnet. CDK: a
  construct other than a load balancer, NAT or VPC endpoint given vpcSubnets (vpc_subnets) of
  SubnetType.PUBLIC. Terraform and CloudFormation: a resource other than a load balancer, NAT
  gateway, route, network ACL, endpoint or firewall that names a subnet whose
  map_public_ip_on_launch (MapPublicIpOnLaunch) is true. A subnet id from a variable,
  parameter or lookup is not resolved.

Compute integrity (SEC 6):

- REPO-037 signed code: when the IaC deploys Lambda functions, a code signing config
  (AWS::Lambda::CodeSigningConfig, aws_lambda_code_signing_config, CDK CodeSigningConfig or
  codeSigningConfig, CodeSigningConfigArn); when it deploys container images (ECS task
  definitions, Lambda container images, EKS), an AWS Signer profile for Notation, or a build
  that runs notation sign or cosign sign. Each kind with no signing is named.
- REPO-038 pinned images: a container image referenced by a mutable tag. CloudFormation Image
  and ImageUri values, Terraform image and image_uri strings, and CDK
  ContainerImage.fromRegistry with no tag or :latest, fromEcrRepository and
  DockerImageCode.fromEcr with no tag or digest. A digest (@sha256:) or a version tag is
  pinned; CDK fromAsset is pinned by its content hash. Images built from a variable or
  parameter are not judged.

Data classification (SEC 7):

- REPO-039 classification tag: each IaC file that declares a data store (S3 bucket,
  DynamoDB table, RDS or Aurora, ElastiCache, OpenSearch, EFS, Redshift, DocumentDB,
  Neptune, Kinesis stream) needs a classification tag key in it (DataClassification,
  data-classification, data_classification, Classification, Confidentiality or
  Sensitivity, in any case), unless the whole app is tagged: CDK Tags.of(app), Tags.of(this)
  or Tags.of(scope) adding such a key, or a Terraform provider default_tags block holding it.
- REPO-040 controls by sensitivity: a file whose classification tag value is high
  (confidential, restricted, secret, sensitive, PII, PHI, PCI) needs a customer managed KMS
  key on its stores (KmsKeyId, KMSMasterKeyID, kms_key_id, kms_master_key_id, kms_key_arn,
  encryptionKey, encryption_key, a CDK BucketEncryption.KMS or TableEncryption
  .CUSTOMER_MANAGED). The per-resource encryption and public access checks still apply to
  every store; this adds the stricter key for the sensitive ones.

Data at rest (SEC 8):

- REPO-041 preventive encryption control: when the IaC declares a data store (as REPO-039)
  or an EBS volume, something must stop an unencrypted one from being created, not only
  report it later: EBS encryption by default (aws_ebs_encryption_by_default, the
  EnableEbsEncryptionByDefault call), a service control policy or bucket policy that denies
  on an encryption condition key (s3:x-amz-server-side-encryption, ec2:Encrypted,
  rds:StorageEncrypted, elasticfilesystem:Encrypted), an AWS Config encryption rule
  (ENCRYPTED_VOLUMES, RDS_STORAGE_ENCRYPTED, S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED,
  EFS_ENCRYPTED_CHECK, DYNAMODB_TABLE_ENCRYPTED_KMS and the like), CDK Nag aspects, or a
  policy-as-code scan in a build (checkov, tfsec, trivy config, cfn-guard validate, KICS).

Failure interactions (REL 5) run by default, and only when the IaC runs compute (as
REPO-018). Throttling, retries, fail fast and timeouts (REL05-BP02 to BP05) are per-resource
checks; these read the repo:

- REPO-042 local state: fires only on evidence of state kept on the compute's own disk: an
  EBS volume attachment (AWS::EC2::VolumeAttachment, aws_volume_attachment,
  CfnVolumeAttachment, grantAttachVolume), a block device on a non-root device name (other
  than /dev/xvda, /dev/sda1, /dev/sda, /dev/nvme0n1) or a Terraform ebs_block_device, an ECS
  host volume (SourcePath, sourcePath, host_path), an autoprovisioned shared Docker volume,
  or a Kubernetes hostPath. Each place is named by file and line. Lambda ephemeral storage
  above 512 MB is not judged: /tmp lives only as long as the execution environment, so it
  is scratch space, and flagging its size would be noise.
- REPO-043 emergency lever: Lambda reserved concurrency, an API Gateway stage or usage plan
  throttle, a WAF rate-based rule, an AppConfig feature flag profile (or the AppConfig
  extension layer), or a feature flag SDK in the function code (the AppConfig agent on
  localhost:2772, LaunchDarkly, Unleash, Flagsmith, OpenFeature, Powertools feature flags).
- REPO-044 fallback: when compute has a dependency (as REPO-020) or an edge (as REPO-019),
  a buffering or degraded path: an SQS queue feeding a consumer (SqsEventSource, an SNS
  subscription to SQS, a SAM SQS event, an event source mapping on a queue), a Lambda
  on-failure destination, a Step Functions Catch, CloudFront origin groups, Route 53
  failover records, an ALB fixed response or API Gateway mock integration, or a circuit
  breaker library in the code (pybreaker, opossum, resilience4j, Polly, Hystrix,
  circuitbreaker, cockatiel). It is repo-wide: one fallback anywhere passes every
  dependency, and which call it guards is not matched.

Workload monitoring (REL 6) runs by default, only when the IaC runs compute (as REPO-018),
and reads the IaC with the OPS 4 and OPS 8 telemetry model. Metrics and notifications
(REL06-BP01, BP03) are per-resource checks; reviewing the monitoring scope
(REL06-BP06) is a process with nothing in IaC to read:

- REPO-045 alarm metrics: a CloudFormation AWS::CloudWatch::Alarm with no MetricName and no
  Metrics, or no Threshold and no ThresholdMetricId, or a Terraform
  aws_cloudwatch_metric_alarm with no metric_name and no metric_query block, or no
  threshold and no threshold_metric_id, fires and is named by file and line. CDK alarms
  cannot be built without both. With every alarm complete, it fires when the alarms watch
  only host metrics (CPU, memory, network, disk), as REPO-027 reads them. No alarm at all is
  REPO-027 and OPS-025.
- REPO-046 log errors: a CloudWatch Logs metric filter whose filter pattern names an error
  (error, exception, fatal, critical, panic in any case, a Java-style FooException, or a
  5xx status), a log anomaly detector, a Logs Insights saved query, or a subscription
  filter. A metric filter that counts something else does not pass. Log group retention
  is CF-CW-001.
- REPO-047 automated response: an EC2 Auto Scaling or Application Auto Scaling policy (CDK
  scaleOn*, autoScale*, addAutoScaling), an alarm or OK action that is an SSM Automation,
  OpsItem, Incident Manager or Lambda ARN (or a CDK Lambda, AutoScaling, Ec2, Ssm or
  SsmIncident alarm action), or an EventBridge rule with a target in a file that names the
  "CloudWatch Alarm State Change" event.
- REPO-048 end to end tracing: fires when compute runs and nothing traces it (Lambda
  active tracing, an X-Ray daemon or ADOT collector container, an EKS ADOT or CloudWatch
  observability add-on, App Runner trace configuration, the ADOT layer, Application
  Signals, or an X-Ray, Powertools Tracer or OpenTelemetry SDK in the function code), or
  when the IaC declares an API Gateway REST API (or a SAM Api event) and no stage turns on
  X-Ray tracing (TracingEnabled, xray_tracing_enabled, tracingEnabled). HTTP APIs have no
  X-Ray and are not judged. Both are repo-wide: one traced function passes every compute
  resource.

Demand and impairment scaling (REL 7) runs by default and reuses the REPO-047 scaling
policy pattern. Load testing (REL07-BP04) is REPO-017, which answers REL 12:

- REPO-049 fixed-size fleet: names each fleet that cannot grow on demand. An ECS service
  (not a DAEMON one; QueueProcessing services scale themselves and are not matched) when
  the repo declares no Application Auto Scaling target on ecs:service:DesiredCount (CDK
  autoScaleTaskCount); an Auto Scaling group whose literal minimum equals its maximum
  (CDK defaults: minimum 1, maximum the minimum) or when the repo has no scaling policy or
  scheduled action; a DynamoDB table in provisioned billing (BillingMode PROVISIONED, or
  unset with provisioned throughput or read capacity) when the repo declares no DynamoDB
  scalable target (CDK autoScale*Capacity, Capacity.autoscaled). Values from variables or
  parameters are not judged. Each check is repo-wide: which target scales which service
  is not matched.
- REPO-050 CPU-only scaling: when the repo has scaling policies and every one tracks CPU or
  memory (predefined CPU or memory types, CDK CPU and memory helpers, a custom metric or
  step scaling alarm on CPU or memory). Any other signal passes: request count per target,
  queue depth or a QueueProcessing service, latency, errors, any other custom metric, or
  predictive scaling. DynamoDB utilization policies and schedules are not judged; a step
  policy whose alarm is not found is not counted as CPU.

Backup recovery (REL 9):

- REPO-051 restore test: when the IaC backs data up (an AWS Backup plan, DynamoDB
  point-in-time recovery, or an RDS or Aurora database, which keeps automated backups by
  default), something must restore it on a schedule: an AWS Backup restore testing plan
  (AWS::Backup::RestoreTestingPlan, aws_backup_restore_testing_plan,
  backup.CfnRestoreTestingPlan), a scheduled rule or schedule in a file that calls a restore
  API (StartRestoreJob, RestoreDBInstanceFromDBSnapshot, RestoreDBClusterToPointInTime,
  RestoreTableToPointInTime and the like), or a build that runs aws backup
  start-restore-job, aws rds restore-db-*, or aws dynamodb restore-table-*.

Disaster recovery (REL 13) runs by default. REL13-BP02 (the copies themselves) is REL-014,
REL-025, REL-026, CF-BAK-002 and CF-S3-010. Three of the rules below judge only a repo that
copies data or workloads to another Region: S3 replication, a DynamoDB global table, an
Aurora global database, an RDS read replica from another Region (SourceRegion, or a
Terraform replicate_source_db that is an ARN), an AWS Backup copy action, or Elastic
Disaster Recovery. S3 and AWS Backup copies to the same Region or another account are not
told apart.

- REPO-052 recovery objectives: when the IaC holds a data store or compute, it must state a
  recovery time or point objective: an AWS Resilience Hub resiliency policy, or a tag,
  object or context key named rto, rpo, RecoveryTimeObjective or RecoveryPointObjective
  (any case, an optional unit suffix such as RtoMinutes). Only key syntax counts, not prose.
- REPO-053 automated failover: the copy needs something that moves traffic: Route 53
  failover records or health checks, CloudFront origin failover, Route 53 Application
  Recovery Controller, Global Accelerator endpoint groups in two or more literal Regions, a
  DynamoDB global table (active-active), Elastic Disaster Recovery, or a tested restore
  (REPO-051). Which record fails over which copy is not matched.
- REPO-054 DR drill: an AWS FIS template or chaos tool (REPO-016), a build that flips an
  ARC routing control, fails over or switches over an Aurora global database, or starts an
  Elastic Disaster Recovery recovery, an ARC readiness check, or a scheduled restore test.
- REPO-055 DR drift: CloudFormation StackSets, an ARC readiness check or resource set, an
  AWS Config aggregator, a build that runs CloudFormation drift detection or terraform plan
  -detailed-exitcode, or one stack deployed to two Regions. That last check is literal: a
  CDK stack class instantiated with two different literal region values, or one Terraform
  module source used by two module blocks with different aws provider aliases (the alias
  regions are not read; a module with no providers map counts as the default provider).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar, List

from aws_arch_agent.models import Finding, Severity
from aws_arch_agent.rules.base import Rule
from aws_arch_agent.rules.environments import from_words
from aws_arch_agent.tools.cfn_yaml import is_cf_template, parse_template_text
from aws_arch_agent.tools.files import read_text_safe

SKIP_DIRS = frozenset({
    ".git", "node_modules", "cdk.out", "dist", "build", ".venv", "venv", ".terraform",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
})
MAX_FILES = 20_000
_BUILD_GLOBS: tuple[str, ...] = tuple(f"**/{d}/**" for d in sorted(SKIP_DIRS))

_TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec"})
_CODE_SUFFIXES = frozenset({
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".java", ".kt", ".cs", ".rb",
})
_TEST_NAME = re.compile(
    r"(?:\.(?:test|spec)\.[cm]?[jt]sx?|^test_.*\.py|_test\.py|_test\.go|\.tftest\.hcl)$"
)
_TASKCAT = frozenset({".taskcat.yml", ".taskcat.yaml", "taskcat.yml", "taskcat.yaml"})
_GUARD_TEST = re.compile(r"[_-]tests?\.ya?ml$")

_CI_FILES = frozenset({
    ".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml", "azure-pipelines.yaml",
    "bitbucket-pipelines.yml", ".travis.yml",
})
_PIPELINE_IN_IAC = re.compile(
    r"AWS::CodePipeline::Pipeline|resource\s+\"aws_codepipeline\""
    r"|\bcodepipeline\.(?:Cfn)?Pipeline\(|\bCodePipeline\("
)
_IAC_TEXT_SUFFIXES = frozenset({
    ".ts", ".js", ".py", ".json", ".yaml", ".yml", ".template", ".tf",
})

# Directories that hold one subdirectory per environment: envs/test is an environment,
# not a test suite.
_ENV_PARENTS = frozenset({
    "env", "envs", "environment", "environments", "stage", "stages", "account", "accounts",
    "deployments", "workspaces", "live",
})
_PARAM_SUFFIXES = frozenset({".json", ".yaml", ".yml"})
_STACK_ID = re.compile(
    r"\b(\w*(?:Stack|Stage))\(\s*[\w.]+\s*,\s*['\"]([^'\"]+)['\"]"
)


def walk(repo_path: Path) -> Iterator[Path]:
    """Every file of the repo, less dependency and build output, in a stable order."""
    seen = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            yield Path(root) / name
            seen += 1
            if seen >= MAX_FILES:
                return


def _rel_parts(path: Path, repo_path: Path) -> tuple[str, ...]:
    return path.relative_to(repo_path).parts


def _in_test_dir(parts: tuple[str, ...]) -> bool:
    """Under a test directory that is not an environment (envs/test stays an environment)."""
    dirs = parts[:-1]
    return any(
        d.lower() in _TEST_DIRS and (i == 0 or dirs[i - 1].lower() not in _ENV_PARENTS)
        for i, d in enumerate(dirs)
    )


def _is_test_file(path: Path, parts: tuple[str, ...], guard_rules: bool) -> bool:
    name = path.name.lower()
    if _TEST_NAME.search(name) or name in _TASKCAT:
        return True
    if guard_rules and _GUARD_TEST.search(name):
        return True
    return path.suffix.lower() in _CODE_SUFFIXES and _in_test_dir(parts)


def _is_ci_file(parts: tuple[str, ...]) -> bool:
    lowered = tuple(p.lower() for p in parts)
    name = lowered[-1]
    if name in _CI_FILES or re.fullmatch(r"buildspec[\w.-]*\.ya?ml", name):
        return True
    if lowered[:2] == (".github", "workflows") and name.endswith((".yml", ".yaml")):
        return True
    if lowered[:1] == (".circleci",) and name == "config.yml":
        return True
    return lowered[:1] == (".buildkite",)


class _RepoRule(Rule):
    category = "Operational Excellence"
    severity: Severity
    exclude_globs: ClassVar[tuple[str, ...]] = _BUILD_GLOBS

    def _finding(
        self, evidence: str, file: str | None = None, line: int | None = None
    ) -> Finding:
        return Finding(
            id=self.id,
            title=self.title,
            severity=self.severity,
            category=self.category,
            file=file,
            line=line,
            evidence=evidence,
            recommendation=self.recommendation,
        )


class RepoTestsMissing(_RepoRule):
    id = "REPO-001"
    title = "Repo has no automated tests"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Add automated tests for the infrastructure code (CDK assertions, pytest, "
        "terraform test, taskcat or cfn-guard rule tests) and run them on every change."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        files = list(walk(repo_path))
        guard_rules = any(p.suffix.lower() == ".guard" for p in files)
        for path in files:
            if _is_test_file(path, _rel_parts(path, repo_path), guard_rules):
                return []
        return [self._finding(
            "Searched the repo for tests (test/, tests/, __tests__/, spec/, "
            "*.test.ts, *.spec.js, test_*.py, *_test.go, *.tftest.hcl, taskcat, cfn-guard "
            "tests); found none"
        )]


class RepoPipelineMissing(_RepoRule):
    id = "REPO-002"
    title = "No CI workflow or pipeline builds the workload"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Build, test and deploy from a pipeline: add a CI workflow (GitHub Actions, GitLab "
        "CI, CodeBuild buildspec) or a CodePipeline, so every change takes the same path to "
        "production."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        files = list(walk(repo_path))
        for path in files:
            if _is_ci_file(_rel_parts(path, repo_path)):
                return []
        for path in files:
            parts = _rel_parts(path, repo_path)
            if path.suffix.lower() not in _IAC_TEXT_SUFFIXES or _in_test_dir(parts):
                continue
            if _PIPELINE_IN_IAC.search(read_text_safe(path)):
                return []
        return [self._finding(
            "Searched the repo for a CI config (.github/workflows, .gitlab-ci.yml, "
            "buildspec.yml, Jenkinsfile, azure-pipelines.yml, bitbucket-pipelines.yml, "
            ".circleci, .buildkite) or a CodePipeline in the IaC; found none"
        )]


def _iac_path(path: Path) -> bool:
    name = path.name.lower()
    if path.suffix.lower() in (".tf", ".tfvars") or name.endswith(".tfvars.json"):
        return True
    if path.suffix.lower() in _PARAM_SUFFIXES and "param" in name:
        return True
    return is_cf_template(path)


def _cdk_context_keys(path: Path) -> List[str]:
    try:
        doc = json.loads(read_text_safe(path))
    except ValueError:
        return []
    context = doc.get("context") if isinstance(doc, dict) else None
    if not isinstance(context, dict):
        return []
    keys = list(context)
    for value in context.values():
        if isinstance(value, dict):
            keys.extend(value)
    # Feature flags (@aws-cdk/pipelines:reduceStageRoleTrustScope) name no environment.
    return [str(k) for k in keys if not str(k).startswith("@") and ":" not in str(k)]


def environments_found(repo_path: Path) -> dict[str, str]:
    """Each environment the repo defines, and where it was first seen."""
    found: dict[str, str] = {}

    def note(text: str, where: str) -> None:
        env = from_words(text)
        if env is not None:
            found.setdefault(env, where)

    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        rel = "/".join(parts)
        if _in_test_dir(parts) or _TEST_NAME.search(path.name.lower()):
            continue
        if path.name == "cdk.json":
            for key in _cdk_context_keys(path):
                note(key, f"{rel} context {key}")
            continue
        if path.suffix.lower() in (".ts", ".js", ".py"):
            for match in _STACK_ID.finditer(read_text_safe(path)):
                note(match.group(2), f"{rel} {match.group(1)} {match.group(2)}")
                note(match.group(1), f"{rel} {match.group(1)}")
            continue
        if _iac_path(path):
            for part in (*parts[:-1], path.name.split(".", 1)[0]):
                note(part, rel)
    return found


class SingleEnvironment(_RepoRule):
    id = "REPO-003"
    title = "Only one environment is defined"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Define at least one environment before production (dev or staging stacks, "
        "per-environment tfvars or parameter files) and promote changes through it."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = environments_found(repo_path)
        if len(found) >= 2:
            return []
        seen = ", ".join(f"{env} ({where})" for env, where in sorted(found.items())) or "none"
        return [self._finding(
            "Environments named in IaC paths, tfvars and parameter files, CDK stack ids and "
            f"cdk.json context: {seen}; two or more expected"
        )]


def iac_texts(repo_path: Path) -> Iterator[tuple[str, str]]:
    """(repo-relative path, text) of each IaC or code file outside tests."""
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if path.suffix.lower() not in _IAC_TEXT_SUFFIXES or _in_test_dir(parts):
            continue
        if _TEST_NAME.search(path.name.lower()):
            continue
        text = read_text_safe(path)
        if path.suffix.lower() == ".json" and _saved_report(text):
            continue
        yield "/".join(parts), text


def _saved_report(text: str) -> bool:
    """A report or baseline this tool wrote: it quotes evidence, so it is not IaC."""
    head = text.lstrip()[:1]
    if head != "{" or ('"findings"' not in text and '"accepted"' not in text):
        return False
    try:
        doc = json.loads(text)
    except ValueError:
        return False
    return isinstance(doc, dict) and "Resources" not in doc and (
        isinstance(doc.get("findings"), list) or isinstance(doc.get("accepted"), list)
    )


_ORG_POLICY = re.compile(
    r"AWS::Organizations::Policy\b|resource\s+\"aws_organizations_policy\""
    r"|organizations\.CfnPolicy\("
)
_OTHER_POLICY_TYPE = re.compile(
    r"\b(?:TAG_POLICY|BACKUP_POLICY|AISERVICES_OPT_OUT_POLICY|CHATBOT_POLICY"
    r"|RESOURCE_CONTROL_POLICY|DECLARATIVE_POLICY_EC2|SECURITYHUB_POLICY|INSPECTOR_POLICY)\b"
)
_CONTROL_TOWER = re.compile(
    r"AWS::ControlTower::(?:EnabledControl|LandingZone)\b"
    r"|resource\s+\"aws_controltower_(?:control|landing_zone)\""
    r"|controltower\.Cfn(?:EnabledControl|LandingZone)\("
)
_ORG_TRAIL = re.compile(
    r"\bIsOrganizationTrail[\"']?\s*:\s*[\"']?true\b"
    r"|\bis_organization_trail\s*=\s*(?:true|True)\b"
    r"|\bisOrganizationTrail\s*:\s*true\b"
)
_ORG_UNITS = re.compile(
    r"AWS::Organizations::(?:Account|OrganizationalUnit)\b"
    r"|resource\s+\"aws_organizations_(?:account|organizational_unit)\""
    r"|organizations\.Cfn(?:Account|OrganizationalUnit)\("
)


def org_guardrails(repo_path: Path) -> dict[str, str]:
    """Each kind of organization guardrail the IaC declares, and the first file with it."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _ORG_POLICY.search(text) and (
            "SERVICE_CONTROL_POLICY" in text or not _OTHER_POLICY_TYPE.search(text)
        ):
            found.setdefault("service control policy", rel)
        if _CONTROL_TOWER.search(text):
            found.setdefault("Control Tower control", rel)
        if _ORG_TRAIL.search(text):
            found.setdefault("organization trail", rel)
        if _ORG_UNITS.search(text):
            found.setdefault("Organizations account or OU", rel)
    return found


class OrgGuardrailsMissing(_RepoRule):
    id = "REPO-004"
    title = "No organization guardrails in the scanned IaC"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Run workloads in separate accounts under AWS Organizations and set guardrails in "
        "code: service control policies, Control Tower controls, and an organization trail."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        if org_guardrails(repo_path):
            return []
        return [self._finding(
            "Searched the IaC for a service control policy, a Control Tower control or "
            "landing zone, an organization CloudTrail trail, and Organizations accounts or "
            "OUs; found none"
        )]


_ACCOUNT = re.compile(
    r"AWS::Organizations::Account\b|resource\s+\"aws_organizations_account\""
    r"|organizations\.CfnAccount\(|aft-account-request"
)
_PROVISIONED_PRODUCT = re.compile(
    r"AWS::ServiceCatalog::CloudFormationProvisionedProduct\b"
    r"|resource\s+\"aws_servicecatalog_provisioned_product\""
    r"|servicecatalog\.CfnCloudFormationProvisionedProduct\("
)
_ACCOUNT_FACTORY = "AWSControlTowerAccountFactory"
BASELINE_SERVICES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("CloudTrail trail", re.compile(
        r"AWS::CloudTrail::Trail\b|resource\s+\"aws_cloudtrail\"|cloudtrail\.(?:Cfn)?Trail\("
    )),
    ("Config recorder", re.compile(
        r"AWS::Config::ConfigurationRecorder\b"
        r"|resource\s+\"aws_config_configuration_recorder\""
        r"|config\.CfnConfigurationRecorder\("
    )),
    ("GuardDuty detector", re.compile(
        r"AWS::GuardDuty::Detector\b|resource\s+\"aws_guardduty_detector\""
        r"|guardduty\.CfnDetector\("
    )),
    ("Security Hub", re.compile(
        r"AWS::SecurityHub::Hub(?:V2)?\b|resource\s+\"aws_securityhub_account\""
        r"|securityhub\.CfnHub(?:V2)?\("
    )),
    ("IAM Access Analyzer", re.compile(
        r"AWS::AccessAnalyzer::Analyzer\b|resource\s+\"aws_accessanalyzer_analyzer\""
        r"|accessanalyzer\.CfnAnalyzer\("
    )),
)


def _account_at(text: str) -> int | None:
    """Offset of the first account definition in text, or None."""
    match = _ACCOUNT.search(text)
    if match:
        return match.start()
    if _PROVISIONED_PRODUCT.search(text) and _ACCOUNT_FACTORY in text:
        return text.index(_ACCOUNT_FACTORY)
    return None


class AccountBaselineMissing(_RepoRule):
    id = "REPO-005"
    title = "Account is defined without a security baseline"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Deploy a security baseline with every account the repo creates: a CloudTrail "
        "trail, an AWS Config recorder, a GuardDuty detector, Security Hub and an IAM "
        "Access Analyzer (or the Control Tower or AFT customizations that set them up)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        account: tuple[str, int] | None = None
        missing = {name: pattern for name, pattern in BASELINE_SERVICES}
        for rel, text in iac_texts(repo_path):
            at = _account_at(text)
            if account is None and at is not None:
                account = (rel, text.count("\n", 0, at) + 1)
            for name, pattern in list(missing.items()):
                if pattern.search(text):
                    del missing[name]
        if account is None or not missing:
            return []
        rel, line = account
        names = [name for name, _ in BASELINE_SERVICES if name in missing]
        return [self._finding(
            f"Defines an account ({rel}:{line}); no {', '.join(names)} in the IaC",
            file=rel, line=line,
        )]


_ROOT_MFA_RULE = re.compile(r"\bROOT_ACCOUNT(?:_HARDWARE)?_MFA_ENABLED\b")
_ROOT_KEY_RULE = re.compile(r"\bIAM_ROOT_ACCESS_KEY_CHECK\b")
_CONFORMANCE_PACK = re.compile(
    r"AWS::Config::(?:Organization)?ConformancePack\b"
    r"|resource\s+\"aws_config_(?:organization_)?conformance_pack\""
    r"|config\.Cfn(?:Organization)?ConformancePack\("
)
_ROOT_STANDARD = re.compile(
    r"cis-aws-foundations-benchmark|aws-foundational-security-best-practices"
)
# A Security Hub hub turns on the default standards (FSBP and CIS) unless told not to.
_HUB = re.compile(
    r"AWS::SecurityHub::Hub\b|resource\s+\"aws_securityhub_account\"|securityhub\.CfnHub\("
)
_NO_DEFAULT_STANDARDS = re.compile(
    r"\bEnableDefaultStandards[\"']?\s*:\s*[\"']?false\b"
    r"|\benable_default_standards\s*=\s*(?:false|False)\b"
    r"|\benableDefaultStandards\s*:\s*false\b"
)
_ROOT_PRINCIPAL = re.compile(r":iam::\*:root\b")


def root_controls(repo_path: Path) -> tuple[tuple[str, int] | None, set[str]]:
    """The first account definition (path, line), and the root controls the IaC declares:
    "mfa rule", "key rule", "conformance pack", "security hub", "scp"."""
    account: tuple[str, int] | None = None
    found: set[str] = set()
    scp = root_condition = False
    for rel, text in iac_texts(repo_path):
        at = _account_at(text)
        if account is None and at is not None:
            account = (rel, text.count("\n", 0, at) + 1)
        if _ROOT_MFA_RULE.search(text):
            found.add("mfa rule")
        if _ROOT_KEY_RULE.search(text):
            found.add("key rule")
        if _CONFORMANCE_PACK.search(text):
            found.add("conformance pack")
        if _ROOT_STANDARD.search(text) or (
            _HUB.search(text) and not _NO_DEFAULT_STANDARDS.search(text)
        ):
            found.add("security hub")
        scp = scp or bool(_ORG_POLICY.search(text))
        root_condition = root_condition or bool(
            "aws:PrincipalArn" in text and _ROOT_PRINCIPAL.search(text)
        )
    if scp and root_condition:
        found.add("scp")
    return account, found


class RootUserUnchecked(_RepoRule):
    """SEC01-BP02 (Secure account root user and properties) is the Well-Architected best
    practice for the root user, so this rule answers SEC 1, not SEC 2."""

    id = "REPO-006"
    title = "Account baseline does not check root MFA or root access keys"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline", "identity")
    recommendation = (
        "Check the root user of every account the repo creates: add the AWS Config managed "
        "rules ROOT_ACCOUNT_MFA_ENABLED and IAM_ROOT_ACCESS_KEY_CHECK (or a conformance pack "
        "that has them), turn on the Security Hub CIS or FSBP standard, or deny the root user "
        "with an SCP on aws:PrincipalArn arn:aws:iam::*:root. With AWS Organizations, "
        "centralized root access management can remove root credentials from member accounts."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        account, found = root_controls(repo_path)
        if account is None or found - {"mfa rule", "key rule"} or {
            "mfa rule", "key rule"
        } <= found:
            return []
        rel, line = account
        rules = [
            name for key, name in (
                ("mfa rule", "ROOT_ACCOUNT_MFA_ENABLED"), ("key rule", "IAM_ROOT_ACCESS_KEY_CHECK")
            ) if key not in found
        ]
        return [self._finding(
            f"Defines an account ({rel}:{line}); no Config rule {' or '.join(rules)}, "
            "conformance pack, Security Hub CIS or FSBP standard, or SCP that denies the root "
            "user in the IaC",
            file=rel, line=line,
        )]


_EVENT_RULE = re.compile(
    r"AWS::Events::Rule\b|resource\s+\"aws_cloudwatch_event_rule\"|\bevents\.(?:Cfn)?Rule\("
)
_FINDING_SOURCE = re.compile(
    r"\baws\.(?:guardduty|securityhub|inspector2|macie)\b"
    r"|GuardDuty Finding|Security Hub Findings - Imported"
)
_CAPTURE = re.compile(
    r"\b[Cc]reateSnapshots?(?:Command)?\b|\bcreate_snapshots?\b"
    r"|\bAWS-Create(?:Snapshot|Image)\b|\bAWSSupport-CollectEC2\w*"
    r"|\bAWSSupport-ContainEC2Instance\b"
)
_DETECTIVE = re.compile(
    r"AWS::Detective::Graph\b|resource\s+\"aws_detective_graph\"|\bdetective\.CfnGraph\("
)


def forensic_controls(repo_path: Path) -> dict[str, str]:
    """Forensic pieces the IaC and code declare, and the first file with each:
    "finding rule", "capture", "detective"."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _EVENT_RULE.search(text) and _FINDING_SOURCE.search(text):
            found.setdefault("finding rule", rel)
        if _CAPTURE.search(text):
            found.setdefault("capture", rel)
        if _DETECTIVE.search(text):
            found.setdefault("detective", rel)
    return found


class ForensicCaptureMissing(_RepoRule):
    id = "REPO-007"
    title = "No forensic capture is automated for security findings"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Automate forensic capture: an EventBridge rule on GuardDuty or Security Hub findings "
        "that starts a Step Functions or SSM Automation workflow to snapshot the instance's EBS "
        "volumes (AWS-CreateSnapshot) and move it to an isolation security group "
        "(AWSSupport-ContainEC2Instance). Turn on Amazon Detective to investigate findings."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = forensic_controls(repo_path)
        if "detective" in found or {"finding rule", "capture"} <= found.keys():
            return []
        rule = found.get("finding rule")
        seen = f"a finding rule ({rule}) but no capture action" if rule else "none"
        return [self._finding(
            "Searched the IaC and code for an EventBridge rule on GuardDuty, Security Hub, "
            "Inspector or Macie findings together with an EBS snapshot or SSM capture "
            f"runbook, and for Amazon Detective; found {seen}"
        )]


_SECURITY_GROUP = re.compile(
    r"AWS::EC2::SecurityGroup\b|resource\s+\"aws_security_group\""
    r"|\bec2\.(?:Cfn)?SecurityGroup\("
)
_ISOLATION_WORD = re.compile(
    r"quarantin|(?<!private_)isolat(?:e|ion)|forensic|containment", re.IGNORECASE
)
# A CloudFormation logical id comes before the type; CDK and Terraform names come after.
_SG_BEFORE, _SG_AFTER = 120, 400
_CONTAIN_RUNBOOK = re.compile(
    r"\bAWSSupport-ContainEC2Instance\b|\bAWS-DisablePublicAccessForSecurityGroup\b"
    r"|\bAWS[\w-]*-Revoke\w*"
)
_REVOKE_SESSIONS = re.compile(r"\bAWSRevokeOlderSessions\b|\baws:TokenIssueTime\b")
_DELETE_LOGIN = re.compile(
    r"\bDeleteLoginProfile(?:Command)?\b|\bdelete_login_profile\b|\bdeleteLoginProfile\b"
)
_UPDATE_KEY = re.compile(
    r"\bUpdateAccessKey(?:Command)?\b|\bupdate_access_key\b|\bupdateAccessKey\b"
)


def _isolation_group(text: str) -> bool:
    for match in _SECURITY_GROUP.finditer(text):
        start = max(0, match.start() - _SG_BEFORE)
        if _ISOLATION_WORD.search(text, start, match.end() + _SG_AFTER):
            return True
    return False


def containment_controls(repo_path: Path) -> dict[str, str]:
    """Containment controls the IaC and code declare, and the first file with each."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _isolation_group(text):
            found.setdefault("isolation security group", rel)
        if _CONTAIN_RUNBOOK.search(text):
            found.setdefault("containment runbook", rel)
        if (
            _REVOKE_SESSIONS.search(text) or _DELETE_LOGIN.search(text)
            or (_UPDATE_KEY.search(text) and "Inactive" in text)
        ):
            found.setdefault("credential revocation", rel)
    return found


class ContainmentMissing(_RepoRule):
    id = "REPO-008"
    title = "No containment control is deployed"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Pre-deploy containment: a quarantine security group with no rules to move a "
        "compromised instance into, the AWSSupport-ContainEC2Instance runbook, and an "
        "automation that revokes credentials (deactivate access keys with UpdateAccessKey, "
        "or attach AWSRevokeOlderSessions to a role)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        if containment_controls(repo_path):
            return []
        return [self._finding(
            "Searched the IaC and code for a quarantine or isolation security group, an SSM "
            "containment runbook, and credential revocation (UpdateAccessKey to Inactive, "
            "AWSRevokeOlderSessions, DeleteLoginProfile); found none"
        )]


# SEC 11: application security in the pipeline (REPO-009 to REPO-011).

_BUILD_IN_IAC = re.compile(
    r"AWS::CodeBuild::Project\b|resource\s+\"aws_codebuild_project\""
    r"|\bcodebuild\.(?:Cfn|Pipeline)?Project\(|\bBuildSpec\.from_?[oO]bject"
    r"|\b(?:ShellStep|CodeBuildStep)\("
)


def build_texts(repo_path: Path) -> List[tuple[str, str]]:
    """(repo-relative path, text) of each build config: the CI files REPO-002 knows, and
    IaC files that declare a CodeBuild project, an inline buildspec or a pipeline."""
    out: dict[str, str] = {}
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if _is_ci_file(parts):
            out["/".join(parts)] = read_text_safe(path)
    for rel, text in iac_texts(repo_path):
        if rel not in out and (_BUILD_IN_IAC.search(text) or _PIPELINE_IN_IAC.search(text)):
            out[rel] = text
    return sorted(out.items())


def _dash(line: str) -> int | None:
    stripped = line.lstrip(" ")
    return len(line) - len(stripped) if stripped.startswith("- ") else None


def _column(line: str) -> int:
    """Where a YAML line's key starts; a list dash counts as indent."""
    stripped = line.lstrip(" ")
    col = len(line) - len(stripped)
    while stripped.startswith("- "):
        rest = stripped[2:].lstrip(" ")
        col += len(stripped) - len(rest)
        stripped = rest
    return col


def _blocks(lines: List[str], i: int) -> Iterator[tuple[int, int, int]]:
    """(first, last, column) of the block line i sits in, then of each block around it.
    A block is the lines at that column or deeper, cut at a list item that starts before
    it."""
    while True:
        col = _column(lines[i])
        if col == 0:
            return
        top = i
        dash = _dash(lines[i])
        if dash is None or dash >= col:
            while top > 0:
                above = lines[top - 1]
                if above.strip() and _column(above) < col:
                    break
                top -= 1
                dash = _dash(above)
                if above.strip() and dash is not None and dash < col:
                    break
        last = i
        while last + 1 < len(lines):
            below = lines[last + 1]
            dash = _dash(below)
            if below.strip() and (_column(below) < col or (dash is not None and dash < col)):
                break
            last += 1
        yield top, last, col
        parent = top - 1
        while parent >= 0 and not (lines[parent].strip() and _column(lines[parent]) < col):
            parent -= 1
        if parent < 0:
            return
        i = parent


def _step(lines: List[str], i: int) -> str:
    """The list item (CI step) line i sits in, or the line alone."""
    for top, last, _col in _blocks(lines, i):
        dash = _dash(lines[top])
        if dash is not None and dash < _column(lines[top]):
            return "\n".join(lines[top:last + 1])
    return lines[i]


_NO_FAIL_TAIL = re.compile(r"\|\|\s*(?:true\b|exit\s+0\b|:(?=\s|$)|echo\b)")
_NO_FAIL_KEY = re.compile(
    r"^[\s-]*(?:continue-on-error|allow_failure|ignore[-_]errors)\s*:\s*[\"']?true\b"
    r"|^[\s-]*on-failure\s*:\s*[\"']?continue\b",
    re.IGNORECASE,
)


def _cannot_fail(lines: List[str], i: int, tail: str) -> bool:
    """The command's failure is swallowed (|| true) or its step may fail (continue-on-error,
    allow_failure, ignore-errors, on-failure: CONTINUE beside it or around it)."""
    if _NO_FAIL_TAIL.search(tail):
        return True
    for top, last, col in _blocks(lines, i):
        for line in lines[top:last + 1]:
            if _column(line) == col and _NO_FAIL_KEY.search(line):
                return True
    return False


_EXIT_CODE = re.compile(r"--exit-code[=\s]+[\"']?[1-9]|\bexit-code\s*:\s*[\"']?[1-9]")
_GRYPE_FAIL = re.compile(r"--fail-on\b|\s-f\s+\w")
_CVSS_FAIL = re.compile(r"fail(?:On|BuildOn)CVSS", re.IGNORECASE)
_FS_SCAN_TYPE = re.compile(r"\bscan-type\s*:\s*[\"']?(?:fs|filesystem|repo|rootfs)\b")
_NO_FAIL_BUILD = re.compile(r"\bfail-build\s*:\s*[\"']?false\b")

# (name, kind, pattern). kind is "dependency", "image" or "both"; "trivy-action" and
# "anchore" take their kind from the step's scan-type or path.
_SCANS: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple(
    (name, kind, re.compile(pattern)) for name, kind, pattern in (
        ("npm audit", "dependency", r"\b(?:npm|yarn|pnpm)\s+audit\b"),
        ("pip-audit", "dependency", r"\bpip-audit\b"),
        ("safety", "dependency", r"\bsafety\s+(?:check|scan)\b"),
        ("osv-scanner", "dependency", r"\bosv-scanner\b"),
        ("snyk test", "dependency", r"\bsnyk\s+test\b|\bsnyk/actions/(?!docker\b)[\w-]+"),
        ("trivy fs", "dependency", r"\btrivy\s+(?:fs|filesystem|repo|repository|rootfs)\b"),
        ("grype", "dependency", r"\bgrype\s+(?:dir:|\.(?=\s|$|[\"']))"),
        ("dependency-check", "dependency",
         r"\bdependency-check(?:\.sh|-maven|-gradle)?\b|\bdependencyCheck(?:Analyze|Aggregate)\b"),
        ("cargo audit", "dependency", r"\bcargo\s+audit\b"),
        ("govulncheck", "dependency", r"\bgovulncheck\b"),
        ("bundler-audit", "dependency", r"\bbundler?-audit\b|\bbundle\s+audit\b"),
        ("dependency review", "dependency", r"\bactions/dependency-review-action\b"),
        ("Amazon Inspector", "both", r"vulnerability-scan-github-action-for-amazon-inspector"),
        ("Amazon Inspector", "both", r"\binspector-(?:scan|sbomgen)\b"),
        ("trivy image", "image", r"\btrivy\s+image\b"),
        ("trivy-action", "trivy-action", r"\baquasecurity/trivy-action\b"),
        ("anchore scan", "anchore", r"\banchore/scan-action\b"),
        ("grype", "image", r"\bgrype\s+(?!dir:|\.(?:\s|$)|sbom:|file:|-)\S"),
        ("docker scout", "image", r"\bdocker\s+scout\s+cves\b"),
        ("snyk container", "image", r"\bsnyk\s+container\s+test\b|\bsnyk/actions/docker\b"),
        ("ECR image scan", "image",
         r"\becr\s+start-image-scan\b|\bimage-scan-complete\b|\bdescribe-image-scan-findings\b"),
    )
)


def _set_to_fail(name: str, tail: str, step: str, text: str) -> bool:
    """Tools that pass on findings unless told otherwise."""
    if name in ("trivy fs", "trivy image", "trivy-action", "docker scout"):
        return bool(_EXIT_CODE.search(tail if name != "trivy-action" else step))
    if name == "grype":
        return bool(_GRYPE_FAIL.search(tail))
    if name == "anchore scan":
        return not _NO_FAIL_BUILD.search(step)
    if name == "dependency-check":
        return bool(_CVSS_FAIL.search(step) or _CVSS_FAIL.search(text))
    if "github-action-for-amazon-inspector" in step:
        return "vulnerability_threshold_exceeded" in text
    return True


_TAIL_END = re.compile(r"\\n|[\"'`;\n]|&&")


def _scans_in(text: str) -> Iterator[tuple[str, str, bool]]:
    """(name, kind, can fail the build) for each scan in a build text."""
    lines = text.split("\n")
    for name, kind, pattern in _SCANS:
        for match in pattern.finditer(text):
            i = text.count("\n", 0, match.start())
            rest = text[match.end():]
            end = _TAIL_END.search(rest)
            tail = rest[:end.start()] if end else rest
            step = _step(lines, i)
            if kind == "trivy-action":
                kind_here = "dependency" if _FS_SCAN_TYPE.search(step) else "image"
            elif kind == "anchore":
                kind_here = "dependency" if re.search(r"^[\s-]*path\s*:", step, re.M) else "image"
            else:
                kind_here = kind
            fails = _set_to_fail(name, tail, step, text) and not _cannot_fail(lines, i, tail)
            yield name, kind_here, fails


_RUN_SCRIPT = re.compile(
    r"\b(?:npm|pnpm)\s+(?:run(?:-script)?\s+)?([\w:.-]+)|\byarn\s+(?:run\s+)?([\w:.-]+)"
)


def _package_scripts(repo_path: Path) -> dict[str, str]:
    """Every package.json script outside tests, by name (the first one wins)."""
    scripts: dict[str, str] = {}
    for path in walk(repo_path):
        if path.name != "package.json" or _in_test_dir(_rel_parts(path, repo_path)):
            continue
        try:
            doc = json.loads(read_text_safe(path))
        except ValueError:
            continue
        found = doc.get("scripts") if isinstance(doc, dict) else None
        if isinstance(found, dict):
            for name, command in found.items():
                if isinstance(command, str):
                    scripts.setdefault(str(name), command)
    return scripts


def _scripts_run(texts: List[str], scripts: dict[str, str]) -> List[tuple[str, str]]:
    """(script name, command) of each package.json script the builds run, two levels deep."""
    out: dict[str, str] = {}
    todo = list(texts)
    for _depth in range(3):
        names = {
            m.group(1) or m.group(2) for text in todo for m in _RUN_SCRIPT.finditer(text)
        }
        todo = []
        for name in sorted(names):
            if name in scripts and name not in out:
                out[name] = scripts[name]
                todo.append(scripts[name])
    return sorted(out.items())


def pipeline_scans(repo_path: Path) -> tuple[List[str], List[tuple[str, str, str, bool]]]:
    """The build configs found, and each scan in them or in the package.json scripts they
    run: (name, kind, where, can fail the build)."""
    builds = build_texts(repo_path)
    scans: List[tuple[str, str, str, bool]] = []
    for rel, text in builds:
        scans.extend((name, kind, rel, fails) for name, kind, fails in _scans_in(text))
    run = _scripts_run([text for _rel, text in builds], _package_scripts(repo_path))
    for script, command in run:
        where = f"package.json script {script}"
        scans.extend((name, kind, where, fails) for name, kind, fails in _scans_in(command))
    return [rel for rel, _text in builds], scans


def _passing(scans: List[tuple[str, str, str, bool]], kind: str) -> bool:
    return any(fails and k in (kind, "both") for _n, k, _w, fails in scans)


def _weak(scans: List[tuple[str, str, str, bool]], kind: str) -> str:
    """ "found <scan> in <where>, but it cannot fail the build", or "found none". """
    for name, k, where, fails in scans:
        if not fails and k in (kind, "both"):
            return f"found {name} in {where}, but it cannot fail the build"
    return "found none"


def _listed(items: List[str], limit: int = 3) -> str:
    more = f" and {len(items) - limit} more" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


_DEPENDENCY_TOOLS = (
    "npm/yarn/pnpm audit, pip-audit, safety, osv-scanner, snyk test, trivy fs, grype, "
    "OWASP dependency-check, cargo audit, govulncheck, bundler-audit, Amazon Inspector"
)


class DependencyScanMissing(_RepoRule):
    id = "REPO-009"
    title = "The build does not scan dependencies"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Scan dependencies in every build and fail it on findings: npm audit "
        "--audit-level=high, pip-audit, osv-scanner, or Amazon Inspector (inspector-sbomgen "
        "and inspector-scan, or the Inspector scan action with a threshold gate). Do not add "
        "|| true or continue-on-error to the scan step."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        builds, scans = pipeline_scans(repo_path)
        if _passing(scans, "dependency"):
            return []
        if not builds:
            return [self._finding(
                "Searched the repo for a build to run a dependency scan (a CI config, or a "
                "CodeBuild buildspec or pipeline in the IaC); found none"
            )]
        return [self._finding(
            f"Searched the build configs ({_listed(builds)}) and the package.json scripts "
            f"they run for a dependency scan that fails the build ({_DEPENDENCY_TOOLS}); "
            f"{_weak(scans, 'dependency')}"
        )]


_CONTAINER_IN_IAC = re.compile(
    r"AWS::ECR::Repository\b|resource\s+\"aws_ecr_repository\"|\becr\.(?:Cfn)?Repository\("
    r"|\bContainerImage\.from_?[aA]sset|\bDockerImageAsset\(|\bDockerImage(?:Function|Code)\b"
)
_IMAGE_BUILD = re.compile(
    r"\bdocker\s+(?:buildx\s+)?build\b|\bdocker/build-push-action\b|\bpodman\s+build\b"
)
_FUNCTION_IN_IAC = re.compile(
    r"AWS::(?:Lambda|Serverless)::Function\b|resource\s+\"aws_lambda_function\""
    r"|\b_?lambda\.(?:Cfn)?Function\(|\b(?:Nodejs|Python|Go)Function\("
)
_SCAN_ON_PUSH = re.compile(
    r"\bScanOnPush[\"']?\s*:\s*[\"']?true\b|\bscan_on_push\s*=\s*true\b"
    r"|\bimageScanOnPush\s*:\s*true\b|\bimage_scan_on_push\s*=\s*True\b"
)
_REGISTRY_SCANNING = re.compile(
    r"AWS::ECR::RegistryScanningConfiguration\b"
    r"|resource\s+\"aws_ecr_registry_scanning_configuration\""
    r"|\becr\.CfnRegistryScanningConfiguration\("
)
# CloudFormation has no Inspector enabler; templates turn it on with a custom resource.
_INSPECTOR = re.compile(
    r"resource\s+\"aws_inspector2_(?:enabler|organization_configuration)\""
    r"|\binspector2:Enable\b|[\"']Inspector2[\"']|\binspector2\s+enable\b"
)
_INSPECTOR_ECR = re.compile(r"[\"']ECR[\"']|\becr\s*=\s*true\b|--resource-types[^\n]*\bECR\b")
_INSPECTOR_LAMBDA = re.compile(
    r"[\"']LAMBDA(?:_CODE)?[\"']|\blambda(?:_code)?\s*=\s*true\b"
    r"|--resource-types[^\n]*\bLAMBDA\b"
)


def artifact_controls(repo_path: Path) -> tuple[dict[str, str], set[str]]:
    """Artifact kinds the repo ships ("container images", "Lambda functions") and where
    first seen, and the scanning the IaC turns on: "ecr", "inspector ecr",
    "inspector lambda"."""
    kinds: dict[str, str] = {}
    controls: set[str] = set()
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        name = path.name.lower()
        if _in_test_dir(parts):
            continue
        if name in ("dockerfile", "containerfile") or name.startswith("dockerfile.") or (
            name.endswith(".dockerfile")
        ):
            kinds.setdefault("container images", "/".join(parts))
    texts = dict(iac_texts(repo_path))
    texts.update(build_texts(repo_path))
    for rel, text in sorted(texts.items()):
        if _CONTAINER_IN_IAC.search(text) or _IMAGE_BUILD.search(text):
            kinds.setdefault("container images", rel)
        if _FUNCTION_IN_IAC.search(text):
            kinds.setdefault("Lambda functions", rel)
        if _SCAN_ON_PUSH.search(text) or _REGISTRY_SCANNING.search(text):
            controls.add("ecr")
        if _INSPECTOR.search(text):
            if _INSPECTOR_ECR.search(text):
                controls.add("inspector ecr")
            if _INSPECTOR_LAMBDA.search(text):
                controls.add("inspector lambda")
    return kinds, controls


class ArtifactScanMissing(_RepoRule):
    id = "REPO-010"
    title = "Container or function artifacts are not scanned before deploy"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Scan what you deploy: turn on Amazon ECR enhanced scanning (a registry scanning "
        "configuration, or Amazon Inspector with ECR) or at least scan on push, and Amazon "
        "Inspector Lambda standard and code scanning for functions. In the pipeline, scan "
        "the image before it is pushed (trivy image --exit-code 1, the Inspector scan action)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        kinds, controls = artifact_controls(repo_path)
        if not kinds:
            return []
        _builds, scans = pipeline_scans(repo_path)
        unscanned: List[str] = []
        if "container images" in kinds and not (
            controls & {"ecr", "inspector ecr"} or _passing(scans, "image")
        ):
            unscanned.append(
                f"Builds container images ({kinds['container images']}); searched for ECR "
                "scan on push, ECR registry scanning, Amazon Inspector for ECR, and a CI "
                f"image scan that fails the build; {_weak(scans, 'image')}"
            )
        if "Lambda functions" in kinds and not (
            "inspector lambda" in controls or _passing(scans, "dependency")
        ):
            unscanned.append(
                f"Deploys Lambda functions ({kinds['Lambda functions']}); searched for "
                "Amazon Inspector Lambda scanning and a dependency scan that fails the "
                "build; found none"
            )
        if not unscanned:
            return []
        return [self._finding("; ".join(unscanned))]


_MANIFEST = re.compile(
    r"package\.json|requirements[\w.-]*\.txt|pyproject\.toml|pipfile|go\.mod|pom\.xml"
    r"|build\.gradle(?:\.kts)?"
)
_CODEARTIFACT = re.compile(
    r"AWS::CodeArtifact::Repository\b|resource\s+\"aws_codeartifact_repository\""
    r"|\bcodeartifact\.CfnRepository\(|\bcodeartifact\s+(?:login|get-authorization-token)\b"
)
_PUBLIC_HOSTS = frozenset({
    "registry.npmjs.org", "registry.npmjs.com", "registry.yarnpkg.com", "pypi.org",
    "pypi.python.org", "files.pythonhosted.org", "repo.maven.apache.org", "repo1.maven.org",
    "maven.google.com", "dl.google.com", "plugins.gradle.org", "jcenter.bintray.com",
    "proxy.golang.org",
})
# A registry url per config file name; "*" applies to the build configs.
_REGISTRY_URL: tuple[tuple[re.Pattern[str], re.Pattern[str]], ...] = tuple(
    (re.compile(name), re.compile(url, re.M | re.S)) for name, url in (
        (r"\.npmrc", r"^\s*registry\s*=\s*(\S+)"),
        (r"\.yarnrc\.ya?ml", r"^\s*npmRegistryServer\s*:\s*[\"']?([^\s\"']+)"),
        (r"\.yarnrc", r"^\s*registry\s+[\"']?([^\s\"']+)"),
        (r"pip\.(?:conf|ini)", r"^\s*index-url\s*=\s*(\S+)"),
        (r"requirements[\w.-]*\.txt", r"^\s*(?:--index-url|-i)[=\s]+(\S+)"),
        (r"pyproject\.toml",
         r"^\s*\[\[tool\.(?:poetry\.source|uv\.index)\]\][^\[]*?^\s*url\s*=\s*\"([^\"]+)\""),
        (r"pom\.xml|settings\.xml",
         r"<(?:repository|mirror)>(?:(?!</(?:repository|mirror)>).)*?<url>\s*([^<\s]+)"),
        (r"(?:build|settings)\.gradle(?:\.kts)?",
         r"\bmaven\s*\{[^}]*?\burl\s*=?\s*(?:uri\()?\s*[\"']([^\"']+)"),
        (r"\*",
         r"\bnpm\s+config\s+set\s+registry[=\s]+(\S+)|\bPIP_INDEX_URL\s*[:=]\s*[\"']?([^\s\"']+)"
         r"|\bGOPROXY\s*[:=]\s*[\"']?([^\s\"',]+)"),
    )
)


def _private_url(url: str) -> bool:
    if url in ("direct", "off"):
        return False
    host = re.match(r"[a-z][\w+.-]*://(?:[^@/]*@)?([^/:]+)", url, re.IGNORECASE)
    return host is None or host.group(1).lower() not in _PUBLIC_HOSTS


def _private_registry(name: str, text: str) -> bool:
    for file_name, url in _REGISTRY_URL:
        if file_name.fullmatch(name):
            for match in url.finditer(text):
                value = next((g for g in match.groups() if g), "")
                if value and _private_url(value):
                    return True
    return False


def package_sources(repo_path: Path) -> tuple[str | None, dict[str, str]]:
    """The first package manifest, and each central repository control and where."""
    manifest: str | None = None
    found: dict[str, str] = {}
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if _in_test_dir(parts):
            continue
        name = path.name.lower()
        rel = "/".join(parts)
        if manifest is None and _MANIFEST.fullmatch(name):
            manifest = rel
        if any(f.fullmatch(name) for f, _url in _REGISTRY_URL[:-1]) and _private_registry(
            name, read_text_safe(path)
        ):
            found.setdefault("private registry", rel)
    for rel, text in [*iac_texts(repo_path), *build_texts(repo_path)]:
        if _CODEARTIFACT.search(text):
            found.setdefault("CodeArtifact", rel)
    for rel, text in build_texts(repo_path):
        if _private_registry("*", text):
            found.setdefault("private registry", rel)
    return manifest, found


class CentralPackageRepoMissing(_RepoRule):
    id = "REPO-011"
    title = "Packages are not pulled through a central repository"
    category = "Security"
    severity = "Low"
    themes = ("security-baseline",)
    recommendation = (
        "Pull packages through AWS CodeArtifact (or another private repository) with "
        "upstreams to the public registries, and point the build at it: aws codeartifact "
        "login, or the registry in .npmrc, pip.conf or the Maven and Gradle settings."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        manifest, found = package_sources(repo_path)
        if manifest is None or found:
            return []
        return [self._finding(
            f"Has a package manifest ({manifest}); searched for AWS CodeArtifact in the IaC, "
            "aws codeartifact login in a build, and a private registry in .npmrc, .yarnrc, "
            "pip.conf, a requirements index-url, a poetry or uv source, Maven or Gradle "
            "repositories, or GOPROXY; found none"
        )]


# Services whose per-account quotas a busy stack runs into (REPO-012).
QUOTA_HEAVY: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Lambda", re.compile(
        r"AWS::(?:Lambda|Serverless)::Function\b|resource\s+\"aws_lambda_function\""
        r"|\b_?lambda_?\.(?:Cfn)?Function\(|\b(?:Nodejs|Python|DockerImage)Function\("
    )),
    ("Elastic IPs", re.compile(
        r"AWS::EC2::EIP\b|resource\s+\"aws_eip\"|\bec2\.CfnEIP\("
    )),
    ("NAT gateways", re.compile(
        r"AWS::EC2::NatGateway\b|resource\s+\"aws_nat_gateway\"|\bec2\.CfnNatGateway\("
        r"|\b(?:natGateways\s*:|nat_gateways\s*=)\s*[1-9]|\bNatProvider\.gateway\("
    )),
    ("load balancers", re.compile(
        r"AWS::ElasticLoadBalancing(?:V2)?::LoadBalancer\b"
        r"|resource\s+\"aws_(?:lb|alb|elb)\""
        r"|\b(?:Application|Network)LoadBalancer\(|\belbv2\.CfnLoadBalancer\("
        r"|\b(?:Application|Network)LoadBalanced\w+\("
    )),
)
_ALARM = re.compile(
    r"AWS::CloudWatch::Alarm\b|resource\s+\"aws_cloudwatch_metric_alarm\""
    r"|\bcloudwatch\.(?:Cfn)?Alarm\(|\.create_?[Aa]larm\("
)
_USAGE_NAMESPACE = re.compile(r"\bnamespace[\"']?\s*[:=]\s*[\"']?AWS/Usage\b", re.IGNORECASE)
_SERVICE_QUOTA_MATH = re.compile(r"\bSERVICE_QUOTA\s*\(")
_QUOTA_MONITOR = re.compile(r"quota[-_ ]?monitor", re.IGNORECASE)
_TRUSTED_ADVISOR = re.compile(r"\baws\.trustedadvisor\b")


def quota_usage(repo_path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """The quota-heavy services the IaC uses, and the quota alarms it declares.

    Each maps a name to the first file with it.
    """
    used: dict[str, str] = {}
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        for name, pattern in QUOTA_HEAVY:
            if pattern.search(text):
                used.setdefault(name, rel)
        if _ALARM.search(text) and _USAGE_NAMESPACE.search(text):
            found.setdefault("AWS/Usage alarm", rel)
        if _SERVICE_QUOTA_MATH.search(text):
            found.setdefault("SERVICE_QUOTA metric math", rel)
        if _QUOTA_MONITOR.search(text):
            found.setdefault("Quota Monitor for AWS", rel)
        if _EVENT_RULE.search(text) and _TRUSTED_ADVISOR.search(text):
            found.setdefault("Trusted Advisor service limit events", rel)
    return used, found


class QuotaAlarmMissing(_RepoRule):
    id = "REPO-012"
    title = "No Service Quotas usage alarm for the services the stack uses"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Alarm on quota usage before it blocks a deploy or a scale-out: a CloudWatch alarm "
        "on the AWS/Usage metric with SERVICE_QUOTA() metric math (for example at 80%), the "
        "Quota Monitor for AWS solution, or Trusted Advisor service limit checks routed "
        "through EventBridge."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        used, found = quota_usage(repo_path)
        if not used or found:
            return []
        services = ", ".join(f"{name} ({rel})" for name, rel in used.items())
        return [self._finding(
            f"Uses {services}; searched the IaC for a CloudWatch alarm on the AWS/Usage "
            "namespace, SERVICE_QUOTA metric math, Quota Monitor for AWS, and Trusted Advisor "
            "service limit events on EventBridge; found none"
        )]


# Default quotas REPO-013 measures the IaC against, per account and Region. Sources: the
# Lambda quotas page (/lambda/latest/dg/gettingstarted-limits.html: 1,000 concurrent
# executions, of which 100 always stay unreserved), the Amazon VPC quotas page
# (/vpc/latest/userguide/amazon-vpc-limits.html: 5 Elastic IPs per Region, 5 NAT gateways
# per Availability Zone) and the EC2 Elastic IP page. An account may have raised them; the
# scan cannot see that, so it uses the defaults.
DEFAULT_QUOTAS: dict[str, int] = {
    "lambda_concurrency": 1_000,
    "lambda_unreserved_minimum": 100,
    "elastic_ips": 5,
    "nat_gateways_per_az": 5,
}
# Failover can double the load on what is left, so a declared limit over half the quota
# leaves no room for it.
_FAILOVER_SHARE = 0.5

_RESERVED_CONCURRENCY = re.compile(
    r"\b(?:ReservedConcurrentExecutions|reserved_concurrent_executions"
    r"|reservedConcurrentExecutions)[\"']?\s*[:=]\s*[\"']?(\d+)\b"
)
_EIP_DECLARATION = QUOTA_HEAVY[1][1]
# A CDK VPC's NAT gateways each allocate an Elastic IP of their own. CloudFormation and
# Terraform NAT gateways take one from an EIP resource, which is counted already.
_CDK_NAT_GATEWAYS = re.compile(r"\b(?:natGateways\s*:|nat_gateways\s*=)\s*(\d+)\b")


def declared_limits(repo_path: Path) -> dict[str, list[tuple[str, int]]]:
    """Per limit, the (file, amount) of each literal the IaC declares."""
    limits: dict[str, list[tuple[str, int]]] = {"lambda_concurrency": [], "elastic_ips": []}
    for rel, text in iac_texts(repo_path):
        reserved = sum(int(m.group(1)) for m in _RESERVED_CONCURRENCY.finditer(text))
        if reserved:
            limits["lambda_concurrency"].append((rel, reserved))
        eips = len(_EIP_DECLARATION.findall(text))
        if not rel.endswith((".json", ".yaml", ".yml", ".template", ".tf")):
            eips += sum(int(m.group(1)) for m in _CDK_NAT_GATEWAYS.finditer(text))
        if eips:
            limits["elastic_ips"].append((rel, eips))
    return limits


def _files(parts: list[tuple[str, int]]) -> str:
    return ", ".join(f"{rel} {amount}" for rel, amount in parts)


class FailoverHeadroomMissing(_RepoRule):
    id = "REPO-013"
    title = "Limits the IaC sets leave no room for failover"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Keep what the IaC reserves well under the quota, so a failover that shifts the load "
        "here can still be served: lower reserved concurrency or Elastic IP use, or request "
        "a quota increase in Service Quotas before you need it."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        limits = declared_limits(repo_path)
        findings: List[Finding] = []
        reservable = (
            DEFAULT_QUOTAS["lambda_concurrency"] - DEFAULT_QUOTAS["lambda_unreserved_minimum"]
        )
        reserved = sum(amount for _rel, amount in limits["lambda_concurrency"])
        if reserved > reservable * _FAILOVER_SHARE:
            findings.append(self._finding(
                f"Lambda reserved concurrency sums to {reserved} "
                f"({_files(limits['lambda_concurrency'])}); the default quota is "
                f"{DEFAULT_QUOTAS['lambda_concurrency']:,} per Region with "
                f"{DEFAULT_QUOTAS['lambda_unreserved_minimum']} unreserved, so {reservable} "
                f"can be reserved; over half ({int(reservable * _FAILOVER_SHARE)}) leaves no "
                "room for failover"
            ))
        eips = sum(amount for _rel, amount in limits["elastic_ips"])
        if eips > DEFAULT_QUOTAS["elastic_ips"] * _FAILOVER_SHARE:
            findings.append(self._finding(
                f"Elastic IPs (EIP resources and CDK NAT gateways) number {eips} "
                f"({_files(limits['elastic_ips'])}); the default quota is "
                f"{DEFAULT_QUOTAS['elastic_ips']} per Region; over half leaves no room for "
                "failover"
            ))
        return findings


# VPC CIDR declarations REPO-014 compares (REL 2).
_TF_VPC_BLOCK = re.compile(
    r"\bresource\s+\"(aws_vpc|aws_vpc_ipv4_cidr_block_association)\"\s+\"([^\"]+)\"\s*\{"
)
_TF_VPC_MODULE = re.compile(r"\bmodule\s+\"([^\"]+)\"\s*\{")
_TF_VPC_MODULE_SOURCE = re.compile(r"\bsource\s*=\s*\"[^\"]*terraform-aws-modules/vpc\b")
_TF_CIDR = re.compile(r"^\s*cidr_block\s*=\s*\"([^\"]+)\"", re.MULTILINE)
_TF_MODULE_CIDR = re.compile(r"^\s*cidr\s*=\s*\"([^\"]+)\"", re.MULTILINE)
_CDK_IP_ADDRESSES = re.compile(r"\bIpAddresses\.cidr\(\s*['\"]([^'\"]+)['\"]")
_CDK_VPC_CALL = re.compile(r"(?<![\w.])(?:ec2\.)?Vpc\(")
_CDK_VPC_CIDR = re.compile(r"(?<![\w.])cidr\s*[:=]\s*['\"]([^'\"]+)['\"]")
_CDK_CFN_VPC_CALL = re.compile(r"\bCfnVPC(?:CidrBlock)?\(")
_CDK_CFN_CIDR = re.compile(r"\b(?:cidrBlock|cidr_block)\s*[:=]\s*['\"]([^'\"]+)['\"]")
_CF_VPC_TYPES = ("AWS::EC2::VPC", "AWS::EC2::VPCCidrBlock")


def _braced(text: str, open_brace: int, opener: str = "{", closer: str = "}") -> str:
    """The text between the bracket at open_brace and its match (or the end of text)."""
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == opener:
            depth += 1
        elif text[i] == closer:
            depth -= 1
            if depth == 0:
                return text[open_brace + 1:i]
    return text[open_brace + 1:]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def _cf_vpc_cidrs(rel: str, text: str) -> List[tuple[str, int, str, str]]:
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template, nothing to compare
        return []
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    out: List[tuple[str, int, str, str]] = []
    for name, body in (resources.items() if isinstance(resources, dict) else ()):
        if not isinstance(body, dict) or body.get("Type") not in _CF_VPC_TYPES:
            continue
        props = body.get("Properties")
        cidr = props.get("CidrBlock") if isinstance(props, dict) else None
        if type(cidr) is str:
            at = text.find(str(name))
            out.append((cidr, _line_of(text, text.find(cidr, max(at, 0))), str(name), rel))
    return out


def _tf_vpc_cidrs(rel: str, text: str) -> List[tuple[str, int, str, str]]:
    out: List[tuple[str, int, str, str]] = []
    for block in _TF_VPC_BLOCK.finditer(text):
        body = _braced(text, block.end() - 1)
        cidr = _TF_CIDR.search(body)
        if cidr:
            out.append((cidr.group(1), _line_of(text, block.start()),
                        f"{block.group(1)}.{block.group(2)}", rel))
    for block in _TF_VPC_MODULE.finditer(text):
        body = _braced(text, block.end() - 1)
        cidr = _TF_MODULE_CIDR.search(body)
        if cidr and _TF_VPC_MODULE_SOURCE.search(body):
            out.append((cidr.group(1), _line_of(text, block.start()),
                        f"module.{block.group(1)}", rel))
    return out


def _cdk_vpc_cidrs(rel: str, text: str) -> List[tuple[str, int, str, str]]:
    out: List[tuple[str, int, str, str]] = []
    for match in _CDK_IP_ADDRESSES.finditer(text):
        out.append((match.group(1), _line_of(text, match.start()), "IpAddresses.cidr", rel))
    for pattern, key, label in ((_CDK_VPC_CALL, _CDK_VPC_CIDR, "Vpc cidr"),
                                (_CDK_CFN_VPC_CALL, _CDK_CFN_CIDR, "CfnVPC cidrBlock")):
        for call in pattern.finditer(text):
            args = _braced(text, call.end() - 1, "(", ")")
            for match in key.finditer(args):
                out.append((match.group(1), _line_of(text, call.start()), label, rel))
    return out


def vpc_cidrs(repo_path: Path) -> List[tuple[ipaddress.IPv4Network, int, str, str]]:
    """Literal IPv4 VPC CIDRs the IaC declares: (network, line, what declares it, file).

    A compiled .js next to its .ts source is the same declaration and is skipped.
    """
    texts = list(iac_texts(repo_path))
    names = {rel for rel, _text in texts}
    out: List[tuple[ipaddress.IPv4Network, int, str, str]] = []
    for rel, text in texts:
        suffix = Path(rel).suffix.lower()
        if suffix == ".js" and rel[:-3] + ".ts" in names:
            continue
        if suffix == ".tf":
            found = _tf_vpc_cidrs(rel, text)
        elif suffix in (".ts", ".js", ".py"):
            found = _cdk_vpc_cidrs(rel, text)
        elif "AWS::EC2::VPC" in text:
            found = _cf_vpc_cidrs(rel, text)
        else:
            continue
        for cidr, line, what, where in found:
            try:
                network = ipaddress.IPv4Network(cidr.strip(), strict=False)
            except ValueError:
                continue  # an IPv6 block, a token or a template string
            out.append((network, line, what, where))
    return out


def _separate_environments(rel_a: str, rel_b: str) -> bool:
    """True when two files are for different environments (dev and prod), which never
    connect, so the same range in both is not an overlap."""
    env_a, env_b = from_words(rel_a), from_words(rel_b)
    return env_a is not None and env_b is not None and env_a != env_b


class VpcCidrOverlap(_RepoRule):
    id = "REPO-014"
    title = "VPC CIDR ranges overlap"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Give each VPC that may ever be connected (peering, a transit gateway, VPN or Direct "
        "Connect) its own range from one address plan, for example from Amazon VPC IP Address "
        "Manager (IPAM) pools. Overlapping ranges cannot be peered or routed to each other "
        "without NAT, and fixing them later means re-addressing the VPC."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        cidrs = vpc_cidrs(repo_path)
        findings: List[Finding] = []
        for i, (net_a, line_a, what_a, rel_a) in enumerate(cidrs):
            for net_b, line_b, what_b, rel_b in cidrs[i + 1:]:
                if not net_a.overlaps(net_b) or _separate_environments(rel_a, rel_b):
                    continue
                findings.append(self._finding(
                    f"{net_a} ({what_a}, {rel_a}:{line_a}) overlaps {net_b} "
                    f"({what_b}, {rel_b}:{line_b})",
                    file=rel_b, line=line_b,
                ))
        return findings


# Lambda event sources that deliver at least once (REPO-015, REL 4).
_EVENT_SOURCES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS::Lambda::EventSourceMapping", re.compile(r"AWS::Lambda::EventSourceMapping\b")),
    ("aws_lambda_event_source_mapping",
     re.compile(r"resource\s+\"aws_lambda_event_source_mapping\"")),
    ("CDK SqsEventSource", re.compile(r"\bSqsEventSource\(")),
    ("CDK KinesisEventSource", re.compile(r"\bKinesisEventSource\(")),
    ("CDK DynamoEventSource", re.compile(r"\bDynamoEventSource\(")),
    ("CDK ManagedKafkaEventSource", re.compile(r"\bManagedKafkaEventSource\(")),
    ("CDK event source mapping",
     re.compile(r"\bCfnEventSourceMapping\("
                r"|\.(?:addEventSourceMapping|add_event_source_mapping)\(")),
)
# A SAM function event of a polled type; only read in a SAM template.
_SAM_TRANSFORM = re.compile(r"AWS::Serverless-2016-10-31")
_SAM_POLLED_EVENT = re.compile(
    r"[\"']?Type[\"']?\s*:\s*[\"']?(SQS|Kinesis|DynamoDB|MSK|MQ)[\"']?\s*(?:,|$)", re.MULTILINE
)
# Idempotency in function code or a dedupe store (REPO-015).
_POWERTOOLS_IDEMPOTENCY = re.compile(
    r"aws_lambda_powertools\.utilities\.idempotency|@aws-lambda-powertools/idempotency"
    r"|software\.amazon\.lambda\.powertools\.idempotency|AWS\.Lambda\.Powertools\.Idempotency"
    r"|\bmake(?:Handler)?Idempotent\b|@idempotent(?:_function)?\b|\bidempotent_function\("
    r"|@Idempotent\b|\[Idempotent\]"
)
_CONTENT_DEDUPE = re.compile(
    r"\b(?:ContentBasedDeduplication|content_based_deduplication|contentBasedDeduplication)"
    r"[\"']?\s*[:=]\s*[\"']?(?:true|True)\b"
)
_DEDUPE_ID = re.compile(
    r"\b(?:MessageDeduplicationId|messageDeduplicationId|message_deduplication_id)\b"
)
_NOT_EXISTS = re.compile(r"\battribute_not_exists\s*\(")
_CONDITION_EXPRESSION = re.compile(
    r"\b(?:ConditionExpression|conditionExpression|condition_expression)\b"
)
# Function code in the languages Powertools ships for, plus Go and Kotlin for a conditional write.
_FUNCTION_CODE_SUFFIXES = frozenset({
    ".py", ".ts", ".js", ".mjs", ".cjs", ".java", ".kt", ".cs", ".go",
})


def event_sources(repo_path: Path) -> dict[str, str]:
    """Lambda event sources on queues and streams the IaC declares: kind -> first file."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        for kind, pattern in _EVENT_SOURCES:
            if pattern.search(text):
                found.setdefault(kind, rel)
        if _SAM_TRANSFORM.search(text):
            for match in _SAM_POLLED_EVENT.finditer(text):
                found.setdefault(f"SAM {match.group(1)} event", rel)
    return found


def idempotency_controls(repo_path: Path) -> dict[str, str]:
    """Idempotency the repo shows: control -> first file. IaC and function code outside
    tests is read."""
    found: dict[str, str] = {}
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        suffix = path.suffix.lower()
        if suffix not in _IAC_TEXT_SUFFIXES and suffix not in _FUNCTION_CODE_SUFFIXES:
            continue
        if _in_test_dir(parts) or _TEST_NAME.search(path.name.lower()):
            continue
        rel, text = "/".join(parts), read_text_safe(path)
        if _POWERTOOLS_IDEMPOTENCY.search(text):
            found.setdefault("Powertools idempotency", rel)
        if _CONTENT_DEDUPE.search(text):
            found.setdefault("SQS FIFO content-based deduplication", rel)
        if _DEDUPE_ID.search(text):
            found.setdefault("SQS MessageDeduplicationId", rel)
        if _NOT_EXISTS.search(text) and _CONDITION_EXPRESSION.search(text):
            found.setdefault("conditional write (attribute_not_exists)", rel)
    return found


class IdempotencyMissing(_RepoRule):
    id = "REPO-015"
    title = "Queue and stream workers have no idempotency key or dedupe store"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Queues and streams deliver at least once, and a failed batch is retried, so a "
        "worker sees the same message more than once. Make the handler idempotent: Powertools "
        "for AWS Lambda idempotency (Python @idempotent, TypeScript makeIdempotent) with a "
        "DynamoDB persistence store, a conditional write (attribute_not_exists in a "
        "ConditionExpression) keyed on the message id, or an SQS FIFO queue with "
        "content-based deduplication."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sources = event_sources(repo_path)
        if not sources or idempotency_controls(repo_path):
            return []
        listed = ", ".join(f"{kind} ({rel})" for kind, rel in sources.items())
        return [self._finding(
            f"Lambda reads from queues or streams: {listed}; searched the IaC and function "
            "code for Powertools idempotency, an SQS FIFO queue with content-based "
            "deduplication or a MessageDeduplicationId, and a conditional write "
            "(attribute_not_exists in a ConditionExpression); found none",
            file=next(iter(sources.values())),
        )]


# Reliability testing (REL 12): fault injection (REPO-016) and load tests (REPO-017).

# Typed, so a report that names the resource type in its evidence is not a template.
_FIS_IN_IAC = re.compile(
    r"[\"']?Type[\"']?\s*:\s*[\"']?AWS::FIS::ExperimentTemplate\b"
    r"|resource\s+\"aws_fis_experiment_template\""
    r"|\bCfnExperimentTemplate\("
)
_CHAOS_TOOLS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern)) for name, pattern in (
        ("aws fis start-experiment", r"\bfis\s+start-experiment\b"),
        ("Litmus", r"\blitmusctl\b|\blitmuschaos/|\bkind:\s*ChaosEngine\b"),
        ("Chaos Mesh", r"\bchaos-mesh\b|\bchaosctl\b"),
        ("Gremlin",
         r"\bgremlin\s+(?:attack|attack-container|scenario)\b|\bapi\.gremlin\.com\b"),
        ("Chaos Toolkit", r"\bchaostoolkit\b|\bchaos\s+run\b"),
    )
)
_LOAD_TOOLS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern)) for name, pattern in (
        ("k6", r"\bk6\s+(?:run|cloud)\b|\bgrafana/(?:run-)?k6-action\b"),
        ("Artillery", r"\bartillery\s+run(?:-fargate|-lambda)?\b|\bartilleryio/action-cli\b"),
        ("Locust", r"\blocust\b[^\n]*\s--(?:headless|no-web)\b"),
        ("JMeter", r"\bjmeter\b[^\n]*\s-n\b|\bjmeter:jmeter\b"),
        ("Gatling", r"\bgatling:test\b|\bgatlingRun\b|\bgatling\.sh\b"),
        ("Vegeta", r"\bvegeta\s+attack\b"),
        ("hey/ab", r"\b(?:hey|ab)\s+(?:[^\n|;&]*\s)?-n\s*\d+"),
        ("Taurus", r"\bbzt\s+\S"),
        ("Distributed Load Testing on AWS",
         r"\bdistributed-load-testing\b|\bDistributedLoadTesting\b"),
    )
)


def _build_places(repo_path: Path, builds: List[tuple[str, str]]) -> List[tuple[str, str]]:
    """(where, text) of each build config and each package.json script they run."""
    places = list(builds)
    run = _scripts_run([text for _rel, text in builds], _package_scripts(repo_path))
    places.extend((f"package.json script {script}", command) for script, command in run)
    return places


def _tools_in_builds(
    repo_path: Path, tools: tuple[tuple[str, re.Pattern[str]], ...],
    builds: List[tuple[str, str]] | None = None,
) -> tuple[List[str], dict[str, str]]:
    """The build configs found, and each tool they (or the package.json scripts they run)
    invoke: tool -> first place. builds narrows the search to some build configs."""
    builds = build_texts(repo_path) if builds is None else builds
    found: dict[str, str] = {}
    for where, text in _build_places(repo_path, builds):
        for name, pattern in tools:
            if pattern.search(text):
                found.setdefault(name, where)
    return [rel for rel, _text in builds], found


def fault_injection(repo_path: Path) -> dict[str, str]:
    """FIS experiment templates in the IaC and chaos tools the builds run: kind -> place."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _FIS_IN_IAC.search(text):
            found.setdefault("AWS FIS experiment template", rel)
            break
    _builds, chaos = _tools_in_builds(repo_path, _CHAOS_TOOLS)
    for name, where in chaos.items():
        found.setdefault(name, where)
    return found


class FaultInjectionMissing(_RepoRule):
    id = "REPO-016"
    title = "No fault injection experiment targets the workload"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Test how the workload behaves when parts of it fail: define an AWS FIS experiment "
        "template (stop an instance, throttle an API, fail an AZ) with a stop condition on a "
        "CloudWatch alarm, and run it on a schedule or from the pipeline (aws fis "
        "start-experiment) against a pre-production environment first."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        if fault_injection(repo_path):
            return []
        return [self._finding(
            "Searched the IaC for an AWS FIS experiment template (AWS::FIS::ExperimentTemplate, "
            "aws_fis_experiment_template, fis.CfnExperimentTemplate) and the build configs for "
            "aws fis start-experiment or a chaos tool (Litmus, Chaos Mesh, Gremlin, Chaos "
            "Toolkit); found none"
        )]


_LOAD_TOOL_NAMES = (
    "k6 run, artillery run, locust --headless, jmeter -n, Gatling, vegeta attack, hey or ab "
    "-n, Taurus, Distributed Load Testing on AWS"
)


class LoadTestMissing(_RepoRule):
    id = "REPO-017"
    title = "No load test runs in the pipeline"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Run a load test in the pipeline against a pre-production environment, sized to the "
        "peak the workload must take: k6 or Artillery in a CI step or CodeBuild stage, or "
        "Distributed Load Testing on AWS. Watch scaling and error rates while it runs."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        builds, found = _tools_in_builds(repo_path, _LOAD_TOOLS)
        if found:
            return []
        if not builds:
            return [self._finding(
                "Searched the repo for a build to run a load test (a CI config, or a "
                "CodeBuild buildspec or pipeline in the IaC); found none"
            )]
        return [self._finding(
            f"Searched the build configs ({_listed(builds)}) and the package.json scripts "
            f"they run for a load test ({_LOAD_TOOL_NAMES}); found none"
        )]


# Observability (OPS 4): an application KPI (REPO-018), user experience telemetry on the edge
# (REPO-019), and telemetry on the datastores and queues the workload calls (REPO-020).


def _cf_type(types: str) -> str:
    """A CloudFormation Type key with one of the types, so a report that names the type in
    its evidence is not a template."""
    return rf"[\"']?Type[\"']?\s*:\s*[\"']?AWS::(?:{types})\b"


def _kinds(*pairs: tuple[str, str]) -> tuple[tuple[str, re.Pattern[str]], ...]:
    return tuple((name, re.compile(pattern)) for name, pattern in pairs)


_COMPUTE = _kinds(
    ("Lambda", _cf_type(r"Lambda::Function|Serverless::Function")
     + r"|resource\s+\"aws_lambda_function\""
     r"|\b_?lambda_?\.(?:Cfn)?Function\(|\b(?:Nodejs|Python|Go|DockerImage)Function\("),
    ("ECS service", _cf_type(r"ECS::Service") + r"|resource\s+\"aws_ecs_service\""
     r"|\b(?:Fargate|Ec2)Service\(|\bLoadBalanced(?:Fargate|Ec2)Service\("
     r"|\becs\.CfnService\("),
    ("EKS cluster", _cf_type(r"EKS::Cluster") + r"|resource\s+\"aws_eks_cluster\""
     r"|\beks\.(?:Cfn|Fargate)?Cluster\("),
    ("EC2", _cf_type(r"EC2::Instance|AutoScaling::AutoScalingGroup")
     + r"|resource\s+\"aws_(?:instance|autoscaling_group)\""
     r"|\bec2\.(?:Cfn)?Instance\(|\bautoscaling\.(?:Cfn)?AutoScalingGroup\("),
    ("App Runner", _cf_type(r"AppRunner::Service") + r"|resource\s+\"aws_apprunner_service\""
     r"|\bapprunner\.(?:Cfn)?Service\("),
)
_EDGES = _kinds(
    ("API Gateway", _cf_type(r"ApiGateway::RestApi|ApiGatewayV2::Api|Serverless::(?:Http)?Api")
     + r"|resource\s+\"aws_(?:api_gateway_rest_api|apigatewayv2_api)\""
     r"|\b(?:apigateway|apigw|apigatewayv2|apigwv2)\.(?:Cfn)?\w*Api\("
     r"|\b(?:LambdaRestApi|RestApi|SpecRestApi|HttpApi|CfnRestApi)\("),
    ("load balancer", _cf_type(r"ElasticLoadBalancingV2::LoadBalancer")
     + r"|resource\s+\"aws_(?:lb|alb)\""
     r"|\bApplicationLoadBalancer\(|\bApplicationLoadBalanced\w+\("),
    ("CloudFront", _cf_type(r"CloudFront::Distribution")
     + r"|resource\s+\"aws_cloudfront_distribution\""
     r"|\bcloudfront\.(?:Cfn)?Distribution\(|\bCloudFrontWebDistribution\("),
)
# A SAM function event behind an implicit API.
_SAM_API_EVENT = re.compile(
    r"[\"']?Type[\"']?\s*:\s*[\"']?(?:Http)?Api[\"']?\s*(?:,|$)", re.MULTILINE
)
_DEPENDENCIES = _kinds(
    ("DynamoDB", _cf_type(r"DynamoDB::(?:Global)?Table|Serverless::SimpleTable")
     + r"|resource\s+\"aws_dynamodb_table\"|\bdynamodb\.(?:Cfn)?Table(?:V2)?\("),
    ("RDS", _cf_type(r"RDS::DB(?:Instance|Cluster)")
     + r"|resource\s+\"aws_(?:db_instance|rds_cluster)\""
     r"|\brds\.Cfn(?:DBInstance|DBCluster)\("
     r"|\b(?:DatabaseInstance|DatabaseCluster|ServerlessCluster)(?:FromSnapshot)?\("),
    ("ElastiCache", _cf_type(r"ElastiCache::(?:CacheCluster|ReplicationGroup|ServerlessCache)")
     + r"|resource\s+\"aws_elasticache_(?:cluster|replication_group|serverless_cache)\""
     r"|\belasticache\.Cfn(?:CacheCluster|ReplicationGroup|ServerlessCache)\("),
    ("SQS", _cf_type(r"SQS::Queue") + r"|resource\s+\"aws_sqs_queue\""
     r"|\bsqs\.(?:Cfn)?Queue\("),
    ("SNS", _cf_type(r"SNS::Topic") + r"|resource\s+\"aws_sns_topic\""
     r"|\bsns\.(?:Cfn)?Topic\("),
    ("Kinesis", _cf_type(r"Kinesis::Stream") + r"|resource\s+\"aws_kinesis_stream\""
     r"|\bkinesis\.(?:Cfn)?Stream\("),
    ("OpenSearch", _cf_type(r"OpenSearchService::Domain|Elasticsearch::Domain")
     + r"|resource\s+\"aws_(?:opensearch|elasticsearch)_domain\""
     r"|\b(?:opensearch|opensearchservice|es)\.(?:Cfn)?Domain\("),
)
_TYPED_ALARM = re.compile(
    _cf_type(r"CloudWatch::Alarm") + r"|resource\s+\"aws_cloudwatch_metric_alarm\""
    r"|\bcloudwatch\.(?:Cfn)?Alarm\(|\bnew\s+Alarm\(|\.create_?[Aa]larm\("
)
# REPO-018: a metric outside the AWS/ namespaces. CloudFormation names it in an alarm or a
# metric filter, Terraform in those resources' blocks, CDK in a Metric or MetricFilter call.
_CF_METRIC_RESOURCE = re.compile(_cf_type(r"CloudWatch::Alarm|Logs::MetricFilter"))
_CF_METRIC_TYPES = frozenset({"AWS::CloudWatch::Alarm", "AWS::Logs::MetricFilter"})
_TF_METRIC_RESOURCE = re.compile(
    r"resource\s+\"aws_cloudwatch_(?:metric_alarm|log_metric_filter)\"\s+\"[^\"]+\"\s*\{"
)
_TF_NAMESPACE = re.compile(r"\bnamespace\s*=\s*(?!\"AWS/)(?:\"[^\"\s]+\"|[A-Za-z_][\w.]*)")
_CDK_METRIC_CALL = re.compile(
    r"\bcloudwatch\.Metric\(|(?<![\w.])Metric\(|\b(?:logs\.)?MetricFilter\("
    r"|\.add_?[Mm]etric_?[Ff]ilter\("
)
_CDK_NAMESPACE = re.compile(
    r"\b(?:namespace|metricNamespace|metric_namespace)\s*[:=]\s*"
    r"(?!['\"]AWS/)(?:['\"][^'\"\s]+['\"]|[A-Za-z_][\w.]*)"
)
# In function code: embedded metric format, PutMetricData, Powertools Metrics.
_CUSTOM_METRIC_CODE = _kinds(
    ("embedded metric format",
     r"\baws-embedded-metrics\b|\baws_embedded_metrics\b|\bcreateMetricsLogger\(|@metric_scope\b"
     r"|\bsoftware\.amazon\.cloudwatchlogs\.emf\b|[\"']CloudWatchMetrics[\"']\s*:"),
    ("PutMetricData", r"(?<!cloudwatch:)\bPutMetricData(?:Command)?\b|\bput_metric_data\("
     r"|\bputMetricData\("),
    ("Powertools Metrics",
     r"@aws-lambda-powertools/metrics|aws_lambda_powertools\.metrics\b"
     r"|from\s+aws_lambda_powertools\s+import\s+[^\n]*\bMetrics\b|@metrics\.log_metrics\b"
     r"|\blogMetrics\(|software\.amazon\.lambda\.powertools\.metrics|"
     r"AWS\.Lambda\.Powertools\.Metrics"),
)
# REPO-019: synthetic and real-user monitoring, health checks, or an alarm on an edge metric.
_EDGE_MONITORS = _kinds(
    ("CloudWatch Synthetics canary", _cf_type(r"Synthetics::Canary")
     + r"|resource\s+\"aws_synthetics_canary\""
     r"|\bsynthetics\.(?:Cfn)?Canary\(|\bCfnCanary\(|\bnew\s+Canary\("),
    ("CloudWatch RUM app monitor", _cf_type(r"RUM::AppMonitor")
     + r"|resource\s+\"aws_rum_app_monitor\"|\bCfnAppMonitor\("),
    ("Route 53 health check", _cf_type(r"Route53::HealthCheck")
     + r"|resource\s+\"aws_route53_health_check\""
     r"|\broute53\.(?:Cfn)?HealthCheck\(|\bCfnHealthCheck\("),
)
_EDGE_NAMESPACE = re.compile(r"\bAWS/(?:ApiGateway|ApplicationELB|CloudFront)\b")
_EDGE_METRIC = re.compile(
    r"(?<![\w-])(?:Latency|IntegrationLatency|5XXError|5xx|TargetResponseTime"
    r"|HTTPCode_(?:Target|ELB)_5XX_Count|OriginLatency|5xxErrorRate|TotalErrorRate)(?![\w-])"
)
_CDK_EDGE_METRIC = re.compile(
    r"\.metric(?:Latency|IntegrationLatency|ServerError|5XXError|5xxErrorRate|OriginLatency"
    r"|TotalErrorRate|TargetResponseTime|HttpCode(?:Target|Elb))\("
    r"|\.metric_(?:latency|integration_latency|server_error|origin_latency|total_error_rate"
    r"|target_response_time|http_code_(?:target|elb))\(|\.metric5xx_error_rate\("
    r"|\.metrics\.(?:targetResponseTime|httpCode(?:Target|Elb)|target_response_time"
    r"|http_code_(?:target|elb))\("
)
# REPO-020: AWS SDK tracing in function code, ADOT or Application Signals in the IaC, or an
# alarm on a datastore or queue metric.
_SDK_TRACING_CODE = _kinds(
    ("X-Ray SDK client capture",
     r"\bcaptureAWS(?:v3)?Client\(|\bcaptureAWS\(|\bpatch_all\(\s*\)"
     r"|\bpatch\(\s*[\[(][^\])]*[\"'](?:boto3|botocore)[\"']"
     r"|\bxray\.AWS(?:V2)?\(|\bAWSV2Instrumentor\b|\bRegisterXRayForAllServices\("
     r"|\bcom\.amazonaws\.xray\.interceptors\.TracingInterceptor\b"),
    ("Powertools Tracer", r"\bcaptureAWSv3Client\("),
    ("OpenTelemetry AWS SDK instrumentation",
     r"@opentelemetry/instrumentation-aws-sdk|@opentelemetry/auto-instrumentations-node"
     r"|\bAwsInstrumentation\(|\bBotocoreInstrumentor\b"
     r"|opentelemetry\.instrumentation\.(?:botocore|boto3sqs)"
     r"|\bio\.opentelemetry\.instrumentation\.awssdk\b"),
)
# Powertools Tracer for Python patches boto3 unless auto_patch is off.
_PY_POWERTOOLS_TRACER = re.compile(
    r"from\s+aws_lambda_powertools\s+import\s+[^\n]*\bTracer\b"
    r"|aws_lambda_powertools\.tracing\b"
)
_NO_AUTO_PATCH = re.compile(r"\bauto_patch\s*=\s*False\b")
_DEPENDENCY_MANIFESTS = frozenset({
    "package.json", "pyproject.toml", "pom.xml", "build.gradle", "build.gradle.kts",
})
_OTEL_PACKAGES = re.compile(
    r"@opentelemetry/(?:instrumentation-aws-sdk|auto-instrumentations-node)\b"
    r"|\bopentelemetry-instrumentation-(?:botocore|boto3sqs)\b|\bopentelemetry-javaagent\b"
    r"|\bio\.opentelemetry\.instrumentation\b[^\n]*\baws-sdk\b"
)
_IAC_TRACING = _kinds(
    ("ADOT Lambda layer",
     r"\baws-otel-(?:nodejs|python|java|collector)\w*|\bAWSOpenTelemetryDistro\w*"
     r"|/opt/otel-(?:instrument|handler|proxy-handler|sqs-handler)\b"
     r"|\bAdotLayerVersion\b|\badot_?[Ii]nstrumentation\b|\bAdotLambdaLayer\w*"),
    ("CloudWatch Application Signals", _cf_type(r"ApplicationSignals::\w+")
     + r"|[\"']application_signals[\"']\s*:|\bApplicationSignalsIntegration\("
     r"|\bCfnServiceLevelObjective\("),
)
_DEPENDENCY_NAMESPACE = re.compile(
    r"\bAWS/(?:DynamoDB|RDS|ElastiCache|SQS|SNS|Kinesis|ES)\b"
)
_CDK_DEPENDENCY_METRIC = re.compile(
    r"\.metric(?:Approximate\w+|NumberOf\w+|SentMessageSize|ThrottledRequests\w*|UserErrors"
    r"|SystemErrors\w*|SuccessfulRequestLatency|Consumed\w+|CPUUtilization|DatabaseConnections"
    r"|FreeStorageSpace|FreeableMemory|Deadlocks|ReadLatency|WriteLatency|ReadIOPS|WriteIOPS"
    r"|ServerlessDatabaseCapacity|GetRecords\w*|PutRecords?\w*|Incoming(?:Records|Bytes)"
    r"|(?:Read|Write)ProvisionedThroughputExceeded|ClusterStatus\w*|JVMMemoryPressure"
    r"|SearchLatency|IndexingLatency|AutomatedSnapshotFailure)\("
    r"|\.metric_(?:approximate_\w+|number_of_\w+|sent_message_size|throttled_requests\w*"
    r"|user_errors|system_errors\w*|successful_request_latency|consumed_\w+"
    r"|database_connections|free_storage_space|freeable_memory|deadlocks|read_latency"
    r"|write_latency|read_iops|write_iops|serverless_database_capacity|get_records\w*"
    r"|put_records?\w*|incoming_(?:records|bytes)|(?:read|write)_provisioned_throughput_exceeded"
    r"|cluster_status\w*|jvm_memory_pressure|search_latency|indexing_latency"
    r"|automated_snapshot_failure)\("
)


def _in_iac(repo_path: Path, kinds: tuple[tuple[str, re.Pattern[str]], ...]) -> dict[str, str]:
    """Each kind the IaC outside tests declares: kind -> first file."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        for name, pattern in kinds:
            if pattern.search(text):
                found.setdefault(name, rel)
    return found


def _function_code(repo_path: Path) -> Iterator[tuple[str, str, str]]:
    """(repo-relative path, file name, text) of function code and dependency manifests
    outside tests."""
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        name = path.name.lower()
        if path.suffix.lower() not in _FUNCTION_CODE_SUFFIXES and name not in (
            _DEPENDENCY_MANIFESTS
        ) and not re.fullmatch(r"requirements[\w.-]*\.txt", name):
            continue
        if _in_test_dir(parts) or _TEST_NAME.search(name):
            continue
        yield "/".join(parts), name, read_text_safe(path)


def _namespaces(node: object) -> Iterator[object]:
    """Every Namespace and MetricNamespace value under a CloudFormation resource."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("Namespace", "MetricNamespace"):
                yield value
            else:
                yield from _namespaces(value)
    elif isinstance(node, list):
        for item in node:
            yield from _namespaces(item)


def _cf_custom_namespace(rel: str, text: str) -> bool:
    """A CloudFormation alarm or metric filter on a namespace outside AWS/ (one built with
    an intrinsic function counts)."""
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return False
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    for body in (resources.values() if isinstance(resources, dict) else ()):
        if not isinstance(body, dict) or body.get("Type") not in _CF_METRIC_TYPES:
            continue
        for value in _namespaces(body.get("Properties")):
            if isinstance(value, dict) or (
                isinstance(value, str) and value and not value.startswith("AWS/")
            ):
                return True
    return False


def _custom_namespace(rel: str, text: str) -> bool:
    """A CloudWatch alarm, metric filter or CDK Metric in the text names a namespace outside
    AWS/."""
    if _CF_METRIC_RESOURCE.search(text) and _cf_custom_namespace(rel, text):
        return True
    for match in _TF_METRIC_RESOURCE.finditer(text):
        if _TF_NAMESPACE.search(_braced(text, match.end() - 1)):
            return True
    for match in _CDK_METRIC_CALL.finditer(text):
        if _CDK_NAMESPACE.search(_braced(text, match.end() - 1, "(", ")")):
            return True
    return False


def kpi_metrics(repo_path: Path) -> dict[str, str]:
    """Custom metrics the repo publishes or alarms on: kind -> first file."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _custom_namespace(rel, text):
            found.setdefault("CloudWatch metric outside AWS/", rel)
            break
    for rel, name, text in _function_code(repo_path):
        if name in _DEPENDENCY_MANIFESTS or name.endswith(".txt"):
            continue
        for kind, pattern in _CUSTOM_METRIC_CODE:
            if pattern.search(text):
                found.setdefault(kind, rel)
    return found


def edges(repo_path: Path) -> dict[str, str]:
    """The user-facing endpoints the IaC declares: kind -> first file."""
    found = _in_iac(repo_path, _EDGES)
    if "API Gateway" not in found:
        for rel, text in iac_texts(repo_path):
            if _SAM_TRANSFORM.search(text) and _SAM_API_EVENT.search(text):
                found.setdefault("API Gateway", rel)
                break
    return found


def edge_telemetry(repo_path: Path) -> dict[str, str]:
    """Canaries, RUM, health checks and edge metric alarms: kind -> first file."""
    found = _in_iac(repo_path, _EDGE_MONITORS)
    for rel, text in iac_texts(repo_path):
        if not _TYPED_ALARM.search(text):
            continue
        if _CDK_EDGE_METRIC.search(text) or (
            _EDGE_NAMESPACE.search(text) and _EDGE_METRIC.search(text)
        ):
            found.setdefault("alarm on an edge latency or error metric", rel)
            break
    return found


def dependency_telemetry(repo_path: Path) -> dict[str, str]:
    """SDK tracing and datastore or queue metric alarms: kind -> first file."""
    found = _in_iac(repo_path, _IAC_TRACING)
    for rel, text in iac_texts(repo_path):
        if _TYPED_ALARM.search(text) and (
            _DEPENDENCY_NAMESPACE.search(text) or _CDK_DEPENDENCY_METRIC.search(text)
        ):
            found.setdefault("alarm on a datastore or queue metric", rel)
            break
    for rel, name, text in _function_code(repo_path):
        if name in _DEPENDENCY_MANIFESTS or name.endswith(".txt"):
            if _OTEL_PACKAGES.search(text):
                found.setdefault("OpenTelemetry AWS SDK instrumentation", rel)
            continue
        for kind, pattern in _SDK_TRACING_CODE:
            if pattern.search(text):
                found.setdefault(kind, rel)
        if _PY_POWERTOOLS_TRACER.search(text) and not _NO_AUTO_PATCH.search(text):
            found.setdefault("Powertools Tracer", rel)
    return found


def _named(found: dict[str, str]) -> str:
    return ", ".join(f"{kind} ({rel})" for kind, rel in found.items())


class KpiMetricMissing(_RepoRule):
    id = "REPO-018"
    title = "No application KPI metric"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Publish the metrics that say whether the workload does its job (orders placed, "
        "jobs completed, sign-ups) in your own CloudWatch namespace: embedded metric format "
        "or Powertools for AWS Lambda Metrics in the function code, or a metric filter on "
        "the application logs. Alarm and build dashboards on them, not only on the AWS/ "
        "service metrics."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute or kpi_metrics(repo_path):
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for a CloudWatch alarm, metric or "
            "metric filter in a namespace outside AWS/, and the function code for embedded "
            "metric format, the CloudWatch put metric data API, or Powertools Metrics; "
            "found none",
        )]


class EdgeTelemetryMissing(_RepoRule):
    id = "REPO-019"
    title = "No user experience telemetry on the edge"
    severity = "Medium"
    themes = ("observability",)
    recommendation = (
        "Measure what users see at the front door: a CloudWatch Synthetics canary on the "
        "main user journeys, CloudWatch RUM for browser clients, a Route 53 health check on "
        "the endpoint, or alarms on the edge latency and 5xx metrics (API Gateway Latency "
        "and 5XXError, ALB TargetResponseTime and HTTPCode_Target_5XX_Count, CloudFront "
        "5xxErrorRate)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = edges(repo_path)
        if not found or edge_telemetry(repo_path):
            return []
        return [self._finding(
            f"Serves users through {_named(found)}; searched the IaC for a CloudWatch "
            "Synthetics canary, a CloudWatch RUM app monitor, a Route 53 health check, and "
            "an alarm on an edge latency or 5xx metric; found none",
        )]


class DependencyTelemetryMissing(_RepoRule):
    id = "REPO-020"
    title = "No telemetry on the datastores and queues the workload calls"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "See how the workload's dependencies behave: trace AWS SDK calls (X-Ray "
        "captureAWSv3Client or patch_all, Powertools Tracer, or OpenTelemetry with the ADOT "
        "Lambda layer or CloudWatch Application Signals), and alarm on the datastore and "
        "queue metrics (DynamoDB throttles, RDS connections, SQS age of oldest message)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = _in_iac(repo_path, _DEPENDENCIES)
        if not found or dependency_telemetry(repo_path):
            return []
        return [self._finding(
            f"Calls {_named(found)}; searched the function code for AWS SDK tracing (X-Ray, "
            "Powertools Tracer, OpenTelemetry), the IaC for the ADOT Lambda layer or "
            "CloudWatch Application Signals, and an alarm on a datastore or queue metric; "
            "found none",
        )]


# Deployment risk (OPS 6): a test gates each deploy (REPO-021), and the compute's deployments
# roll back on their own (REPO-022).

# A tool name only counts at the start of a command (a line or list item, a run: key, after a
# quote, ;, && or |), so pip install pytest is not a test run.
_CMD_START = (
    r"(?:^[ \t-]*|\brun:[ \t]*|[\"'`;&|(][ \t]*|\bpython3?\s+-m\s+|\bnpx\s+|\buv\s+run\s+"
    r"|\bpoetry\s+run\s+)"
)
_TEST_COMMANDS = re.compile(
    r"\b(?:npm|yarn|pnpm)\s+(?:run\s+)?test\b"
    rf"|{_CMD_START}(?:jest|vitest|pytest|tox|taskcat\s+test)(?=[\s\"'`;&|)]|$)"
    r"|\bgo\s+test\b|\bterraform\s+test\b|\bcfn-guard\s+(?:test|validate)\b"
    r"|\b(?:mvn|mvnw)\b[^\n]*?\s(?:test|verify)\b|\b(?:gradle|gradlew)\b[^\n]*?\stest\b"
    r"|\bdotnet\s+test\b|\bcargo\s+test\b|\bmake\s+test\b"
    r"|[\"']?Category[\"']?\s*:\s*[\"']?Test\b|\bcategory\s*=\s*\"Test\""
    r"|\bCodeBuildActionType\.TEST\b",
    re.MULTILINE,
)
_DEPLOY_COMMANDS = re.compile(
    r"\bcdk\s+deploy\b|\bterraform(?:\s+-chdir=\S+)?\s+apply\b"
    r"|\bterragrunt\s+(?:run-all\s+)?apply\b"
    r"|\baws\s+cloudformation\s+(?:deploy|create-stack|update-stack|execute-change-set)\b"
    r"|\bsam\s+deploy\b|\b(?:serverless|sls)\s+deploy\b|\bcopilot\s+(?:\w+\s+)?deploy\b"
    r"|\baws\s+ecs\s+update-service\b|\baws\s+lambda\s+update-function-code\b"
    r"|\baws-actions/(?:aws-cloudformation-github-deploy|amazon-ecs-deploy-task-definition)\b"
    r"|[\"']?Category[\"']?\s*:\s*[\"']?Deploy\b|\bcategory\s*=\s*\"Deploy\""
    r"|\b\w*DeployAction\(|\bCloudFormation(?:CreateUpdateStack|CreateReplaceChangeSet"
    r"|ExecuteChangeSet)Action\("
    # CDK pipelines: addStage(new AppStage(...)), not a codepipeline.Pipeline stage literal.
    r"|\.add_?[sS]tage\(\s*(?!\{|stage_name\b)",
)
_POST_STEPS = re.compile(r"\bpost\s*[:=]")
# A CDK pipelines post: list that holds a step (ShellStep, CodeBuildStep, ...).
_POST_STEP = re.compile(r"post\s*[:=]\s*\[[^\]]*?\w*Step\(")
# Functional tests for REPO-024 beyond the REPO-021 test commands: curl that fails on an HTTP
# error, against a URL; Postman, Playwright and Cypress runs; integ, e2e and smoke scripts;
# the CDK integ-runner.
_SMOKE_TESTS = (
    rf"{_CMD_START}curl(?=\s)(?=[^\n]*?\s(?:--fail(?:-with-body)?|-[a-zA-Z]*f[a-zA-Z]*)"
    r"(?=[\s\"'`;&|)]|$))(?=[^\n]*?(?:https?://|\$\{*\s*\w))"
    rf"|{_CMD_START}(?:newman\s+run|playwright\s+test|cypress\s+run|integ-runner)\b"
    r"|\b(?:npm|yarn|pnpm)\s+(?:run\s+)?(?:integ|e2e|smoke)[\w:.-]*"
)
_FUNCTIONAL_TESTS = re.compile(f"{_TEST_COMMANDS.pattern}|{_SMOKE_TESTS}", re.MULTILINE)
_TEST_COMMAND_NAMES = (
    "npm, yarn or pnpm test, jest, vitest, pytest, tox, go test, terraform test, taskcat, "
    "cfn-guard, mvn, gradle, dotnet, cargo or make test, a CodePipeline test action"
)


def _deploy_at(text: str, match: re.Match[str]) -> int:
    """Where a deploy takes effect. A CDK pipelines stage deploys after its pre steps, so a
    test in pre: gates it and one in post: does not."""
    if not match.group(0).startswith("."):
        return match.start()
    paren = match.start() + match.group(0).index("(")
    call = _braced(text, paren, "(", ")")
    post = _POST_STEPS.search(call)
    return paren + 1 + (post.start() if post else len(call))


def _events(
    text: str, scripts: dict[str, str], depth: int = 0, functional: bool = False
) -> List[tuple[tuple[int, ...], str, bool]]:
    """(position, "test" or "deploy", can fail) in the order the text runs them. A
    package.json script the text runs stands in for its own commands, at the place it is
    run: its position is the offset of the call, then the offset in the script. With
    functional, smoke, integration and end-to-end tests and CDK pipelines post steps count
    as tests too (REPO-024)."""
    lines = text.split("\n")
    out: List[tuple[tuple[int, ...], str, bool]] = []

    def tail_at(end: int) -> str:
        rest = text[end:]
        stop = _TAIL_END.search(rest)
        return rest[:stop.start()] if stop else rest

    for m in (_FUNCTIONAL_TESTS if functional else _TEST_COMMANDS).finditer(text):
        i = text.count("\n", 0, m.start())
        out.append(((m.start(),), "test", not _cannot_fail(lines, i, tail_at(m.end()))))
    for m in _DEPLOY_COMMANDS.finditer(text):
        at = _deploy_at(text, m)
        out.append(((at,), "deploy", True))
        if functional and m.group(0).startswith(".") and _POST_STEP.match(text, at):
            out.append(((at + 1,), "test", True))
    if depth < 3:
        for m in _RUN_SCRIPT.finditer(text):
            command = scripts.get(m.group(1) or m.group(2) or "")
            if command is None:
                continue
            i = text.count("\n", 0, m.start())
            swallowed = _cannot_fail(lines, i, tail_at(m.end()))
            out.extend(
                ((m.start(), *inner), kind, fails and not swallowed)
                for inner, kind, fails in _events(command, scripts, depth + 1, functional)
            )
    return sorted(out, key=lambda event: event[0])


def deploying_builds(
    repo_path: Path, functional: bool = False
) -> List[tuple[str, str, List[tuple[tuple[int, ...], str, bool]]]]:
    """(build config, text, events) of each build config that deploys, itself or through
    the package.json scripts it runs."""
    scripts = _package_scripts(repo_path)
    out: List[tuple[str, str, List[tuple[tuple[int, ...], str, bool]]]] = []
    for rel, text in build_texts(repo_path):
        events = _events(text, scripts, functional=functional)
        if any(kind == "deploy" for _offset, kind, _fails in events):
            out.append((rel, text, events))
    return out


def ungated_deploys(repo_path: Path) -> List[tuple[str, int]]:
    """(build config, line of its first deploy) for each build config that deploys with no
    test that can fail before its last deploy. A test between a staging and a production
    deploy gates the promotion."""
    out: List[tuple[str, int]] = []
    for rel, text, events in deploying_builds(repo_path):
        deploys = [offset for offset, kind, _fails in events if kind == "deploy"]
        gated = any(
            kind == "test" and fails and offset < deploys[-1]
            for offset, kind, fails in events
        )
        if not gated:
            out.append((rel, _line_of(text, deploys[0][0])))
    return out


class DeployTestGateMissing(_RepoRule):
    id = "REPO-021"
    title = "A deploy runs with no test gate before it"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Run the tests before the deploy in the same pipeline, and let a failed test stop "
        "it: a test step ahead of the deploy step in the CI job, a test action in a "
        "CodePipeline stage before the deploy stage, or a pre step on a CDK pipelines stage. "
        "Do not swallow the test's exit code, and deploy to a staging environment and test "
        "it before promoting to production."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        ungated = ungated_deploys(repo_path)
        if not ungated:
            return []
        places = [f"{rel} (line {line})" for rel, line in ungated]
        return [self._finding(
            f"Deploys from {_listed(places)} with no test that can fail before the deploy; "
            "searched each build config and the package.json scripts it runs for a test "
            f"({_TEST_COMMAND_NAMES}) ahead of it; found none",
            file=ungated[0][0],
            line=ungated[0][1],
        )]


_I = re.IGNORECASE
_M = re.MULTILINE
_ROLLBACK_CONTROLS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, flags)) for name, pattern, flags in (
        ("ECS circuit breaker with rollback",
         r"circuit_?breaker[\s\S]{0,200}?\brollback[\"']?\s*[:=]\s*[\"']?true\b", _I),
        ("ECS deployment alarms with rollback",
         r"\balarms[\"']?\s*[:{][\s\S]{0,200}?"
         r"\brollback[\"']?\s*[:=]\s*[\"']?true\b", _I),
        # CDK deploymentAlarms roll back by default.
        ("ECS deployment alarms (CDK)", r"\bdeploymentAlarms\s*:|\bdeployment_alarms\s*=", 0),
        ("CodeDeploy automatic rollback",
         r"auto_?rollback_?configuration[\"']?\s*[:={][\s\S]{0,200}?"
         r"\benabled[\"']?\s*[:=]\s*[\"']?true\b", _I),
        ("SAM DeploymentPreference", r"[\"']?DeploymentPreference[\"']?\s*:", 0),
        ("CloudFormation rollback triggers",
         r"[\"']?RollbackTriggers[\"']?\s*:|--rollback-configuration\b", 0),
        ("CodePipeline stage rollback on failure",
         r"on_?failure[\"']?\s*[:={][\s\S]{0,120}?\bresult[\"']?\s*[:=]\s*[\"']?ROLLBACK\b"
         r"|\bResult\.ROLLBACK\b", _I),
        ("Auto Scaling instance refresh rollback",
         r"[\"']?auto_?rollback[\"']?\s*[:=]\s*[\"']?true\b", _I),
        ("Auto Scaling rolling update on signals",
         r"AutoScalingRollingUpdate[\"']?\s*:[\s\S]{0,400}?"
         r"WaitOnResourceSignals[\"']?\s*:\s*[\"']?true\b", 0),
        ("Argo Rollouts", r"^apiVersion:\s*argoproj\.io/[\s\S]*^kind:\s*Rollout\b"
         r"|^kind:\s*Rollout\b[\s\S]*^apiVersion:\s*argoproj\.io/", _M),
        ("Flagger canary", r"^apiVersion:\s*flagger\.app/[\s\S]*^kind:\s*Canary\b"
         r"|^kind:\s*Canary\b[\s\S]*^apiVersion:\s*flagger\.app/", _M),
    )
)
# CDK deployment groups roll back a failed deployment unless told not to.
_CDK_DEPLOYMENT_GROUP = re.compile(r"\b(?:Lambda|Ecs|Server)DeploymentGroup\(")
_CDK_NO_ROLLBACK = re.compile(r"\bfailedDeployment\s*:\s*false\b|\bfailed_deployment\s*=\s*False\b")


def rollback_controls(repo_path: Path) -> dict[str, str]:
    """Each automated rollback the IaC or builds declare: kind -> first file."""
    found: dict[str, str] = {}
    places = list(iac_texts(repo_path))
    known = {rel for rel, _text in places}
    places.extend((rel, text) for rel, text in build_texts(repo_path) if rel not in known)
    for rel, text in places:
        for name, pattern in _ROLLBACK_CONTROLS:
            if pattern.search(text):
                found.setdefault(name, rel)
        if _CDK_DEPLOYMENT_GROUP.search(text) and not _CDK_NO_ROLLBACK.search(text):
            found.setdefault("CodeDeploy deployment group (CDK)", rel)
    return found


class AutomatedRollbackMissing(_RepoRule):
    id = "REPO-022"
    title = "Deployments of the workload's compute have no automated rollback"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Let a failed deployment roll itself back: turn on the ECS deployment circuit breaker "
        "with rollback (or deployment alarms), deploy Lambda and ECS through CodeDeploy with "
        "automatic rollback on failure and on alarm (SAM DeploymentPreference does this for "
        "Lambda), set CloudFormation rollback triggers on a CloudWatch alarm, or set a "
        "CodePipeline V2 stage to roll back on failure."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute or rollback_controls(repo_path):
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC and builds for an ECS deployment "
            "circuit breaker or deployment alarms with rollback, CodeDeploy automatic "
            "rollback, a SAM deployment preference, CloudFormation rollback triggers, a "
            "CodePipeline stage that rolls back on failure, an Auto Scaling instance refresh "
            "or rolling update that rolls back, and Argo Rollouts or Flagger; found none",
        )]


# Change management (REL 8): live instances are replaced, not changed in place (REPO-023);
# a functional test runs against the deployed change (REPO-024); the infrastructure is
# deployed by automation, the runbook for a deploy (REPO-025); and the deploy runs a
# resiliency test (REPO-026).

_HOST_TARGET = r"(?!git@)[\w.${}-]+@[\w.${}-]+"
_IN_PLACE_COMMANDS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern, re.MULTILINE)) for name, pattern in (
        ("ssh, scp or rsync to a host",
         rf"{_CMD_START}(?:ssh|scp|rsync)\s[^\n]*?\s{_HOST_TARGET}"
         r"|\bappleboy/(?:ssh|scp)-action\b"),
        ("ansible-playbook", rf"{_CMD_START}ansible-playbook\b"),
        ("SSM Run Command", rf"{_CMD_START}aws\s+ssm\s+send-command\b"),
    )
)
_CREATE_DEPLOYMENT = re.compile(rf"{_CMD_START}aws\s+deploy\s+create-deployment\b", re.M)
_REPLACING_CONFIG = re.compile(r"CodeDeployDefault\.(?:Lambda|ECS)")
# CodeDeploy deploys in place on the Server platform unless told to go blue/green.
_NOT_IN_PLACE = re.compile(
    r"\b[dD]eployment_?[tT]ype[\"']?\s*[:=]\s*[\"']?BLUE_GREEN\b"
    r"|\b[cC]ompute_?[pP]latform[\"']?\s*[:=]\s*[\"']?(?:ECS|Lambda)\b"
    r"|\b(?:Lambda|Ecs)DeploymentGroup\("
)
_EXPLICIT_IN_PLACE = re.compile(r"\b[dD]eployment_?[tT]ype[\"']?\s*[:=]\s*[\"']?IN_PLACE\b")
_RUN_DOCUMENTS = frozenset({
    "AWS-RunShellScript", "AWS-RunPowerShellScript", "AWS-ApplyAnsiblePlaybooks",
})
_RUN_DOCUMENT = r"AWS-(?:RunShellScript|RunPowerShellScript|ApplyAnsiblePlaybooks)\b"
_TF_GROUP = re.compile(r"resource\s+\"aws_codedeploy_deployment_group\"\s+\"[^\"]+\"\s*\{")
_TF_ASSOCIATION = re.compile(r"resource\s+\"aws_ssm_association\"\s+\"[^\"]+\"\s*\{")
_TF_RUN_DOCUMENT = re.compile(rf"\bname\s*=\s*\"{_RUN_DOCUMENT}")
_CDK_SERVER_GROUP = re.compile(r"\bServerDeploymentGroup\(")
_CDK_CFN_GROUP = re.compile(r"\bCfnDeploymentGroup\(")
_CDK_ASSOCIATION = re.compile(r"\bCfnAssociation\(")
_CDK_RUN_DOCUMENT = re.compile(rf"\bname\s*[:=]\s*['\"]{_RUN_DOCUMENT}")
_CFN_HUP = re.compile(
    r"/etc/cfn/cfn-hup\.conf\b|\bInitService\.enable\(\s*['\"]cfn-hup['\"]"
    r"|['\"]cfn-hup['\"]\s*:|^\s*cfn-hup\s*:",
    re.MULTILINE,
)
_CF_SUFFIXES = (".json", ".yaml", ".yml", ".template")


def _cf_in_place(rel: str, text: str, replacing: bool) -> List[tuple[str, int]]:
    """(what, line) of each in-place CodeDeploy group and Run Command association in a
    CloudFormation template."""
    if not rel.endswith(_CF_SUFFIXES) or "AWS::" not in text:
        return []
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return []
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    out: List[tuple[str, int]] = []
    for name, body in (resources.items() if isinstance(resources, dict) else ()):
        if not isinstance(body, dict):
            continue
        props = body.get("Properties")
        props = props if isinstance(props, dict) else {}
        line = _line_of(text, text.find(str(name)))
        if body.get("Type") == "AWS::CodeDeploy::DeploymentGroup":
            style = props.get("DeploymentStyle")
            kind = style.get("DeploymentType") if isinstance(style, dict) else None
            if kind == "IN_PLACE" or (style is None and not replacing):
                out.append((f"in-place CodeDeploy deployment group {name}", line))
        elif body.get("Type") == "AWS::SSM::Association":
            if props.get("Name") in _RUN_DOCUMENTS:
                out.append((f"SSM association {name} running {props['Name']}", line))
    return out


def _tf_in_place(text: str, replacing: bool) -> List[tuple[str, int]]:
    out: List[tuple[str, int]] = []
    for m in _TF_GROUP.finditer(text):
        body = _braced(text, m.end() - 1)
        if _EXPLICIT_IN_PLACE.search(body) or (
            "deployment_style" not in body and not replacing
        ):
            out.append(("in-place CodeDeploy deployment group", _line_of(text, m.start())))
    for m in _TF_ASSOCIATION.finditer(text):
        doc = _TF_RUN_DOCUMENT.search(_braced(text, m.end() - 1))
        if doc:
            out.append((
                f"SSM association running {doc.group(0).split(chr(34))[-1]}",
                _line_of(text, m.start()),
            ))
    return out


def _cdk_in_place(text: str, replacing: bool) -> List[tuple[str, int]]:
    out: List[tuple[str, int]] = []
    for m in _CDK_SERVER_GROUP.finditer(text):
        out.append(("CodeDeploy ServerDeploymentGroup (in place)", _line_of(text, m.start())))
    for m in _CDK_CFN_GROUP.finditer(text):
        call = _braced(text, m.end() - 1, "(", ")")
        if _EXPLICIT_IN_PLACE.search(call) or (
            not re.search(r"\bdeployment_?[sS]tyle\b", call) and not replacing
        ):
            out.append(("in-place CodeDeploy deployment group", _line_of(text, m.start())))
    for m in _CDK_ASSOCIATION.finditer(text):
        doc = _CDK_RUN_DOCUMENT.search(_braced(text, m.end() - 1, "(", ")"))
        if doc:
            name = re.search(_RUN_DOCUMENT, doc.group(0))
            out.append((
                f"SSM association running {name.group(0) if name else 'a shell script'}",
                _line_of(text, m.start()),
            ))
    return out


def in_place_changes(repo_path: Path) -> List[tuple[str, str, int | None]]:
    """(what, where, line) for each place the repo changes running instances in place:
    commands in the builds, in-place CodeDeploy groups, Run Command associations, and
    cfn-hup."""
    iac = list(iac_texts(repo_path))
    replacing = any(_NOT_IN_PLACE.search(text) for _rel, text in iac)
    out: List[tuple[str, str, int | None]] = []
    for where, text in _build_places(repo_path, build_texts(repo_path)):
        script = where.startswith("package.json")
        hits = [(name, pattern.search(text)) for name, pattern in _IN_PLACE_COMMANDS]
        for deploy in _CREATE_DEPLOYMENT.finditer(text):
            rest = text[deploy.end():]
            stop = _TAIL_END.search(rest)
            if not replacing and not _REPLACING_CONFIG.search(rest[:stop.start()] if stop else rest):
                hits.append(("in-place CodeDeploy deployment", deploy))
                break
        out.extend(
            (name, where, None if script else _line_of(text, m.start()))
            for name, m in hits if m is not None
        )
    for rel, text in iac:
        found = _cf_in_place(rel, text, replacing)
        if rel.endswith(".tf"):
            found += _tf_in_place(text, replacing)
        elif rel.endswith((".ts", ".js", ".py")):
            found += _cdk_in_place(text, replacing)
        m = _CFN_HUP.search(text)
        if m:
            found.append(("cfn-hup updating live instances", _line_of(text, m.start())))
        out.extend((what, rel, line) for what, line in found)
    return out


class InPlaceChange(_RepoRule):
    id = "REPO-023"
    title = "Live instances are changed in place"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Deploy by replacing instances, not by changing them: bake each release into a new "
        "AMI or container image, and roll it out with an Auto Scaling instance refresh, ECS, "
        "Lambda versions, or CodeDeploy blue/green. Stop running shell sessions, Ansible, "
        "Run Command scripts or cfn-hup against live hosts, so every instance matches a "
        "known, tested image and a failed release is undone by going back to the old one."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        changes = in_place_changes(repo_path)
        if not changes:
            return []
        places = [
            f"{what} in {where}" + (f" (line {line})" if line else "")
            for what, where, line in changes
        ]
        return [self._finding(
            f"Changes running instances in place instead of replacing them: {_listed(places)}",
            file=changes[0][1] if not changes[0][1].startswith("package.json") else None,
            line=changes[0][2],
        )]


_FUNCTIONAL_TEST_NAMES = (
    "the test commands REPO-021 knows, curl with a fail flag against a URL, Newman, "
    "Playwright, Cypress, integ, e2e or smoke package scripts, the CDK integ runner, a "
    "CodePipeline test action, a CDK pipelines post step"
)


def untested_deploys(repo_path: Path) -> List[tuple[str, int]]:
    """(build config, line of its first deploy) for each build config that deploys with no
    functional test that can fail after a deploy: between the first and the last deploy when
    it deploys more than once (staging, test, production), after the deploy otherwise."""
    out: List[tuple[str, int]] = []
    for rel, text, events in deploying_builds(repo_path, functional=True):
        deploys = [offset for offset, kind, _fails in events if kind == "deploy"]
        last = deploys[-1] if len(deploys) > 1 else None
        tested = any(
            kind == "test" and fails and offset > deploys[0]
            and (last is None or offset < last)
            for offset, kind, fails in events
        )
        if not tested:
            out.append((rel, _line_of(text, deploys[0][0])))
    return out


class FunctionalTestMissing(_RepoRule):
    id = "REPO-024"
    title = "No functional test runs against the deployed change"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Test the change once it is deployed, in the same pipeline: after the deploy to a "
        "staging environment, run smoke, integration or end-to-end tests against it (an "
        "HTTP check that fails on an error, Playwright, Cypress, Newman, or a CDK pipelines "
        "post step), and promote to production only when they pass. Do not swallow the "
        "tests' exit code."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        untested = untested_deploys(repo_path)
        if not untested:
            return []
        places = [f"{rel} (line {line})" for rel, line in untested]
        return [self._finding(
            f"Deploys from {_listed(places)} with no functional test that can fail after the "
            "deploy; searched each build config and the package.json scripts it runs for a "
            f"test ({_FUNCTIONAL_TEST_NAMES}) after a deploy, and before the last deploy when "
            "it deploys more than once; found none",
            file=untested[0][0],
            line=untested[0][1],
        )]


_CF_TEMPLATE_TEXT = re.compile(
    r"\bAWSTemplateFormatVersion\b|[\"']?Type[\"']?\s*:\s*[\"']?AWS::\w+::\w+"
)
_CDK_CODE = re.compile(
    r"\baws-cdk-lib\b|\baws_cdk\b|\bnew\s+\w+(?:\.\w+)?\(\s*(?:this|scope|app)\s*,\s*['\"]"
    r"|\b\w+\.\w+\(\s*(?:self|scope|app)\s*,\s*['\"]"
)
_PIPELINE_DECLARED = re.compile(
    _cf_type(r"CodePipeline::Pipeline") + r"|resource\s+\"aws_codepipeline\""
    r"|\bcodepipeline\.(?:Cfn)?Pipeline\(|\bCodePipeline\("
)


def iac_files(repo_path: Path) -> dict[str, int]:
    """How many IaC files outside tests the repo holds, by kind: Terraform, CloudFormation
    templates, and CDK code (cdk.json counts as CDK)."""
    out: dict[str, int] = {}

    def add(kind: str) -> None:
        out[kind] = out.get(kind, 0) + 1

    if (repo_path / "cdk.json").is_file():
        add("CDK")
    for rel, text in iac_texts(repo_path):
        if rel.endswith(".tf"):
            add("Terraform")
        elif rel.endswith(_CF_SUFFIXES) and _CF_TEMPLATE_TEXT.search(text):
            add("CloudFormation")
        elif rel.endswith((".ts", ".js", ".py")) and _CDK_CODE.search(text):
            add("CDK")
    return out


def automated_deploys(repo_path: Path) -> List[str]:
    """Where the repo deploys by automation: build configs that deploy, and pipelines in the
    IaC."""
    found = [rel for rel, _text, _events in deploying_builds(repo_path)]
    found.extend(
        rel for rel, text in iac_texts(repo_path)
        if rel not in found and _PIPELINE_DECLARED.search(text)
    )
    return found


class AutomatedDeployMissing(_RepoRule):
    id = "REPO-025"
    title = "Infrastructure is not deployed by automation"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Deploy the infrastructure from a pipeline, the runbook for every change: a CI job "
        "or CodeBuild project that runs the CDK, CloudFormation or Terraform deploy, a "
        "CodePipeline, or CDK pipelines. Take deploys from laptops out of the path to "
        "production, so each change takes the same reviewed, repeatable steps."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        iac = iac_files(repo_path)
        if not iac or automated_deploys(repo_path):
            return []
        builds = [rel for rel, _text in build_texts(repo_path)]
        searched = (
            f"the build configs ({_listed(builds)}) and the package.json scripts they run "
            "for a deploy step" if builds else "the repo for a build config that deploys"
        )
        held = "; ".join(
            f"{kind}: {count} file{'s' if count > 1 else ''}" for kind, count in sorted(iac.items())
        )
        return [self._finding(
            f"Holds IaC ({held}); searched {searched}, and the IaC for a pipeline; found none",
        )]


_FIS_TASK = re.compile(
    r"\baws-sdk:fis:startExperiment\b"
    r"|\bservice\s*[:=]\s*['\"]fis['\"][\s\S]{0,200}?\baction\s*[:=]\s*['\"]startExperiment['\"]"
)


class ResiliencyTestMissing(_RepoRule):
    id = "REPO-026"
    title = "Deployments run no resiliency test"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Run a resiliency test as part of the deployment: after the deploy to a "
        "pre-production environment, start an AWS FIS experiment from the pipeline (with a "
        "stop condition on a CloudWatch alarm) or run a chaos tool, and promote only when "
        "the workload rides it out."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        deploying = deploying_builds(repo_path)
        if not deploying:
            return []
        builds = [(rel, text) for rel, text, _events in deploying]
        _found, chaos = _tools_in_builds(repo_path, _CHAOS_TOOLS, builds)
        if chaos or any(_FIS_TASK.search(text) for _rel, text in iac_texts(repo_path)):
            return []
        return [self._finding(
            f"Deploys from {_listed([rel for rel, _text in builds])}; searched those builds "
            "and the package.json scripts they run for a started AWS FIS experiment or a "
            "chaos tool (Litmus, Chaos Mesh, Gremlin, Chaos Toolkit), and the IaC for a Step "
            "Functions task that starts an FIS experiment; found none",
            file=builds[0][0],
        )]


# Telemetry analysis (OPS 8): alarms on workload metrics (REPO-027), log analysis (REPO-028),
# trace analysis (REPO-029), and dashboards that show workload metrics (REPO-030). It reuses
# the OPS 4 model above: what counts as a KPI, edge and dependency metric is shared.
_HOST_METRIC = re.compile(
    r"(?<![\w-])(?:CPUUtilization|MemoryUtilization|CPUCreditBalance|CPUCreditUsage"
    r"|NetworkIn|NetworkOut|NetworkPacketsIn|NetworkPacketsOut|DiskReadBytes|DiskWriteBytes"
    r"|DiskReadOps|DiskWriteOps|EBSReadBytes|EBSWriteBytes|EBSReadOps|EBSWriteOps"
    r"|StatusCheckFailed\w*|mem_used_percent|disk_used_percent|cpu_usage_\w+)(?![\w-])"
    r"|\.metric_?[Cc]pu_?[Uu]tilization\(|\.metric_?[Mm]emory_?[Uu]tilization\("
)
_ANOMALY_DETECTOR = re.compile(
    _cf_type(r"CloudWatch::AnomalyDetector")
    + r"|resource\s+\"aws_cloudwatch_anomaly_detector\"|\bCfnAnomalyDetector\("
)
# An alarm on an anomaly detection band (a typed alarm must be in the same file).
_ANOMALY_BAND = re.compile(r"\bANOMALY_DETECTION_BAND\(")
# Application Signals publishes in the ApplicationSignals namespace, X-Ray group metrics in
# AWS/X-Ray.
_TRACE_NAMESPACE = re.compile(r"(?<![\w/])(?:ApplicationSignals|AWS/X-Ray)(?![\w/-])")
_LOG_ANALYSIS = _kinds(
    ("CloudWatch Logs metric filter", _cf_type(r"Logs::MetricFilter")
     + r"|resource\s+\"aws_cloudwatch_log_metric_filter\""
     r"|\blogs\.(?:Cfn)?MetricFilter\(|(?<![\w.])(?:Cfn)?MetricFilter\("
     r"|\.add_?[Mm]etric_?[Ff]ilter\("),
    ("Contributor Insights rule", _cf_type(r"CloudWatch::InsightRule")
     + r"|resource\s+\"aws_cloudwatch_contributor_insight_rule\"|\bCfnInsightRule\("),
    ("Logs Insights saved query", _cf_type(r"Logs::QueryDefinition")
     + r"|resource\s+\"aws_cloudwatch_query_definition\""
     r"|\blogs\.(?:Cfn)?QueryDefinition\(|\bCfnQueryDefinition\(|\bnew\s+QueryDefinition\("),
    ("log anomaly detector", _cf_type(r"Logs::LogAnomalyDetector")
     + r"|resource\s+\"aws_cloudwatch_log_anomaly_detector\"|\bCfnLogAnomalyDetector\("),
    ("subscription filter", _cf_type(r"Logs::SubscriptionFilter")
     + r"|resource\s+\"aws_cloudwatch_log_subscription_filter\""
     r"|\blogs\.(?:Cfn)?SubscriptionFilter\(|(?<![\w.])(?:Cfn)?SubscriptionFilter\("
     r"|\.add_?[Ss]ubscription_?[Ff]ilter\("),
)
_TRACE_ANALYSIS = _kinds(
    ("X-Ray group", _cf_type(r"XRay::Group") + r"|resource\s+\"aws_xray_group\""
     r"|\bxray\.CfnGroup\("),
    ("X-Ray sampling rule", _cf_type(r"XRay::SamplingRule")
     + r"|resource\s+\"aws_xray_sampling_rule\"|\bxray\.CfnSamplingRule\("
     r"|\bCfnSamplingRule\("),
    ("CloudWatch Application Signals",
     _cf_type(r"ApplicationSignals::(?:ServiceLevelObjective|Discovery)")
     + r"|resource\s+\"aws_applicationsignals_\w+\""
     r"|\b(?:applicationsignals|application_signals|aws_applicationsignals)\.Cfn\w+\("
     r"|\bCfnServiceLevelObjective\(|\bApplicationSignalsIntegration\("),
)
_DASHBOARD = re.compile(
    _cf_type(r"CloudWatch::Dashboard") + r"|resource\s+\"aws_cloudwatch_dashboard\""
    r"|\bcloudwatch\.(?:Cfn)?Dashboard\(|\bnew\s+(?:Cfn)?Dashboard\(|\bCfnDashboard\("
)
_CF_DASHBOARD = re.compile(_cf_type(r"CloudWatch::Dashboard"))
_TF_DASHBOARD = re.compile(r"resource\s+\"aws_cloudwatch_dashboard\"\s+\"[^\"]+\"\s*\{")
_CDK_DASHBOARD = re.compile(r"\b(?:cloudwatch\.)?(?:Cfn)?Dashboard\(")
# A metric in a dashboard body: ["Namespace", "MetricName", ...], quotes possibly escaped.
_BODY_METRIC = re.compile(
    r"\[\s*\\*[\"']([\w./:#-]+)\\*[\"']\s*,\s*\\*[\"']([\w./:#-]+)\\*[\"']"
)


def _workload_metric_text(rel: str, text: str) -> bool:
    """The text names a workload metric: a namespace outside AWS/ in an alarm, metric filter
    or CDK Metric, an edge latency or 5xx metric, a datastore or queue metric, or an
    Application Signals or X-Ray metric."""
    return bool(
        _custom_namespace(rel, text) or _CDK_EDGE_METRIC.search(text)
        or (_EDGE_NAMESPACE.search(text) and _EDGE_METRIC.search(text))
        or _DEPENDENCY_NAMESPACE.search(text) or _CDK_DEPENDENCY_METRIC.search(text)
        or _TRACE_NAMESPACE.search(text)
    )


def workload_alarms(repo_path: Path) -> tuple[dict[str, str], list[str], list[str]]:
    """(workload alarm kinds -> first file, files with an alarm, host metrics alarmed on)."""
    found: dict[str, str] = {}
    files: list[str] = []
    host: list[str] = []
    for rel, text in iac_texts(repo_path):
        if _ANOMALY_DETECTOR.search(text):
            found.setdefault("CloudWatch anomaly detector", rel)
        if not _TYPED_ALARM.search(text):
            continue
        if _ANOMALY_BAND.search(text):
            found.setdefault("anomaly detection alarm", rel)
        files.append(rel)
        if _workload_metric_text(rel, text):
            found.setdefault("alarm on a workload metric", rel)
        for match in _HOST_METRIC.finditer(text):
            name = match.group(0).strip(".(")
            if name not in host:
                host.append(name)
    return found, files, host


def log_analysis(repo_path: Path) -> dict[str, str]:
    """Metric filters, Contributor Insights, saved queries, log anomaly detectors and
    subscription filters: kind -> first file."""
    return _in_iac(repo_path, _LOG_ANALYSIS)


def trace_analysis(repo_path: Path) -> dict[str, str]:
    """X-Ray groups and sampling rules, Application Signals, and alarms on trace metrics:
    kind -> first file."""
    found = _in_iac(repo_path, _TRACE_ANALYSIS)
    for rel, text in iac_texts(repo_path):
        if _TYPED_ALARM.search(text) and _TRACE_NAMESPACE.search(text):
            found.setdefault("alarm on an Application Signals or X-Ray metric", rel)
            break
    return found


def _cf_dashboard_bodies(rel: str, text: str) -> list[str]:
    """The DashboardBody of each CloudWatch dashboard in a template, as JSON text."""
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return []
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    bodies: list[str] = []
    for body in (resources.values() if isinstance(resources, dict) else ()):
        if isinstance(body, dict) and body.get("Type") == "AWS::CloudWatch::Dashboard":
            props = body.get("Properties")
            if isinstance(props, dict):
                bodies.append(json.dumps(props.get("DashboardBody"), default=str))
    return bodies


def _dashboard_texts(rel: str, text: str) -> list[str]:
    """The parts of an IaC file that hold its dashboards: CloudFormation dashboard bodies,
    Terraform dashboard blocks, and for CDK the whole file (its metrics feed the widgets)."""
    if _CF_DASHBOARD.search(text):
        return _cf_dashboard_bodies(rel, text)
    blocks = [_braced(text, m.end() - 1) for m in _TF_DASHBOARD.finditer(text)]
    if blocks:
        return blocks
    return [text] if _CDK_DASHBOARD.search(text) else []



def _body_workload(body: str) -> tuple[bool, list[str]]:
    """(the dashboard text shows a workload metric, host metrics it shows)."""
    workload = False
    host: list[str] = []
    for match in _BODY_METRIC.finditer(body):
        namespace, metric = match.groups()
        if not namespace.strip("."):
            continue
        if (not namespace.startswith("AWS/") or _DEPENDENCY_NAMESPACE.fullmatch(namespace)
                or _TRACE_NAMESPACE.fullmatch(namespace)
                or (_EDGE_NAMESPACE.fullmatch(namespace) and _EDGE_METRIC.fullmatch(metric))):
            workload = True
    for match in _HOST_METRIC.finditer(body):
        name = match.group(0).strip(".(")
        if name not in host:
            host.append(name)
    return workload, host


def dashboard_content(repo_path: Path) -> tuple[list[str], bool, list[str]]:
    """(files with a dashboard, any dashboard shows a workload metric, host metrics shown)."""
    files: list[str] = []
    host: list[str] = []
    workload = False
    for rel, text in iac_texts(repo_path):
        if not _DASHBOARD.search(text):
            continue
        files.append(rel)
        cdk = not _CF_DASHBOARD.search(text) and not _TF_DASHBOARD.search(text)
        if cdk and _workload_metric_text(rel, text):
            workload = True
        for part in _dashboard_texts(rel, text):
            shows, seen = _body_workload(part)
            workload = workload or shows
            host.extend(name for name in seen if name not in host)
    return files, workload, host


class WorkloadAlarmMissing(_RepoRule):
    id = "REPO-027"
    title = "Alarms watch only infrastructure metrics, not the workload's"
    severity = "Medium"
    themes = ("observability",)
    recommendation = (
        "Alarm on the metrics that say whether the workload serves its users, not only on "
        "host CPU and memory: the application KPIs in your own namespace, the edge latency "
        "and 5xx metrics, and the datastore and queue metrics the workload depends on. Use "
        "CloudWatch anomaly detection where a static threshold does not fit."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute:
            return []
        found, files, host = workload_alarms(repo_path)
        if found:
            return []
        if not files:
            seen = "found no CloudWatch alarm"
        elif host:
            seen = (f"the alarms in {_listed(files)} watch only infrastructure metrics "
                    f"({_listed(host, 4)})")
        else:
            seen = f"the alarms in {_listed(files)} watch no workload metric"
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for an alarm on a metric outside AWS/, "
            "an edge latency or 5xx metric, a datastore or queue metric, or with anomaly "
            f"detection; {seen}",
        )]


class LogAnalysisMissing(_RepoRule):
    id = "REPO-028"
    title = "Workload logs are not analyzed"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Turn the workload's logs into signals: a CloudWatch Logs metric filter on error "
        "and business events, a Contributor Insights rule for the top callers and failing "
        "keys, saved CloudWatch Logs Insights queries for investigations, a log anomaly "
        "detector, or a subscription filter that ships the logs to an analysis service."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute or log_analysis(repo_path):
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for a CloudWatch Logs metric filter, a "
            "Contributor Insights rule, a Logs Insights saved query, a log anomaly detector, "
            "and a subscription filter; found none",
        )]


class TraceAnalysisMissing(_RepoRule):
    id = "REPO-029"
    title = "Workload traces are not analyzed"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Analyze the traces, not only collect them: define X-Ray groups (with insights) for "
        "the main paths and sampling rules for what matters, or use CloudWatch Application "
        "Signals with service level objectives, and alarm on the trace and SLO metrics."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute or trace_analysis(repo_path):
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for an X-Ray group or sampling rule, "
            "CloudWatch Application Signals service level objectives or discovery, and an "
            "alarm on an Application Signals or X-Ray metric; found none",
        )]


class DashboardWorkloadMetricMissing(_RepoRule):
    id = "REPO-030"
    title = "Dashboards show no workload metric"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Put the workload on the dashboard, not only the hosts: graph the application KPIs, "
        "the edge latency and 5xx metrics, and the datastore and queue metrics next to CPU "
        "and memory, so the dashboard shows whether users are served."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        files, workload, host = dashboard_content(repo_path)
        if not files or workload or not host:
            return []
        return [self._finding(
            f"The CloudWatch dashboards in {_listed(files)} show only infrastructure metrics "
            f"({_listed(host, 4)}); searched them for a metric outside AWS/, an edge "
            "latency or 5xx metric, a datastore or queue metric, and Application Signals; "
            "found none",
        )]


# SEC 3: permission guardrails (REPO-031) and emergency access (REPO-032).

_IAM_PRINCIPAL = re.compile(
    r"[\"']?Type[\"']?\s*:\s*[\"']?AWS::IAM::(?:Role|User)\b"
    r"|resource\s+\"aws_iam_(?:role|user)\"\s+\"|\biam\.(?:Role|User)\("
)
_BOUNDARY = re.compile(
    r"[\"']?PermissionsBoundary[\"']?\s*:|\bpermissions_boundary\s*="
    r"|\bpermissionsBoundary\s*:|\bPermissionsBoundary\.of\(|\bpermissions_boundary\s*:"
    r"|[\"']@aws-cdk/core:permissionsBoundary[\"']\s*:"
)


class PermissionBoundaryMissing(_RepoRule):
    id = "REPO-031"
    title = "IAM roles have no permissions boundary or SCP to cap them"
    category = "Security"
    severity = "Low"
    themes = ("identity",)
    recommendation = (
        "Cap the most a role can do, whatever its own policy says: set a permissions "
        "boundary on the roles and users the workload creates (CDK "
        "PermissionsBoundary.of(app).apply(), or the @aws-cdk/core:permissionsBoundary "
        "context; PermissionsBoundary in CloudFormation; permissions_boundary in Terraform), "
        "or govern the account with service control policies."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        principals: dict[str, str] = {}
        for rel, text in iac_texts(repo_path):
            if _BOUNDARY.search(text):
                return []
            if _IAM_PRINCIPAL.search(text):
                principals.setdefault("IAM role or user", rel)
        if not principals or "service control policy" in org_guardrails(repo_path):
            return []
        return [self._finding(
            f"Declares {_named(principals)}; searched the IaC for a permissions boundary "
            "(PermissionsBoundary, permissions_boundary, CDK permissionsBoundary or "
            "PermissionsBoundary.of, the @aws-cdk/core:permissionsBoundary context) and a "
            "service control policy; found none",
        )]


_ROLE_DECL = re.compile(
    r"[\"']?Type[\"']?\s*:\s*[\"']?AWS::(?:IAM::Role|SSO::PermissionSet)\b"
    r"|resource\s+\"aws_(?:iam_role|ssoadmin_permission_set)\"\s+\""
    r"|\b(?:iam\.Role|sso\.CfnPermissionSet)\("
)
_BREAK_GLASS = re.compile(r"break[\s_-]?glass|emergency[\s_-]?access", re.IGNORECASE)
_BREAK_GLASS_WINDOW = 300
_DAILY_ROLE = re.compile(
    r"(?:\b(?:Role|Roles|ExecutionRoleArn|TaskRoleArn|ServiceRoleArn|role|role_arn"
    r"|execution_role_arn|task_role_arn|service_role|executionRole|taskRole)\b)"
    # The value is a reference: GetAtt, Ref or Sub around an id, or a dotted name.
    r"[\"']?\s*[:=]\s*(?:[\s\[{\"':,]|Fn::\w+|!\w+|\$\{)*[\w.$-]{0,80}?"
    r"(?:break[_-]?glass|emergency[_-]?access)",
    re.IGNORECASE,
)

# The resource a property sits in: the last CloudFormation type, Terraform resource or CDK
# construct declared before it.
_DECLARATION = re.compile(
    r"[\"']?Type[\"']?\s*:\s*[\"']?(AWS::[\w:]+)|resource\s+\"(\w+)\""
    r"|\bnew\s+([\w.]+)\(|\b([\w]+\.[A-Z]\w*)\(\s*self\b"
)
# Attaching a policy to the role, or letting someone assume it, is not using it.
_IAM_OWNER = re.compile(r"^(?:AWS::IAM::|aws_iam_|iam\.)")


def _owner(text: str, offset: int) -> str:
    last = ""
    for match in _DECLARATION.finditer(text, 0, offset):
        last = next(g for g in match.groups() if g)
    return last


def break_glass_roles(repo_path: Path) -> tuple[dict[str, str], List[tuple[str, int]]]:
    """Break-glass roles the IaC declares (kind -> first file), and the places a workload
    resource uses one as its role (file, line)."""
    found: dict[str, str] = {}
    daily: List[tuple[str, int]] = []
    for rel, text in iac_texts(repo_path):
        for match in _ROLE_DECL.finditer(text):
            start = max(0, match.start() - _BREAK_GLASS_WINDOW)
            if _BREAK_GLASS.search(text[start:match.end() + _BREAK_GLASS_WINDOW]):
                kind = "permission set" if "ermission" in match.group(0) else "IAM role"
                found.setdefault(f"break-glass {kind}", rel)
        for match in _DAILY_ROLE.finditer(text):
            if not _IAM_OWNER.search(_owner(text, match.start())):
                daily.append((rel, _line_of(text, match.start())))
    return found, daily


class BreakGlassRoleMissing(_RepoRule):
    id = "REPO-032"
    title = "No break-glass role kept apart from the workload's roles"
    category = "Security"
    severity = "Low"
    themes = ("identity",)
    recommendation = (
        "Keep an emergency access path for when the normal one fails: a break-glass IAM role "
        "(or Identity Center permission set) that only a few people can assume, with MFA, "
        "whose use alarms. Never give it to a workload resource as its everyday role."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found, daily = break_glass_roles(repo_path)
        if not found:
            return [self._finding(
                "Searched the IaC for an IAM role or Identity Center permission set named "
                "for break-glass or emergency access; found none"
            )]
        if not daily:
            return []
        places = [f"{rel} (line {line})" for rel, line in daily]
        return [self._finding(
            f"Declares {_named(found)}, and a workload resource uses it as its role at "
            f"{_listed(places)}",
            file=daily[0][0],
            line=daily[0][1],
        )]


# SEC 4: security findings meet in one place (REPO-033).

_DETECTORS: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple(
    (name, source, re.compile(pattern)) for name, source, pattern in (
        ("GuardDuty detector", "guardduty",
         r"AWS::GuardDuty::Detector\b|resource\s+\"aws_guardduty_detector\""
         r"|guardduty\.CfnDetector\("),
        ("AWS Config", "config",
         r"AWS::Config::(?:ConfigurationRecorder|ConfigRule)\b"
         r"|resource\s+\"aws_config_(?:configuration_recorder|config_rule)\""
         r"|\bconfig\.(?:CfnConfigurationRecorder|CfnConfigRule|ManagedRule|CustomRule)\("),
        ("Amazon Inspector", "inspector2",
         r"AWS::InspectorV2::\w+|resource\s+\"aws_inspector2_enabler\""
         r"|\binspectorv2\.Cfn\w+\("),
        ("Amazon Macie", "macie",
         r"AWS::Macie::Session\b|resource\s+\"aws_macie2_account\"|\bmacie\.CfnSession\("),
        ("IAM Access Analyzer", "access-analyzer",
         r"AWS::AccessAnalyzer::Analyzer\b|resource\s+\"aws_accessanalyzer_analyzer\""
         r"|accessanalyzer\.CfnAnalyzer\("),
    )
)
_FINDING_HUB = re.compile(
    r"AWS::SecurityHub::Hub(?:V2)?\b|resource\s+\"aws_securityhub_account\""
    r"|securityhub\.CfnHub(?:V2)?\("
    r"|AWS::SecurityLake::DataLake\b|resource\s+\"aws_securitylake_data_lake\""
    r"|securitylake\.CfnDataLake\("
)
_RULE_TARGET = re.compile(
    r"[\"']?Targets[\"']?\s*:|resource\s+\"aws_cloudwatch_event_target\""
    r"|\.add_?[tT]arget\(|\btargets\s*[:=]"
)


def finding_destinations(repo_path: Path) -> tuple[dict[str, str], set[str], bool]:
    """The detectors the IaC turns on (name -> first file), the event sources an
    EventBridge rule with a target routes, and whether Security Hub or Security Lake is
    declared."""
    detectors: dict[str, str] = {}
    routed: set[str] = set()
    hub = False
    for rel, text in iac_texts(repo_path):
        hub = hub or bool(_FINDING_HUB.search(text))
        routes = bool(_EVENT_RULE.search(text) and _RULE_TARGET.search(text))
        for name, source, pattern in _DETECTORS:
            if pattern.search(text):
                detectors.setdefault(name, rel)
            if routes and re.search(rf"\baws\.{re.escape(source)}\b", text):
                routed.add(source)
    return detectors, routed, hub


class SecurityFindingsUncorrelated(_RepoRule):
    id = "REPO-033"
    title = "Security findings have no place to meet"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Bring the findings together so one alert can be read with the others: enable "
        "Security Hub (it takes GuardDuty, Config, Inspector, Macie and Access Analyzer "
        "findings), or Amazon Security Lake, or route each detector's events with an "
        "EventBridge rule to one destination your responders watch."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        detectors, routed, hub = finding_destinations(repo_path)
        if hub:
            return []
        alone = {
            name: rel for name, source, _pattern in _DETECTORS
            if (rel := detectors.get(name)) and source not in routed
        }
        if not alone:
            return []
        return [self._finding(
            f"Turns on {_named(alone)}; searched the IaC for Security Hub, Amazon Security "
            "Lake, and an EventBridge rule with a target on the detector's event source; "
            "found none",
        )]


# SEC 5: egress inspection (REPO-034), automated protection (REPO-035), and workloads in
# public subnets (REPO-036).

_EGRESS = _kinds(
    ("NAT gateway", _cf_type(r"EC2::NatGateway") + r"|resource\s+\"aws_nat_gateway\""
     r"|\bec2\.CfnNatGateway\(|\b(?:natGateways\s*:|nat_gateways\s*=)\s*[1-9]"
     r"|\bNatProvider\.(?:gateway|instance\w*)\("),
    ("internet gateway", _cf_type(r"EC2::InternetGateway")
     + r"|resource\s+\"aws_internet_gateway\"|\bec2\.CfnInternetGateway\("),
)
_CDK_VPC = re.compile(r"\bec2\.Vpc(?:V2)?\(")
_NO_NAT = re.compile(r"\b(?:natGateways\s*:|nat_gateways\s*=)\s*0\b")
_INSPECTION = _kinds(
    ("Network Firewall", _cf_type(r"NetworkFirewall::Firewall")
     + r"|resource\s+\"aws_networkfirewall_firewall\"|\bnetworkfirewall\.CfnFirewall\("),
    ("DNS Firewall", _cf_type(r"Route53Resolver::FirewallRuleGroupAssociation")
     + r"|resource\s+\"aws_route53_resolver_firewall_rule_group_association\""
     r"|\broute53resolver\.CfnFirewallRuleGroupAssociation\("),
    ("Gateway Load Balancer endpoint",
     r"[\"']?VpcEndpointType[\"']?\s*:\s*[\"']?GatewayLoadBalancer\b"
     r"|\bvpc_endpoint_type\s*=\s*\"GatewayLoadBalancer\""
     r"|\bvpcEndpointType\s*:\s*['\"]GatewayLoadBalancer['\"]"),
)
_AUTO_PROTECTION = _kinds(
    ("WAF AWS managed rule group",
     r"[\"']?ManagedRuleGroupStatement[\"']?\s*:|\bmanaged_rule_group_statement\s*\{"
     r"|\bmanagedRuleGroupStatement\s*:|\bmanaged_rule_group_statement\s*="),
    ("Shield Advanced protection", _cf_type(r"Shield::Protection")
     + r"|resource\s+\"aws_shield_protection\"|\bshield\.CfnProtection\("),
    ("Firewall Manager policy", _cf_type(r"FMS::Policy")
     + r"|resource\s+\"aws_fms_policy\"|\bfms\.CfnPolicy\("),
    ("Network Firewall managed threat signatures",
     r"aws-managed:(?:stateful|stateless)-rulegroup/(?:ThreatSignatures|AttackInfrastructure"
     r"|BotNet|MalwareDomains|AbusedLegitMalwareDomains)\w*"),
    ("DNS Firewall AWS managed domain list",
     r"\bAWSManagedDomains\w+|[\"']?ManagedOwnerName[\"']?\s*:\s*[\"']?Route\s?53"),
)


def egress_paths(repo_path: Path) -> dict[str, str]:
    """Paths out of a VPC to the internet the IaC declares: kind -> first file."""
    found = _in_iac(repo_path, _EGRESS)
    if "NAT gateway" not in found:
        for rel, text in iac_texts(repo_path):
            if _CDK_VPC.search(text) and not _NO_NAT.search(text):
                found.setdefault("NAT gateway", rel)
                break
    return found


class EgressInspectionMissing(_RepoRule):
    id = "REPO-034"
    title = "Traffic leaves the VPC with no inspection"
    category = "Security"
    severity = "Low"
    themes = ("network-exposure",)
    recommendation = (
        "Inspect what leaves the VPC: route egress through AWS Network Firewall (or a "
        "Gateway Load Balancer with inspection appliances), and associate a Route 53 "
        "Resolver DNS Firewall rule group to block lookups of known-bad domains. A central "
        "inspection VPC behind a transit gateway works too, with no NAT in this VPC."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        egress = egress_paths(repo_path)
        if not egress or _in_iac(repo_path, _INSPECTION):
            return []
        return [self._finding(
            f"Sends traffic out through {_named(egress)}; searched the IaC for AWS Network "
            "Firewall, a Route 53 Resolver DNS Firewall association, and a Gateway Load "
            "Balancer endpoint; found none",
        )]


class AutomatedNetworkProtectionMissing(_RepoRule):
    id = "REPO-035"
    title = "Network protection does not update itself"
    category = "Security"
    severity = "Low"
    themes = ("network-exposure",)
    recommendation = (
        "Use protection that AWS keeps current: AWS managed rule groups in the WAF web ACL "
        "(core rule set, known bad inputs, IP reputation), Shield Advanced with automatic "
        "application layer DDoS mitigation, Firewall Manager policies across accounts, and "
        "AWS managed threat signature rule groups or managed domain lists in Network "
        "Firewall and DNS Firewall."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        exposed = {**edges(repo_path), **egress_paths(repo_path)}
        if not exposed or _in_iac(repo_path, _AUTO_PROTECTION):
            return []
        return [self._finding(
            f"Exposes {_named(exposed)}; searched the IaC for a WAF AWS managed rule group, "
            "Shield Advanced protection, a Firewall Manager policy, and AWS managed threat "
            "signatures or domain lists in Network Firewall or DNS Firewall; found none",
        )]


_CDK_PUBLIC_PLACEMENT = re.compile(
    r"\b(?:vpcSubnets\s*:\s*\{|vpc_subnets\s*=\s*(?:ec2\.)?SubnetSelection\(|vpc_subnets\s*="
    r"\s*\{)[^}]{0,120}?\bsubnet_?[tT]ype\b[\"']?\s*[:=]\s*(?:ec2\.)?SubnetType\.PUBLIC\b"
)
# Constructs that belong in a public subnet.
_PUBLIC_TIER = re.compile(
    r"LoadBalancer|LoadBalanced|NatGateway|NatInstance|InterfaceVpcEndpoint|VpcEndpoint"
    r"|Bastion|^ec2\.Vpc|^aws_(?:lb|alb|elb|nat_gateway|route\w*|network_acl\w*|vpc_endpoint\w*"
    r"|networkfirewall_\w+|eip\w*|subnet\w*|ec2_transit_gateway\w*|globalaccelerator\w*)$"
    r"|^AWS::(?:ElasticLoadBalancing\w*::\w+|EC2::(?:NatGateway|Route|RouteTable"
    r"|SubnetRouteTableAssociation|NetworkAcl\w*|SubnetNetworkAclAssociation|VPCEndpoint"
    r"|EIP\w*|Subnet\w*|TransitGatewayAttachment|TransitGatewayVpcAttachment)"
    r"|NetworkFirewall::\w+|GlobalAccelerator::\w+)$"
)
_TF_SUBNET = re.compile(r"resource\s+\"aws_subnet\"\s+\"(\w+)\"\s*\{")
_TF_MAPS_PUBLIC_IP = re.compile(r"\bmap_public_ip_on_launch\s*=\s*true\b")


def _tf_public_subnets(text: str) -> set[str]:
    return {
        m.group(1) for m in _TF_SUBNET.finditer(text)
        if _TF_MAPS_PUBLIC_IP.search(_braced(text, m.end() - 1))
    }


def _cf_public_workloads(rel: str, text: str) -> List[tuple[str, str]]:
    """(resource, type) of CloudFormation resources that name a public subnet."""
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return []
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    if not isinstance(resources, dict):
        return []
    public = {
        name for name, body in resources.items()
        if isinstance(body, dict) and body.get("Type") == "AWS::EC2::Subnet"
        and str((body.get("Properties") or {}).get("MapPublicIpOnLaunch")).lower() == "true"
    }
    out: List[tuple[str, str]] = []
    for name, body in resources.items():
        if not public or not isinstance(body, dict):
            continue
        rtype = str(body.get("Type", ""))
        if _PUBLIC_TIER.search(rtype):
            continue
        refs = json.dumps(body.get("Properties") or {})
        if any(re.search(rf"\"{re.escape(sub)}\"", refs) for sub in public):
            out.append((name, rtype))
    return out


def public_subnet_workloads(repo_path: Path) -> List[tuple[str, int, str]]:
    """(file, line, what) for each workload the IaC places in a public subnet."""
    out: List[tuple[str, int, str]] = []
    for rel, text in iac_texts(repo_path):
        for match in _CDK_PUBLIC_PLACEMENT.finditer(text):
            owner = _owner(text, match.start())
            if owner and not _PUBLIC_TIER.search(owner):
                out.append((rel, _line_of(text, match.start()), owner))
        public = _tf_public_subnets(text)
        if public:
            for match in re.finditer(r"resource\s+\"(\w+)\"\s+\"(\w+)\"\s*\{", text):
                rtype = match.group(1)
                if _PUBLIC_TIER.search(rtype):
                    continue
                body = _braced(text, match.end() - 1)
                if any(re.search(rf"\baws_subnet\.{re.escape(sub)}\b", body) for sub in public):
                    out.append((rel, _line_of(text, match.start()),
                                f"{rtype}.{match.group(2)}"))
        if '"Resources"' in text or "Resources:" in text:
            for name, rtype in _cf_public_workloads(rel, text):
                at = text.find(name)
                out.append((rel, _line_of(text, max(at, 0)), f"{name} ({rtype})"))
    return out


class PublicSubnetWorkload(_RepoRule):
    id = "REPO-036"
    title = "A workload sits in a public subnet"
    category = "Security"
    severity = "Medium"
    themes = ("network-exposure",)
    recommendation = (
        "Keep public subnets for load balancers, NAT gateways and endpoints. Put instances, "
        "containers, functions and databases in private subnets (CDK "
        "SubnetType.PRIVATE_WITH_EGRESS or PRIVATE_ISOLATED) and reach them through the "
        "load balancer."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = public_subnet_workloads(repo_path)
        if not found:
            return []
        places = [f"{what} in {rel} (line {line})" for rel, line, what in found]
        return [self._finding(
            f"Places {_listed(places)} in a public subnet",
            file=found[0][0],
            line=found[0][1],
        )]


# SEC 6: signed code (REPO-037) and pinned images (REPO-038).

_CODE_SIGNING = re.compile(
    _cf_type(r"Lambda::CodeSigningConfig")
    + r"|resource\s+\"aws_lambda_code_signing_config\"|[\"']?CodeSigningConfigArn[\"']?\s*:"
    r"|\bcode_signing_config_arn\s*=|\bcodeSigningConfig\s*:|\bcode_signing_config\s*="
    r"|\blambda\.(?:Cfn)?CodeSigningConfig\("
)
_ZIP_LAMBDA = re.compile(
    _cf_type(r"Lambda::Function|Serverless::Function")
    + r"|resource\s+\"aws_lambda_function\"|\b_?lambda_?\.(?:Cfn)?Function\("
    r"|\b(?:Nodejs|Python|Go)Function\("
)
_CONTAINERS = re.compile(
    _cf_type(r"ECS::TaskDefinition|EKS::Cluster")
    + r"|resource\s+\"aws_(?:ecs_task_definition|eks_cluster)\""
    r"|\bContainerImage\.from\w+\(|\bDockerImage(?:Function|Code)\b|\beks\.Cluster\("
    r"|[\"']?PackageType[\"']?\s*:\s*[\"']?Image\b|\bpackage_type\s*=\s*\"Image\""
)
_IMAGE_SIGNING = re.compile(
    r"[\"']?PlatformId[\"']?\s*:\s*[\"']?Notation-OCI|\bplatform_id\s*=\s*\"Notation-OCI"
    r"|\bplatformId\s*:\s*['\"]Notation-OCI|\bPlatform\.NOTATION_OCI|\bnotation\s+sign\b"
    r"|\bcosign\s+sign\b"
)


def signing_gaps(repo_path: Path) -> dict[str, str]:
    """Kinds of deployed code with no signing anywhere in the IaC or builds: kind -> file."""
    lambdas: dict[str, str] = {}
    containers: dict[str, str] = {}
    signed_code = signed_images = False
    for rel, text in iac_texts(repo_path):
        signed_code = signed_code or bool(_CODE_SIGNING.search(text))
        signed_images = signed_images or bool(_IMAGE_SIGNING.search(text))
        if _ZIP_LAMBDA.search(text):
            lambdas.setdefault("Lambda functions", rel)
        if _CONTAINERS.search(text):
            containers.setdefault("container images", rel)
    if not signed_images:
        signed_images = any(_IMAGE_SIGNING.search(text) for _rel, text in build_texts(repo_path))
    gaps: dict[str, str] = {}
    if lambdas and not signed_code:
        gaps.update(lambdas)
    if containers and not signed_images:
        gaps.update(containers)
    return gaps


class CodeSigningMissing(_RepoRule):
    id = "REPO-037"
    title = "Deployed code and images are not signed"
    category = "Security"
    severity = "Low"
    themes = ("security-baseline",)
    recommendation = (
        "Check that what runs is what you built: attach a Lambda code signing config with an "
        "AWS Signer profile (and enforce it), and sign container images with AWS Signer and "
        "Notation (or cosign) in the build, verifying the signature before deploy."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        gaps = signing_gaps(repo_path)
        if not gaps:
            return []
        return [self._finding(
            f"Deploys {_named(gaps)}; searched the IaC for a Lambda code signing config and "
            "an AWS Signer Notation profile, and the builds for notation sign or cosign "
            "sign; found none for these",
        )]


_IMAGE_VALUE = re.compile(
    r"[\"']?(?:Image|ImageUri|image|image_uri)[\"']?\s*[:=]\s*[\"']([^\"'\s$]+)[\"']"
    # CloudFormation YAML, unquoted.
    r"|^[ \t-]*(?:Image|ImageUri)[ \t]*:[ \t]+([^\s\"'#{!$&*|>]+)[ \t]*$",
    re.MULTILINE,
)
_CDK_REGISTRY = re.compile(r"\bContainerImage\.from_?[rR]egistry\(\s*['\"]([^'\"]+)['\"]")
_CDK_ECR_LATEST = re.compile(
    r"\b(?:ContainerImage\.from_?[eE]cr_?[rR]epository|DockerImageCode\.from_?[eE]cr)"
    r"\(\s*[\w.]+\s*\)"
)
_REGISTRY_IMAGE = re.compile(r"^[\w.-]+(?::\d+)?(?:/[\w.-]+)*(?::[\w.-]+)?$")


def _mutable(image: str) -> bool:
    """An image reference with no tag, or the latest tag, and no digest."""
    if "@sha256:" in image or not _REGISTRY_IMAGE.match(image):
        return False
    last = image.rsplit("/", 1)[-1]
    if "/" not in image and "." in last.split(":")[0]:
        return False  # a bare host or file name, not an image
    return ":" not in last or last.endswith(":latest")


def mutable_images(repo_path: Path) -> List[tuple[str, int, str]]:
    """(file, line, image) for each container image the IaC references by a mutable tag."""
    out: List[tuple[str, int, str]] = []
    for rel, text in iac_texts(repo_path):
        if not _CONTAINERS.search(text) and not _CDK_REGISTRY.search(text):
            continue
        for match in _IMAGE_VALUE.finditer(text):
            image = match.group(1) or match.group(2)
            if _mutable(image):
                out.append((rel, _line_of(text, match.start()), image))
        for match in _CDK_REGISTRY.finditer(text):
            if _mutable(match.group(1)):
                out.append((rel, _line_of(text, match.start()), match.group(1)))
        for match in _CDK_ECR_LATEST.finditer(text):
            out.append((rel, _line_of(text, match.start()), "ECR repository, latest tag"))
    return out


class MutableImageTag(_RepoRule):
    id = "REPO-038"
    title = "A container image is referenced by a mutable tag"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Pin every image to what you scanned and approved: reference it by digest "
        "(image@sha256:...) or by an immutable version tag in an ECR repository with tag "
        "immutability on. Never deploy :latest or an untagged image."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = mutable_images(repo_path)
        if not found:
            return []
        places = [f"{image} in {rel} (line {line})" for rel, line, image in found]
        return [self._finding(
            f"References {_listed(places)} by a mutable tag",
            file=found[0][0],
            line=found[0][1],
        )]


# SEC 7: classification tags (REPO-039) and controls by sensitivity (REPO-040).

_DATA_STORES = _kinds(
    ("S3 bucket", _cf_type(r"S3::Bucket") + r"|resource\s+\"aws_s3_bucket\""
     r"|\bs3\.(?:Cfn)?Bucket\("),
    ("DynamoDB table", _cf_type(r"DynamoDB::(?:Global)?Table")
     + r"|resource\s+\"aws_dynamodb_table\"|\bdynamodb\.(?:Cfn)?Table(?:V2)?\("),
    ("RDS database", _cf_type(r"RDS::DB(?:Instance|Cluster)")
     + r"|resource\s+\"aws_(?:db_instance|rds_cluster)\""
     r"|\brds\.Cfn(?:DBInstance|DBCluster)\("
     r"|\b(?:DatabaseInstance|DatabaseCluster|ServerlessCluster)(?:FromSnapshot)?\("),
    ("ElastiCache", _cf_type(r"ElastiCache::(?:CacheCluster|ReplicationGroup|ServerlessCache)")
     + r"|resource\s+\"aws_elasticache_(?:cluster|replication_group|serverless_cache)\""
     r"|\belasticache\.Cfn(?:CacheCluster|ReplicationGroup|ServerlessCache)\("),
    ("OpenSearch domain", _cf_type(r"OpenSearchService::Domain|Elasticsearch::Domain")
     + r"|resource\s+\"aws_(?:opensearch|elasticsearch)_domain\""
     r"|\b(?:opensearch|opensearchservice|es)\.(?:Cfn)?Domain\("),
    ("EFS file system", _cf_type(r"EFS::FileSystem") + r"|resource\s+\"aws_efs_file_system\""
     r"|\befs\.(?:Cfn)?FileSystem\("),
    ("Redshift cluster", _cf_type(r"Redshift::Cluster|RedshiftServerless::Namespace")
     + r"|resource\s+\"aws_redshift(?:_cluster|serverless_namespace)\""
     r"|\bredshift\.Cfn(?:Cluster)\("),
    ("DocumentDB cluster", _cf_type(r"DocDB::DBCluster") + r"|resource\s+\"aws_docdb_cluster\""
     r"|\bdocdb\.(?:Cfn)?DatabaseCluster\(|\bdocdb\.CfnDBCluster\("),
    ("Neptune cluster", _cf_type(r"Neptune::DBCluster")
     + r"|resource\s+\"aws_neptune_cluster\"|\bneptune\.CfnDBCluster\("),
    ("Kinesis stream", _cf_type(r"Kinesis::Stream") + r"|resource\s+\"aws_kinesis_stream\""
     r"|\bkinesis\.(?:Cfn)?Stream\("),
)
_CLASS_KEY = r"(?:data[-_ ]?classification|classification|confidentiality|sensitivity)"
# A classification key used as a tag key: CloudFormation Key:, Terraform map key, CDK add().
_CLASS_TAG = re.compile(
    rf"[\"']?Key[\"']?\s*:\s*[\"']?{_CLASS_KEY}[\"']?\s*(?:,|$)"
    rf"|^\s*[\"']?{_CLASS_KEY}[\"']?\s*=\s*\S"
    rf"|\.add\(\s*['\"]{_CLASS_KEY}['\"]"
    rf"|[{{,]\s*[\"']?{_CLASS_KEY}[\"']?\s*:\s*['\"]",
    re.IGNORECASE | re.MULTILINE,
)
_APP_TAGS = re.compile(
    rf"\bTags\.of\(\s*(?:app|this|scope|self)\s*\)\.add\(\s*['\"]{_CLASS_KEY}['\"]",
    re.IGNORECASE,
)
_TF_DEFAULT_TAGS = re.compile(r"\bdefault_tags\s*\{")
_HIGH_VALUE = r"(?:confidential|restricted|secret|sensitive|pii|phi|pci|highly[-_ ]?\w+)"
_HIGH_CLASS = re.compile(
    rf"{_CLASS_KEY}[\"']?\s*(?:[:=,]|\)\.add\()?\s*[^\n]{{0,40}}?['\"]?{_HIGH_VALUE}\b"
    rf"|[\"']?Key[\"']?\s*:\s*[\"']?{_CLASS_KEY}[\"']?\s*,?\s*\n?\s*[\"']?Value[\"']?\s*:"
    rf"\s*[\"']?{_HIGH_VALUE}\b",
    re.IGNORECASE,
)
_CMK = re.compile(
    r"[\"']?(?:KmsKeyId|KMSMasterKeyID|KmsKeyArn|KMSKeyArn)[\"']?\s*:"
    r"|\b(?:kms_key_id|kms_master_key_id|kms_key_arn|kms_key)\s*="
    r"|\bencryption_?[kK]ey\s*[:=]|\bBucketEncryption\.KMS\b"
    r"|\bTableEncryption(?:V2)?\.CUSTOMER_MANAGED\b|\bTableEncryptionV2\.customerManagedKey\("
)


def _app_classified(repo_path: Path) -> bool:
    for _rel, text in iac_texts(repo_path):
        if _APP_TAGS.search(text):
            return True
        for match in _TF_DEFAULT_TAGS.finditer(text):
            if _CLASS_TAG.search(_braced(text, match.end() - 1)):
                return True
    return False


def unclassified_stores(repo_path: Path) -> dict[str, str]:
    """Files that declare a data store and no classification tag: file -> first store."""
    out: dict[str, str] = {}
    files = [
        (rel, text, kinds) for rel, text in iac_texts(repo_path)
        if (kinds := [name for name, pattern in _DATA_STORES if pattern.search(text)])
    ]
    if not files or _app_classified(repo_path):
        return out
    for rel, text, kinds in files:
        if not _CLASS_TAG.search(text):
            out[rel] = kinds[0]
    return out


class DataClassificationMissing(_RepoRule):
    id = "REPO-039"
    title = "Data stores carry no classification tag"
    category = "Security"
    severity = "Low"
    themes = ("data-protection",)
    recommendation = (
        "Tag every data store with its classification (for example DataClassification = "
        "public, internal, confidential or restricted), or tag the whole app (CDK "
        "Tags.of(app), Terraform provider default_tags), so the controls and the people "
        "handling the data follow from its sensitivity. Enforce the key with a tag policy."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = unclassified_stores(repo_path)
        if not found:
            return []
        places = [f"{kind} in {rel}" for rel, kind in found.items()]
        return [self._finding(
            f"Declares {_listed(places)} with no classification tag (DataClassification, "
            "Classification, Confidentiality or Sensitivity) on the store or the app",
        )]


class SensitiveDataWithoutCmk(_RepoRule):
    id = "REPO-040"
    title = "Data classified as sensitive has no customer managed key"
    category = "Security"
    severity = "Medium"
    themes = ("data-protection",)
    recommendation = (
        "Give data classified confidential or restricted the stronger controls: encrypt the "
        "store with a customer managed KMS key whose key policy names who may decrypt, keep "
        "it private, and log access to it."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found: List[str] = []
        for rel, text in iac_texts(repo_path):
            if not any(pattern.search(text) for _name, pattern in _DATA_STORES):
                continue
            if _HIGH_CLASS.search(text) and not _CMK.search(text):
                found.append(rel)
        if not found:
            return []
        return [self._finding(
            f"Classifies data stores in {_listed(found)} as sensitive and encrypts them with "
            "no customer managed KMS key",
        )]


# SEC 8: a control that keeps unencrypted storage from being created (REPO-041).

_EBS_VOLUME = re.compile(
    _cf_type(r"EC2::Volume") + r"|resource\s+\"aws_ebs_volume\"|\bec2\.(?:Cfn)?Volume\("
)
_ENCRYPTION_GUARDS = _kinds(
    ("EBS encryption by default",
     r"resource\s+\"aws_ebs_encryption_by_default\"|\bEnableEbsEncryptionByDefault\b"
     r"|\benable_ebs_encryption_by_default\b"),
    ("deny on an encryption condition key",
     r"[\"']?(?:s3:x-amz-server-side-encryption(?:-aws-kms-key-id)?|ec2:Encrypted"
     r"|rds:StorageEncrypted|elasticfilesystem:Encrypted|dynamodb:\w*Encrypt\w*)[\"']?\s*[:=,]"),
    ("AWS Config encryption rule",
     r"\b(?:ENCRYPTED_VOLUMES|EC2_EBS_ENCRYPTION_BY_DEFAULT|RDS_STORAGE_ENCRYPTED"
     r"|RDS_SNAPSHOT_ENCRYPTED|S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
     r"|S3_DEFAULT_ENCRYPTION_KMS|EFS_ENCRYPTED_CHECK|DYNAMODB_TABLE_ENCRYPTED_KMS"
     r"|DYNAMODB_TABLE_ENCRYPTION_ENABLED|ELASTICSEARCH_ENCRYPTED_AT_REST"
     r"|OPENSEARCH_ENCRYPTED_AT_REST|REDSHIFT_CLUSTER_KMS_ENABLED"
     r"|ELASTICACHE_REPL_GRP_ENCRYPTED_AT_REST|KINESIS_STREAM_ENCRYPTED)\b"
     r"|\bManagedRuleIdentifiers\.(?:EC2_EBS_ENCRYPTION_BY_DEFAULT|EBS_ENCRYPTED_VOLUMES"
     r"|RDS_STORAGE_ENCRYPTED|S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED|EFS_ENCRYPTED_CHECK"
     r"|DYNAMODB_TABLE_ENCRYPTED_KMS)\b"),
    ("CDK Nag", r"\bAspects\.of\([^)]*\)\.add\(\s*new\s+\w*Checks\("
     r"|\bAspects\.of\([^)]*\)\.add\(\s*\w*Checks\(|from\s+['\"]cdk-nag['\"]|\bimport\s+cdk_nag\b"),
)
_POLICY_SCANNERS = _kinds(
    ("checkov", rf"{_CMD_START}checkov\b|\bbridgecrewio/checkov-action\b"),
    ("tfsec", rf"{_CMD_START}tfsec\b|\baquasecurity/tfsec-action\b"),
    ("trivy config", r"\btrivy\s+(?:config|conf)\b|\bscan-type:\s*['\"]?config\b"),
    ("cfn-guard", r"\bcfn-guard\s+validate\b"),
    ("KICS", rf"{_CMD_START}kics\s+scan\b|\bcheckmarx/kics-github-action\b"),
)


def encryption_guards(repo_path: Path) -> dict[str, str]:
    """Controls that stop unencrypted storage being created: kind -> first place."""
    found = _in_iac(repo_path, _ENCRYPTION_GUARDS)
    _builds, scanners = _tools_in_builds(repo_path, _POLICY_SCANNERS)
    for name, where in scanners.items():
        found.setdefault(name, where)
    return found


class EncryptionGuardrailMissing(_RepoRule):
    id = "REPO-041"
    title = "Nothing stops unencrypted storage from being created"
    category = "Security"
    severity = "Low"
    themes = ("data-protection",)
    recommendation = (
        "Make encryption at rest the only way: turn on EBS encryption by default, deny "
        "unencrypted creates with an SCP or bucket policy on the encryption condition keys, "
        "and fail the build when IaC declares unencrypted storage (CDK Nag, checkov, tfsec "
        "or cfn-guard). Back it with AWS Config encryption rules and auto-remediation."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        stores = _in_iac(repo_path, (*_DATA_STORES, ("EBS volume", _EBS_VOLUME)))
        if not stores or encryption_guards(repo_path):
            return []
        return [self._finding(
            f"Declares {_named(stores)}; searched the IaC for EBS encryption by default, a "
            "deny on an encryption condition key, an AWS Config encryption rule and CDK Nag, "
            "and the builds for checkov, tfsec, trivy config, cfn-guard and KICS; found none",
        )]


# Failure interactions (REL 5): local state on compute (REPO-042), an emergency lever to shed
# load (REPO-043), and a fallback when a dependency fails (REPO-044).

_ROOT_DEVICE = r"/dev/(?!(?:xvda|sda1?|nvme0n1)(?![\w/]))"
_LOCAL_STATE = _kinds(
    ("EBS data volume attached",
     _cf_type(r"EC2::VolumeAttachment") + r"|resource\s+\"aws_volume_attachment\""
     r"|\bec2\.CfnVolumeAttachment\(|\.grant_?[aA]ttach_?[vV]olume\w*\("),
    ("EBS data volume on a non-root device",
     rf"[\"']?(?:Device|DeviceName|deviceName|device_name)[\"']?\s*[:=]\s*[\"']?{_ROOT_DEVICE}"
     r"|\bebs_block_device\s*\{"),
    ("ECS host volume",
     r"[\"']?SourcePath[\"']?\s*:|\bsourcePath\s*:|\bHost\(\s*source_path\s*="
     r"|\bhost_path\s*="),
    ("Docker volume shared and autoprovisioned",
     r"[\"']?[aA]utoprovision[\"']?\s*[:=]\s*[\"']?(?:true|True)\b"),
    ("Kubernetes hostPath volume", r"\bhostPath\s*:|\bhost_path\s*\{"),
)


def local_state(repo_path: Path) -> List[tuple[str, str, int]]:
    """Compute that keeps state on local disk: (kind, file, line), first per kind and file."""
    found: List[tuple[str, str, int]] = []
    for rel, text in iac_texts(repo_path):
        for kind, pattern in _LOCAL_STATE:
            match = pattern.search(text)
            if match:
                found.append((kind, rel, _line_of(text, match.start())))
    return found


class LocalStateOnCompute(_RepoRule):
    id = "REPO-042"
    title = "Compute keeps state on local disk"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Keep compute stateless so any instance or task can serve any request and a lost "
        "one loses nothing: put state in DynamoDB, S3, ElastiCache or an EFS mount instead "
        "of an attached data volume, a host volume or a shared Docker volume."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        if not _in_iac(repo_path, _COMPUTE):
            return []
        found = local_state(repo_path)
        if not found:
            return []
        places = [f"{kind} at {rel}:{line}" for kind, rel, line in found]
        return [self._finding(
            f"Keeps state on local disk: {_listed(places, 5)}",
            file=found[0][1],
            line=found[0][2],
        )]


_LEVERS = _kinds(
    ("Lambda reserved concurrency",
     r"[\"']?ReservedConcurrentExecutions[\"']?\s*:|\breservedConcurrentExecutions\s*:"
     r"|\breserved_concurrent_executions\s*=\s*[^-\s]"),
    ("API Gateway throttle",
     r"[\"']?Throttling(?:Burst|Rate)Limit[\"']?\s*:|\bthrottling(?:Burst|Rate)Limit\s*:"
     r"|\bthrottling_(?:burst|rate)_limit\s*=|\bthrottle_settings\s*\{"
     r"|\bthrottle\s*[:=]\s*(?:\{|\w+\.ThrottleSettings\()"
     + "|" + _cf_type(r"ApiGateway::UsagePlan")
     + r"|resource\s+\"aws_api_gateway_usage_plan\"|\.add_?[uU]sage_?[pP]lan\("),
    ("WAF rate-based rule",
     r"[\"']?RateBasedStatement[\"']?\s*:|\brateBasedStatement\s*:"
     r"|\brate_based_statement\s*[{=]"),
    ("AppConfig feature flags",
     r"[\"']?[tT]ype[\"']?\s*[:=]\s*[\"']?AWS\.AppConfig\.FeatureFlags\b"
     r"|\bConfigurationType\.FEATURE_FLAGS\b|AWS-AppConfig-Extension"),
)
_FLAG_CODE = _kinds(
    ("AppConfig agent", r"\blocalhost:2772\b"),
    ("LaunchDarkly", r"@launchdarkly/|\blaunchdarkly[-_][\w-]+|\bldclient\b"),
    ("Unleash", r"\bunleash[-_]client\b|\bUnleashClient\b"),
    ("Flagsmith", r"\bflagsmith\b"),
    ("OpenFeature", r"@openfeature/|\bopenfeature\b"),
    ("Powertools feature flags",
     r"\butilities\.feature_flags\b|software\.amazon\.lambda\.powertools\.featureflags"),
)


def emergency_levers(repo_path: Path) -> dict[str, str]:
    """Ways to shed load or turn a feature off: kind -> first file."""
    found = _in_iac(repo_path, _LEVERS)
    for rel, _name, text in _function_code(repo_path):
        for kind, pattern in _FLAG_CODE:
            if pattern.search(text):
                found.setdefault(kind, rel)
    return found


class EmergencyLeverMissing(_RepoRule):
    id = "REPO-043"
    title = "No emergency lever to shed load"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Give operators a lever they can pull in an incident without a deploy: reserved "
        "concurrency on the Lambda functions, an API Gateway stage or usage plan throttle, "
        "a WAF rate-based rule, or feature flags (AWS AppConfig, LaunchDarkly, Unleash, "
        "OpenFeature) that turn off non-critical paths. Write down when to pull each one."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute or emergency_levers(repo_path):
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for Lambda reserved concurrency, an API "
            "Gateway throttle or usage plan, a WAF rate-based rule and AppConfig feature flags, "
            "and the function code for a feature flag SDK; found none",
            file=next(iter(compute.values())),
        )]


_FALLBACKS = _kinds(
    ("SQS buffer",
     r"\bSqsEventSource\(|\bSqsSubscription\(|\bQueueProcessing(?:Fargate|Ec2)Service\("
     r"|(?m:[\"']?Type[\"']?\s*:\s*[\"']?SQS[\"']?\s*(?:,|$))"
     r"|[\"']?[pP]rotocol[\"']?\s*[:=]\s*[\"']?sqs\b"
     r"|\bevent_source_arn\s*=\s*aws_sqs_queue\."),
    ("Lambda on-failure destination",
     r"[\"']?OnFailure[\"']?\s*:|\bonFailure\s*:|\bon_failure\s*(?:\{|=)"),
    ("Step Functions Catch", r"\\?[\"']Catch\\?[\"']\s*:|(?m:^\s*Catch\s*:)|\bCatch\s*=\s*\["
     r"|\.add_?[cC]atch\("),
    ("CloudFront origin failover",
     r"[\"']?OriginGroups[\"']?\s*:|\borigin_group\s*\{|\bOriginGroup\("
     r"|\bfallback_?[oO]rigin\s*[:=]"),
    ("Route 53 failover routing",
     r"[\"']?[fF]ailover[\"']?\s*[:=]\s*[\"']?(?:PRIMARY|SECONDARY)\b"
     r"|\bfailover_routing_policy\s*\{"),
    ("fixed response or mock integration",
     r"[\"']?FixedResponseConfig[\"']?\s*:|\bfixed_response\s*\{"
     r"|\bListenerAction\.fixed_?[rR]esponse\(|\bMockIntegration\("
     r"|[\"']?Type[\"']?\s*:\s*[\"']?MOCK\b|\btype\s*=\s*\"MOCK\""),
)
_FALLBACK_CODE = re.compile(
    r"\bpybreaker\b|\bopossum\b|\bresilience4j\b|\busing\s+Polly\b|\bhystrix\b"
    r"|\bHystrix\w*|\bcircuitbreaker\b|\bcockatiel\b"
)
# CloudFormation needs the queue and the mapping in one file to call it a buffer.
_CF_SQS_MAPPING = re.compile(_cf_type(r"Lambda::EventSourceMapping"))
_CF_SQS_QUEUE = re.compile(_cf_type(r"SQS::Queue"))


def fallbacks(repo_path: Path) -> dict[str, str]:
    """Buffering or degraded paths when a dependency fails: kind -> first file."""
    found = _in_iac(repo_path, _FALLBACKS)
    for rel, text in iac_texts(repo_path):
        if _CF_SQS_MAPPING.search(text) and _CF_SQS_QUEUE.search(text):
            found.setdefault("SQS buffer", rel)
    for rel, _name, text in _function_code(repo_path):
        if _FALLBACK_CODE.search(text):
            found.setdefault("circuit breaker library", rel)
    return found


class FallbackMissing(_RepoRule):
    id = "REPO-044"
    title = "No fallback when a dependency fails"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Turn hard dependencies into soft ones: buffer work in an SQS queue so callers do "
        "not wait on the consumer, send failed async calls to an on-failure destination, "
        "catch errors in Step Functions, fail over with CloudFront origin groups or Route 53 "
        "failover records, return a degraded or cached answer, or wrap calls in a circuit "
        "breaker."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        if not _in_iac(repo_path, _COMPUTE):
            return []
        deps = {**_in_iac(repo_path, _DEPENDENCIES), **edges(repo_path)}
        if not deps or fallbacks(repo_path):
            return []
        return [self._finding(
            f"Compute depends on {_named(deps)}; searched the IaC for an SQS buffer, an "
            "on-failure destination, a Step Functions catch, origin or DNS failover and a "
            "fixed or mock response, and the function code for a circuit breaker; found none",
            file=next(iter(deps.values())),
        )]


# Workload monitoring (REL 6): alarms defined on workload metrics (REPO-045), logs analyzed
# for errors (REPO-046), alarms that start an automated response (REPO-047), and end to end
# tracing (REPO-048). It reuses the OPS 4 and OPS 8 telemetry model above.

_CF_ALARM = re.compile(_cf_type(r"CloudWatch::Alarm"))
_TF_ALARM = re.compile(r"resource\s+\"aws_cloudwatch_metric_alarm\"\s+\"([^\"]+)\"\s*\{")
_TF_ALARM_METRIC = re.compile(r"\bmetric_name\s*=|\bmetric_query\s*\{")
_TF_ALARM_THRESHOLD = re.compile(r"\bthreshold\s*=|\bthreshold_metric_id\s*=")


def _cf_logical_line(text: str, name: str) -> int | None:
    match = re.search(rf"[\"']?{re.escape(name)}[\"']?\s*:", text)
    return _line_of(text, match.start()) if match else None


def _cf_incomplete_alarms(rel: str, text: str) -> List[tuple[str, int | None, str]]:
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return []
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    found: List[tuple[str, int | None, str]] = []
    for name, body in (resources.items() if isinstance(resources, dict) else ()):
        if not isinstance(body, dict) or body.get("Type") != "AWS::CloudWatch::Alarm":
            continue
        props = body.get("Properties")
        props = props if isinstance(props, dict) else {}
        missing = []
        if "MetricName" not in props and "Metrics" not in props:
            missing.append("metric")
        if "Threshold" not in props and "ThresholdMetricId" not in props:
            missing.append("threshold")
        if missing:
            found.append((str(name), _cf_logical_line(text, str(name)), " or ".join(missing)))
    return found


def _tf_incomplete_alarms(text: str) -> List[tuple[str, int | None, str]]:
    found: List[tuple[str, int | None, str]] = []
    for match in _TF_ALARM.finditer(text):
        block = _braced(text, match.end() - 1)
        missing = []
        if not _TF_ALARM_METRIC.search(block):
            missing.append("metric")
        if not _TF_ALARM_THRESHOLD.search(block):
            missing.append("threshold")
        if missing:
            found.append((match.group(1), _line_of(text, match.start()), " or ".join(missing)))
    return found


def incomplete_alarms(repo_path: Path) -> List[tuple[str, str, int | None, str]]:
    """CloudFormation and Terraform alarms with no metric or no threshold:
    (name, file, line, what is missing). CDK alarms need both to be built."""
    found: List[tuple[str, str, int | None, str]] = []
    for rel, text in iac_texts(repo_path):
        alarms = _tf_incomplete_alarms(text)
        if _CF_ALARM.search(text):
            alarms += _cf_incomplete_alarms(rel, text)
        found.extend((name, rel, line, missing) for name, line, missing in alarms)
    return found


class AlarmMetricUndefined(_RepoRule):
    id = "REPO-045"
    title = "Alarms are not defined on workload metrics"
    category = "Reliability"
    severity = "Medium"
    themes = ("observability",)
    recommendation = (
        "Define each alarm on a named metric with a statistic, a period and a threshold, and "
        "pick metrics that show whether the workload works: request errors and latency, "
        "queue depth and age, failed jobs, and the application's own KPIs. CPU and memory "
        "alone say how busy the hosts are, not whether requests succeed."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute:
            return []
        incomplete = incomplete_alarms(repo_path)
        if incomplete:
            places = [f"{name} at {rel}:{line} (no {missing})" if line else
                      f"{name} in {rel} (no {missing})"
                      for name, rel, line, missing in incomplete]
            return [self._finding(
                f"Declares CloudWatch alarms without a metric or a threshold: "
                f"{_listed(places, 4)}",
                file=incomplete[0][1],
                line=incomplete[0][2],
            )]
        found, files, host = workload_alarms(repo_path)
        if not files or found or not host:
            return []
        return [self._finding(
            f"Runs {_named(compute)}; every alarm defined (in {_listed(files)}) is on a host "
            f"metric ({_listed(host, 4)}), and none is defined on a request, error, queue or "
            "application metric",
            file=files[0],
        )]


_LOG_ERROR_ANALYSIS = tuple(
    (kind, pattern) for kind, pattern in _LOG_ANALYSIS
    if kind in ("Logs Insights saved query", "log anomaly detector", "subscription filter")
)
_CF_METRIC_FILTER = re.compile(_cf_type(r"Logs::MetricFilter"))
_TF_METRIC_FILTER = re.compile(
    r"resource\s+\"aws_cloudwatch_log_metric_filter\"\s+\"[^\"]+\"\s*\{"
)
_TF_PATTERN = re.compile(r"(?m)^\s*pattern\s*=\s*(.*)$")
_CDK_METRIC_FILTER = re.compile(
    r"\b(?:logs\.)?(?:Cfn)?MetricFilter\(|\.add_?[Mm]etric_?[Ff]ilter\("
)
_CDK_FILTER_PATTERN = re.compile(r"\bFilterPattern\.\w+\(")
_CDK_PATTERN_STRING = re.compile(r"\bfilter_?[pP]attern\s*[:=]\s*(['\"`])(.*?)\1")
# An error in a filter pattern: ERROR, Exception, FATAL, a 5xx status.
_ERROR_TERM = re.compile(
    r"(?i:(?<![\w-])(?:errors?|exceptions?|fatal|critical|panic)(?![\w-]))"
    r"|[a-z]Exception\b|(?<![\w.])5(?:\d\d|xx|XX|\*)(?!\d)"
)


def _cf_error_filter(rel: str, text: str) -> bool:
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return False
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    for body in (resources.values() if isinstance(resources, dict) else ()):
        if not isinstance(body, dict) or body.get("Type") != "AWS::Logs::MetricFilter":
            continue
        props = body.get("Properties")
        pattern = props.get("FilterPattern") if isinstance(props, dict) else None
        if _ERROR_TERM.search(json.dumps(pattern, default=str)):
            return True
    return False


def _error_filter(rel: str, text: str) -> bool:
    """The text holds a CloudWatch Logs metric filter whose pattern names an error."""
    if _CF_METRIC_FILTER.search(text) and _cf_error_filter(rel, text):
        return True
    for match in _TF_METRIC_FILTER.finditer(text):
        for pattern in _TF_PATTERN.finditer(_braced(text, match.end() - 1)):
            if _ERROR_TERM.search(pattern.group(1)):
                return True
    if not _CDK_METRIC_FILTER.search(text):
        return False
    for match in _CDK_FILTER_PATTERN.finditer(text):
        if _ERROR_TERM.search(_braced(text, match.end() - 1, "(", ")")):
            return True
    return any(_ERROR_TERM.search(m.group(2)) for m in _CDK_PATTERN_STRING.finditer(text))


def error_log_analysis(repo_path: Path) -> dict[str, str]:
    """Error metric filters, saved queries, log anomaly detectors and subscription filters:
    kind -> first file."""
    found = _in_iac(repo_path, _LOG_ERROR_ANALYSIS)
    for rel, text in iac_texts(repo_path):
        if _error_filter(rel, text):
            found.setdefault("metric filter on errors", rel)
            break
    return found


class LogErrorAnalysisMissing(_RepoRule):
    id = "REPO-046"
    title = "Logs are not analyzed for errors"
    category = "Reliability"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Read the logs for failures, not only keep them: add a CloudWatch Logs metric filter "
        "that counts error lines (ERROR, exceptions, 5xx status codes) and alarm on it, turn "
        "on a log anomaly detector, save Logs Insights queries for errors, or stream the logs "
        "to an analysis service with a subscription filter. Set a retention on each log "
        "group too (CF-CW-001)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute or error_log_analysis(repo_path):
            return []
        filters = _in_iac(repo_path, _LOG_ANALYSIS[:1])
        seen = (f"the metric filters in {_listed(list(filters.values()))} count no error"
                if filters else "found none")
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for a CloudWatch Logs metric filter on "
            "errors, a log anomaly detector, a Logs Insights saved query and a subscription "
            f"filter; {seen}",
            file=next(iter(compute.values())),
        )]


# An EC2 Auto Scaling or Application Auto Scaling policy (REPO-047, REPO-049, REPO-050).
_SCALING_POLICY = (
    _cf_type(r"ApplicationAutoScaling::ScalingPolicy|AutoScaling::ScalingPolicy")
    + r"|resource\s+\"aws_(?:appautoscaling|autoscaling)_policy\""
    r"|\.(?:scaleOn\w+|scale_on_\w+|autoScale\w+|auto_scale_\w+|scaleToTrack\w*"
    r"|scale_to_track\w*|add_?[aA]uto_?[sS]caling)\("
    r"|\b(?:Cfn)?(?:Step|TargetTracking)?ScalingPolicy\("
)
_AUTOMATED_RESPONSE = _kinds(
    ("scaling policy", _SCALING_POLICY),
    ("alarm action that runs automation",
     r"[\"']?(?:AlarmActions|OKActions|alarm_actions|ok_actions)[\"']?\s*[:=]\s*[^\]]{0,300}?"
     r"(?:arn:[^:\s\"']+:(?:automate|lambda|ssm|ssm-incidents):"
     r"|aws_lambda_(?:function|alias)\.|aws_ssmincidents_response_plan\.)"
     r"|\.add_?(?:[aA]larm|[oO]k)_?[aA]ction\(\s*(?:new\s+)?(?:\w+\.)*"
     r"(?:Lambda|AutoScaling|Ec2|Ssm|SsmIncident)Action\("),
)
_EVENT_RULE_DECL = re.compile(
    _cf_type(r"Events::Rule") + r"|resource\s+\"aws_cloudwatch_event_rule\""
    r"|\bevents\.(?:Cfn)?Rule\(|\bnew\s+Rule\("
)
_ALARM_STATE_EVENT = re.compile(r"\\?[\"']CloudWatch Alarm State Change\\?[\"']")
_EVENT_TARGET = re.compile(
    r"[\"']?Targets[\"']?\s*:|resource\s+\"aws_cloudwatch_event_target\""
    r"|\btargets\s*[:=]\s*\[|\.add_?[tT]arget\("
)


def automated_responses(repo_path: Path) -> dict[str, str]:
    """Scaling policies, alarm actions that run automation, and EventBridge rules on alarm
    state changes with a target: kind -> first file."""
    found = _in_iac(repo_path, _AUTOMATED_RESPONSE)
    for rel, text in iac_texts(repo_path):
        if (_EVENT_RULE_DECL.search(text) and _ALARM_STATE_EVENT.search(text)
                and _EVENT_TARGET.search(text)):
            found.setdefault("EventBridge rule on alarm state", rel)
            break
    return found


class AlarmResponseMissing(_RepoRule):
    id = "REPO-047"
    title = "Alarms trigger no automated response"
    category = "Reliability"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Let monitoring act, not only notify: scale on load with a target tracking or step "
        "scaling policy, point alarm actions at an SSM Automation runbook, an OpsItem, an "
        "Incident Manager response plan or a Lambda function, or route alarm state changes "
        "through an EventBridge rule to automation."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute or automated_responses(repo_path):
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for an Auto Scaling or Application "
            "Auto Scaling policy, an alarm action that runs automation or a Lambda function, "
            "and an EventBridge rule on alarm state changes; found none",
            file=next(iter(compute.values())),
        )]


_COMPUTE_TRACING = _kinds(
    ("Lambda active tracing",
     r"[\"']?Tracing[\"']?\s*:\s*[\"']?Active\b"
     r"|[\"']?TracingConfig[\"']?\s*:\s*\{?\s*[\"']?Mode[\"']?\s*:\s*[\"']?Active\b"
     r"|\btracing_config\s*\{[^}]*\bmode\s*=\s*\"Active\""
     r"|\btracing\s*[:=]\s*(?:\w+\.)*Tracing\.ACTIVE\b"),
    ("X-Ray daemon or ADOT collector container",
     r"\baws-xray-daemon\b|\baws-otel-collector\b|\bAwsOtelCollector\w*"),
    ("EKS observability add-on",
     r"[\"']?(?:AddonName|addon_name|addonName)[\"']?\s*[:=]\s*[\"']?"
     r"(?:adot|amazon-cloudwatch-observability)\b"),
    ("App Runner tracing",
     r"[\"']?(?:TraceConfiguration|trace_configuration|traceConfiguration)[\"']?\s*[:={]"),
)
_REST_API = re.compile(
    _cf_type(r"ApiGateway::RestApi|Serverless::Api")
    + r"|resource\s+\"aws_api_gateway_rest_api\""
    r"|\b(?:apigateway|apigw)\.(?:Cfn)?(?:RestApi|LambdaRestApi|SpecRestApi|StepFunctionsRestApi)\("
    r"|(?<![\w.])(?:LambdaRestApi|RestApi|SpecRestApi|StepFunctionsRestApi|CfnRestApi)\("
)
# A SAM function event behind an implicit REST API (HttpApi has no X-Ray).
_SAM_REST_EVENT = re.compile(r"(?m)[\"']?Type[\"']?\s*:\s*[\"']?Api[\"']?\s*(?:,|$)")
_STAGE_TRACING = re.compile(
    r"[\"']?TracingEnabled[\"']?\s*:\s*[\"']?(?:true|True)\b"
    r"|\bxray_tracing_enabled\s*=\s*true\b"
    r"|\btracing_?[eE]nabled\s*[:=]\s*(?:true|True)\b"
)


def compute_tracing(repo_path: Path) -> dict[str, str]:
    """Tracing on compute: active tracing, an X-Ray or ADOT collector, the ADOT layer,
    Application Signals, or a tracing SDK in the function code: kind -> first file."""
    found = _in_iac(repo_path, _COMPUTE_TRACING + _IAC_TRACING)
    for rel, name, text in _function_code(repo_path):
        if name in _DEPENDENCY_MANIFESTS or name.endswith(".txt"):
            if _OTEL_PACKAGES.search(text):
                found.setdefault("OpenTelemetry SDK", rel)
            continue
        for kind, pattern in _SDK_TRACING_CODE:
            if pattern.search(text):
                found.setdefault(kind, rel)
        if _PY_POWERTOOLS_TRACER.search(text):
            found.setdefault("Powertools Tracer", rel)
    return found


def untraced_rest_apis(repo_path: Path) -> List[str]:
    """Files with an API Gateway REST API when no stage in the repo turns on X-Ray."""
    files: List[str] = []
    traced = False
    for rel, text in iac_texts(repo_path):
        if _STAGE_TRACING.search(text):
            traced = True
        if _REST_API.search(text) or (
            _SAM_TRANSFORM.search(text) and _SAM_REST_EVENT.search(text)
        ):
            files.append(rel)
    return [] if traced else files


class EndToEndTracingMissing(_RepoRule):
    id = "REPO-048"
    title = "Requests are not traced end to end"
    category = "Reliability"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Trace each request through every hop: turn on X-Ray active tracing on the Lambda "
        "functions, run the X-Ray daemon or the AWS Distro for OpenTelemetry collector next "
        "to containers (or use CloudWatch Application Signals), instrument the code with "
        "the X-Ray or OpenTelemetry SDK, and enable X-Ray tracing on API Gateway REST API "
        "stages so the trace starts at the edge."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        gaps: List[str] = []
        file: str | None = None
        compute = _in_iac(repo_path, _COMPUTE)
        if compute and not compute_tracing(repo_path):
            gaps.append(
                f"runs {_named(compute)} and no compute is traced (searched for Lambda active "
                "tracing, an X-Ray daemon or ADOT collector, the ADOT layer, Application "
                "Signals, and an X-Ray or OpenTelemetry SDK in the function code)"
            )
            file = next(iter(compute.values()))
        apis = untraced_rest_apis(repo_path)
        if apis:
            gaps.append(f"the API Gateway REST API in {_listed(apis)} has no stage with X-Ray "
                        "tracing on")
            file = file or apis[0]
        if not gaps:
            return []
        text = "; ".join(gaps)
        return [self._finding(text[0].upper() + text[1:], file=file)]


# Demand and impairment scaling (REL 7): fleets that cannot grow on demand (REPO-049) and
# scaling that reacts only to CPU or memory (REPO-050). Both reuse the REPO-047 scaling
# policy pattern.

_CDK_ID = r"\(\s*(?:this|self)\s*,\s*['\"]([^'\"]+)['\"]"
_SCALABLE_DIMENSION = (
    r"[\"']?(?:ScalableDimension|scalable_dimension|scalableDimension)[\"']?\s*[:=]\s*[\"']?"
)
_ECS_SCALABLE_TARGET = re.compile(
    _SCALABLE_DIMENSION + r"ecs:service:DesiredCount\b"
    r"|\.(?:autoScaleTaskCount|auto_scale_task_count)\("
)
_DYNAMODB_AUTOSCALING = re.compile(
    _SCALABLE_DIMENSION + r"dynamodb:(?:table|index):"
    r"|\.(?:autoScale\w*Capacity|auto_scale_\w*capacity)\(|\bCapacity\.autoscaled\("
)
_ASG_SCALING = re.compile(
    _SCALING_POLICY + "|" + _cf_type(r"AutoScaling::ScheduledAction")
    + r"|resource\s+\"aws_autoscaling_schedule\""
)
_CF_FLEET = re.compile(_cf_type(r"ECS::Service|AutoScaling::AutoScalingGroup|DynamoDB::Table"))
_TF_FLEET = re.compile(
    r"resource\s+\"(aws_ecs_service|aws_autoscaling_group|aws_dynamodb_table)\"\s+"
    r"\"([^\"]+)\"\s*\{"
)
# QueueProcessing services scale on their queue by themselves and are not matched.
_CDK_FLEET = re.compile(
    r"\b(?:new\s+)?(?:\w+\.)?((?:ApplicationLoadBalanced|NetworkLoadBalanced)?"
    r"(?:Fargate|Ec2)Service|CfnService|CfnAutoScalingGroup|AutoScalingGroup|CfnTable|Table)"
    + _CDK_ID
)
_TF_DAEMON = re.compile(r"\bscheduling_strategy\s*=\s*\"DAEMON\"")
_CDK_DAEMON = re.compile(
    r"\bdaemon\s*[:=]\s*(?:true|True)\b|\bscheduling_?[sS]trategy\s*[:=]\s*['\"]DAEMON['\"]"
)
_SPREAD = re.compile(r"\.\.\.|\*\*")


def _num(value: object) -> int | None:
    """A literal whole number (CloudFormation sizes are often strings)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value)
    return None


def _same_size(low: int | None, high: int | None) -> int | None:
    return low if low is not None and low == high else None


def _cf_fleets(rel: str, text: str) -> List[tuple[str, str, int | None, int | None]]:
    """(check, name, line, fixed size) for ECS services, Auto Scaling groups and
    provisioned DynamoDB tables in a CloudFormation template."""
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return []
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    found: List[tuple[str, str, int | None, int | None]] = []
    for name, body in (resources.items() if isinstance(resources, dict) else ()):
        if not isinstance(body, dict):
            continue
        props = body.get("Properties")
        props = props if isinstance(props, dict) else {}
        line = _cf_logical_line(text, str(name))
        kind = body.get("Type")
        if kind == "AWS::ECS::Service" and props.get("SchedulingStrategy") != "DAEMON":
            found.append(("ecs", str(name), line, None))
        elif kind == "AWS::AutoScaling::AutoScalingGroup":
            size = _same_size(_num(props.get("MinSize")), _num(props.get("MaxSize")))
            found.append(("asg", str(name), line, size))
        elif kind == "AWS::DynamoDB::Table":
            mode = props.get("BillingMode")
            if mode == "PROVISIONED" or (mode is None and "ProvisionedThroughput" in props):
                found.append(("dynamodb", str(name), line, None))
    return found


def _tf_setting(block: str, key: str) -> str | None:
    match = re.search(rf"(?m)^\s*{key}\s*=\s*(.+?)\s*(?:#.*)?$", block)
    return match.group(1) if match else None


def _tf_number(block: str, key: str) -> int | None:
    value = _tf_setting(block, key)
    match = re.fullmatch(r"\"?(\d+)\"?", value or "")
    return int(match.group(1)) if match else None


def _tf_fleets(text: str) -> List[tuple[str, str, int | None, int | None]]:
    found: List[tuple[str, str, int | None, int | None]] = []
    for match in _TF_FLEET.finditer(text):
        kind, name = match.groups()
        block = _braced(text, match.end() - 1)
        line = _line_of(text, match.start())
        if kind == "aws_ecs_service" and not _TF_DAEMON.search(block):
            found.append(("ecs", name, line, None))
        elif kind == "aws_autoscaling_group":
            size = _same_size(_tf_number(block, "min_size"), _tf_number(block, "max_size"))
            found.append(("asg", name, line, size))
        elif kind == "aws_dynamodb_table":
            mode = _tf_setting(block, "billing_mode")
            if mode == '"PROVISIONED"' or (
                mode is None and _tf_setting(block, "read_capacity") is not None
            ):
                found.append(("dynamodb", name, line, None))
    return found


def _cdk_literal(args: str, key: str) -> tuple[bool, int | None]:
    """Whether the props set the key, and its value when it is a literal number."""
    if not re.search(rf"\b{key}\s*[:=]", args):
        return False, None
    match = re.search(rf"\b{key}\s*[:=]\s*['\"]?(\d+)(?![\w.])['\"]?(?![ \t]*[*+\-/])", args)
    return True, int(match.group(1)) if match else None


def _cdk_group_size(cls: str, args: str) -> tuple[bool, int | None]:
    """(judged, fixed size) of a CDK Auto Scaling group. An AutoScalingGroup defaults to a
    minimum of 1 and a maximum of max(minimum, 1)."""
    keys = ("min_?[sS]ize", "max_?[sS]ize") if cls.startswith("Cfn") else (
        "min_?[cC]apacity", "max_?[cC]apacity")
    (has_low, low), (has_high, high) = (_cdk_literal(args, k) for k in keys)
    if (has_low and low is None) or (has_high and high is None):
        return False, None
    if not (has_low and has_high) and (cls.startswith("Cfn") or _SPREAD.search(args)):
        return False, None
    floor = low if low is not None else 1
    ceiling = high if high is not None else max(floor, 1)
    return True, _same_size(floor, ceiling)


def _cdk_provisioned_table(cls: str, args: str) -> bool:
    if cls == "Table":
        if not re.search(r"\bpartition_?[kK]ey\b", args):
            return False
        if re.search(r"\bBillingMode\.PROVISIONED\b", args):
            return True
        if re.search(r"\bbilling_?[mM]ode\s*[:=]", args):
            return False
        return bool(re.search(r"\b(?:read|write)_?[cC]apacity\s*[:=]", args))
    if not re.search(r"\bkey_?[sS]chema\b", args):
        return False
    if re.search(r"\bbilling_?[mM]ode\s*[:=]\s*['\"]PROVISIONED['\"]", args):
        return True
    return not re.search(r"\bbilling_?[mM]ode\s*[:=]", args) and bool(
        re.search(r"\bprovisioned_?[tT]hroughput\s*[:=]", args))


def _cdk_fleets(text: str) -> List[tuple[str, str, int | None, int | None]]:
    found: List[tuple[str, str, int | None, int | None]] = []
    for match in _CDK_FLEET.finditer(text):
        cls, name = match.groups()
        args = _braced(text, match.start() + match.group(0).index("("), "(", ")")
        line = _line_of(text, match.start())
        if cls.endswith("Service"):
            if cls == "CfnService" and "ecs.CfnService" not in match.group(0):
                continue
            if not _CDK_DAEMON.search(args):
                found.append(("ecs", name, line, None))
        elif cls.endswith("AutoScalingGroup"):
            judged, size = _cdk_group_size(cls, args)
            found.append(("asg", name, line, size if judged else None))
        elif _cdk_provisioned_table(cls, args):
            found.append(("dynamodb", name, line, None))
    return found


def fixed_fleets(repo_path: Path) -> List[tuple[str, str, int | None, str]]:
    """Fleets that cannot grow on demand: (fleet, file, line, why)."""
    candidates: List[tuple[str, str, str, int | None, int | None]] = []
    ecs_target = asg_policy = table_scaling = False
    for rel, text in iac_texts(repo_path):
        ecs_target = ecs_target or bool(_ECS_SCALABLE_TARGET.search(text))
        asg_policy = asg_policy or bool(_ASG_SCALING.search(text))
        table_scaling = table_scaling or bool(_DYNAMODB_AUTOSCALING.search(text))
        fleets = _tf_fleets(text) + _cdk_fleets(text)
        if _CF_FLEET.search(text):
            fleets += _cf_fleets(rel, text)
        candidates.extend((check, name, rel, line, size) for check, name, line, size in fleets)
    found: List[tuple[str, str, int | None, str]] = []
    for check, name, rel, line, size in candidates:
        if check == "ecs" and not ecs_target:
            fleet, why = f"ECS service {name}", "no Application Auto Scaling target on its tasks"
        elif check == "asg" and size is not None:
            fleet, why = f"Auto Scaling group {name}", f"minimum and maximum size both {size}"
        elif check == "asg" and not asg_policy:
            fleet, why = f"Auto Scaling group {name}", "no scaling policy in the repo"
        elif check == "dynamodb" and not table_scaling:
            fleet, why = f"DynamoDB table {name}", "provisioned capacity, no auto scaling"
        else:
            continue
        found.append((fleet, rel, line, why))
    return found


class FixedSizeFleet(_RepoRule):
    id = "REPO-049"
    title = "A fleet has a fixed size"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Let each fleet grow and shrink with demand: register the ECS service's desired "
        "task count with Application Auto Scaling and attach a scaling policy, give each Auto "
        "Scaling group a maximum above its minimum and a scaling policy, and switch DynamoDB "
        "tables to on-demand capacity or turn on auto scaling for their read and write "
        "capacity."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        fleets = fixed_fleets(repo_path)
        if not fleets:
            return []
        places = [f"{fleet} at {rel}:{line} ({why})" if line else f"{fleet} in {rel} ({why})"
                  for fleet, rel, line, why in fleets]
        return [self._finding(
            f"Fleets that cannot grow on demand: {_listed(places, 4)}",
            file=fleets[0][1],
            line=fleets[0][2],
        )]


_CPU_OR_MEMORY = re.compile(r"(?i)cpu|memory")
_DYNAMODB_UTILIZATION = re.compile(r"(?i)dynamodb_?(?:read|write)_?capacity_?utilization")
_CF_POLICY_TYPES = ("AWS::AutoScaling::ScalingPolicy", "AWS::ApplicationAutoScaling::ScalingPolicy")
_CF_POLICY = re.compile(
    _cf_type(r"ApplicationAutoScaling::ScalingPolicy|AutoScaling::ScalingPolicy")
)
_TF_POLICY = re.compile(
    r"resource\s+\"aws_(?:appautoscaling|autoscaling)_policy\"\s+\"([^\"]+)\"\s*\{"
)
_TF_POLICY_REF = re.compile(r"\baws_(?:appautoscaling|autoscaling)_policy\.(\w+)\b")
_TF_PREDICTIVE = re.compile(
    r"\bpolicy_type\s*=\s*\"PredictiveScaling\"|\bpredictive_scaling_configuration\s*\{"
)
_TF_TARGET_TRACKING = re.compile(r"\btarget_tracking_(?:scaling_policy_)?configuration\s*\{")
_TF_METRIC = re.compile(r"\bmetric_name\s*=\s*[^\n]+|\bmetric_query\s*\{")
_CDK_SCALE_CALL = re.compile(r"\.(scaleOn\w+|scale_on_\w+|scaleToTrack\w*|scale_to_track\w*)\(")
_CDK_POLICY_CTOR = re.compile(r"\b(?:Cfn)?(?:Step|TargetTracking)?ScalingPolicy" + _CDK_ID)
_CDK_QUEUE_SERVICE = re.compile(r"\bQueueProcessing(?:Fargate|Ec2)Service" + _CDK_ID)
_CDK_FIRST_STRING = re.compile(r"\s*['\"]([^'\"]+)['\"]\s*,")


def _metric_kind(text: str) -> str | None:
    """'cpu' for a CPU or memory metric, None for DynamoDB utilization (not judged), and
    'other' for any other signal."""
    if _DYNAMODB_UTILIZATION.search(text):
        return None
    return "cpu" if _CPU_OR_MEMORY.search(text) else "other"


def _alarm_kind(metrics: List[str]) -> str:
    """A step or simple scaling policy reacts to the alarms that call it; with no alarm
    found, the signal is unknown and not counted as CPU."""
    kinds = {_metric_kind(m) for m in metrics}
    return "cpu" if kinds == {"cpu"} else "other"


def _cf_policies(rel: str, text: str) -> List[tuple[str, int | None, str | None]]:
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return []
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    if not isinstance(resources, dict):
        return []
    alarms: List[tuple[str, str]] = []
    for body in resources.values():
        if isinstance(body, dict) and body.get("Type") == "AWS::CloudWatch::Alarm":
            props = body.get("Properties")
            props = props if isinstance(props, dict) else {}
            alarms.append((json.dumps(props.get("AlarmActions"), default=str),
                           json.dumps([props.get("MetricName"), props.get("Metrics")],
                                      default=str)))
    found: List[tuple[str, int | None, str | None]] = []
    for name, body in resources.items():
        if not isinstance(body, dict) or body.get("Type") not in _CF_POLICY_TYPES:
            continue
        props = body.get("Properties")
        props = props if isinstance(props, dict) else {}
        config = (props.get("TargetTrackingConfiguration")
                  or props.get("TargetTrackingScalingPolicyConfiguration"))
        if props.get("PolicyType") == "PredictiveScaling":
            kind: str | None = "other"
        elif config is not None:
            kind = _metric_kind(json.dumps(config, default=str))
        else:
            kind = _alarm_kind([m for actions, m in alarms if f'"{name}"' in actions])
        found.append((str(name), _cf_logical_line(text, str(name)), kind))
    return found


def _tf_alarm_metrics(text: str) -> dict[str, List[str]]:
    """Terraform scaling policy name -> the metrics of the alarms that call it."""
    found: dict[str, List[str]] = {}
    for match in _TF_ALARM.finditer(text):
        block = _braced(text, match.end() - 1)
        metric = " ".join(m.group(0) for m in _TF_METRIC.finditer(block))
        for ref in _TF_POLICY_REF.finditer(block):
            found.setdefault(ref.group(1), []).append(metric)
    return found


def _tf_policies(text: str, alarms: dict[str, List[str]]
                 ) -> List[tuple[str, int | None, str | None]]:
    found: List[tuple[str, int | None, str | None]] = []
    for match in _TF_POLICY.finditer(text):
        name = match.group(1)
        block = _braced(text, match.end() - 1)
        tracking = _TF_TARGET_TRACKING.search(block)
        if _TF_PREDICTIVE.search(block):
            kind: str | None = "other"
        elif tracking:
            kind = _metric_kind(_braced(block, tracking.end() - 1))
        else:
            kind = _alarm_kind(alarms.get(name, []))
        found.append((name, _line_of(text, match.start()), kind))
    return found


def _cdk_policies(text: str) -> List[tuple[str, int | None, str | None]]:
    found: List[tuple[str, int | None, str | None]] = []
    for match in _CDK_SCALE_CALL.finditer(text):
        method = match.group(1).replace("_", "").lower()
        args = _braced(text, match.end() - 1, "(", ")")
        named = _CDK_FIRST_STRING.match(args)
        name = named.group(1) if named else match.group(1)
        rest = args[named.end():] if named else args
        if method in ("scaleoncpuutilization", "scaleonmemoryutilization"):
            kind: str | None = "cpu"
        elif method in ("scaleonschedule", "scaleonutilization"):
            continue  # a schedule, or DynamoDB utilization
        elif method in ("scaleonmetric", "scaletotrackmetric"):
            kind = _metric_kind(rest)
        else:
            kind = "other"
        found.append((name, _line_of(text, match.start()), kind))
    for match in _CDK_POLICY_CTOR.finditer(text):
        args = _braced(text, match.start() + match.group(0).index("("), "(", ")")
        rest = args[args.find(",") + 1:]
        kind = "other" if re.search(r"(?i)predictive", rest) else _metric_kind(rest)
        found.append((match.group(1), _line_of(text, match.start()), kind))
    for match in _CDK_QUEUE_SERVICE.finditer(text):
        found.append((match.group(1), _line_of(text, match.start()), "other"))
    return found


def scaling_policies(repo_path: Path) -> List[tuple[str, str, int | None, str]]:
    """Scaling policies and what they react to: (name, file, line, 'cpu' or 'other').
    DynamoDB utilization and scheduled actions are left out."""
    texts = list(iac_texts(repo_path))
    alarms: dict[str, List[str]] = {}
    for _, text in texts:
        for name, metrics in _tf_alarm_metrics(text).items():
            alarms.setdefault(name, []).extend(metrics)
    found: List[tuple[str, str, int | None, str]] = []
    for rel, text in texts:
        policies = _tf_policies(text, alarms) + _cdk_policies(text)
        if _CF_POLICY.search(text):
            policies += _cf_policies(rel, text)
        found.extend((name, rel, line, kind) for name, line, kind in policies if kind)
    return found


class CpuOnlyScaling(_RepoRule):
    id = "REPO-050"
    title = "Scaling reacts only to CPU or memory"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Scale on the signals that show demand rising or the workload failing, not only on "
        "host load: track request count per target, queue backlog per task or the age of "
        "the oldest message, response latency, or the rate of server errors with a target "
        "tracking or step scaling policy, and add predictive scaling for regular traffic. "
        "CPU and memory lag behind a queue that is filling or a dependency that is slow."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        policies = scaling_policies(repo_path)
        if not policies or any(kind != "cpu" for *_, kind in policies):
            return []
        places = [f"{name} at {rel}:{line}" if line else f"{name} in {rel}"
                  for name, rel, line, _ in policies]
        return [self._finding(
            f"Every scaling policy reacts to CPU or memory ({_listed(places, 4)}); none "
            "scales on queue depth, request count, latency, error rate or a forecast",
            file=policies[0][1],
            line=policies[0][2],
        )]


# REL 9: backups are restored on a schedule (REPO-051).

_BACKUP_SOURCES = _kinds(
    ("AWS Backup plan", _cf_type(r"Backup::BackupPlan") + r"|resource\s+\"aws_backup_plan\""
     r"|\bbackup\.(?:Cfn)?BackupPlan\(|\bBackupPlan\.(?:daily|weekly|monthly)\w*\("),
    ("DynamoDB point-in-time recovery",
     r"[\"']?PointInTimeRecoveryEnabled[\"']?\s*:\s*[\"']?true\b"
     r"|\bpoint_in_time_recovery\s*\{[^}]*\benabled\s*=\s*true\b"
     r"|\bpointInTimeRecovery(?:Specification)?\s*:\s*(?:true|\{)"
     r"|\bpoint_in_time_recovery\s*=\s*True\b"),
    ("RDS or Aurora backups", _cf_type(r"RDS::DB(?:Instance|Cluster)")
     + r"|resource\s+\"aws_(?:db_instance|rds_cluster)\""
     r"|\brds\.(?:Cfn)?(?:DBInstance|DBCluster|DatabaseInstance|DatabaseCluster)\("
     r"|\b(?:DatabaseInstance|DatabaseCluster|ServerlessCluster)\("),
)
_RESTORE_TESTING = re.compile(
    _cf_type(r"Backup::RestoreTestingPlan") + r"|resource\s+\"aws_backup_restore_testing_plan\""
    r"|\bbackup\.CfnRestoreTestingPlan\("
)
_RESTORE_CALL = re.compile(
    r"\b(?:StartRestoreJob|start_restore_job|startRestoreJob"
    r"|RestoreDBInstanceFromDBSnapshot|restore_db_instance_from_db_snapshot"
    r"|RestoreDBInstanceToPointInTime|restore_db_instance_to_point_in_time"
    r"|RestoreDBClusterToPointInTime|restore_db_cluster_to_point_in_time"
    r"|RestoreDBClusterFromSnapshot|restore_db_cluster_from_snapshot"
    r"|RestoreTableToPointInTime|restore_table_to_point_in_time"
    r"|RestoreTableFromBackup|restore_table_from_backup)\b"
)
_SCHEDULE = re.compile(
    r"[\"']?ScheduleExpression[\"']?\s*:|\bschedule_expression\s*=|\bSchedule\.(?:cron|rate|expression)\("
    + "|" + _cf_type(r"Scheduler::Schedule") + r"|resource\s+\"aws_scheduler_schedule\""
)
_RESTORE_COMMAND = re.compile(
    r"\baws\s+backup\s+start-restore-job\b|\baws\s+rds\s+restore-db-[\w-]+"
    r"|\baws\s+dynamodb\s+restore-table-[\w-]+"
)


def restore_tests(repo_path: Path) -> dict[str, str]:
    """Scheduled restores the IaC, code or builds declare: kind -> first place."""
    found: dict[str, str] = {}
    texts = list(iac_texts(repo_path))
    for rel, text in texts:
        if _RESTORE_TESTING.search(text):
            found.setdefault("AWS Backup restore testing plan", rel)
    calls = any(_RESTORE_CALL.search(text) for _rel, text in texts)
    if calls:
        calls_in_code = any(
            _RESTORE_CALL.search(text) for _rel, _name, text in _function_code(repo_path)
        )
        for rel, text in texts:
            if _SCHEDULE.search(text) and (_RESTORE_CALL.search(text) or calls_in_code):
                found.setdefault("scheduled restore", rel)
                break
    for rel, text in build_texts(repo_path):
        if _RESTORE_COMMAND.search(text):
            found.setdefault("restore in a build", rel)
    return found


class RestoreTestMissing(_RepoRule):
    id = "REPO-051"
    title = "Backups are never restored to test them"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Prove the backups work: add an AWS Backup restore testing plan that restores recovery "
        "points on a schedule and validates them, or schedule a job that restores the latest "
        "snapshot or point in time into a scratch resource, checks it, and deletes it."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        sources = _in_iac(repo_path, _BACKUP_SOURCES)
        if not sources or restore_tests(repo_path):
            return []
        return [self._finding(
            f"Backs up data with {_named(sources)}; searched the IaC for an AWS Backup restore "
            "testing plan, a schedule that calls a restore API, and the builds for a restore "
            "command; found none",
        )]


# Disaster recovery (REL 13): recovery objectives (REPO-052), automated failover (REPO-053),
# DR drills (REPO-054) and drift between the Regions (REPO-055).

_DR_REPLICATION = _kinds(
    ("S3 replication",
     r"[\"']?ReplicationConfiguration[\"']?\s*:\s*(?:$|\{|\n)"
     r"|resource\s+\"aws_s3_bucket_replication_configuration\""
     r"|\breplication_?[rR]ules\s*[:=]\s*\["
     r"|\breplication_?[cC]onfiguration\s*[:=]\s*(?:\{|s3\.)"),
    ("DynamoDB global table", _cf_type(r"DynamoDB::GlobalTable")
     + r"|resource\s+\"aws_dynamodb_global_table\""
     r"|\breplica\s*\{[^}]*\bregion_name\s*="
     r"|\breplication_?[rR]egions\s*[:=]\s*\["
     r"|\breplicas\s*[:=]\s*\[\s*(?:\{|dynamodb\.)"
     r"|\bdynamodb\.CfnGlobalTable\("),
    ("Aurora global database", _cf_type(r"RDS::GlobalCluster")
     + r"|resource\s+\"aws_rds_global_cluster\"|\brds\.CfnGlobalCluster\("),
    ("RDS cross-Region read replica",
     r"[\"']?SourceRegion[\"']?\s*:\s*\S|\bsourceRegion\s*:\s*\S"
     r"|\breplicate_source_db\s*=\s*\"arn:"),
    ("AWS Backup copy action",
     r"[\"']?CopyActions[\"']?\s*:|\bcopyActions\s*:|\bcopy_actions\s*="
     r"|\bcopy_action\s*\{[^}]*\bdestination_vault_arn\s*="),
    ("Elastic Disaster Recovery", _cf_type(r"DRS::\w+") + r"|resource\s+\"aws_drs_\w+\""
     r"|\bdrs\.Cfn\w+\("),
)
_OBJECTIVE = (
    r"(?:rto|rpo|recovery[-_]?(?:time|point)[-_]?objective)"
    r"(?:[-_]?(?:in)?[-_]?(?:s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?))?"
)
_RECOVERY_OBJECTIVES = _kinds(
    ("Resilience Hub resiliency policy", _cf_type(r"ResilienceHub::ResiliencyPolicy")
     + r"|resource\s+\"aws_resiliencehub_resiliency_policy\""
     r"|\bresiliencehub\.CfnResiliencyPolicy\(|\bCfnResiliencyPolicy\("),
    ("recovery objective tag or context key",
     rf"(?i:[\"']{_OBJECTIVE}[\"']\s*[:=]"
     rf"|\bkey[\"']?\s*[:=]\s*[\"']{_OBJECTIVE}[\"']"
     rf"|\.add\(\s*[\"']{_OBJECTIVE}[\"']\s*,)"
     rf"|(?im:^\s*{_OBJECTIVE}\s*[:=])"),
)
_ARC_READINESS = (
    _cf_type(r"Route53RecoveryReadiness::(?:ReadinessCheck|ResourceSet)")
    + r"|resource\s+\"aws_route53recoveryreadiness_(?:readiness_check|resource_set)\""
    r"|\broute53recoveryreadiness\.Cfn(?:ReadinessCheck|ResourceSet)\("
)
_FAILOVER = _kinds(
    ("Route 53 failover routing", dict(_FALLBACKS)["Route 53 failover routing"].pattern),
    ("Route 53 health check", dict(_EDGE_MONITORS)["Route 53 health check"].pattern),
    ("CloudFront origin failover", dict(_FALLBACKS)["CloudFront origin failover"].pattern),
    ("Route 53 Application Recovery Controller",
     _cf_type(r"Route53Recovery(?:Control|Readiness)::\w+")
     + r"|resource\s+\"aws_route53recovery(?:controlconfig|readiness)_\w+\""
     r"|\broute53recovery(?:control|readiness)\.Cfn\w+\("),
)
_ACTIVE_REPLICATION = ("DynamoDB global table", "Elastic Disaster Recovery")
_REGION = r"[a-z]{2}(?:-gov|-iso[a-z]?)?-[a-z]+-\d"
_ENDPOINT_GROUP_REGION = re.compile(
    rf"[\"']?(?:EndpointGroupRegion|endpointGroupRegion|endpoint_group_region)[\"']?\s*[:=]"
    rf"\s*[\"']?({_REGION})\b"
)
_DR_DRILL_TOOLS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern)) for name, pattern in (
        ("ARC routing control switch",
         r"\baws\s+route53-recovery-cluster\s+update-routing-control-states?\b"),
        ("Aurora global database failover",
         r"\baws\s+rds\s+(?:failover|switchover)-global-cluster\b"),
        ("Elastic Disaster Recovery drill", r"\baws\s+drs\s+start-(?:recovery|drill)\b"),
    )
)
_DR_SYNC = _kinds(
    ("CloudFormation StackSet", _cf_type(r"CloudFormation::StackSet")
     + r"|resource\s+\"aws_cloudformation_stack_set\""
     r"|\bCfnStackSet\(|\bnew\s+StackSet\(|\bcdk[-_]stacksets\b"),
    ("ARC readiness check", _ARC_READINESS),
    ("AWS Config aggregator", _cf_type(r"Config::ConfigurationAggregator")
     + r"|resource\s+\"aws_config_configuration_aggregator\""
     r"|\bCfnConfigurationAggregator\("),
)
_DRIFT_TOOLS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern)) for name, pattern in (
        ("CloudFormation drift detection",
         r"\baws\s+cloudformation\s+detect-stack(?:-set)?-drift\b"),
        ("terraform plan -detailed-exitcode",
         r"\bterraform\s+plan\b[^\n]*\s-detailed-exitcode\b"),
    )
)
_CDK_NEW = re.compile(r"\bnew\s+([A-Z]\w*)\s*\(")
_PY_CALL = re.compile(r"(?<![\w.])([A-Z]\w*)\s*\(")
_LITERAL_REGION = re.compile(rf"\bregion\s*[:=]\s*['\"]({_REGION})['\"]")
_NOT_STACKS = frozenset({"Environment"})
_TF_MODULE = re.compile(r"\bmodule\s+\"[^\"]+\"\s*\{")
_TF_SOURCE = re.compile(r"^\s*source\s*=\s*\"([^\"]+)\"", re.MULTILINE)
_TF_AWS_PROVIDER = re.compile(r"\bproviders\s*=\s*\{[^}]*?\baws\s*=\s*aws\.(\w+)")


def dr_replication(repo_path: Path) -> dict[str, str]:
    """Data or workloads the IaC copies to another Region: kind -> first file."""
    return _in_iac(repo_path, _DR_REPLICATION)


def failover_controls(repo_path: Path, replication: dict[str, str]) -> dict[str, str]:
    """What moves traffic to the copy when the primary fails: kind -> first place."""
    found = {kind: rel for kind, rel in replication.items() if kind in _ACTIVE_REPLICATION}
    found.update(_in_iac(repo_path, _FAILOVER))
    regions: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        for match in _ENDPOINT_GROUP_REGION.finditer(text):
            regions.setdefault(match.group(1), rel)
    if len(regions) > 1:
        found.setdefault("Global Accelerator in two Regions", next(iter(regions.values())))
    for kind, rel in restore_tests(repo_path).items():
        found.setdefault(kind, rel)
    return found


def dr_drills(repo_path: Path) -> dict[str, str]:
    """Fault injection, failover or recovery drills and restore tests: kind -> place."""
    found = fault_injection(repo_path)
    _builds, drills = _tools_in_builds(repo_path, _DR_DRILL_TOOLS)
    found.update(drills)
    for rel, text in iac_texts(repo_path):
        if re.search(_ARC_READINESS, text):
            found.setdefault("ARC readiness check", rel)
            break
    for kind, rel in restore_tests(repo_path).items():
        found.setdefault(kind, rel)
    return found


def _stack_regions(rel: str, text: str) -> Iterator[tuple[str, str]]:
    """(class, literal region) of each CDK construct call that names a region."""
    if rel.endswith((".ts", ".js")):
        calls = _CDK_NEW
    elif rel.endswith(".py"):
        calls = _PY_CALL
    else:
        return
    for match in calls.finditer(text):
        if match.group(1) in _NOT_STACKS:
            continue
        args = _braced(text, match.end() - 1, "(", ")")
        for region in _LITERAL_REGION.finditer(args):
            yield match.group(1), region.group(1)


def _module_providers(text: str) -> Iterator[tuple[str, str]]:
    """(source, aws provider alias) of each Terraform module block."""
    for match in _TF_MODULE.finditer(text):
        body = _braced(text, match.end() - 1)
        source = _TF_SOURCE.search(body)
        if source:
            provider = _TF_AWS_PROVIDER.search(body)
            yield source.group(1), provider.group(1) if provider else "default"


def multi_region_deploys(repo_path: Path) -> dict[str, str]:
    """A CDK stack class or Terraform module deployed to two Regions: name -> file."""
    stacks: dict[str, set[str]] = {}
    modules: dict[str, set[str]] = {}
    where: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        for name, region in _stack_regions(rel, text):
            stacks.setdefault(name, set()).add(region)
            where.setdefault(name, rel)
        if rel.endswith(".tf"):
            for source, alias in _module_providers(text):
                modules.setdefault(source, set()).add(alias)
                where.setdefault(source, rel)
    found = {f"stack {name} in two Regions": where[name]
             for name, regions in stacks.items() if len(regions) > 1}
    found.update({f"module {source} in two Regions": where[source]
                  for source, aliases in modules.items() if len(aliases) > 1})
    return found


def drift_controls(repo_path: Path) -> dict[str, str]:
    """StackSets, readiness checks, aggregators, drift checks and two-Region deploys."""
    found = _in_iac(repo_path, _DR_SYNC)
    _builds, drift = _tools_in_builds(repo_path, _DRIFT_TOOLS)
    found.update(drift)
    found.update(multi_region_deploys(repo_path))
    return found


class RecoveryObjectivesMissing(_RepoRule):
    id = "REPO-052"
    title = "Recovery objectives are not defined"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Write down how long the workload may be down and how much data it may lose, and "
        "keep it next to the code: an AWS Resilience Hub resiliency policy with RTO and RPO "
        "per disruption type, or recovery time and recovery point objective tags on the "
        "stacks. Pick the backup frequency and the DR strategy from those numbers."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        workload = {**_in_iac(repo_path, _DATA_STORES), **_in_iac(repo_path, _COMPUTE)}
        if not workload or _in_iac(repo_path, _RECOVERY_OBJECTIVES):
            return []
        return [self._finding(
            f"Runs {_named(workload)}; searched the IaC for a Resilience Hub resiliency policy "
            "and for a recovery time or recovery point objective tag or context key; found "
            "none",
        )]


class FailoverAutomationMissing(_RepoRule):
    id = "REPO-053"
    title = "Replicated data has no automated failover"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "A copy in another Region only shortens recovery if traffic can reach it: add DNS "
        "failover records with health checks, Application Recovery Controller routing "
        "controls, Global Accelerator endpoints in both Regions, CloudFront origin failover, "
        "or active-active global tables, and rehearse a restore so the recovery time is known."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        replication = dr_replication(repo_path)
        if not replication or failover_controls(repo_path, replication):
            return []
        return [self._finding(
            f"Copies data to another Region with {_named(replication)}; searched the IaC for "
            "DNS failover, health checks, origin failover, Application Recovery Controller, "
            "Global Accelerator in two Regions, an active-active global table, Elastic "
            "Disaster Recovery and a tested restore; found none",
            file=next(iter(replication.values())),
        )]


class DisasterRecoveryUntested(_RepoRule):
    id = "REPO-054"
    title = "Disaster recovery is never tested"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Run a DR drill on a schedule: fail the workload over to the recovery Region with a "
        "fault injection experiment, an Application Recovery Controller routing control "
        "change, an Aurora global database switchover or an Elastic Disaster Recovery drill, "
        "or restore backups in the recovery Region, and measure the recovery time and point "
        "against the objectives."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        replication = dr_replication(repo_path)
        if not replication or dr_drills(repo_path):
            return []
        return [self._finding(
            f"Copies data to another Region with {_named(replication)}; searched the IaC and "
            "builds for a fault injection experiment, a routing control or global database "
            "failover, a recovery drill, a readiness check and a scheduled restore; found none",
            file=next(iter(replication.values())),
        )]


class DisasterRecoveryDrift(_RepoRule):
    id = "REPO-055"
    title = "The DR Region can drift from the primary"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Deploy the recovery Region from the same code as the primary and check it stays "
        "the same: deploy one stack or module to both Regions, or use CloudFormation "
        "StackSets, add Application Recovery Controller readiness checks or an AWS Config "
        "aggregator across the Regions, and run drift detection on a schedule."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        replication = dr_replication(repo_path)
        if not replication or drift_controls(repo_path):
            return []
        return [self._finding(
            f"Copies data to another Region with {_named(replication)}; searched the IaC for "
            "StackSets, a readiness check, a Config aggregator and one stack or module "
            "deployed to two Regions, and the builds for drift detection; found none",
            file=next(iter(replication.values())),
        )]


REPO_RULES: List[Rule] = [
    RepoTestsMissing(), RepoPipelineMissing(), SingleEnvironment(),
    OrgGuardrailsMissing(), AccountBaselineMissing(), RootUserUnchecked(),
    ForensicCaptureMissing(), ContainmentMissing(),
    DependencyScanMissing(), ArtifactScanMissing(), CentralPackageRepoMissing(),
    QuotaAlarmMissing(), FailoverHeadroomMissing(), VpcCidrOverlap(),
    IdempotencyMissing(), FaultInjectionMissing(), LoadTestMissing(),
    KpiMetricMissing(), EdgeTelemetryMissing(), DependencyTelemetryMissing(),
    DeployTestGateMissing(), AutomatedRollbackMissing(),
    InPlaceChange(), FunctionalTestMissing(), AutomatedDeployMissing(), ResiliencyTestMissing(),
    WorkloadAlarmMissing(), LogAnalysisMissing(), TraceAnalysisMissing(),
    DashboardWorkloadMetricMissing(),
    PermissionBoundaryMissing(), BreakGlassRoleMissing(),
    SecurityFindingsUncorrelated(),
    EgressInspectionMissing(), AutomatedNetworkProtectionMissing(), PublicSubnetWorkload(),
    CodeSigningMissing(), MutableImageTag(),
    DataClassificationMissing(), SensitiveDataWithoutCmk(),
    EncryptionGuardrailMissing(),
    LocalStateOnCompute(), EmergencyLeverMissing(), FallbackMissing(),
    AlarmMetricUndefined(), LogErrorAnalysisMissing(), AlarmResponseMissing(),
    EndToEndTracingMissing(),
    FixedSizeFleet(), CpuOnlyScaling(),
    RestoreTestMissing(),
    RecoveryObjectivesMissing(), FailoverAutomationMissing(), DisasterRecoveryUntested(),
    DisasterRecoveryDrift(),
]
