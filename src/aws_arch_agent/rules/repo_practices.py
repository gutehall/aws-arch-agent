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
- REPO-107 named dependencies: a client call (Python requests, httpx, urlopen; TypeScript
  and JavaScript fetch, axios, got) whose first argument is a literal http(s) URL, in code
  outside tests. Local, link-local and AWS endpoint hosts do not fire, and a URL built from a
  variable, an environment variable or a parameter is not seen.
- REPO-108 constant work: a file with one of those calls and no timeout, AbortSignal or
  AbortController fires when the IaC declares no SQS queue, Kinesis stream, Lambda event
  source or schedule. One queue or schedule anywhere passes every call.

Event management (OPS 10) runs by default and fires only when the IaC declares a CloudWatch
alarm (or, for REPO-109 and REPO-112, an Incident Manager response plan):

- REPO-109 priority: an alarm or response plan file that names a severity, priority, impact
  or a Sev1 to Sev5 or P1 to P5 label passes.
- REPO-110 customer communication: an SNS, SES or Pinpoint resource in a file that names
  customers, subscribers or a status page passes.
- REPO-111 event status: a CloudWatch dashboard with an alarm status or alarm widget passes.
- REPO-112 automated response: an alarm action that runs automation, an EventBridge rule on
  alarm state changes with a target, or an SSM Automation target or response-plan action
  passes. A scaling policy alone does not.

Change flow (OPS 5) runs by default:

- REPO-113 version control: a .git entry (a directory, or a file in a worktree or submodule)
  in the scanned folder or any folder above it, or a CodeCommit repository, CodeConnections
  or CodeStar connection or hosted pipeline source in the IaC, passes.
- REPO-114 configuration: when the IaC runs compute, SSM parameters, Secrets Manager, AppConfig,
  a parameter lookup, or a tfvars, cdk.context or config-directory file per environment passes.
- REPO-115 quality gate: a linter, type checker, static analyzer or coverage threshold in a
  build config or in a package.json script a build runs passes. A repo with no CI fires.
- REPO-116 small, reversible changes: when the IaC runs compute, a rollback control (as
  REPO-022), blue/green, a canary or linear traffic shift, a CodeDeploy deployment group or
  Lambda alias weights passes.

Application security practices (SEC 11) run by default on a repo that holds IaC:

- REPO-117 training: a note named or headed for security training, security awareness or
  secure coding passes.
- REPO-118 penetration test: a note named or headed for a penetration test that holds a date
  passes.
- REPO-119 code review: a CODEOWNERS file, branch protection or a ruleset with required
  reviews (IaC or repository settings as code) or a CodeCommit approval rule passes.
- REPO-120 programmatic deploy: a build config or pipeline that deploys passes (the detection
  REPO-025 uses).
- REPO-121 security ownership: a SECURITY.md, a security owners or champions note, or a
  CODEOWNERS line that names security passes.

Reliability testing practices (REL 12) run by default on a repo that holds IaC:

- REPO-122 playbooks: a note or folder named or headed for playbooks, failure investigations
  or a troubleshooting guide passes.
- REPO-123 post-incident analysis: a note named or headed for a post-incident review,
  postmortem, incident report or root cause analysis passes.
- REPO-124 game days: a note named or headed for a game day, chaos day or fire drill passes.

Incident readiness (SEC 10) runs by default on a repo that holds IaC (REPO-007 and REPO-008
answer forensics and containment):

- REPO-125 contacts: an Incident Manager contact or plan, or a note or folder named or headed
  for contacts, on-call, key personnel or responders, passes.
- REPO-126 incident plan: an Incident Manager response plan, or a note named or headed for an
  incident management or response plan, passes.
- REPO-127 security playbooks: a note, folder or heading for security incident playbooks
  passes.
- REPO-128 response access: an IAM role or Identity Center permission set named for incident
  response, a responder, an investigator or forensics passes.
- REPO-129 simulations: an AWS FIS experiment template in the IaC passes.
- REPO-130 learning: a note or heading for a security post-incident review or postmortem
  passes.

Network connectivity (REL 2) runs by default:

- REPO-131 public endpoint: an EC2 instance with a public IP address and no load balancer or
  Global Accelerator in the IaC fires; an EIP on a NAT gateway does not count.
- REPO-132 on-premises links: exactly one VPN connection, Direct Connect connection or virtual
  interface in the IaC fires; none, or two or more, pass.

Service quotas (REL 1) run by default (REPO-012 and REPO-013 answer alarms and headroom):

- REPO-133 managed quotas: compute with no Service Quotas resource, template or quotas module
  fires.
- REPO-134 quota automation: compute with no Service Quotas resource or template and no
  RequestServiceQuotaIncrease call or permission fires.
- REPO-135 fixed quotas: an SQS FIFO queue without high-throughput mode, or a provisioned
  one-shard Kinesis stream with no on-demand mode, fires.

Security operations (SEC 1) run by default on a repo that holds IaC (REPO-006 answers the root
user):

- REPO-136 control objectives: a Security Hub standards subscription or a Config conformance
  pack passes.
- REPO-137 management scope: an Organizations delegated administrator, a service organization
  admin account or a Control Tower control passes.
- REPO-138 threat model: a file named for a threat model, or a note with a threat model
  heading, passes.
- REPO-139 new security services: IAM Access Analyzer or Inspector in the IaC, or a dated
  security service review note, passes.

Permissions (SEC 3) run by default, except REPO-141, which runs only with rules.org
(REPO-031 and REPO-032 answer guardrails and emergency access):

- REPO-140 access requirements: a permissions boundary or two IAM roles in the IaC, or an access
  requirements note, passes; it fires only on a repo that holds IaC.
- REPO-141 permission reduction: an IAM Access Analyzer in the IaC, or a dated access review
  note, passes; it fires only on a repo that holds IaC, and only with rules.org.
- REPO-142 access lifecycle: an IAM user or access key in the IaC fires.
- REPO-143 organization sharing: a RAM resource share that does not set AllowExternalPrincipals
  to false fires.

Compute protection (SEC 6) runs by default (REPO-010 answers artifact scanning, REPO-037 and
REPO-038 integrity and hardened images):

- REPO-144 interactive access: an EC2 instance, launch template or Auto Scaling group with an SSH
  key pair and no Session Manager access (AmazonSSMManagedInstanceCore, ssm:StartSession,
  ssmSessionPermissions) in the IaC fires.
- REPO-145 automated protection: compute in the IaC with no Inspector enablement and no SSM
  association or patch baseline fires; it runs only with rules.org.

Data lifecycle (SEC 7) runs by default (REPO-039 and REPO-040 answer classification):

- REPO-146 retention: a data store in a file tagged with a classification (or in an app tagged
  with one) with no lifecycle, TTL, backup retention or delete-after setting fires.

Monitoring scope (REL 6) runs by default (REPO-045 to REPO-048 answer metrics, logs, responses
and traces):

- REPO-147 monitoring review: a data store in the IaC with no dated note named for a monitoring,
  alarm or observability review, scope, coverage or inventory fires.

Demand (REL 7) runs by default (CF-ASG-006 answers automation of scaling):

- REPO-148 load test: the same search as REPO-017 for a load test in the builds, answering
  REL07-BP04; no load test fires.

Recovery (REL 11) runs by default (REPO-057 to REPO-059 answer health checks, failover and
healing):

- REPO-149 data plane recovery: an EC2 instance in the IaC and no Auto Scaling group, target group,
  Route 53 health check or recovery alarm fires.

Accelerators (SUS 5) run by default (SUST-002, SUST-005 and SUST-007 answer the other hardware
practices):

- REPO-150 accelerator utilization: the REPO-062 accelerators with no GPU or Neuron core
  utilization alarm and no scheduled scaling or schedule fire; no accelerator passes.

Data management (SUS 4) runs by default (REL-018, CF-EFS-003 and SUST-006 answer lifecycle and
data movement):

- REPO-151 classification: the REPO-039 search, answering SUS04-BP01.
- REPO-152 access pattern: instance store (an ephemeral mapping or a storage-optimized or NVMe
  instance type) with no S3, EFS, FSx, EBS, DynamoDB or database in the IaC fires.
- REPO-153 elastic block storage: an EBS volume of 500 GiB or more with no Elastic Volumes
  call, EBS autoscaling script or grow command fires.
- REPO-154 unneeded data: a file with an S3 bucket and no lifecycle, TTL, retention or backup
  delete-after fires.
- REPO-155 shared storage: two or more EBS volumes and no EFS, FSx or S3 in the IaC fires.
- REPO-156 needless backups: a file with an AWS Backup selection and a cache cluster or a bucket
  named tmp, temp, scratch or cache fires.

Operations health (OPS 9) runs by default (REPO-018 answers the workload KPIs):

- REPO-157 operations metrics: a repo that holds IaC with no deployment, change failure, recovery
  time, alarm count, error budget, burn rate or service level objective metric in the IaC or
  the build configs fires.
- REPO-158 operator status: CloudWatch alarms with no dashboard and no status topic fire.
- REPO-159 operations review: a repo that holds IaC with no dated note named for an operations
  review, report, metrics, health or retrospective fires.

Cost of effort (COST 11) runs by default:

- REPO-160 automated operations: an EC2 instance, launch template or Auto Scaling group with no
  SSM association, patch baseline, maintenance window or Automation document and no CI or
  pipeline fires.

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

Fault isolation (REL 10). Multi-AZ (REL10-BP01) and bulkheads (REL10-BP03) are mapped
template and CDK checks; this one reads the rest:

- REPO-056 single-location recovery: a standalone EC2 instance (AWS::EC2::Instance,
  aws_instance, ec2.Instance, ec2.CfnInstance) lives in one Availability Zone and is not
  replaced when it fails. It needs one of: an Auto Scaling group that the repo declares
  (an instance of one is rebuilt), a CloudWatch alarm whose action recovers or reboots it
  (arn:aws:automate:...:ec2:recover or :reboot, CDK Ec2Action with RECOVER or REBOOT), or
  an AWS Backup plan or a restore test (as REPO-051) to rebuild it from. Simplified
  automatic recovery is on by default but recovers only from host failures; an instance that
  turns it off (AutoRecovery disabled, auto_recovery = "disabled") always fires.

Withstanding component failures (REL 11). Monitoring components (REL11-BP01), failing over
to healthy resources (REL11-BP02) and replacing unhealthy targets (REL11-BP03) are mapped
template and CDK checks; these read the rest. Relying on the data plane during recovery
(REL11-BP04) is not checked: nothing in the IaC tells recovery steps that call control-plane
APIs apart.

- REPO-057 static stability: a production fleet whose literal minimum is one cannot lose an
  Availability Zone without a scale-out. It fires on an Auto Scaling group with MinSize 1
  (min_size, CDK minCapacity, which defaults to 1 when unset), an ECS Application Auto
  Scaling target with MinCapacity 1 (CDK autoScaleTaskCount without minCapacity or with 1),
  and an ECS service with a desired count of 1 when the repo has no ECS scaling target.
  Files whose path reads as dev or staging are skipped; values from variables or
  parameters are not judged.
- REPO-058 availability target: when the IaC declares an edge (as REPO-019), it needs an
  alarm on an edge 5xx, error or latency metric (the alarm half of REPO-019; canaries and
  health checks do not count), or a CloudWatch Application Signals service level
  objective.
- REPO-059 availability notifications: when compute runs, someone must be told: an alarm
  whose action is an SNS topic (an SNS ARN, a Terraform aws_sns_topic reference, a CDK topic
  ARN or SnsAction, or in a template a Ref or GetAtt of an SNS topic), an Incident Manager
  response plan, an AWS Chatbot (Amazon Q Developer in chat applications) configuration, or
  an EventBridge rule on AWS Health events with a target.

Compute selection and use (PERF 2). Picking the best compute option, instance size and
Graviton (PERF02-BP01, BP02, BP04) are mapped CDK and template checks; these read the rest.
Files whose path reads as dev or staging are skipped by REPO-060 and REPO-061.

- REPO-060 compute metrics: production compute (as REPO-059) and nothing collects its
  utilization: no alarm whose metric name is CPUUtilization, MemoryUtilization, Duration or
  ConcurrentExecutions (or a CDK metricCpuUtilization, metricMemoryUtilization,
  metricDuration or metricConcurrentExecutions helper), no ECS Container Insights (cluster
  setting containerInsights enabled or enhanced, CDK containerInsights or
  containerInsightsV2), no EKS CloudWatch observability add-on, and no CloudWatch agent
  (its package or SSM config parameter, or CloudWatchAgentServerPolicy).
- REPO-061 dynamic scaling: a production ECS service (not DAEMON) when the repo has no ECS
  scalable target with a scaling policy, and an Auto Scaling group whose literal minimum
  equals its maximum or when the repo has no scaling policy (a scheduled action alone does
  not scale with demand). It shares the fleet scan with REPO-049; Lambda and other
  serverless compute have no fleet and pass.
- REPO-062 accelerators: an accelerated instance type (p, g, gr, inf, trn, dl, f and vt
  families written as family.size, also as SageMaker ml. types, or a CDK InstanceClass)
  in a file that declares an instance, launch template, Auto Scaling group, EKS node group,
  Batch compute environment or SageMaker resource, and no alarm on a GPU or Neuron core
  utilization metric (nvidia_smi_utilization_gpu, GPUUtilization, GPUMemoryUtilization,
  neuroncore_utilization, NeuronCoreUtilization, Container Insights GPU metrics).

Data management (PERF 3). Access patterns, store configuration, metrics and caching
(PERF03-BP02 to BP05) are mapped CDK and template checks; this reads the rest.

- REPO-063 purpose-built data store: production IaC keeps data only on instance-attached
  storage: an EBS data volume or attachment (AWS::EC2::Volume, AWS::EC2::VolumeAttachment,
  aws_ebs_volume, aws_volume_attachment, CDK Volume or CfnVolumeAttachment), a block device
  on a non-root device name or a Terraform ebs_block_device, an instance store (ephemeral)
  mapping, or user data or an SSM document that installs or runs a database engine on the
  host (mysql-server, mariadb-server, postgresql, mongodb, redis, cassandra, elasticsearch,
  opensearch, through a package manager, systemctl, or docker run of a postgres, mysql,
  mariadb, mongo or redis image). It passes when the repo declares any managed data store
  (S3, DynamoDB, RDS or Aurora, ElastiCache, MemoryDB, DocumentDB, Neptune, Keyspaces,
  OpenSearch Service, Timestream, Redshift, EFS or FSx), and when nothing keeps data on the
  instance. Files whose path reads as dev or staging are skipped.

Networking (PERF 4). Evaluating networking features (PERF04-BP02) and choosing the
workload's location (PERF04-BP06) are mapped CDK checks; these read the rest. Files whose
path reads as dev or staging are skipped by all five.

- REPO-064 edge latency: a load balancer, API Gateway or CloudFront distribution (as
  REPO-019) and no alarm on TargetResponseTime, Latency, IntegrationLatency or OriginLatency
  (or the CDK metricLatency, metricIntegrationLatency, metricOriginLatency or
  metrics.targetResponseTime helper). Error and 5xx alarms do not count.
- REPO-065 tuning on metrics: an edge and neither VPC Flow Logs (AWS::EC2::FlowLog,
  aws_flow_log, CDK FlowLog, addFlowLog or flowLogs) nor a latency alarm with a literal
  numeric threshold (a parameter, variable or anomaly band is not one).
- REPO-066 redundant hybrid links: exactly one Direct Connect connection or virtual
  interface with no second one, no LAG and no VPN; or exactly one VPN connection (CDK
  VpnConnection, addVpnConnection or one vpnConnections entry) on at most one customer
  gateway and no Direct Connect. A Terraform block with count or for_each counts as two.
- REPO-067 load balancing: an EC2 instance with a public IP (AssociatePublicIpAddress,
  associate_public_ip_address, CDK associatePublicIpAddress or a PUBLIC subnet type) or an
  Elastic IP when the repo declares no load balancer; and a target group with exactly one
  literal target (CloudFormation Targets, one aws_lb_target_group_attachment, one CDK
  InstanceTarget or IpTarget) and no Auto Scaling group or ECS service registered with it.
- REPO-068 network protocols: CloudFront HttpVersion http1.1, a CloudFront viewer
  MinimumProtocolVersion below TLSv1.2, a load balancer SslPolicy that allows TLS 1.0 or
  1.1, an API Gateway domain SecurityPolicy TLS_1_0, or an internet-facing load balancer
  listener on HTTP that forwards instead of redirecting. Only explicit values are read: the
  CloudFront default is HTTP/2, and an unset SslPolicy is the template check's job.

Cost and usage monitoring (COST 3). Cost allocation tags (COST03-BP02) and billing and cost
management tools (COST03-BP05) are mapped CDK and template checks; these read the rest.
Workload means compute, a data store or an edge; files whose path reads as dev or staging
do not count as one.

- REPO-069 detailed cost source (an account-level rule, off unless rules.org or
  rules.include, like COST-014): workload resources and no Cost and Usage Report or data
  export (AWS::CUR::ReportDefinition, aws_cur_report_definition, AWS::BCMDataExports::Export,
  aws_bcmdataexports_export, CDK cur.CfnReportDefinition or bcmdataexports.CfnExport).
- REPO-070 cost attribution: workload resources, no tag keyed CostCenter (or cost-center,
  cost_center, CostCentre), BusinessUnit, Project, Product or CostCategory, matched on the
  key without regard to case (CloudFormation Key, Terraform tags or default_tags, CDK
  Tags.of(x).add), and no cost category (AWS::CE::CostCategory, aws_ce_cost_category, CDK
  ce.CfnCostCategory). Owner, Environment and Name keys do not count.
- REPO-071 organization metric: production compute and no metric named like a unit cost
  (CostPerRequest, cost_per_tenant, UnitCost) in a metric-name position: MetricName,
  metric_name or metricName, a metric math label or id, a Terraform log metric filter
  metric_transformation name, a Powertools add_metric or put_metric name, or an embedded
  metric format Name. Comments and README text do not count.
- REPO-072 allocation by workload metrics: production compute and no metric math (an
  Expression on a CloudFormation or Terraform alarm or dashboard, or a CDK MathExpression in
  the same file) that reads a cost metric (EstimatedCharges or a unit-cost name) and at
  least one other metric. When REPO-071 fires, REPO-072 usually fires too.

Cloud financial management (COST 1). The cost optimization function (COST01-BP03, COST-014,
account-level) and budgets (COST01-BP05, CF-BUDGET-001) are mapped checks; these read the
rest. REPO-073 and REPO-074 read only budgets the repo declares (AWS::Budgets::Budget,
aws_budgets_budget, CDK CfnBudget): a repo with none is COST-014's job.

- REPO-073 ownership: a budget with no Owner, CostOwner or Team tag and no notification
  subscriber (email address or SNS topic).
- REPO-074 proactive monitoring: every budget notifies only at 100 percent or more of
  ACTUAL spend (no FORECASTED notification, no threshold below 100) and there is no Cost
  Anomaly Detection monitor or subscription. A threshold that is not a literal percentage
  is taken as an early warning.
- REPO-075 new releases: production IaC uses a previous-generation type SUST-007 does not
  report (EC2 m1, m2, c1, t1, cc2, cg1, cr1, hi1, hs1, i2, d2, g2, g3, p2, x1, x1e; RDS
  db.m1, db.m2; ElastiCache cache.m1, m2, t1, c1) or a deprecated Lambda runtime set
  literally (nodejs12.x to 16.x, python3.6 to 3.8, java8, dotnetcore3.1, go1.x, ruby2.7),
  and no dated note reads as a service or architecture review.
- REPO-076 business value: production compute, no unit-cost metric (as REPO-071) and no
  budget whose name or tags name a unit (per request, tenant, order, user, transaction).
- REPO-077 finance and technology, REPO-078 organizational processes and REPO-079 culture:
  production workload resources and no cost note that names an owner (COST.md, FINOPS.md,
  docs/cost*.md, or a README or docs section headed Cost, FinOps or Cost ownership).
  REPO-078 also passes on a pull or merge request template with a cost checklist item.
  Notes are markdown or text files outside tests; reports this tool saved do not count.

Usage governance (COST 2). A cost policy is a service control policy, or any policy that
Denies an expensive choice: ec2:RunInstances or sagemaker:Create*, or a condition on
ec2:InstanceType, sagemaker:InstanceTypes, rds:DatabaseClass or aws:RequestedRegion.

- REPO-080 policies (account-level, off unless rules.org): production workload resources
  and no cost policy in the IaC.
- REPO-081 cost controls: production workload resources and no cost policy, no
  permissions boundary and no AWS Budgets action.
- REPO-082 goals and targets: budgets are declared and none sets a limit or planned limits.
  A repo with no budget is COST-014's job.
- REPO-083 account structure: the repo declares workload resources and deploys production
  and dev or staging (as REPO-003 finds them), and nothing shows separate accounts: no Organizations account or OU, no
  StackSets account targets, and fewer than two distinct literal account ids.
- REPO-084 groups and roles: billing access (aws-portal, billing, ce, budgets, cur actions,
  the Billing or AWSBillingReadOnlyAccess managed policy) granted to an IAM user directly.
- REPO-085 project lifecycle: a temporary stack (path or stack id reads as sandbox, test,
  preview, ephemeral, feature, demo, poc or pr-<n>; long-lived dev and staging are not) with no end-date tag (ExpiryDate,
  DeleteAfter, ttl and the like) or no environment tag, in its file or its directory.

Decommissioning (COST 4). Unused Elastic IPs (COST04-BP03), ECR lifecycle policies
(COST04-BP04) and S3 lifecycle and log retention (COST04-BP05) are mapped checks; these
read the rest.

- REPO-086 track resources: production workload resources and no created-by tag
  (CreatedBy, ManagedBy, Creator, Source, Repository, Repo, IaC) or no owner tag (Owner,
  CostOwner, Team) anywhere in the IaC. A tag in any IaC file counts for every resource.
- REPO-087 decommissioning process: the repo creates temporary environments (a temporary
  stack as REPO-085 finds it, a GitHub workflow that deploys on pull requests, a GitLab
  review/ environment) and nothing tears them down: no destroy or delete step in CI, no
  GitLab on_stop job, no scheduled cleanup in the IaC, no aws-nuke config and no
  decommissioning note that describes the process.

Resource type, size and number (COST 6). Right-sized types (COST06-BP02) and managed
scaling (COST06-BP03) are mapped checks; these read the rest.

- REPO-088 cost modeling: production workload resources and no cost estimate: no Infracost
  config or CI step, no cost-estimate tool config, and no estimate note (named or headed
  cost estimate, cost model, estimated cost or pricing) with an amount or a Pricing
  Calculator link.
- REPO-089 shared resources: production IaC creates its own VPC or ECS or EKS cluster and
  looks up or imports nothing shared, has no AWS RAM share, and says nothing about single
  tenancy (a Tenancy tag of single or dedicated, or a single-tenant comment).

Pricing models (COST 7). Spot and commitment advice for single resources (COST07-BP04) is
mapped checks; these read the rest.

- REPO-090 pricing model analysis: a production Auto Scaling group, ECS service, EKS node
  group or Batch compute environment, no Spot setting in production IaC, and no recorded
  commitment (a pricing-model, savings plan or reserved instance note, or a PricingModel,
  Commitment or SavingsPlan tag).
- REPO-091 Region by cost: production IaC hardcodes a Region priced above us-east-1,
  us-west-2 and eu-west-1, with no comment next to it and no Region note that names it and
  gives a reason (cost, latency, residency, sovereignty or compliance).
- REPO-092 third-party terms: the IaC uses an AWS Marketplace image or product and no
  contract-term tag or vendor or licence note gives the term.
- REPO-093 management-account pricing: an organization stack with no Savings Plans or RI
  utilization or coverage budget, no RI or Savings Plans sharing setting, and no
  commitment note.

Data transfer (COST 8). Gateway endpoints and NAT cost (COST08-BP03) are mapped checks;
these read the rest.

- REPO-094 data transfer modeling: production IaC creates resources that move data across
  Availability Zones or Regions (a Multi-AZ database, a replicated cache, a zone-aware
  search domain, MSK, a fleet over several subnets, S3 or DynamoDB replication, an AWS
  Backup copy action, a snapshot copy, EFS replication) and nothing records the transfer
  (a DataTransfer, TransferCost or CrossAZTraffic tag, a data-transfer note with a size or
  a service name, or a data-transfer comment next to the resource).
- REPO-095 data transfer cost: a Lambda function, ECS service or EC2 instance in a VPC
  with a NAT gateway, S3 or DynamoDB in the stack and no gateway endpoint for them, in a
  stack that spans Availability Zones; or a cross-Region copy with no recorded reason and
  no VPC endpoint.

Demand management (COST 9). Scaling on demand (COST09-BP03) is mapped checks; these read the
rest.

- REPO-096 demand analysis: production compute and no demand signal: no scheduled scaling
  action, no demand metric (queue depth, request rate, concurrency) used to scale or
  alarm, and no demand note (named or headed demand, traffic, usage pattern, load profile
  or capacity plan) that gives a rate, a volume or a calendar pattern. CPU and memory alone
  are utilization, not demand.
- REPO-097 buffer or throttle: production IaC with an API Gateway API and no throttle,
  usage plan, WAF rate-based rule or reserved concurrency; or a Lambda function invoked
  directly by SNS or S3 with no queue, stream or event bus and no reserved concurrency.

Aligning resources to demand (SUS 2). Right-sizing to demand (SUS02-BP01) is a mapped check;
these read the rest.

- REPO-098 SLAs: production workload and no note named or headed SLA, SLO, service level,
  availability target or reliability target that weighs it against sustainability (idle
  capacity, utilization, right-sizing, scale to zero, off-hours).
- REPO-099 unused assets: an EBS volume, load balancer, target group, NAT gateway or network
  interface in production IaC whose name nothing else in the repo refers to.
- REPO-100 geographic placement: a CloudFront price class that does not cover the Region a
  literal stack Region, S3 origin, load balancer or API domain names, with no comment or
  placement note giving a reason.
- REPO-101 team resources: production workload and no note on developer environments,
  workstations, CI runners or build agents that says how they are sized and shut down.
- REPO-102 demand curve: the REPO-097 gaps (an API with no throttle, a directly triggered
  Lambda function with no queue or reserved concurrency), read as spikes that drive
  over-provisioning.

Software and architecture patterns (SUS 3). Reading the sustainability pillar's SUS 3
questions: SUS03-BP01 is a mapped check; these read the rest.

- REPO-103 unused components: production IaC with an ECS service at desired count 0, an Auto
  Scaling group with a maximum of 0, a Lambda function with reserved concurrency 0, an
  EventBridge rule that is disabled or has no target, an SNS topic with no subscription, or a
  Lambda function nothing triggers or refers to.
- REPO-104 hot code: a Lambda function at 10240 MB (or 900 s with 3008 MB or more) or an ECS
  task at the Fargate maximum, with no CodeGuru Profiler, Lambda Insights, Power Tuning or
  note on a load test or profile that gives numbers.
- REPO-105 devices: the repo builds for end-user devices (a mobile app or an IoT fleet) and
  has no Device Farm setup and no note on supported devices, minimum OS, battery or hardware
  lifecycle.
- REPO-106 data access patterns: the REPO-063 gap (data kept on instance volumes or a database
  engine run on the host, with no managed data store), read as a mismatch of storage to the
  access pattern.
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


# Dependencies and constant work (REL 4): hardcoded client URLs (REPO-107) and synchronous
# calls with no timeout and no queue (REPO-108).
_HTTP_CODE_SUFFIXES = frozenset({
    ".py", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs",
})
# A client call whose first argument is a literal http(s) URL; group 1 is the host.
_LITERAL_URL_CALL = re.compile(
    r"(?:\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request)"
    r"|\burlopen|(?<![\w.])fetch|\baxios(?:\.(?:get|post|put|patch|delete|request))?"
    r"|(?<![\w.])got(?:\.(?:get|post|put|patch|delete))?)"
    r"\(\s*[fF]?[`\"']https?://(\[[^\]]+\]|[^/`\"'\s:{$]+)"
)
# Hosts that are local or are AWS endpoints: not a third-party dependency to name.
_LOCAL_HOST = re.compile(
    r"^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|\[::1?\])$"
    r"|\.amazonaws\.com(?:\.cn)?$|\.local$|\.internal$",
    re.IGNORECASE,
)
# A synchronous HTTP client call in function code.
_SYNC_HTTP_CALL = re.compile(
    r"\b(?:requests|httpx)\.(?:get|post|put|patch|delete|head|request)\("
    r"|\burlopen\(|(?<![\w.])fetch\(|\baxios(?:\.(?:get|post|put|patch|delete|request))?\("
    r"|(?<![\w.])got(?:\.(?:get|post|put|patch|delete))?\("
)
_HTTP_TIMEOUT = re.compile(
    r"\btimeout\w*\s*[=:]|\bAbortSignal\b|\bAbortController\b|\bsignal\s*:", re.IGNORECASE
)
# A queue, a stream or a schedule the IaC declares, so a call can be decoupled or repeated.
_QUEUE_OR_SCHEDULE = re.compile(
    r"AWS::SQS::Queue\b|resource\s+\"aws_sqs_queue\"|\bsqs\.Queue\(|\bCfnQueue\("
    r"|AWS::Kinesis::Stream\b|resource\s+\"aws_kinesis_stream\""
    r"|AWS::Scheduler::Schedule\b|resource\s+\"aws_scheduler_schedule\""
    r"|\bevents\.Schedule\.|\bschedule_expression\b|\bScheduleExpression\b"
    r"|\bscheduler\.CfnSchedule\(|\bSchedule\.(?:rate|cron|expression)\("
)


def http_client_files(repo_path: Path) -> Iterator[tuple[str, str]]:
    """(repo-relative path, text) of each Python, TypeScript or JavaScript file outside tests."""
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if path.suffix.lower() not in _HTTP_CODE_SUFFIXES or _in_test_dir(parts):
            continue
        if _TEST_NAME.search(path.name.lower()):
            continue
        yield "/".join(parts), read_text_safe(path)


class DependencyUrlHardcoded(_RepoRule):
    id = "REPO-107"
    title = "Code calls a hardcoded external URL"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Name each service the workload calls. Put the endpoint in a stack parameter, an SSM "
        "parameter or an environment variable the IaC sets, or define the dependency as a "
        "resource, so the workload's dependencies are visible and can change without a code "
        "edit. Then decide per dependency how its failure is handled."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        hits: list[tuple[str, str]] = []
        for rel, text in http_client_files(repo_path):
            for match in _LITERAL_URL_CALL.finditer(text):
                host = match.group(1)
                if not _LOCAL_HOST.search(host):
                    hits.append((host, rel))
                    break
        if not hits:
            return []
        listed = ", ".join(f"{host} ({rel})" for host, rel in hits[:5])
        return [self._finding(
            f"Code calls a literal URL: {listed}"
            + (f" and {len(hits) - 5} more" if len(hits) > 5 else "")
            + "; the host is in neither a parameter, an environment variable nor a resource",
            file=hits[0][1],
        )]


class SyncCallNoTimeoutOrQueue(_RepoRule):
    id = "REPO-108"
    title = "Synchronous calls have no timeout, and no queue or schedule sits behind them"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "A synchronous client of a dependency that can fail or stall holds its caller. Set a "
        "timeout on every HTTP call (requests timeout=, an AbortSignal or the client timeout "
        "option), and put the work behind a queue or a scheduled consumer when the dependency "
        "is hard, so the load on it stays constant and a slow call does not back up callers."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        untimed = [
            rel for rel, text in http_client_files(repo_path)
            if _SYNC_HTTP_CALL.search(text) and not _HTTP_TIMEOUT.search(text)
        ]
        if not untimed:
            return []
        if event_sources(repo_path) or any(
            _QUEUE_OR_SCHEDULE.search(text) for _, text in iac_texts(repo_path)
        ):
            return []
        listed = ", ".join(untimed[:5])
        return [self._finding(
            f"Synchronous HTTP calls with no timeout in: {listed}"
            + (f" and {len(untimed) - 5} more" if len(untimed) > 5 else "")
            + "; the IaC declares no queue, stream, event source or schedule",
            file=untimed[0],
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


class LoadTestForDemand(LoadTestMissing):
    """The same search as REPO-017, answering REL07-BP04 for the question on demand."""

    id = "REPO-148"
    title = "No load test shows that the workload adapts to changes in demand"
    themes = ("resilience",)
    recommendation = (
        "Prove the workload scales with demand: run a load test in the pipeline (k6, "
        "Artillery, Locust, JMeter or Distributed Load Testing on AWS) that ramps traffic "
        "past the current peak against a pre-production environment, and watch the Auto "
        "Scaling activity, the throttles and the error rates while it runs."
    )


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
    alarm = edge_alarm(repo_path)
    if alarm:
        found.setdefault("alarm on an edge latency or error metric", alarm)
    return found


def edge_alarm(repo_path: Path) -> str | None:
    """The first file with an alarm on an edge latency or 5xx metric."""
    for rel, text in iac_texts(repo_path):
        if not _TYPED_ALARM.search(text):
            continue
        if _CDK_EDGE_METRIC.search(text) or (
            _EDGE_NAMESPACE.search(text) and _EDGE_METRIC.search(text)
        ):
            return rel
    return None


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
    r"|^[ \t-]*(?:Image|ImageUri)[ \t]*:[ \t]+([^\s\"'#{!$&*|>]+)[ \t\r]*$",
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


def _tag_key(key: str) -> re.Pattern[str]:
    """A tag with one of the keys: CloudFormation Key:, Terraform map key, CDK add() or a
    CDK tags map. The key is matched without regard to case."""
    return re.compile(
        rf"[\"']?Key[\"']?\s*:\s*[\"']?{key}[\"']?\s*(?:,|$)"
        rf"|^\s*[\"']?{key}[\"']?\s*=\s*\S"
        rf"|\.add\(\s*['\"]{key}['\"]"
        rf"|[{{,]\s*[\"']?{key}[\"']?\s*:\s*['\"]",
        re.IGNORECASE | re.MULTILINE,
    )


_CLASS_TAG = _tag_key(_CLASS_KEY)
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


# Event management (OPS 10): priority (REPO-109), customer communication (REPO-110), an event
# status dashboard (REPO-111) and automated responses (REPO-112).
_RESPONSE_PLAN = re.compile(
    _cf_type(r"SSMIncidents::ResponsePlan") + r"|resource\s+\"aws_ssmincidents_response_plan\""
    r"|\bssmincidents\.(?:Cfn)?ResponsePlan\("
)
_EVENT_SEVERITY = re.compile(
    r"\b(?:[Ss]everity|SEVERITY|[Pp]riority|PRIORITY|[Ii]mpact|[Ss]ev[-_]?[1-5]|P[1-5])\b"
)
_CUSTOMER_CHANNEL = re.compile(
    r"customer|status[-_ ]?page|statuspage|service[-_ ]?status|public[-_ ]?status|subscriber",
    re.IGNORECASE,
)
_MESSAGING = re.compile(
    _cf_type(r"SNS::Topic|Pinpoint::\w+|SES::\w+|PinpointEmail::\w+|SMS-?Voice\w*::\w+")
    + r"|resource\s+\"aws_(?:sns_topic|pinpoint_\w+|ses_\w+|sesv2_\w+)\""
    r"|\b(?:sns|pinpoint|ses|sesv2)\.(?:Cfn)?\w+\("
)
_ALARM_WIDGET = re.compile(
    r"\bAlarmStatusWidget\b|\bAlarmWidget\b|\balarm_status_widget\b"
    r"|[\"']?type[\"']?\s*[:=]\s*\\?[\"']alarm\\?[\"']"
)
_RESPONSE_AUTOMATION = re.compile(
    r"automation-definition|StartAutomationExecution|\b[Ss]sm_?[Aa]utomation\b"
    r"|RunCommandParameters"
)


def event_signals(repo_path: Path) -> tuple[list[str], list[str]]:
    """(files with a CloudWatch alarm, files with an Incident Manager response plan)."""
    alarms: list[str] = []
    plans: list[str] = []
    for rel, text in iac_texts(repo_path):
        if _TYPED_ALARM.search(text):
            alarms.append(rel)
        if _RESPONSE_PLAN.search(text):
            plans.append(rel)
    return alarms, plans


class EventSeverityMissing(_RepoRule):
    id = "REPO-109"
    title = "Alarms and response plans carry no severity"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Rank events by business impact so responders start with the worst. Give each alarm "
        "a severity or priority in its name, description or tags, and set the impact of each "
        "Incident Manager response plan, so a page for a checkout outage is not "
        "indistinguishable from a warning about disk usage."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        alarms, plans = event_signals(repo_path)
        if not alarms and not plans:
            return []
        files = set(alarms) | set(plans)
        for rel, text in iac_texts(repo_path):
            if rel in files and _EVENT_SEVERITY.search(text):
                return []
        what = []
        if alarms:
            what.append(f"CloudWatch alarms ({_listed(alarms)})")
        if plans:
            what.append(f"Incident Manager response plans ({_listed(plans)})")
        return [self._finding(
            f"The IaC declares {' and '.join(what)}; searched those files for a severity, "
            "priority or impact; found none",
            file=(alarms or plans)[0],
        )]


class CustomerCommunicationMissing(_RepoRule):
    id = "REPO-110"
    title = "No customer communication channel is separate from the operator alarms"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Plan how customers hear about a service-impacting event: a status page, or an SNS "
        "topic, SES or Pinpoint channel that customers or their account teams subscribe to, "
        "kept apart from the topic that pages operators."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        alarms, _plans = event_signals(repo_path)
        if not alarms:
            return []
        for rel, text in iac_texts(repo_path):
            if _MESSAGING.search(text) and _CUSTOMER_CHANNEL.search(text):
                return []
        return [self._finding(
            f"The IaC declares CloudWatch alarms ({_listed(alarms)}); searched it for an SNS "
            "topic, SES or Pinpoint resource with a customer, subscriber or status-page "
            "name; found none",
            file=alarms[0],
        )]


class EventStatusDashboardMissing(_RepoRule):
    id = "REPO-111"
    title = "No dashboard shows the state of the alarms"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Show event status in one place: add a CloudWatch dashboard with an alarm status "
        "widget (or an alarm widget) for the workload's alarms, separate from the dashboard "
        "of workload metrics, so responders and stakeholders see which alarms are firing."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        alarms, _plans = event_signals(repo_path)
        if not alarms:
            return []
        dashboards = 0
        for rel, text in iac_texts(repo_path):
            if not _DASHBOARD.search(text):
                continue
            dashboards += 1
            if any(_ALARM_WIDGET.search(part) for part in _dashboard_texts(rel, text)):
                return []
        seen = (f"found {dashboards} dashboard file(s) with no alarm status widget"
                if dashboards else "found no CloudWatch dashboard")
        return [self._finding(
            f"The IaC declares CloudWatch alarms ({_listed(alarms)}); searched it for a "
            f"dashboard with an alarm status widget; {seen}",
            file=alarms[0],
        )]


class EventResponseNotAutomated(_RepoRule):
    id = "REPO-112"
    title = "Events start no automated response beyond a notification"
    severity = "Medium"
    themes = ("observability",)
    recommendation = (
        "Automate the first response to an event: route alarm state changes through an "
        "EventBridge rule to an SSM Automation runbook or a Lambda function, point an alarm "
        "action at an SSM OpsItem or automation, or give the Incident Manager response plan "
        "an SSM Automation action, so a notification is not the only thing that happens."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        alarms, plans = event_signals(repo_path)
        if not alarms and not plans:
            return []
        responses = {
            kind: rel for kind, rel in automated_responses(repo_path).items()
            if kind != "scaling policy"
        }
        if responses:
            return []
        if any(_RESPONSE_AUTOMATION.search(text) for _, text in iac_texts(repo_path)):
            return []
        return [self._finding(
            f"The IaC declares {'alarms' if alarms else 'response plans'} "
            f"({_listed(alarms or plans)}); searched it for an alarm action that runs "
            "automation, an EventBridge rule on alarm state changes, and an SSM Automation "
            "target or response-plan action; found none",
            file=(alarms or plans)[0],
        )]


# Change flow (OPS 5): version control (REPO-113), a configuration store (REPO-114), a code
# quality gate in CI (REPO-115) and small, reversible changes (REPO-116).
_HOSTED_REPO = re.compile(
    _cf_type(r"CodeCommit::Repository") + r"|resource\s+\"aws_codecommit_repository\""
    r"|\bcodecommit\.(?:Cfn)?Repository\(|\bcodestarconnections\b|\bCodeStarConnections\b"
    r"|\baws_codestarconnections_connection\b|\bcodeconnections\b|\bAWS::CodeConnections::"
    r"|\bCodePipelineSource\.(?:gitHub|connection|codeCommit|git_hub|code_commit)\("
    r"|\bConnectionSourceAction\b|\bCodeCommitSourceAction\b"
)
_CONFIG_STORE = re.compile(
    _cf_type(r"SSM::Parameter|SecretsManager::Secret|AppConfig::\w+")
    + r"|resource\s+\"aws_(?:ssm_parameter|secretsmanager_secret|appconfig_\w+)\""
    r"|\bssm\.(?:Cfn)?StringParameter\(|\bStringParameter\.(?:value\w*|from\w+)\("
    r"|\bsecretsmanager\.(?:Cfn)?Secret\(|\bSecret\.from\w+\("
    r"|\{\{resolve:(?:ssm|ssm-secure|secretsmanager):|\bvalueForStringParameter\("
    r"|\bdata\s+\"aws_(?:ssm_parameter|secretsmanager_secret\w*)\""
    r"|\bssm:GetParameter|\bsecretsmanager:GetSecretValue"
)
_ENV_CONFIG_FILE = re.compile(
    r"(?:^|/)(?:config|conf|settings|environments?|envs)/(?:[^/]*[-_.])?"
    r"(?:dev|development|test|qa|uat|stage|staging|prod|production)(?:[-_.][^/]*)?"
    r"\.(?:json|ya?ml|toml|ts|js)$"
    r"|(?:^|/)(?:config|conf|settings|environments?|envs)/(?:dev|development|test|qa|uat|stage"
    r"|staging|prod|production)/[^/]+$"
    r"|\.tfvars(?:\.json)?$|(?:^|/)(?:cdk\.context|context)[^/]*\.json$"
    r"|(?:^|/)[^/]*(?:param|parameters|config)[-_.](?:dev|test|stage|staging|prod|production)"
    r"[^/]*\.(?:json|ya?ml)$",
    re.IGNORECASE,
)
_QUALITY_GATE = re.compile(
    r"(?<!\w)(?:eslint|ruff|flake8|pylint|pycodestyle|black\s+--check|prettier\s+--check|biome"
    r"|mypy|pyright|tsc\b[^\n]*--noEmit|golangci-lint|rubocop|checkstyle|spotbugs|sonar\w*"
    r"|codeql|cfn-lint|tflint|cdk-nag|terraform\s+validate|cargo\s+clippy"
    r"|--cov-fail-under|--fail-under|--coverage-threshold|coverageThreshold"
    r"|npm\s+run\s+(?:lint|typecheck|type-check|check)|make\s+(?:lint|check))\b",
    re.IGNORECASE,
)
_SMALL_STEP_DEPLOY = re.compile(
    r"blue[-_ /]?green|BlueGreen|canary[-_ ]?(?:deploy\w*|release|traffic)|Canary\d+Percent"
    r"|Linear\d+Percent|\btraffic_?shifting\b|AdditionalVersionWeights|\badditional_?versions\b"
    r"|\brouting_?config\b|RoutingConfig"
    r"|AWS::CodeDeploy::DeploymentGroup|resource\s+\"aws_codedeploy_deployment_group\"",
    re.IGNORECASE,
)


def _is_git_checkout(repo_path: Path) -> bool:
    """A .git entry (a directory, or a file in a worktree or submodule) in the scanned
    folder or any folder above it."""
    try:
        start = repo_path.resolve()
    except OSError:
        start = repo_path
    return any((folder / ".git").exists() for folder in (start, *start.parents))


class VersionControlMissing(_RepoRule):
    id = "REPO-113"
    title = "The workload is not in version control"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Keep the infrastructure and application code in version control (a git repository, "
        "or AWS CodeCommit or a CodeConnections-linked repository) so every change is "
        "recorded, reviewed and can be reverted."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        if _is_git_checkout(repo_path):
            return []
        for _rel, text in iac_texts(repo_path):
            if _HOSTED_REPO.search(text):
                return []
        return [self._finding(
            "Searched the scanned folder and the folders above it for a .git entry, and the "
            "IaC for a CodeCommit repository, a CodeConnections or CodeStar connection and a "
            "pipeline source from a hosted repository; found none"
        )]


class ConfigurationStoreMissing(_RepoRule):
    id = "REPO-114"
    title = "Configuration is not kept in a configuration store or per-environment files"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Keep configuration out of the code: store it in SSM Parameter Store, Secrets "
        "Manager or AppConfig, or in a file per environment (tfvars, cdk.context or a config "
        "directory), so a change to configuration is a reviewed, versioned change that does "
        "not need a code edit."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute:
            return []
        for _rel, text in iac_texts(repo_path):
            if _CONFIG_STORE.search(text):
                return []
        for path in walk(repo_path):
            if _ENV_CONFIG_FILE.search("/".join(_rel_parts(path, repo_path))):
                return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for SSM parameters, Secrets Manager "
            "secrets, AppConfig and parameter lookups, and the repo for a tfvars, cdk.context "
            "or config directory file per environment; found none",
            file=next(iter(compute.values())),
        )]


def quality_gates(repo_path: Path) -> dict[str, str]:
    """Lint, type-check, static analysis and coverage-threshold commands in the build
    configs and the package.json scripts they run: command -> first place."""
    builds = build_texts(repo_path)
    found: dict[str, str] = {}
    for rel, text in builds:
        for match in _QUALITY_GATE.finditer(text):
            found.setdefault(match.group(0).split()[0].lower(), rel)
    for script, command in _scripts_run([text for _rel, text in builds],
                                        _package_scripts(repo_path)):
        for match in _QUALITY_GATE.finditer(command):
            found.setdefault(match.group(0).split()[0].lower(), f"package.json script {script}")
    return found


class QualityGateMissing(_RepoRule):
    id = "REPO-115"
    title = "No CI step lints, type-checks or sets a coverage gate"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Make code quality a gate: run a linter or type checker (ESLint, ruff, mypy, tsc "
        "--noEmit, golangci-lint), a static analyzer (CodeQL, SonarQube, cfn-lint, tflint, "
        "cdk-nag) or a coverage threshold in the CI workflow or pipeline, and fail the build "
        "on findings."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        builds = [rel for rel, _text in build_texts(repo_path)]
        if quality_gates(repo_path):
            return []
        seen = (f"searched the build configs ({_listed(builds)}) and the package.json "
                "scripts they run" if builds else "found no CI config or pipeline")
        return [self._finding(
            f"{seen[0].upper()}{seen[1:]} for a linter, type checker, static analyzer or "
            "coverage threshold; found none",
            file=builds[0] if builds else None,
        )]


class SmallReversibleChangesMissing(_RepoRule):
    id = "REPO-116"
    title = "Deployments have no rollback, blue/green or canary step"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Ship small changes that can be undone: deploy through CodeDeploy with a canary or "
        "linear traffic shift (SAM DeploymentPreference, Lambda alias weights), blue/green, "
        "an ECS deployment circuit breaker, or a pipeline stage that rolls back on failure."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute or rollback_controls(repo_path):
            return []
        places = list(iac_texts(repo_path)) + build_texts(repo_path)
        if any(_SMALL_STEP_DEPLOY.search(text) for _rel, text in places):
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC and builds for a rollback control, "
            "blue/green, a canary or linear traffic shift, a CodeDeploy deployment group and "
            "Lambda alias weights; found none",
            file=next(iter(compute.values())),
        )]


# Application security practices (SEC 11): training (REPO-117), penetration testing
# (REPO-118), code review (REPO-119), programmatic deploys (REPO-120) and security ownership
# (REPO-121). They fire only on a repo that holds IaC.
_TRAINING_NAME = re.compile(
    r"security[-_ ]?(?:awareness[-_ ]?)?training|security[-_ ]?awareness|secure[-_ ]?coding"
    r"|app(?:lication)?[-_ ]?sec(?:urity)?[-_ ]?training"
)
_TRAINING_HEADING = re.compile(
    r"(?i).*\b(?:security[- ](?:awareness[- ])?training|security[- ]awareness"
    r"|secure[- ]coding|app(?:lication)?[- ]?sec(?:urity)?[- ]training)\b.*"
)
_PENTEST_NAME = re.compile(r"pen[-_ ]?tests?|pentests?|penetration[-_ ]?test(?:s|ing)?")
_PENTEST_HEADING = re.compile(r"(?i).*\b(?:pen[- ]?tests?|penetration[- ]test(?:s|ing)?)\b.*")
_CODEOWNERS_PATHS = frozenset({"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS",
                               ".gitlab/CODEOWNERS"})
_REVIEW_ENFORCED = re.compile(
    r"resource\s+\"github_(?:branch_protection(?:_v3)?|repository_ruleset)\""
    r"|resource\s+\"aws_codecommit_approval_rule_template\""
    r"|[\"']?required_?[pP]ull_?[rR]equest_?[rR]eviews[\"']?\s*[:={]"
    r"|[\"']?required_?[aA]pproving_?[rR]eview_?[cC]ount[\"']?\s*[:=]"
    r"|[aA]pprovalRuleTemplate\b"
    r"|resource\s+\"gitlab_(?:branch_protection|project_approval_rule)\""
)
_REVIEW_CONFIG_PATHS = (".github/settings.yml", ".github/settings.yaml", ".github/rulesets/")
_SECURITY_OWNER_NAME = re.compile(
    r"^security(?:[-_ ]?(?:owners?|champions?|team|contacts?|ownership))?$"
    r"|^security[-_ ]?owners?$|^security[-_ ]?champions?$"
)
_SECURITY_OWNER_HEADING = re.compile(
    r"(?i).*\b(?:security[- ](?:owners?|champions?|ownership|contacts?)"
    r"|who owns security)\b.*"
)
_OWNER_TOKEN = re.compile(r"(?:^|\s)(@[\w./-]+|[\w.+-]+@[\w-]+\.[\w.]+)(?=\s|$)")


def _codeowners(repo_path: Path) -> Iterator[tuple[str, List[List[str]]]]:
    """(path, owners per rule line) of each CODEOWNERS file; comments and lines with no owner
    are left out, so an empty or comment-only file yields no lines."""
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if "/".join(parts) not in _CODEOWNERS_PATHS:
            continue
        lines: List[List[str]] = []
        for line in read_text_safe(path).splitlines():
            line = line.split("#", 1)[0]
            owners = [m.group(1) for m in _OWNER_TOKEN.finditer(line)]
            if owners:
                lines.append(owners)
        yield "/".join(parts), lines


def review_enforced(repo_path: Path) -> str | None:
    """A CODEOWNERS file, or branch protection, a ruleset or an approval rule in the IaC or
    the repo settings: the first place."""
    for rel, lines in _codeowners(repo_path):
        if lines:
            return rel
    for rel, text in iac_texts(repo_path):
        if _REVIEW_ENFORCED.search(text):
            return rel
    for path in walk(repo_path):
        rel = "/".join(_rel_parts(path, repo_path))
        if rel.startswith(_REVIEW_CONFIG_PATHS) and _REVIEW_ENFORCED.search(read_text_safe(path)):
            return rel
        if rel.lower() in (".github/settings.yml", ".github/settings.yaml") and re.search(
            r"(?m)^\s*required_pull_request_reviews\s*:", read_text_safe(path)
        ):
            return rel
    return None


def security_owner_note(repo_path: Path) -> str | None:
    """A SECURITY.md, a note named or headed for security ownership, or a CODEOWNERS line
    that names security."""
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        if stem == "security" or _SECURITY_OWNER_NAME.search(stem) or any(
            _SECURITY_OWNER_HEADING.fullmatch(h.group(2).strip()) for h in _HEADING.finditer(text)
        ):
            return rel
    for rel, lines in _codeowners(repo_path):
        if any("security" in owner.lower() for owners in lines for owner in owners):
            return rel
    return None


def pentest_note(repo_path: Path) -> str | None:
    """The first dated note named or headed for a penetration test."""
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        titled = _PENTEST_NAME.search(stem) or any(
            _PENTEST_HEADING.fullmatch(h.group(2).strip()) for h in _HEADING.finditer(text)
        )
        if titled and _DATE.search(text):
            return rel
    return None


def _holds_iac(repo_path: Path) -> str:
    held = iac_files(repo_path)
    return "; ".join(f"{kind}: {count} file{'s' if count > 1 else ''}"
                     for kind, count in sorted(held.items()))


class SecurityTrainingMissing(_RepoRule):
    id = "REPO-117"
    title = "No note records application security training"
    category = "Security"
    severity = "Low"
    themes = ("security-baseline",)
    recommendation = (
        "Record how the team learns application security: a SECURITY_TRAINING.md or a "
        "\"Security training\" section in the README or docs that names the training (secure "
        "coding, OWASP, a vendor course), who takes it and how often."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held or _titled_note(repo_path, _TRAINING_NAME, _TRAINING_HEADING):
            return []
        return [self._finding(
            f"Holds IaC ({held}); searched the notes for a file or heading on security "
            "training, security awareness or secure coding; found none"
        )]


class PenetrationTestMissing(_RepoRule):
    id = "REPO-118"
    title = "No dated penetration test record is in the repo"
    category = "Security"
    severity = "Low"
    themes = ("security-baseline",)
    recommendation = (
        "Test the application with a penetration test on a schedule and keep the dated "
        "result in the repo (docs/pentest-2026-03.md): scope, date, findings and their "
        "status, so the next test starts from the last one."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held or pentest_note(repo_path):
            return []
        return [self._finding(
            f"Holds IaC ({held}); searched the notes for a dated file or heading on a "
            "penetration test; found none"
        )]


class CodeReviewNotEnforced(_RepoRule):
    id = "REPO-119"
    title = "Nothing requires a code review before a change merges"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Require a review: add a CODEOWNERS file, and protect the main branch so a pull "
        "request needs an approving review (a github_branch_protection or "
        "github_repository_ruleset resource, repository settings as code, or a CodeCommit "
        "approval rule template)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held or review_enforced(repo_path):
            return []
        return [self._finding(
            f"Holds IaC ({held}); searched for a CODEOWNERS file, branch protection or a "
            "ruleset with required reviews, repository settings with required pull request "
            "reviews, and a CodeCommit approval rule; found none"
        )]


class ProgrammaticDeployMissing(_RepoRule):
    id = "REPO-120"
    title = "Software is not deployed programmatically"
    category = "Security"
    severity = "Medium"
    themes = ("security-baseline",)
    recommendation = (
        "Deploy from a pipeline with a role of its own, not from a person's laptop: a CI "
        "job or CodeBuild project that runs the CDK, CloudFormation, SAM or Terraform "
        "deploy, a CodePipeline, or CDK pipelines, so every release is repeatable and "
        "logged."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held or automated_deploys(repo_path):
            return []
        return [self._finding(
            f"Holds IaC ({held}); searched the build configs, the package.json scripts they "
            "run and the IaC for a deploy step or a pipeline; found none"
        )]


class SecurityOwnershipMissing(_RepoRule):
    id = "REPO-121"
    title = "No file names who owns security for the workload"
    category = "Security"
    severity = "Low"
    themes = ("security-baseline",)
    recommendation = (
        "Name who owns security in the team: a SECURITY.md with a contact and the owner, a "
        "security-owners or security-champions note, or a CODEOWNERS entry for security-"
        "sensitive paths that names a security team."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held or security_owner_note(repo_path):
            return []
        return [self._finding(
            f"Holds IaC ({held}); searched for a SECURITY.md, a security owners or champions "
            "note, and a CODEOWNERS line that names security; found none"
        )]


# Reliability testing practices (REL 12): failure playbooks (REPO-122), post-incident analysis
# (REPO-123) and game days (REPO-124). They read notes and fire only on a repo that holds IaC.
_PLAYBOOK_NAME = re.compile(
    r"playbooks?|failure[-_ ]?investigations?|troubleshooting[-_ ]?(?:guide|playbook)s?"
)
_PLAYBOOK_HEADING = re.compile(
    r"(?i).*\b(?:playbooks?|failure investigations?|troubleshooting guide)\b.*"
)
_POST_INCIDENT_NAME = re.compile(
    r"post[-_ ]?(?:incident|mortems?)|postmortems?|incident[-_ ]?(?:review|report|analysis)"
    r"|root[-_ ]?cause|rcas?(?:$|[-_ .])|blameless"
)
_POST_INCIDENT_HEADING = re.compile(
    r"(?i).*\b(?:post[- ]?incident|post[- ]?mortems?|incident (?:review|report|analysis)"
    r"|root cause analysis|blameless)\b.*"
)
_GAME_DAY_NAME = re.compile(r"game[-_ ]?days?|gamedays?|chaos[-_ ]?days?|fire[-_ ]?drills?")
_GAME_DAY_HEADING = re.compile(
    r"(?i).*\b(?:game[- ]?days?|chaos days?|fire drills?|failure drills?)\b.*"
)


def _noted(repo_path: Path, name: re.Pattern[str], heading: re.Pattern[str]) -> str | None:
    """The first note whose file stem or folder name matches, or that has a matching heading."""
    for rel, text in note_texts(repo_path):
        parts = rel.lower().split("/")
        names = [*parts[:-1], parts[-1].rsplit(".", 1)[0]]
        if any(name.search(part) for part in names) or any(
            heading.fullmatch(h.group(2).strip()) for h in _HEADING.finditer(text)
        ):
            return rel
    return None


class FailurePlaybookMissing(_RepoRule):
    id = "REPO-122"
    title = "No playbook is in the repo for investigating failures"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Write down how to investigate a failure: a playbook per likely failure (a "
        "docs/playbooks directory or PLAYBOOK.md) that names the symptoms, the dashboards "
        "and logs to open, the checks to run and who to call, and keep it with the code it "
        "describes."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held or _noted(repo_path, _PLAYBOOK_NAME, _PLAYBOOK_HEADING):
            return []
        return [self._finding(
            f"Holds IaC ({held}); searched the notes for a file or heading on a playbook, a "
            "failure investigation or a troubleshooting guide; found none"
        )]


class PostIncidentAnalysisMissing(_RepoRule):
    id = "REPO-123"
    title = "No post-incident template or record is in the repo"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Learn from every incident: keep a post-incident (postmortem) template in the repo, "
        "such as docs/postmortem-template.md or an issue template, with the timeline, the "
        "root cause, what worked, what did not and the follow-ups, and file the analysis "
        "next to the code."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held or _noted(repo_path, _POST_INCIDENT_NAME, _POST_INCIDENT_HEADING):
            return []
        return [self._finding(
            f"Holds IaC ({held}); searched the notes for a file or heading on a post-incident "
            "review, a postmortem or a root cause analysis; found none"
        )]


class GameDayMissing(_RepoRule):
    id = "REPO-124"
    title = "No game day is recorded in the repo"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Practise failure on a schedule: keep a game-day plan in the repo (docs/game-days.md) "
        "that lists the scenarios, the dates or the cadence, who takes part and what the last "
        "one found, and run the scenarios against a non-production copy first."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held or _noted(repo_path, _GAME_DAY_NAME, _GAME_DAY_HEADING):
            return []
        return [self._finding(
            f"Holds IaC ({held}); searched the notes for a file or heading on a game day, a "
            "chaos day or a fire drill; found none"
        )]


# Incident readiness (SEC 10): key contacts (REPO-125), an incident plan (REPO-126), security
# playbooks (REPO-127), pre-provisioned response access (REPO-128), simulations (REPO-129)
# and learning from incidents (REPO-130). REPO-007 and REPO-008 answer SEC10-BP03 and
# SEC10-BP06 (forensics and containment). They fire only on a repo that holds IaC.
_CONTACTS_IN_IAC = re.compile(
    _cf_type(r"SSMContacts::\w+") + r"|resource\s+\"aws_ssmcontacts_(?:contact|plan|rotation)\""
    r"|\bssmcontacts\.(?:Cfn)?\w+\("
)
_CONTACTS_NAME = re.compile(
    r"contacts?|on[-_ ]?call|key[-_ ]?personnel|escalation|responders?|incident[-_ ]?team"
)
_CONTACTS_HEADING = re.compile(
    r"(?i).*\b(?:key personnel|security contacts?|on-?call|escalation contacts?"
    r"|incident (?:contacts?|team)|responders?)\b.*"
)
_IR_PLAN_NAME = re.compile(
    r"incident[-_ ]?(?:management|response)[-_ ]?plan|incident[-_ ]?response|ir[-_ ]?plan"
)
_IR_PLAN_HEADING = re.compile(
    r"(?i).*\b(?:incident (?:management|response) plan|incident response|security incident plan)\b.*"
)
_SECURITY_PLAYBOOK_NAME = re.compile(
    r"security[-_ ]?(?:incident[-_ ]?)?playbooks?|ir[-_ ]?playbooks?"
    r"|incident[-_ ]?response[-_ ]?playbooks?"
)
_SECURITY_PLAYBOOK_HEADING = re.compile(
    r"(?i).*\b(?:security (?:incident )?playbooks?|incident response playbooks?|ir playbooks?)\b.*"
)
_IAM_ROLE_DECL = re.compile(
    r"AWS::IAM::Role\b|resource\s+\"aws_iam_role\"|\biam\.(?:Cfn)?Role\(|\bnew\s+Role\("
    r"|\bSSO::PermissionSet\b|resource\s+\"aws_ssoadmin_permission_set\""
)
_IR_ROLE_NAME = re.compile(
    r"(?i)(?:incident|security)[-_ ]?(?:response|responder|investigat\w*|forensic\w*)"
    r"|\bIncidentResponse\w*|\bSecurityIR\w*|\bforensic[-_ ]?(?:analyst|access|role)\b"
)
_SECURITY_LEARNING_NAME = re.compile(
    r"security[-_ ]?(?:post[-_ ]?incident|postmortem|incident[-_ ]?review|lessons?)"
)
_SECURITY_LEARNING_HEADING = re.compile(
    r"(?i).*\b(?:security (?:post[- ]?incident|post[- ]?mortem|incident review|lessons learned))\b.*"
)


def _in_iac_text(repo_path: Path, pattern: re.Pattern[str]) -> str | None:
    """The first IaC file outside tests whose text matches."""
    for rel, text in iac_texts(repo_path):
        if pattern.search(text):
            return rel
    return None


def _ir_role(repo_path: Path) -> str | None:
    for rel, text in iac_texts(repo_path):
        if _IAM_ROLE_DECL.search(text) and _IR_ROLE_NAME.search(text):
            return rel
    return None


class _IncidentRule(_RepoRule):
    """A SEC 10 rule: it fires on a repo that holds IaC when nothing answers the practice."""

    category = "Security"
    severity = "Low"
    themes = ("security-baseline",)
    searched = ""

    def present(self, repo_path: Path) -> str | None:
        raise NotImplementedError

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held or self.present(repo_path):
            return []
        return [self._finding(f"Holds IaC ({held}); searched {self.searched}; found none")]


class KeyContactsMissing(_IncidentRule):
    id = "REPO-125"
    title = "No Incident Manager contact or note names who responds to security incidents"
    themes = ("security-baseline",)
    recommendation = (
        "Name who responds: define Incident Manager contacts and an escalation plan "
        "(AWS::SSMContacts::Contact and Plan), or keep a contacts note in the repo with the "
        "security responders, the on-call rotation and the external resources (the AWS "
        "account team, a retainer) to call."
    )
    searched = (
        "the IaC for Incident Manager contacts and plans, and the notes for a file or heading "
        "on contacts, on-call, key personnel or responders"
    )

    def present(self, repo_path: Path) -> str | None:
        return (_in_iac_text(repo_path, _CONTACTS_IN_IAC)
                or _noted(repo_path, _CONTACTS_NAME, _CONTACTS_HEADING))


class IncidentPlanMissing(_IncidentRule):
    id = "REPO-126"
    title = "No security incident management plan is in the template or the repo"
    themes = ("security-baseline",)
    recommendation = (
        "Write the plan before the incident: an Incident Manager response plan in the IaC, or "
        "an incident response plan note (docs/incident-response-plan.md) that says what "
        "counts as an incident, who leads, how to contain it and how to communicate."
    )
    searched = (
        "the IaC for an Incident Manager response plan, and the notes for a file or heading "
        "on an incident management or response plan"
    )

    def present(self, repo_path: Path) -> str | None:
        return (_in_iac_text(repo_path, _RESPONSE_PLAN)
                or _noted(repo_path, _IR_PLAN_NAME, _IR_PLAN_HEADING))


class SecurityPlaybookMissing(_IncidentRule):
    id = "REPO-127"
    title = "No security incident response playbook is in the repo"
    themes = ("security-baseline",)
    recommendation = (
        "Write playbooks for the incidents you expect (leaked credentials, a compromised "
        "instance, public data exposure): detection, triage, containment, eradication and "
        "recovery steps, kept as docs/security-playbooks and exercised in a simulation."
    )
    searched = "the notes for a file, folder or heading on security incident playbooks"

    def present(self, repo_path: Path) -> str | None:
        return _noted(repo_path, _SECURITY_PLAYBOOK_NAME, _SECURITY_PLAYBOOK_HEADING)


class ResponseAccessMissing(_IncidentRule):
    id = "REPO-128"
    title = "No incident response role is provisioned before an incident"
    themes = ("security-baseline",)
    recommendation = (
        "Provision responder access in advance: an IAM role or an Identity Center permission "
        "set for incident response (IncidentResponder, SecurityInvestigator) with the read "
        "and containment permissions it needs, assumed with MFA, so nobody creates access "
        "in the middle of an incident."
    )
    searched = (
        "the IaC for an IAM role or permission set named for incident response, a responder, "
        "an investigator or forensics"
    )

    def present(self, repo_path: Path) -> str | None:
        return _ir_role(repo_path)


class SecuritySimulationMissing(_IncidentRule):
    id = "REPO-129"
    title = "No simulation of an incident is defined"
    themes = ("security-baseline",)
    recommendation = (
        "Run simulations so the response is practised: define an AWS FIS experiment template "
        "for the failures you plan for, and run it with the responders on a schedule."
    )
    searched = "the IaC for an AWS FIS experiment template"

    def present(self, repo_path: Path) -> str | None:
        return _in_iac_text(repo_path, _FIS_IN_IAC)


class IncidentLearningMissing(_IncidentRule):
    id = "REPO-130"
    title = "No security post-incident template is in the repo"
    themes = ("security-baseline",)
    recommendation = (
        "Learn from security incidents: keep a security post-incident template "
        "(docs/security-postmortem-template.md) with the timeline, the root cause, the "
        "detection and response gaps and the follow-ups, and review each one."
    )
    searched = "the notes for a file or heading on a security post-incident review or postmortem"

    def present(self, repo_path: Path) -> str | None:
        return _noted(repo_path, _SECURITY_LEARNING_NAME, _SECURITY_LEARNING_HEADING)


# Network connectivity (REL 2): a public endpoint behind a load balancer (REPO-131) and more
# than one link to an on-premises network (REPO-132). They share their detection with
# REPO-064 and REPO-066, which answer the same conditions under PERF 4.


_GLOBAL_ACCELERATOR = re.compile(
    r"AWS::GlobalAccelerator::Accelerator\b|resource\s+\"aws_globalaccelerator_accelerator\""
    r"|\bglobalaccelerator\.(?:Cfn)?Accelerator\("
)


class PublicEndpointNotHighlyAvailable(_RepoRule):
    id = "REPO-131"
    title = "A public endpoint is an instance with a public IP, not a load balancer"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Do not serve the public from one instance's address: put the endpoint behind an "
        "Application or Network Load Balancer across at least two Availability Zones, or "
        "AWS Global Accelerator, and keep the instances in private subnets."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        exposed = public_instances(repo_path)
        if not exposed or _in_iac(repo_path, _LOAD_BALANCERS) or _in_iac_text(
            repo_path, _GLOBAL_ACCELERATOR
        ):
            return []
        names = [f"{name} in {rel}" for name, rel in exposed]
        return [self._finding(
            f"Declares an EC2 instance with a public IP or an Elastic IP ({_listed(names)}); "
            "searched the IaC for an Application, Network or Classic Load Balancer and a Global "
            "Accelerator; found none",
            file=exposed[0][1],
        )]


class SingleOnPremLink(_RepoRule):
    id = "REPO-132"
    title = "Only one link connects the VPC to the on-premises network"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Provision a second path to the on-premises network: a second Site-to-Site VPN "
        "connection to a second customer gateway device, a second Direct Connect connection "
        "or virtual interface in another location, or a VPN as the backup for Direct Connect."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        single = single_hybrid_link(repo_path)
        if not single:
            return []
        what, rel = single
        return [self._finding(
            f"Declares one {what} in {rel}; searched the IaC for a second link: another "
            "Direct Connect connection or virtual interface, a LAG, or a Site-to-Site VPN "
            "connection on another customer gateway; found none",
            file=rel,
        )]


# Service quotas (REL 1): quotas managed across accounts and Regions (REPO-133), quota
# increases automated (REPO-134) and fixed quotas designed around (REPO-135).
_SERVICE_QUOTAS_RESOURCE = re.compile(
    r"AWS::ServiceQuotas::\w+|resource\s+\"aws_servicequotas_\w+\""
    r"|\bservicequotas\.(?:Cfn)?\w+\("
    r"|\bmodule\s+\"[^\"]*quotas?[^\"]*\"|\bsource\s*=\s*\"[^\"]*quotas?[^\"]*\""
)
_QUOTA_INCREASE = re.compile(
    r"resource\s+\"aws_servicequotas_(?:service_quota|template)\"|AWS::ServiceQuotas::\w+"
    r"|\bservicequotas\.(?:Cfn)?\w+\("
    r"|RequestServiceQuotaIncrease|request_service_quota_increase"
    r"|servicequotas:RequestServiceQuotaIncrease"
    r"|put[-_]service[-_]quota[-_]increase[-_]request[-_]into[-_]template"
    r"|PutServiceQuotaIncreaseRequestIntoTemplate"
)
_FIFO_QUEUE = re.compile(
    r"[\"']?(?:FifoQueue|fifo_queue)[\"']?\s*[:=]\s*[\"']?(?:true|True)\b"
    r"|\bfifo\s*[:=]\s*(?:true|True)\b"
)
_FIFO_HIGH_THROUGHPUT = re.compile(
    r"per_?[mM]essage_?[gG]roup_?[iI]d|PER_MESSAGE_GROUP_ID"
)
_KINESIS_STREAM = re.compile(
    _cf_type(r"Kinesis::Stream") + r"|resource\s+\"aws_kinesis_stream\""
    r"|\bkinesis\.(?:Cfn)?Stream\("
)
_ONE_SHARD = re.compile(r"[\"']?(?:ShardCount|shard_count|shardCount)[\"']?\s*[:=]\s*[\"']?1\b(?!\d)")
_ON_DEMAND_STREAM = re.compile(r"\bON_DEMAND\b|StreamMode\.ON_DEMAND")


def fixed_quota_designs(repo_path: Path) -> list[str]:
    """FIFO queues without high-throughput mode and one-shard provisioned Kinesis streams,
    as "kind in file"."""
    found: list[str] = []
    for rel, text in iac_texts(repo_path):
        if _FIFO_QUEUE.search(text) and not _FIFO_HIGH_THROUGHPUT.search(text):
            found.append(f"a FIFO queue without high-throughput mode in {rel}")
        if (_KINESIS_STREAM.search(text) and _ONE_SHARD.search(text)
                and not _ON_DEMAND_STREAM.search(text)):
            found.append(f"a one-shard provisioned Kinesis stream in {rel}")
    return found


class QuotasNotManaged(_RepoRule):
    id = "REPO-133"
    title = "Service quotas are not managed as code across accounts and Regions"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Manage service quotas where the workload runs: Service Quotas resources "
        "(aws_servicequotas_service_quota, a Service Quotas request template for the "
        "organization) or a quotas module applied to every account and Region the stack "
        "uses, so a new Region starts with the quotas the workload needs."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute or _in_iac_text(repo_path, _SERVICE_QUOTAS_RESOURCE):
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for Service Quotas resources and a "
            "quotas module; found none",
            file=next(iter(compute.values())),
        )]


class QuotaIncreaseNotAutomated(_RepoRule):
    id = "REPO-134"
    title = "No quota increase is requested by the template or by automation"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Automate quota increases: declare the quota in the template (aws_servicequotas_"
        "service_quota or a Service Quotas template), or let an alarm on quota usage start a "
        "function that calls RequestServiceQuotaIncrease."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute:
            return []
        if _in_iac_text(repo_path, _QUOTA_INCREASE):
            return []
        for rel, text in note_texts_code(repo_path):
            if _QUOTA_INCREASE.search(text):
                return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC and the function code for a Service "
            "Quotas resource or template and a RequestServiceQuotaIncrease call; found none",
            file=next(iter(compute.values())),
        )]


def note_texts_code(repo_path: Path) -> Iterator[tuple[str, str]]:
    """(repo-relative path, text) of function code outside tests."""
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if path.suffix.lower() not in _FUNCTION_CODE_SUFFIXES or _in_test_dir(parts):
            continue
        if _TEST_NAME.search(path.name.lower()):
            continue
        yield "/".join(parts), read_text_safe(path)


class FixedQuotaNotDesignedAround(_RepoRule):
    id = "REPO-135"
    title = "A fixed service quota is not designed around"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Design around quotas you cannot raise: turn on SQS FIFO high-throughput mode "
        "(deduplication scope per message group, throughput limit per message group id) or "
        "partition across queues, and use on-demand capacity mode or more shards for Kinesis, "
        "so one queue or stream is not the ceiling for the workload."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        designs = fixed_quota_designs(repo_path)
        if not designs:
            return []
        return [self._finding(
            f"Declares {_listed(designs)}; searched for FIFO high-throughput mode "
            "(per message group deduplication and throughput) and for an on-demand or "
            "multi-shard stream; found none",
            file=designs[0].rsplit(" in ", 1)[-1],
        )]


# Security operations (SEC 1): control objectives (REPO-136), a smaller security management
# scope (REPO-137), a threat model (REPO-138) and new security services (REPO-139). REPO-006
# answers the root user (SEC01-BP02). They fire only on a repo that holds IaC.
_CONTROL_OBJECTIVES = re.compile(
    r"AWS::SecurityHub::StandardsSubscription|resource\s+\"aws_securityhub_standards_subscription\""
    r"|AWS::Config::(?:Organization)?ConformancePack"
    r"|resource\s+\"aws_config_(?:organization_)?conformance_pack\""
    r"|\bsecurityhub\.Cfn\w*Standard\w*\(|\bconfig\.Cfn(?:Organization)?ConformancePack\("
)
_DELEGATED_ADMIN = re.compile(
    r"resource\s+\"aws_(?:organizations_delegated_administrator|securityhub_organization_admin_account"
    r"|guardduty_organization_admin_account|macie2_organization_admin_account"
    r"|inspector2_delegated_admin_account|fms_admin_account|controltower_control"
    r"|detective_organization_admin_account|auditmanager_organization_admin_account)\""
    r"|AWS::ControlTower::EnabledControl|\bCfnEnabledControl\("
    r"|\bDelegatedAdmin\b|\bdelegated_administrator\b"
)
_THREAT_MODEL_PATH = re.compile(r"threat[-_ ]?model|threat[-_ ]?dragon|\.tm7$|\.threatmodel$")
_THREAT_MODEL_HEADING = re.compile(r"(?i).*\bthreat model(?:l?ing)?\b.*")
_SECURITY_SERVICE = re.compile(
    r"AWS::AccessAnalyzer::Analyzer|resource\s+\"aws_accessanalyzer_analyzer\""
    r"|\baccessanalyzer\.(?:Cfn)?Analyzer\(|AWS::InspectorV2::\w+|AWS::Inspector::\w+"
    r"|resource\s+\"aws_inspector2?_\w+\"|\binspectorv2\.\w+\(|\binspector2\.\w+\("
)
_SECURITY_REVIEW_NAME = re.compile(
    r"security[-_ ]?(?:service[-_ ]?)?reviews?|new[-_ ]?security[-_ ]?(?:services?|features?)"
    r"|security[-_ ]?roadmap"
)
_SECURITY_REVIEW_HEADING = re.compile(
    r"(?i).*\b(?:security (?:service )?reviews?|new security (?:services?|features?)"
    r"|security roadmap)\b.*"
)


def threat_model(repo_path: Path) -> str | None:
    """A file named for a threat model, or a note with a threat model heading."""
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        rel = "/".join(parts).lower()
        if not _in_test_dir(parts) and _THREAT_MODEL_PATH.search(rel):
            return "/".join(parts)
    for rel, text in note_texts(repo_path):
        if any(_THREAT_MODEL_HEADING.fullmatch(h.group(2).strip()) for h in _HEADING.finditer(text)):
            return rel
    return None


def security_service_review(repo_path: Path) -> str | None:
    """Access Analyzer or Inspector in the IaC, or a dated security review note."""
    found = _in_iac_text(repo_path, _SECURITY_SERVICE)
    if found:
        return found
    for rel, text in note_texts(repo_path):
        parts = rel.lower().split("/")
        names = [*parts[:-1], parts[-1].rsplit(".", 1)[0]]
        titled = any(_SECURITY_REVIEW_NAME.search(n) for n in names) or any(
            _SECURITY_REVIEW_HEADING.fullmatch(h.group(2).strip()) for h in _HEADING.finditer(text)
        )
        if titled and _DATE.search(text):
            return rel
    return None


class ControlObjectivesMissing(_IncidentRule):
    id = "REPO-136"
    title = "No Security Hub standard or Config conformance pack validates control objectives"
    themes = ("security-baseline",)
    recommendation = (
        "Turn the control objectives into checks that run: enable a Security Hub standard "
        "(AWS Foundational Security Best Practices, CIS) or deploy a Config conformance pack "
        "that matches your compliance requirements, and review the failed controls."
    )
    searched = (
        "the IaC for a Security Hub standards subscription and a Config conformance pack "
        "(account or organization)"
    )

    def present(self, repo_path: Path) -> str | None:
        return _in_iac_text(repo_path, _CONTROL_OBJECTIVES)


class SecurityScopeNotReduced(_IncidentRule):
    id = "REPO-137"
    title = "Security services are not centralized through a delegated administrator or controls"
    themes = ("security-baseline",)
    recommendation = (
        "Reduce what each workload team manages: designate a security account as the "
        "delegated administrator for GuardDuty, Security Hub, Inspector and Macie "
        "(aws_organizations_delegated_administrator and the *_organization_admin_account "
        "resources), or deploy preventive and detective controls with AWS Control Tower."
    )
    searched = (
        "the IaC for an Organizations delegated administrator, a service organization admin "
        "account and a Control Tower control"
    )

    def present(self, repo_path: Path) -> str | None:
        return _in_iac_text(repo_path, _DELEGATED_ADMIN)


class ThreatModelMissing(_IncidentRule):
    id = "REPO-138"
    title = "No threat model is in the repo"
    themes = ("security-baseline",)
    recommendation = (
        "Model the threats: keep a threat model in the repo (docs/threat-model.md, an OWASP "
        "Threat Dragon file or a Threagile model) that lists the assets, the trust boundaries, "
        "the threats (STRIDE) and the mitigations, and update it when the design changes."
    )
    searched = "the repo for a file named for a threat model and a note with a threat model heading"

    def present(self, repo_path: Path) -> str | None:
        return threat_model(repo_path)


class SecurityServiceReviewMissing(_IncidentRule):
    id = "REPO-139"
    title = "No IAM Access Analyzer, Inspector or dated security service review is in the repo"
    themes = ("security-baseline",)
    recommendation = (
        "Keep up with new security services: enable IAM Access Analyzer and Amazon Inspector "
        "in the IaC, or keep a dated security service review (docs/security-review-2026-03.md) "
        "that records which new AWS security services and features you evaluated and adopted."
    )
    searched = (
        "the IaC for IAM Access Analyzer and Amazon Inspector, and the notes for a dated "
        "security service review"
    )

    def present(self, repo_path: Path) -> str | None:
        return security_service_review(repo_path)


# Permissions (SEC 3): access requirements (REPO-140), continuous permission reduction
# (REPO-141), access tied to a lifecycle (REPO-142) and sharing within the organization
# (REPO-143). REPO-031 and REPO-032 answer guardrails and emergency access.
_ACCESS_NAME = re.compile(
    r"access[-_ ]?(?:requirements?|model|matrix|control[-_ ]?policy)|permissions?[-_ ]?model"
    r"|iam[-_ ]?(?:design|model|requirements?)|rbac"
)
_ACCESS_HEADING = re.compile(
    r"(?i).*\b(?:access requirements?|access model|permissions? model|access matrix"
    r"|who (?:can|needs) access)\b.*"
)
_ACCESS_ANALYZER = re.compile(
    r"AWS::AccessAnalyzer::Analyzer|resource\s+\"aws_accessanalyzer_analyzer\""
    r"|\baccessanalyzer\.(?:Cfn)?Analyzer\("
)
_ACCESS_REVIEW_NAME = re.compile(
    r"(?:access|permissions?|iam|privilege)[-_ ]?reviews?|least[-_ ]?privilege"
    r"|unused[-_ ]?access"
)
_ACCESS_REVIEW_HEADING = re.compile(
    r"(?i).*\b(?:access reviews?|permissions? reviews?|iam reviews?|least privilege"
    r"|unused access)\b.*"
)
_LONG_LIVED_IDENTITY = re.compile(
    r"[\"']?Type[\"']?\s*:\s*[\"']?AWS::IAM::(?:User|AccessKey)\b"
    r"|resource\s+\"aws_iam_(?:user|access_key)\"\s+\""
    r"|\biam\.(?:Cfn)?(?:User|AccessKey)\("
)
_RAM_SHARE = re.compile(
    r"[\"']?Type[\"']?\s*:\s*[\"']?AWS::RAM::ResourceShare\b"
    r"|resource\s+\"aws_ram_resource_share\"\s+\"|\bram\.CfnResourceShare\("
)
_RAM_ORG_ONLY = re.compile(
    r"[\"']?(?:AllowExternalPrincipals|allow_external_principals|allowExternalPrincipals)[\"']?"
    r"\s*[:=]\s*[\"']?(?:false|False)\b"
)


class AccessRequirementsMissing(_IncidentRule):
    id = "REPO-140"
    title = "No permissions boundary, per-component roles or access requirements note define access"
    themes = ("identity",)
    recommendation = (
        "Write down who and what needs access, then encode it: give each workload component "
        "its own IAM role (one role per function, task or service), cap the roles with a "
        "permissions boundary, or keep an access requirements note (docs/access-model.md) "
        "that lists each principal, the resources it reaches and why."
    )
    searched = (
        "the IaC for a permissions boundary and for two or more IAM roles, and the notes for "
        "a file or heading on access requirements or the access model"
    )

    def present(self, repo_path: Path) -> str | None:
        roles = 0
        first: str | None = None
        for rel, text in iac_texts(repo_path):
            if _BOUNDARY.search(text):
                return rel
            found = len(_ROLE_DECL.findall(text))
            if found:
                roles += found
                first = first or rel
        if roles >= 2:
            return first
        return _noted(repo_path, _ACCESS_NAME, _ACCESS_HEADING)


class PermissionsNotReduced(_IncidentRule):
    id = "REPO-141"
    title = "No IAM Access Analyzer or dated access review reduces permissions over time"
    themes = ("identity",)
    recommendation = (
        "Reduce permissions continuously: create an IAM Access Analyzer (an unused access "
        "analyzer for the organization or account) and act on its findings, or keep a dated "
        "access review note (docs/access-review-2026-03.md) that records which permissions "
        "you removed."
    )
    searched = (
        "the IaC for an IAM Access Analyzer, and the notes for a dated access or permission "
        "review"
    )

    def present(self, repo_path: Path) -> str | None:
        found = _in_iac_text(repo_path, _ACCESS_ANALYZER)
        if found:
            return found
        for rel, text in note_texts(repo_path):
            parts = rel.lower().split("/")
            names = [*parts[:-1], parts[-1].rsplit(".", 1)[0]]
            titled = any(_ACCESS_REVIEW_NAME.search(n) for n in names) or any(
                _ACCESS_REVIEW_HEADING.fullmatch(h.group(2).strip())
                for h in _HEADING.finditer(text)
            )
            if titled and _DATE.search(text):
                return rel
        return None


class LongLivedIdentity(_RepoRule):
    id = "REPO-142"
    title = "The IaC creates a long-lived IAM user or access key"
    category = "Security"
    severity = "Medium"
    themes = ("identity",)
    recommendation = (
        "Tie access to a lifecycle: give people access through IAM Identity Center (SSO) and "
        "give workloads IAM roles that the pipeline or the service assumes, so credentials "
        "expire. Remove the IAM user and access key; if one must stay, rotate the key and "
        "alarm on its age."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        for rel, text in iac_texts(repo_path):
            match = _LONG_LIVED_IDENTITY.search(text)
            if match:
                return [self._finding(
                    f"{rel} declares an IAM user or access key ({match.group(0).strip()[:60]}); "
                    "its credentials do not expire. Searched the IaC for IAM users and access "
                    "keys",
                    file=rel,
                    line=_line_of(text, match.start()),
                )]
        return []


class OrgShareOpenToExternal(_RepoRule):
    id = "REPO-143"
    title = "A RAM resource share is not limited to the organization"
    category = "Security"
    severity = "Medium"
    themes = ("identity",)
    recommendation = (
        "Share within the organization only: set AllowExternalPrincipals to false "
        "(allow_external_principals = false in Terraform) on the AWS RAM resource share and "
        "name the organization or its units as principals. Resource policies that share "
        "outside RAM need an aws:PrincipalOrgID condition, never a wildcard principal."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        for rel, text in iac_texts(repo_path):
            match = _RAM_SHARE.search(text)
            if match and not _RAM_ORG_ONLY.search(text):
                return [self._finding(
                    f"{rel} declares a RAM resource share and does not set AllowExternalPrincipals "
                    "to false, so the share can reach principals outside the organization "
                    "(the default is true)",
                    file=rel,
                    line=_line_of(text, match.start()),
                )]
        return []


# Compute protection (SEC 6): interactive access (REPO-144) and automated protection
# (REPO-145). REPO-010 answers scanning of artifacts (SEC06-BP01).
_EC2_HOST = re.compile(
    _cf_type(r"EC2::(?:Instance|LaunchTemplate)|AutoScaling::LaunchConfiguration")
    + r"|resource\s+\"aws_(?:instance|launch_template|launch_configuration)\""
    r"|\bec2\.(?:Cfn)?(?:Instance|LaunchTemplate)\(|\bautoscaling\.AutoScalingGroup\("
)
_KEY_PAIR = re.compile(
    r"[\"']?KeyName[\"']?\s*:|\bkey_name\s*=|\bkeyName\s*:|\bkey_name\s*:"
    r"|\bkey_pair\s*[=:]|\bkeyPair\s*:|\bKeyPair\.from\w+\("
)
_SESSION_MANAGER = re.compile(
    r"AmazonSSMManagedInstanceCore|AmazonSSMManagedEC2InstanceDefaultPolicy"
    r"|\bssm:StartSession\b|\bssmSessionPermissions\s*:\s*true\b"
    r"|\bssm_session_permissions\s*=\s*True\b|\bSSMManagedInstanceCore\b"
)
_SSM_BASELINE = re.compile(
    r"AWS::SSM::(?:Association|PatchBaseline)\b"
    r"|resource\s+\"aws_ssm_(?:association|patch_baseline|default_patch_baseline)\""
    r"|\bssm\.Cfn(?:Association|PatchBaseline)\("
)


class InteractiveAccessWithKeyPair(_RepoRule):
    id = "REPO-144"
    title = "EC2 instances use an SSH key pair and no Session Manager access"
    category = "Security"
    severity = "Medium"
    themes = ("identity", "network-exposure")
    recommendation = (
        "Reduce interactive access: manage instances through AWS Systems Manager Session "
        "Manager (attach AmazonSSMManagedInstanceCore to the instance role, or set "
        "ssmSessionPermissions in CDK), drop the key pair and close port 22. Session "
        "Manager logs each session to CloudTrail and S3 or CloudWatch Logs."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        keyed: tuple[str, int] | None = None
        for rel, text in iac_texts(repo_path):
            if _SESSION_MANAGER.search(text):
                return []
            if keyed is None and _EC2_HOST.search(text):
                key = _KEY_PAIR.search(text)
                if key:
                    keyed = (rel, _line_of(text, key.start()))
        if keyed is None:
            return []
        return [self._finding(
            f"{keyed[0]} gives EC2 instances an SSH key pair; searched the IaC for Session "
            "Manager access (AmazonSSMManagedInstanceCore, ssm:StartSession, "
            "ssmSessionPermissions); found none",
            file=keyed[0],
            line=keyed[1],
        )]


class ComputeProtectionNotAutomated(_RepoRule):
    id = "REPO-145"
    title = "Compute protection is not automated with Inspector or an SSM association"
    category = "Security"
    severity = "Low"
    themes = ("security-baseline",)
    recommendation = (
        "Automate compute protection: enable Amazon Inspector for EC2, ECR and Lambda (the "
        "aws_inspector2_enabler resource or an Inspector2 Enable custom resource), and "
        "apply the hardening baseline with an SSM State Manager association or a patch "
        "baseline so every instance is configured and patched without a person."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute:
            return []
        if _in_iac_text(repo_path, _INSPECTOR) or _in_iac_text(repo_path, _SSM_BASELINE):
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for Amazon Inspector enablement and "
            "for an SSM association or patch baseline; found none",
            file=next(iter(compute.values())),
        )]


# Data lifecycle (SEC 7): classified data with no retention rule (REPO-146). REPO-039 and
# REPO-040 answer the classification scheme and the controls it implies.
_RETENTION = re.compile(
    r"LifecycleConfiguration|\baws_s3_bucket_lifecycle_configuration\b|\blifecycle_rule\b"
    r"|\blifecycle_?[rR]ules\b|\blifecycleConfiguration\b"
    r"|TimeToLiveSpecification|\btime_to_live_attribute\b|\btimeToLiveAttribute\b"
    r"|\bttl\s*\{|\bttl\s*=\s*\{"
    r"|[\"']?BackupRetentionPeriod[\"']?\s*:|\bbackup_retention_period\b|\bbackupRetention\b"
    r"|\bRetentionInDays\b|\bretention_in_days\b|\bretentionPeriod\b|\bretention_period\b"
    r"|\bDeleteAfterDays\b|\bdelete_after\b|\bdeleteAfter\b"
)


class ClassifiedDataWithoutLifecycle(_RepoRule):
    id = "REPO-146"
    title = "Data classified by tag has no lifecycle or retention rule"
    category = "Security"
    severity = "Low"
    themes = ("data-protection",)
    recommendation = (
        "Manage the data's lifecycle at scale: give each classified store a retention rule "
        "that follows its class (an S3 lifecycle rule that expires or transitions objects, a "
        "DynamoDB TTL attribute, database backup retention, an AWS Backup plan with "
        "DeleteAfterDays), so data is deleted when its purpose ends."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        app = _app_classified(repo_path)
        found: List[str] = []
        for rel, text in iac_texts(repo_path):
            kinds = [name for name, pattern in _DATA_STORES if pattern.search(text)]
            if not kinds or _RETENTION.search(text):
                continue
            if app or _CLASS_TAG.search(text):
                found.append(f"{kinds[0]} in {rel}")
        if not found:
            return []
        return [self._finding(
            f"Declares classified data in {_listed(found)} with no retention rule; searched for "
            "an S3 lifecycle rule, a DynamoDB TTL, database backup retention and an AWS "
            "Backup delete-after setting",
            file=found[0].rsplit(" in ", 1)[-1],
        )]


# Monitoring scope (REL 6): a dated record of what the alarms cover (REPO-147). REPO-045 to
# REPO-048 answer the metrics, the log analysis, the automated response and the traces.
_MONITORING_REVIEW_NAME = re.compile(
    r"(?:monitoring|alarms?|alerting|observability)[-_ ]?(?:review|scope|coverage|inventory)"
)
_MONITORING_REVIEW_HEADING = re.compile(
    r"(?i).*\b(?:monitoring|alarm|alerting|observability) (?:review|scope|coverage|inventory)\b.*"
)


def monitoring_review(repo_path: Path) -> str | None:
    """A dated note on the scope of monitoring: file name or heading, and a date."""
    for rel, text in note_texts(repo_path):
        parts = rel.lower().split("/")
        names = [*parts[:-1], parts[-1].rsplit(".", 1)[0]]
        titled = any(_MONITORING_REVIEW_NAME.search(n) for n in names) or any(
            _MONITORING_REVIEW_HEADING.fullmatch(h.group(2).strip())
            for h in _HEADING.finditer(text)
        )
        if titled and _DATE.search(text):
            return rel
    return None


class MonitoringScopeNotReviewed(_RepoRule):
    id = "REPO-147"
    title = "No dated review record lists the stateful resources and their alarms"
    category = "Reliability"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Review the monitoring scope on a schedule: keep a dated note "
        "(docs/monitoring-review-2026-03.md) that lists each stateful resource, the alarms "
        "that watch it, what changed since the last review and which gaps you accepted."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        stores = _in_iac(repo_path, _DATA_STORES)
        if not stores or monitoring_review(repo_path):
            return []
        return [self._finding(
            f"Declares {_named(stores)}; searched the notes for a dated monitoring or alarm "
            "review (a file or heading named for a monitoring review, scope, coverage or "
            "inventory); found none",
        )]


# Recovery on the data plane (REL 11): a lone instance has no health check, scaling group or
# target group to replace it (REPO-149). REPO-057 to REPO-059 answer health checks, failover
# and healing.
_EC2_INSTANCE = re.compile(
    _cf_type(r"EC2::Instance") + r"|resource\s+\"aws_instance\""
    r"|\bec2\.(?:Cfn)?Instance\("
)
_DATA_PLANE_RECOVERY = re.compile(
    _cf_type(r"AutoScaling::AutoScalingGroup|Route53::HealthCheck"
             r"|ElasticLoadBalancingV2::TargetGroup")
    + r"|resource\s+\"aws_(?:autoscaling_group|route53_health_check|lb_target_group"
    r"|alb_target_group)\""
    r"|\bautoscaling\.(?:Cfn)?AutoScalingGroup\(|\broute53\.CfnHealthCheck\("
    r"|\b(?:Application|Network)TargetGroup\(|\belbv2\.Cfn\w*TargetGroup\("
    r"|\bec2\.Instance\([^)]*\bautoRecovery\b|\brecovery[-_ ]?alarm\b"
    r"|\bec2:recover\b|\bautomate:[\w-]+:recover\b"
)


class ControlPlaneOnlyRecovery(_RepoRule):
    id = "REPO-149"
    title = "A lone EC2 instance has no data plane recovery"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Recover on the data plane: run instances in an Auto Scaling group behind a target "
        "group with health checks, or add a Route 53 health check with failover, so a failed "
        "instance is replaced without anyone calling a control plane API (a pipeline run, "
        "RunInstances or a console action) in the middle of the incident."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        instance = _in_iac_text(repo_path, _EC2_INSTANCE)
        if not instance or _in_iac_text(repo_path, _DATA_PLANE_RECOVERY):
            return []
        return [self._finding(
            f"{instance} runs an EC2 instance on its own; searched the IaC for an Auto Scaling "
            "group, a load balancer target group, a Route 53 health check and an instance "
            "recovery alarm; found none",
            file=instance,
        )]


# Accelerators (SUS 5): accelerator instances with no utilization alarm or batch window
# (REPO-150). REPO-062 answers the same instances for PERF 2.
_BATCH_WINDOW = re.compile(
    r"ScheduledAction|\baws_autoscaling_schedule\b|\bscheduled_action\b|\bscaleOnSchedule\("
    r"|\bscale_on_schedule\("
    r"|AWS::Scheduler::Schedule|\baws_scheduler_schedule\b"
    r"|[\"']?ScheduleExpression[\"']?\s*:|\bschedule_expression\b"
)


class AcceleratorUtilizationUnchecked(_RepoRule):
    id = "REPO-150"
    title = "Accelerator instances have no utilization alarm or batch window"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Use accelerators only while they work: alarm on GPU or NeuronCore utilization (the "
        "CloudWatch agent with nvidia_gpu, or DCGM) and scale in when it is low, or run the "
        "capacity on a schedule that matches the batch window so it is released when the "
        "jobs end."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = accelerators(repo_path)
        if not found or accelerator_alarm(repo_path):
            return []
        if _in_iac_text(repo_path, _BATCH_WINDOW):
            return []
        places = [f"{kind} in {rel}" for kind, rel in found.items()]
        return [self._finding(
            f"Runs accelerated instances ({_listed(places, 4)}); searched the IaC for an alarm "
            "on a GPU or Neuron core utilization metric, a scheduled scaling action and a "
            "schedule; found none",
            file=next(iter(found.values())),
        )]


# Data management (SUS 4): a classification tag (REPO-151), data that is not tied to an
# instance store (REPO-152), block storage that grows (REPO-153), data that is deleted
# (REPO-154), common data on shared storage (REPO-155) and no backup of what is cheap to
# recreate (REPO-156). SUS04-BP03 and BP07 are answered by REL-018, CF-EFS-003 and SUST-006. REPO-154 answers
# SUS04-BP05 for S3 with the same fact as COST-013, because a rule maps to one question.
_INSTANCE_STORE = re.compile(
    r"\bephemeral\d\b|[\"']?VirtualName[\"']?\s*:\s*[\"']?ephemeral|\bvirtual_name\s*=\s*\"ephemeral"
    r"|\b(?:i3(?:en)?|i4[a-z]+|im4gn|is4gen|d3(?:en)?|d2|[mcrzx]\d+[a-z]*d[a-z]*)"
    r"\.(?:\d*x?large|\d+xlarge|metal|medium)\b"
)
_PERSISTENT_STORE = re.compile(
    _cf_type(r"EFS::FileSystem|FSx::FileSystem|S3::Bucket|DynamoDB::(?:Global)?Table"
             r"|RDS::DB(?:Instance|Cluster)|EC2::Volume")
    + r"|resource\s+\"aws_(?:efs_file_system|fsx_\w+|s3_bucket|dynamodb_table|db_instance"
    r"|rds_cluster|ebs_volume)\""
    r"|\b(?:efs|fsx|s3|dynamodb|rds)\.(?:Cfn)?\w+\(|\bec2\.(?:Cfn)?Volume\("
)
_VOLUME_DECL = _EBS_VOLUME
_VOLUME_SIZE = re.compile(
    r"(?<![A-Za-z])[\"']?(?:Size|VolumeSize)[\"']?\s*:\s*[\"']?(\d+)|\b(?:size|volume_size)\s*=\s*(\d+)"
    r"|\b(?:size|volumeSize)\s*[:=]\s*(?:\w+\.)?Size\.gibibytes\((\d+)\)"
)
_VOLUME_GROWS = re.compile(
    r"ebs[-_]autoscale|\bModifyVolume\b|\bmodify-volume\b|\bresize2fs\b|\bgrowpart\b"
    r"|\bxfs_growfs\b|\bElasticVolumes\b"
)
_LARGE_VOLUME_GIB = 500
_SHARED_STORAGE = re.compile(
    _cf_type(r"EFS::FileSystem|FSx::FileSystem|S3::Bucket")
    + r"|resource\s+\"aws_(?:efs_file_system|fsx_\w+|s3_bucket)\""
    r"|\b(?:efs|fsx|s3)\.(?:Cfn)?\w+\("
)
_BACKUP_SELECTION = re.compile(
    _cf_type(r"Backup::BackupSelection") + r"|resource\s+\"aws_backup_selection\""
    r"|\bbackup\.(?:Cfn)?BackupSelection\(|\bplan\.addSelection\(|\bplan\.add_selection\("
    r"|\bBackupResource\.from\w+\("
)
_RECREATABLE = re.compile(
    _cf_type(r"ElastiCache::(?:CacheCluster|ReplicationGroup|ServerlessCache)")
    + r"|resource\s+\"aws_elasticache_(?:cluster|replication_group|serverless_cache)\""
    r"|\belasticache\.Cfn(?:CacheCluster|ReplicationGroup|ServerlessCache)\("
    r"|\b(?:Bucket|bucket|BucketName|bucket_name|aws_s3_bucket\"\s+\")[\"']?\s*[:=(,]?\s*"
    r"[\"']?[\w.${}-]*?(?<![a-z])(?:tmp|temp|scratch|cache)(?![a-z])[\w.${}-]*",
    re.IGNORECASE,
)


class DataClassificationForSustainability(DataClassificationMissing):
    """The REPO-039 search, answering SUS04-BP01 for the question on data management."""

    id = "REPO-151"
    title = "Data stores carry no classification tag to drive retention and storage tiers"
    themes = ("sustainability",)
    recommendation = (
        "Classify the data so the footprint follows its value: tag every data store with its "
        "class (DataClassification = public, internal, confidential or restricted), or tag "
        "the whole app (CDK Tags.of(app), Terraform provider default_tags), and let the class "
        "choose the retention, the storage tier and whether the data is backed up."
    )


class InstanceStoreOnlyData(_RepoRule):
    id = "REPO-152"
    title = "Instances keep their data on instance store with no durable store behind it"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "resilience")
    recommendation = (
        "Match the store to the access pattern: keep data that must last on a durable store "
        "(S3, EFS, EBS, DynamoDB or a database) and use instance store only as scratch space "
        "for data you can rebuild, so you do not copy or keep the same data on every host."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found: str | None = None
        for rel, text in iac_texts(repo_path):
            if _PERSISTENT_STORE.search(text):
                return []
            if found is None and _INSTANCE_STORE.search(text):
                found = rel
        if found is None:
            return []
        return [self._finding(
            f"{found} gives instances an instance store (an ephemeral device mapping or a "
            "storage-optimized or NVMe instance type); searched the IaC for S3, EFS, FSx, "
            "EBS, DynamoDB and a database; found none",
            file=found,
        )]


class BlockStorageFixedAndLarge(_RepoRule):
    id = "REPO-153"
    title = "A large EBS volume is a fixed size with nothing to grow it"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Provision the storage the data needs today and grow it with demand: start the EBS "
        "volume small and expand it with Elastic Volumes (ModifyVolume, or the amazon-ebs-"
        "autoscale script) when it fills, or use EFS, which grows by itself, instead of "
        "reserving a large volume up front."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found: tuple[str, int] | None = None
        for rel, text in iac_texts(repo_path):
            if _VOLUME_GROWS.search(text):
                return []
            if found is not None or not _VOLUME_DECL.search(text):
                continue
            for match in _VOLUME_SIZE.finditer(text):
                size = int(next(g for g in match.groups() if g))
                if size >= _LARGE_VOLUME_GIB:
                    found = (rel, size)
                    break
        if found is None:
            return []
        return [self._finding(
            f"{found[0]} declares an EBS volume of {found[1]} GiB; searched the IaC for "
            "Elastic Volumes (ModifyVolume), an EBS autoscaling script and a file system "
            "grow command; found none",
            file=found[0],
        )]


class UnneededDataNotDeleted(_RepoRule):
    id = "REPO-154"
    title = "S3 buckets have no rule that deletes unneeded data"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Delete what nobody needs: give each S3 bucket a lifecycle rule that expires old "
        "objects and incomplete multipart uploads, so data does not accumulate and keep "
        "consuming storage."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        for rel, text in iac_texts(repo_path):
            if _DATA_STORES[0][1].search(text) and not _RETENTION.search(text):
                return [self._finding(
                    f"{rel} declares an S3 bucket and sets no lifecycle expiration or "
                    "retention; searched the file for an S3 lifecycle rule, a DynamoDB TTL, a log "
                    "retention period and a backup delete-after; found none",
                )]
        return []


class CommonDataCopiedPerInstance(_RepoRule):
    id = "REPO-155"
    title = "Several EBS volumes hold data and no shared file system or bucket does"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Store common data once: put data that several instances read on EFS, FSx or S3 and "
        "mount or fetch it, instead of attaching an EBS volume with its own copy to each "
        "instance."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        volumes: List[str] = []
        for rel, text in iac_texts(repo_path):
            if _SHARED_STORAGE.search(text):
                return []
            volumes.extend(rel for _ in _VOLUME_DECL.finditer(text))
        if len(volumes) < 2:
            return []
        return [self._finding(
            f"Declares {len(volumes)} EBS volumes ({_listed(sorted(set(volumes)))}); searched "
            "the IaC for an EFS or FSx file system and an S3 bucket for common data; found none",
            file=volumes[0],
        )]


class RecreatableDataBackedUp(_RepoRule):
    id = "REPO-156"
    title = "A backup plan covers a cache or a temporary bucket"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Back up only what is hard to recreate: take the cache cluster and the temporary or "
        "scratch bucket out of the AWS Backup selection, or select resources by a tag that "
        "only durable data carries."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        for rel, text in iac_texts(repo_path):
            if not _BACKUP_SELECTION.search(text):
                continue
            match = _RECREATABLE.search(text)
            if match:
                return [self._finding(
                    f"{rel} selects resources for AWS Backup and declares a cache or a "
                    f"temporary bucket ({match.group(0).strip()[:50]}) that is cheap to "
                    "recreate",
                    file=rel,
                    line=_line_of(text, match.start()),
                )]
        return []


# Operations health (OPS 9): an operations metric (REPO-157), status for operators (REPO-158)
# and a dated review of the operations metrics (REPO-159). REPO-018 answers the workload KPIs.
_OPS_METRIC = re.compile(
    r"Deployment(?:Count|Frequency)|\bDeploy(?:Count|Frequency)\b|\bdeploy_(?:count|frequency)\b"
    r"|ChangeFailureRate|LeadTimeForChanges|MeanTimeTo(?:Recover|Restore)|\bMTT[RD]\b"
    r"|[Ee]rror[-_ ]?[Bb]udget|[Bb]urn[-_ ]?[Rr]ate|\bAlarmCount\b|\bServiceLevelObjective\b"
    r"|AWS::ApplicationSignals::ServiceLevelObjective|\baws_applicationsignals_\w+"
    r"|\bdora[-_ ]?metrics?\b"
)
_OPS_REVIEW_NAME = re.compile(
    r"(?:operations?|operational|ops)[-_ ]?(?:review|metrics|health|report)"
    r"|(?:weekly|monthly)[-_ ]?ops|retrospective|\bretro\b"
)
_OPS_REVIEW_HEADING = re.compile(
    r"(?i).*\b(?:operations? (?:review|metrics|health|report)|operational review"
    r"|ops (?:review|metrics)|retrospective)\b.*"
)


class OpsMetricsMissing(_IncidentRule):
    id = "REPO-157"
    title = "No operations metric (deploys, alarms, error budget) is measured"
    category = "Operational Excellence"
    themes = ("observability",)
    recommendation = (
        "Measure how operations are doing, not only the workload: publish a metric for "
        "deployments (a DeploymentCount or the DORA metrics from the pipeline), the alarm "
        "count or time to recover, and define an SLO with an error budget (CloudWatch "
        "Application Signals service level objective)."
    )
    searched = (
        "the IaC and the build configs for a deployment, change failure, recovery time, alarm "
        "count, error budget, burn rate or service level objective metric"
    )

    def present(self, repo_path: Path) -> str | None:
        found = _in_iac_text(repo_path, _OPS_METRIC)
        if found:
            return found
        for rel, text in sorted(build_texts(repo_path)):
            if _OPS_METRIC.search(text):
                return rel
        return None


class OperatorStatusMissing(_RepoRule):
    id = "REPO-158"
    title = "No dashboard or status topic shows operations status to operators"
    category = "Operational Excellence"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Make operations status visible: add a CloudWatch dashboard with the alarms, "
        "deployments and trends operators watch, or an SNS topic that posts status to the "
        "operators' channel, and keep it where the team already looks."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        alarms, _plans = event_signals(repo_path)
        if not alarms:
            return []
        for _rel, text in iac_texts(repo_path):
            if _DASHBOARD.search(text) or (
                _MESSAGING.search(text) and _CUSTOMER_CHANNEL.search(text)
            ):
                return []
        return [self._finding(
            f"The IaC declares CloudWatch alarms ({_listed(alarms)}); searched it for a "
            "CloudWatch dashboard and for an SNS, SES or Pinpoint resource that names a "
            "status, customer or subscriber channel; found none",
            file=alarms[0],
        )]


class OpsReviewMissing(_IncidentRule):
    id = "REPO-159"
    title = "No dated review of the operations metrics is in the repo"
    category = "Operational Excellence"
    themes = ("observability",)
    recommendation = (
        "Review the operations metrics on a schedule: keep a dated operations review "
        "(docs/ops-review-2026-03.md) that lists the metrics, the trend, what you decided "
        "to improve and who owns it, and run it weekly or monthly."
    )
    searched = (
        "the notes for a dated file or heading named for an operations review, report, "
        "metrics, health or retrospective"
    )

    def present(self, repo_path: Path) -> str | None:
        for rel, text in note_texts(repo_path):
            parts = rel.lower().split("/")
            names = [*parts[:-1], parts[-1].rsplit(".", 1)[0]]
            titled = any(_OPS_REVIEW_NAME.search(n) for n in names) or any(
                _OPS_REVIEW_HEADING.fullmatch(h.group(2).strip())
                for h in _HEADING.finditer(text)
            )
            if titled and _DATE.search(text):
                return rel
        return None


# Cost of effort (COST 11): instances run by hand (REPO-160). REPO-002 answers the pipeline,
# REPO-145 the SSM baseline for SEC 6.
_SSM_OPERATIONS = re.compile(
    _SSM_BASELINE.pattern
    + r"|AWS::SSM::(?:MaintenanceWindow|Document)\b"
    r"|resource\s+\"aws_ssm_(?:maintenance_window|document)\""
    r"|\bssm\.Cfn(?:MaintenanceWindow|Document)\("
)


class OperationsNotAutomated(_RepoRule):
    id = "REPO-160"
    title = "EC2 instances have no SSM association and no pipeline automates operations"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Spend less effort on routine work: manage instances with Systems Manager (a State "
        "Manager association, a maintenance window or an Automation runbook) and deploy and "
        "change them from a pipeline, so patching, configuration and releases do not need a "
        "person logged in."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        hosts = _in_iac_text(repo_path, _EC2_HOST)
        if not hosts or _in_iac_text(repo_path, _SSM_OPERATIONS):
            return []
        if not RepoPipelineMissing().run(repo_path):
            return []
        return [self._finding(
            f"{hosts} runs EC2 instances; searched the IaC for an SSM association, patch "
            "baseline, maintenance window or Automation document, and the repo for a CI "
            "workflow or pipeline; found none",
            file=hosts,
        )]


# Priorities (OPS 1): the customers a workload serves (REPO-161), the governance and
# compliance controls it follows (REPO-162), the threats it faces (REPO-163) and the
# tradeoffs it recorded (REPO-164).


def _note_having(
    repo_path: Path, name: re.Pattern[str], heading: re.Pattern[str],
    needs: re.Pattern[str] | None = None,
) -> str | None:
    """The first note named or headed for a topic whose text also matches needs."""
    for rel, text in note_texts(repo_path):
        parts = rel.lower().split("/")
        names = [*parts[:-1], parts[-1].rsplit(".", 1)[0]]
        titled = any(name.search(part) for part in names) or any(
            heading.fullmatch(h.group(2).strip()) for h in _HEADING.finditer(text)
        )
        if titled and (needs is None or needs.search(text)):
            return rel
    return None


class _NoteRule(_IncidentRule):
    """An operations rule that fires on a repo that holds IaC when no note, and no IaC
    resource, answers the practice."""

    category = "Operational Excellence"
    themes = ("observability",)
    note_name: ClassVar[re.Pattern[str]]
    note_heading: ClassVar[re.Pattern[str]]
    note_needs: ClassVar[re.Pattern[str] | None] = None
    iac: ClassVar[re.Pattern[str] | None] = None

    def present(self, repo_path: Path) -> str | None:
        found = _in_iac_text(repo_path, self.iac) if self.iac else None
        return found or _note_having(
            repo_path, self.note_name, self.note_heading, self.note_needs
        )


class CustomerNeedsMissing(_NoteRule):
    id = "REPO-161"
    title = "No note names the external and internal customers the workload serves"
    note_name = re.compile(
        r"customers?|stakeholders?|personas?|user[-_ ]?needs|business[-_ ]?(?:goals|priorities)"
    )
    note_heading = re.compile(
        r"(?i).*\b(?:customers?|stakeholders?|personas?|users and needs|business priorities"
        r"|business goals|requirements)\b.*"
    )
    recommendation = (
        "Write down who the workload is for: a customers note (docs/customers.md or a "
        "Stakeholders section in the README) that names the external customers, the internal "
        "customers and teams, what each needs and which need comes first when they conflict."
    )
    searched = (
        "the notes for a file or heading on customers, stakeholders, personas, user needs, "
        "business goals or requirements"
    )


_GOVERNANCE_IN_IAC = re.compile(
    _cf_type(r"Config::(?:Organization)?ConformancePack")
    + r"|" + _cf_type(r"SecurityHub::Standard") + r"|" + _cf_type(r"Organizations::Policy")
    + r"|resource\s+\"aws_(?:config_(?:organization_)?conformance_pack|organizations_policy"
    r"|securityhub_standards_subscription)\""
    r"|\b(?:config\.Cfn(?:Organization)?ConformancePack|securityhub\.CfnStandard"
    r"|organizations\.CfnPolicy)\("
)


class GovernanceControlsMissing(_NoteRule):
    id = "REPO-162"
    title = "No conformance pack, Security Hub standard, SCP or compliance note names the controls"
    category = "Operational Excellence"
    note_name = re.compile(
        r"compliance|governance|regulat(?:ion|ory)|standards?|controls?[-_ ]?framework"
        r"|soc[-_ ]?2|pci|hipaa|gdpr|iso[-_ ]?27001"
    )
    note_heading = re.compile(
        r"(?i).*\b(?:compliance|governance|regulatory|regulations?|standards? we follow"
        r"|control framework|soc ?2|pci[- ]dss|hipaa|gdpr|iso ?27001)\b.*"
    )
    iac = _GOVERNANCE_IN_IAC
    recommendation = (
        "Make the rules the workload must follow explicit: define an AWS Config conformance "
        "pack, a Security Hub standards subscription or a service control policy in the IaC "
        "(this runs with rules.org, because these are usually account-level), or keep a "
        "compliance note that names the standard (PCI DSS, SOC 2, HIPAA, GDPR, ISO 27001) and "
        "the controls that answer it."
    )
    searched = (
        "the IaC for a Config conformance pack, a Security Hub standard or an Organizations "
        "policy, and the notes for a file or heading on compliance, governance or a standard"
    )


_THREAT_IN_IAC = re.compile(
    _cf_type(r"GuardDuty::Detector") + r"|" + _cf_type(r"SecurityHub::Hub")
    + r"|resource\s+\"aws_(?:guardduty_detector|securityhub_account)\""
    r"|\b(?:guardduty\.CfnDetector|securityhub\.CfnHub)\("
)


class ThreatLandscapeMissing(_NoteRule):
    id = "REPO-163"
    title = "Neither GuardDuty, Security Hub nor a threat model covers the threats to the workload"
    category = "Operational Excellence"
    themes = ("security-baseline",)
    note_name = re.compile(r"threat[-_ ]?(?:model|landscape|analysis|assessment)s?")
    note_heading = re.compile(
        r"(?i).*\b(?:threat (?:model|landscape|analysis|assessment)s?|threats?)\b.*"
    )
    iac = _THREAT_IN_IAC
    recommendation = (
        "Evaluate what threatens the workload: enable GuardDuty or Security Hub in the IaC "
        "(this runs with rules.org, because these are usually account-level), or keep a "
        "threat model note (docs/threat-model.md) that lists the assets, the threats to them "
        "and the controls against each."
    )
    searched = (
        "the IaC for a GuardDuty detector or a Security Hub hub, and the notes for a file or "
        "heading on a threat model or the threat landscape"
    )


class TradeoffsUnrecorded(_NoteRule):
    id = "REPO-164"
    title = "No architecture decision record weighs a tradeoff"
    note_name = re.compile(
        r"adrs?|decision[-_ ]?records?|architecture[-_ ]?decisions?|decisions?|tradeoffs?"
    )
    note_heading = re.compile(
        r"(?i).*\b(?:decision records?|architecture decisions?|trade-?offs?)\b.*"
    )
    note_needs = re.compile(
        r"(?i)\b(?:trade-?offs?|consequences|alternatives? considered|pros and cons|risks?)\b"
    )
    recommendation = (
        "Record decisions with their tradeoffs: keep an architecture decision record per "
        "choice (docs/adr/0001-queue-or-stream.md) that states the options, the benefit and "
        "the risk of each, and why you took this one."
    )
    searched = (
        "the notes for an architecture decision record, in a file, a folder or a heading, "
        "that names a tradeoff, a consequence, an alternative or a risk"
    )


# Ownership (OPS 2): who owns procedures (REPO-165), operations activities (REPO-166), the
# ownership mechanism (REPO-167) and the way to ask for a change or an exception (REPO-168).
_PROCEDURE_NAME = re.compile(
    r"run[-_ ]?books?|playbooks?|procedures?|sops?(?:$|[-_ .])|standard[-_ ]operating"
    r"|operations?[-_ ]?guide|how[-_ ]?to"
)
_PROCEDURE_HEADING = re.compile(
    r"(?i).*\b(?:run-?books?|playbooks?|procedures?|standard operating procedures?)\b.*"
)


class ProcedureOwnerMissing(_NoteRule):
    id = "REPO-165"
    title = "No runbook, playbook or procedure names an owner"
    note_name = _PROCEDURE_NAME
    note_heading = _PROCEDURE_HEADING
    recommendation = (
        "Give each procedure an owner: put an Owner line (a team or a person) at the top of "
        "every runbook, playbook and procedure note, so someone keeps it current and answers "
        "for it."
    )
    searched = (
        "the notes named or headed for a runbook, playbook or procedure for an Owner, "
        "Contact or Responsible line that names a team or a person"
    )

    def present(self, repo_path: Path) -> str | None:
        for rel, text in note_texts(repo_path):
            parts = rel.lower().split("/")
            names = [*parts[:-1], parts[-1].rsplit(".", 1)[0]]
            titled = any(_PROCEDURE_NAME.search(n) for n in names) or any(
                _PROCEDURE_HEADING.fullmatch(h.group(2).strip()) for h in _HEADING.finditer(text)
            )
            if titled and _names_owner(text):
                return rel
        return None


class ActivityOwnerMissing(KeyContactsMissing):
    """The same search as REPO-125, answering OPS02-BP03 for the question on structure."""

    id = "REPO-166"
    title = "No Incident Manager contact or note names who owns operations activities"
    category = "Operational Excellence"
    themes = ("observability",)
    recommendation = (
        "Name who performs each operations activity: define Incident Manager contacts and an "
        "engagement plan (AWS::SSMContacts::Contact and Plan), or keep an on-call note that "
        "says which team patches, restores, responds and approves changes."
    )


_OWNERSHIP_NAME = re.compile(
    r"owners?(?:hip)?|responsibilit(?:y|ies)|raci|team[-_ ]?agreements?|working[-_ ]?agreements?"
)
_OWNERSHIP_HEADING = re.compile(
    r"(?i).*\b(?:ownership|owners|responsibilit(?:y|ies)|raci|who owns|team agreements?)\b.*"
)


class OwnershipMechanismMissing(_NoteRule):
    id = "REPO-167"
    title = "No CODEOWNERS file, escalation plan or ownership note says who owns what"
    note_name = _OWNERSHIP_NAME
    note_heading = _OWNERSHIP_HEADING
    recommendation = (
        "Keep ownership where it can be changed: add a CODEOWNERS file with an owner for each "
        "path, or an Incident Manager escalation plan, or an ownership note that lists who "
        "owns each stack and how a team hands one over. A repo that one team owns says so."
    )
    searched = (
        "the repo for a CODEOWNERS file with an owner, the IaC for an Incident Manager "
        "contact or plan, and the notes for a file or heading on ownership or responsibilities"
    )

    def present(self, repo_path: Path) -> str | None:
        for rel, lines in _codeowners(repo_path):
            if lines:
                return rel
        return (_in_iac_text(repo_path, _CONTACTS_IN_IAC)
                or _note_having(repo_path, self.note_name, self.note_heading))


_CHANGE_REQUEST = re.compile(
    r"\bpull_request(?:_target)?\b|\bmerge_requests?\b|ManualApprovalAction|\bmanual_approval\b"
    r"|Category[\"']?\s*[:=]\s*[\"']?Approval\b|\bcategory\s*=\s*\"Approval\""
    r"|\bapprovals?\.ManualApproval\b|\bIssueTemplates?\b"
)
_REQUEST_TEMPLATES = (".github/pull_request_template", ".github/issue_template",
                      ".gitlab/merge_request_templates", ".gitlab/issue_templates")


class ChangeRequestPathMissing(_RepoRule):
    id = "REPO-168"
    title = "No pull request check, manual approval or request template shows how to ask for a change"
    category = "Operational Excellence"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Give people one way to ask for an addition, a change or an exception: run a CI "
        "check on pull requests, add a manual approval action to the pipeline, or keep an "
        "issue or pull request template that says what to include and who approves."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held:
            return []
        for _rel, text in build_texts(repo_path):
            if _CHANGE_REQUEST.search(text):
                return []
        for rel, text in iac_texts(repo_path):
            if _CHANGE_REQUEST.search(text):
                return []
        for path in walk(repo_path):
            rel = "/".join(_rel_parts(path, repo_path)).lower()
            if rel.startswith(_REQUEST_TEMPLATES):
                return []
        return [self._finding(
            f"Holds IaC ({held}); searched the CI configs and the IaC for a pull request "
            "trigger, a merge request or a CodePipeline manual approval, and the repo for an "
            "issue or pull request template; found none"
        )]


# Culture (OPS 3): escalation (REPO-169), the operator channel (REPO-170) and one note that
# says how the team is sponsored, empowered, trained and staffed (REPO-171).
_ESCALATION_IN_IAC = re.compile(
    _cf_type(r"SSMContacts::Plan") + r"|resource\s+\"aws_ssmcontacts_plan\""
    r"|\bssmcontacts\.CfnPlan\(|" + _RESPONSE_PLAN.pattern
)
_ESCALATION_NAME = re.compile(r"escalat(?:e|es|ion|ions)")
_ESCALATION_HEADING = re.compile(r"(?i).*\b(?:escalat(?:e|es|ion|ions)|escalation path)\b.*")


class EscalationMissing(_NoteRule):
    id = "REPO-169"
    title = "No escalation plan or note says who to turn to when the first responder cannot fix it"
    note_name = _ESCALATION_NAME
    note_heading = _ESCALATION_HEADING
    iac = _ESCALATION_IN_IAC
    recommendation = (
        "Make escalation normal: define an Incident Manager engagement plan with a second "
        "stage (AWS::SSMContacts::Plan), or keep an escalation note that says after how long "
        "and to whom an alarm moves up, and that asking for help early is expected."
    )
    searched = (
        "the IaC for an Incident Manager plan or response plan, and the notes for a file or "
        "heading on escalation"
    )


_CHANNEL_IN_IAC = re.compile(
    _cf_type(r"Chatbot::\w+|SSMContacts::Rotation|SNS::Subscription")
    + r"|resource\s+\"aws_(?:chatbot_\w+|ssmcontacts_rotation|sns_topic_subscription)\""
    r"|\b(?:chatbot\.\w+|ssmcontacts\.CfnRotation|sns\.Subscription|subs\.\w+Subscription)\("
    r"|\.addSubscription\(|\.add_subscription\("
)
_CHANNEL_NAME = re.compile(
    r"on[-_ ]?call|communications?|comms|channels?|alerting|notifications?|paging|pager"
)
_CHANNEL_HEADING = re.compile(
    r"(?i).*\b(?:on-?call|communications?|alerting|notifications?|paging|status updates?"
    r"|operator channel)\b.*"
)


class OperatorChannelMissing(_NoteRule):
    id = "REPO-170"
    title = "No chat channel, subscription, on-call schedule or note tells operators what is wrong"
    note_name = _CHANNEL_NAME
    note_heading = _CHANNEL_HEADING
    iac = _CHANNEL_IN_IAC
    recommendation = (
        "Tell the operators in a place they watch: subscribe the team to the alarm topic, "
        "send alarms to chat with AWS Chatbot, and define an on-call rotation "
        "(AWS::SSMContacts::Rotation), or keep a note that names the channel and says what an "
        "alert must contain to be actionable."
    )
    searched = (
        "the IaC for an SNS subscription, an AWS Chatbot channel or an on-call rotation, and "
        "the notes for a file or heading on on-call, alerting, notifications or communications"
    )


_CULTURE_NAME = re.compile(
    r"ops[-_ ]?(?:ownership|culture|model)|operations?[-_ ]?(?:ownership|culture|model)"
    r"|team[-_ ]?(?:culture|charter|norms|health)|culture|sponsor(?:ship)?|charter"
)
_CULTURE_HEADING = re.compile(
    r"(?i).*\b(?:culture|executive sponsor(?:ship)?|sponsor(?:ship)?|team charter"
    r"|operating model|team norms|skills and training|team (?:growth|staffing))\b.*"
)


class OperationsCultureMissing(_NoteRule):
    id = "REPO-171"
    title = "No ownership note says how the team is sponsored, empowered, trained and staffed"
    note_name = _CULTURE_NAME
    note_heading = _CULTURE_HEADING
    recommendation = (
        "Write one operations ownership note (docs/ops-ownership.md) that names the executive "
        "sponsor, what the team may do on its own when an outcome is at risk, how it "
        "experiments, how people keep their skills current and how the team is staffed for "
        "the workload."
    )
    searched = (
        "the notes for a file or heading on operations ownership, culture, sponsorship, a "
        "team charter or an operating model"
    )


# Readiness (OPS 7): runbooks (REPO-172), playbooks (REPO-173), a support plan (REPO-174) and
# the operational readiness review (REPO-175).
_SSM_DOCUMENT = re.compile(
    _cf_type(r"SSM::Document") + r"|resource\s+\"aws_ssm_document\"|\bssm\.CfnDocument\("
)


class RunbooksMissing(_NoteRule):
    id = "REPO-172"
    title = "No runbook is in the repo for deploying and operating the workload"
    note_name = re.compile(r"run[-_ ]?books?|operations?[-_ ]?guide|operating[-_ ]?procedures?")
    note_heading = re.compile(
        r"(?i).*\b(?:run-?books?|operations? guide|operating procedures?)\b.*"
    )
    iac = _SSM_DOCUMENT
    recommendation = (
        "Write the routine procedures down: a runbook per task (docs/runbooks/deploy.md, "
        "restore.md, rotate-keys.md) with the steps, the checks and the rollback, or an SSM "
        "Automation document that performs them."
    )
    searched = (
        "the IaC for an SSM document, and the notes for a file, folder or heading on a runbook "
        "or an operations guide"
    )


class OperationalPlaybooksMissing(FailurePlaybookMissing):
    """The same search as REPO-122, answering OPS07-BP04 for the question on readiness."""

    id = "REPO-173"
    title = "No playbook is in the repo for investigating issues in the workload"
    category = "Operational Excellence"
    themes = ("observability",)
    recommendation = (
        "Separate investigating from doing: keep playbooks (docs/playbooks) that say how to "
        "find the cause of a symptom, with the dashboards, logs and queries to open, next to "
        "the runbooks that say how to run a procedure."
    )


class SupportPlanMissing(_NoteRule):
    id = "REPO-174"
    title = "No note or resource names the support plan for production"
    note_name = re.compile(
        r"support[-_ ]?plans?|aws[-_ ]?support|(?:business|enterprise)[-_ ]?support|support[-_ ]?cases?"
    )
    note_heading = re.compile(
        r"(?i).*\b(?:support plans?|aws support|(?:business|enterprise) support|support cases?)\b.*"
    )
    iac = re.compile(_cf_type(r"Support::\w+") + r"|resource\s+\"aws_support_\w+\"")
    recommendation = (
        "Decide what support production has: name the AWS Support plan (Business or "
        "Enterprise) in a support note, with who may open a case and the severity each kind "
        "of issue gets, and keep it with the other operations notes."
    )
    searched = (
        "the IaC for an AWS Support resource, and the notes for a file or heading on a "
        "support plan or support cases"
    )


class ReadinessReviewMissing(_NoteRule):
    id = "REPO-175"
    title = "No operational readiness checklist is in the repo"
    note_name = re.compile(
        r"readiness|orr(?:$|[-_ .])|launch[-_ ]?checklist|go[-_ ]?live|production[-_ ]?checklist"
    )
    note_heading = re.compile(
        r"(?i).*\b(?:operational readiness|readiness (?:review|checklist)|launch checklist"
        r"|go-live|production checklist)\b.*"
    )
    recommendation = (
        "Check readiness before every launch: keep an operational readiness checklist "
        "(docs/readiness.md) that asks whether the team can run the workload (people, "
        "runbooks, alarms, backups, on-call) and review it before each release to production."
    )
    searched = (
        "the notes for a file or heading on operational readiness, a launch checklist or a "
        "go-live checklist"
    )


# Evolving operations (OPS 11): lessons from incidents (REPO-176), feedback on changes
# (REPO-177) and one note on the improvement loop (REPO-178).
class PostIncidentLessonsMissing(_NoteRule):
    id = "REPO-176"
    title = "No post-incident template or review records the lessons learned"
    note_name = _POST_INCIDENT_NAME
    note_heading = _POST_INCIDENT_HEADING
    note_needs = re.compile(r"(?i)\blessons?(?:[- ]learned)?\b|\bwhat we learned\b|\baction items?\b")
    recommendation = (
        "Learn from every incident: keep a post-incident template (docs/post-incident-"
        "template.md) with the timeline, the cause, what went well, what did not, the lessons "
        "learned and the action items with owners, and share each review with the team."
    )
    searched = (
        "the notes for a post-incident file or heading that has a lessons learned or action "
        "items section"
    )


_FEEDBACK_IN_IAC = re.compile(
    _cf_type(r"CodeStarNotifications::NotificationRule")
    + r"|resource\s+\"aws_codestarnotifications_notification_rule\""
    r"|\bnotifications\.NotificationRule\(|\.notifyOn\w*\(|\.notify_on_\w+\("
)
_FEEDBACK_NAME = re.compile(r"feedback|retro(?:spective)?s?(?:$|[-_ .])|change[-_ ]?outcomes?")
_FEEDBACK_HEADING = re.compile(r"(?i).*\b(?:feedback|retrospectives?|change outcomes?)\b.*")


class FeedbackLoopMissing(_NoteRule):
    id = "REPO-177"
    title = "No issue template, pipeline notification or note records what a change did"
    note_name = _FEEDBACK_NAME
    note_heading = _FEEDBACK_HEADING
    iac = _FEEDBACK_IN_IAC
    recommendation = (
        "Close the loop on every change: send the pipeline's success and failure events to "
        "the team (a CodeStar notification rule), keep an issue template that asks what the "
        "change did, and review the outcomes in a retrospective."
    )
    searched = (
        "the IaC for a pipeline notification rule, the repo for an issue template, and the "
        "notes for a file or heading on feedback, retrospectives or change outcomes"
    )

    def present(self, repo_path: Path) -> str | None:
        for path in walk(repo_path):
            rel = "/".join(_rel_parts(path, repo_path))
            if rel.lower().startswith((".github/issue_template", ".gitlab/issue_templates")):
                return rel
        return super().present(repo_path)


class ImprovementLoopMissing(_NoteRule):
    id = "REPO-178"
    title = "No improvement note names how the team improves, shares knowledge and finds time"
    note_name = re.compile(
        r"improvements?|retro(?:spective)?s?(?:$|[-_ .])|kaizen|knowledge|learning[-_ ]?loop"
    )
    note_heading = re.compile(
        r"(?i).*\b(?:continuous improvement|improvements?(?: process| backlog)?|knowledge"
        r"(?: management| sharing)?|learning loop|retrospectives?)\b.*"
    )
    recommendation = (
        "Write down the improvement loop (docs/improvement.md): what drives an improvement "
        "(incidents, metrics, cost), how an insight is checked before it becomes work, where "
        "the knowledge lives, how metrics are reviewed and how much time the team reserves "
        "for it."
    )
    searched = (
        "the notes for a file or heading on continuous improvement, retrospectives, knowledge "
        "management or a learning loop"
    )


# Choosing architecture (PERF 1): one decision record that shows how the choice was made
# (REPO-183).
_ADR_SECTIONS = (
    ("the services considered", re.compile(
        r"(?i)\b(?:alternatives?|options?|services?) (?:considered|evaluated|compared)\b"
        r"|\bconsidered\b|\bcompared\b")),
    ("the guidance or partner used", re.compile(
        r"(?i)\bwell-architected\b|\bprescriptive guidance\b|\bsolutions? architects?\b"
        r"|\bpartner\b|\bAWS guidance\b|\bbest practices?\b")),
    ("the cost comparison", re.compile(r"(?i)\bcosts?\b|\bpric(?:e|es|ing)\b|\$\s?\d")),
    ("the tradeoff", re.compile(r"(?i)\btrade-?offs?\b|\bconsequences\b|\bdownsides?\b")),
    ("the reference architecture", re.compile(
        r"(?i)\breference architectures?\b|\blanding zone\b|\bsolutions? library\b"
        r"|\barchitecture center\b|\bblueprints?\b")),
    ("the benchmark", re.compile(r"(?i)\bbenchmarks?(?:ed|ing)?\b|\bload test\b|\bproof of concept\b")),
    ("the data used", re.compile(
        r"(?i)\bdata-driven\b|\bevidence\b|\bmetrics?\b|\bmeasure(?:d|ments?)?\b|\bresults?\b")),
)


class ArchitectureDecisionIncomplete(_RepoRule):
    id = "REPO-183"
    title = "No architecture decision record names the services considered, the cost, the tradeoff and the benchmark"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Record how you chose the architecture: write an architecture decision record "
        "(docs/adr/0001-compute.md) that names the services you considered, the guidance or "
        "partner you used, the cost comparison, the tradeoff for customers, the reference "
        "architecture you followed, the benchmark you ran and the data that decided it."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        held = _holds_iac(repo_path)
        if not held:
            return []
        texts = []
        for rel, text in note_texts(repo_path):
            parts = rel.lower().split("/")
            names = [*parts[:-1], parts[-1].rsplit(".", 1)[0]]
            if any(TradeoffsUnrecorded.note_name.search(n) for n in names) or any(
                TradeoffsUnrecorded.note_heading.fullmatch(h.group(2).strip())
                for h in _HEADING.finditer(text)
            ):
                texts.append(text)
        if not texts:
            return [self._finding(
                f"Holds IaC ({held}); searched the notes for an architecture decision record, "
                "in a file, a folder or a heading; found none"
            )]
        joined = "\n".join(texts)
        missing = [label for label, found in _ADR_SECTIONS if not found.search(joined)]
        if not missing:
            return []
        return [self._finding(
            f"Holds IaC ({held}); the decision records do not name {_listed(missing, 7)}"
        )]


# Performance culture (PERF 5): KPIs with a threshold (REPO-184), automated remediation
# (REPO-185), a load test (REPO-186) and a review note (REPO-187).
_PERF_METRIC = re.compile(
    r"(?i)\b(?:latency|duration|response[-_ ]?time|targetresponsetime|integratedlatency"
    r"|cpuutilization|cpu[-_ ]?utili[sz]ation|memoryutili[sz]ation|throttl\w*|queuedepth"
    r"|approximatenumberofmessagesvisible|iterator[-_ ]?age|p9[0-9](?:\.\d+)?)\b"
)
_NUMERIC_THRESHOLD = re.compile(r"(?i)\bthreshold[\"']?\s*[:=]\s*[\"']?\d")


class PerformanceKpiMissing(_RepoRule):
    id = "REPO-184"
    title = "No alarm on latency or saturation has a numeric threshold"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Turn performance goals into numbers: alarm on the latency (p99, TargetResponseTime, "
        "Duration) and the saturation (CPU, queue depth, throttles) of the critical path, "
        "each with a threshold taken from the goal, and name the path in the alarm."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute:
            return []
        for _rel, text in iac_texts(repo_path):
            if _ALARM.search(text) and _PERF_METRIC.search(text) and _NUMERIC_THRESHOLD.search(text):
                return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for a CloudWatch alarm on a latency, "
            "duration, utilization, throttle or queue metric with a numeric threshold; "
            "found none",
            file=next(iter(compute.values())),
        )]


class PerformanceRemediationMissing(AlarmResponseMissing):
    """The same search as REPO-047, answering PERF05-BP05 for the question on culture."""

    id = "REPO-185"
    title = "Performance alarms trigger no automated remediation"
    category = "Performance Efficiency"
    themes = ("observability",)
    recommendation = (
        "Fix performance problems without a person: scale on load with a target tracking or "
        "step scaling policy, or point the alarm at an SSM Automation runbook, a Lambda "
        "function or an EventBridge rule that restarts, resizes or scales the resource."
    )


class PerformanceLoadTestMissing(LoadTestMissing):
    """The same search as REPO-017, answering PERF05-BP04 for the question on culture."""

    id = "REPO-186"
    title = "No load test shows how the workload performs under load"
    category = "Performance Efficiency"
    themes = ("observability",)
    recommendation = (
        "Measure performance before users do: run a load test in the pipeline (k6, Artillery, "
        "Locust, JMeter or Distributed Load Testing on AWS) against pre-production at the "
        "expected peak, and fail the build when latency or errors pass the target."
    )


class PerformanceReviewMissing(_NoteRule):
    id = "REPO-187"
    title = "No performance review note names how the team improves and reviews performance"
    category = "Performance Efficiency"
    note_name = re.compile(
        r"perf(?:ormance)?[-_ ]?(?:review|reviews|report|improvement|kpis?|metrics|process)"
    )
    note_heading = re.compile(
        r"(?i).*\b(?:performance (?:review|reviews|report|improvement|kpis?|metrics|process))\b.*"
    )
    recommendation = (
        "Write down how performance is reviewed (docs/performance-review.md): the KPIs, how "
        "often the team reads them, what starts an improvement and who owns it."
    )
    searched = (
        "the notes for a file or heading on a performance review, report, improvement process "
        "or KPIs"
    )


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


_SCALING_SIGNALS = (
    ("ecs_target", _ECS_SCALABLE_TARGET),
    ("asg_scaling", _ASG_SCALING),
    ("table_scaling", _DYNAMODB_AUTOSCALING),
    ("policy", re.compile(_SCALING_POLICY)),
)


def scan_fleets(
    repo_path: Path,
) -> tuple[List[tuple[str, str, str, int | None, int | None]], frozenset[str]]:
    """Fleets in the IaC as (check, name, file, line, fixed size), and the repo-wide scaling
    signals found (ecs_target, asg_scaling, table_scaling, policy). REPO-049 and REPO-061."""
    candidates: List[tuple[str, str, str, int | None, int | None]] = []
    signals: set[str] = set()
    for rel, text in iac_texts(repo_path):
        signals.update(name for name, pattern in _SCALING_SIGNALS if pattern.search(text))
        fleets = _tf_fleets(text) + _cdk_fleets(text)
        if _CF_FLEET.search(text):
            fleets += _cf_fleets(rel, text)
        candidates.extend((check, name, rel, line, size) for check, name, line, size in fleets)
    return candidates, frozenset(signals)


def fixed_fleets(repo_path: Path) -> List[tuple[str, str, int | None, str]]:
    """Fleets that cannot grow on demand: (fleet, file, line, why)."""
    candidates, signals = scan_fleets(repo_path)
    ecs_target = "ecs_target" in signals
    asg_policy = "asg_scaling" in signals
    table_scaling = "table_scaling" in signals
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


# REL 10: a component in one location is rebuilt automatically (REPO-056).

_STANDALONE_INSTANCE = re.compile(
    _cf_type(r"EC2::Instance") + r"|resource\s+\"aws_instance\"\s+\"|\bec2\.(?:Cfn)?Instance\("
)
_ASG = re.compile(
    _cf_type(r"AutoScaling::AutoScalingGroup") + r"|resource\s+\"aws_autoscaling_group\""
    r"|\bautoscaling\.(?:Cfn)?AutoScalingGroup\("
)
_INSTANCE_RECOVERY_ACTION = re.compile(
    r"arn:aws:automate:[^\"'\s]*:ec2:(?:recover|reboot)\b|:ec2:(?:recover|reboot)[\"']"
    r"|\bEc2InstanceAction\.(?:RECOVER|REBOOT)\b"
)
_AUTO_RECOVERY_OFF = re.compile(
    r"[\"']?AutoRecovery[\"']?\s*:\s*[\"']?disabled\b|\bauto_recovery\s*=\s*\"disabled\"",
    re.IGNORECASE,
)


def single_location_rebuild(repo_path: Path) -> dict[str, str]:
    """What rebuilds a standalone instance: kind -> first place."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _ASG.search(text):
            found.setdefault("Auto Scaling group", rel)
        if _INSTANCE_RECOVERY_ACTION.search(text):
            found.setdefault("alarm that recovers or reboots the instance", rel)
    backups = _in_iac(repo_path, _BACKUP_SOURCES[:1])
    if backups:
        found.setdefault("AWS Backup plan", next(iter(backups.values())))
    for kind, where in restore_tests(repo_path).items():
        found.setdefault(kind, where)
    return found


class SingleLocationRecoveryMissing(_RepoRule):
    id = "REPO-056"
    title = "A standalone instance is not rebuilt when it fails"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Let a component that runs in one place come back by itself: run it in an Auto "
        "Scaling group of one (min = max = 1) so a failed instance is replaced, add a status "
        "check alarm whose action recovers or reboots the instance, or back it up with AWS "
        "Backup and test the restore. Keep simplified automatic recovery on."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        instances: List[tuple[str, int]] = []
        disabled: List[tuple[str, int]] = []
        for rel, text in iac_texts(repo_path):
            match = _STANDALONE_INSTANCE.search(text)
            if match:
                instances.append((rel, _line_of(text, match.start())))
            off = _AUTO_RECOVERY_OFF.search(text)
            if off:
                disabled.append((rel, _line_of(text, off.start())))
        if disabled:
            places = [f"{rel} (line {line})" for rel, line in disabled]
            return [self._finding(
                f"Turns off automatic recovery for an EC2 instance at {_listed(places)}",
            )]
        if not instances or single_location_rebuild(repo_path):
            return []
        places = [f"{rel} (line {line})" for rel, line in instances]
        return [self._finding(
            f"Runs a standalone EC2 instance at {_listed(places)}; searched the IaC for an "
            "Auto Scaling group, an alarm that recovers or reboots the instance, an AWS Backup "
            "plan, and a restore test; found none",
        )]


# REL 11: capacity that rides out a failure (REPO-057), an availability target on the edge
# (REPO-058), and someone told when availability drops (REPO-059).

_CF_MIN_ONE_TYPES = frozenset({
    "AWS::AutoScaling::AutoScalingGroup", "AWS::ApplicationAutoScaling::ScalableTarget",
    "AWS::ECS::Service",
})
_CF_MIN_ONE = re.compile(_cf_type(
    r"AutoScaling::AutoScalingGroup|ApplicationAutoScaling::ScalableTarget|ECS::Service"))
_TF_MIN_ONE = re.compile(
    r"resource\s+\"(aws_autoscaling_group|aws_appautoscaling_target|aws_ecs_service)\"\s+"
    r"\"([^\"]+)\"\s*\{"
)
_ECS_DIMENSION = "ecs:service:DesiredCount"
_CDK_TASK_COUNT = re.compile(r"(\w+)\s*\.\s*(?:autoScaleTaskCount|auto_scale_task_count)\(")


def _cf_min_one(rel: str, text: str) -> List[tuple[str, str, int | None]]:
    """(check, fleet, line) for template fleets whose literal minimum is one."""
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return []
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    found: List[tuple[str, str, int | None]] = []
    for name, body in (resources.items() if isinstance(resources, dict) else ()):
        if not isinstance(body, dict) or body.get("Type") not in _CF_MIN_ONE_TYPES:
            continue
        props = body.get("Properties")
        props = props if isinstance(props, dict) else {}
        line = _cf_logical_line(text, str(name))
        kind = body.get("Type")
        if kind == "AWS::AutoScaling::AutoScalingGroup" and _num(props.get("MinSize")) == 1:
            found.append(("fleet", f"Auto Scaling group {name} (minimum 1)", line))
        elif (kind == "AWS::ApplicationAutoScaling::ScalableTarget"
              and props.get("ScalableDimension") == _ECS_DIMENSION
              and _num(props.get("MinCapacity")) == 1):
            found.append(("fleet", f"ECS scaling target {name} (minimum 1)", line))
        elif kind == "AWS::ECS::Service" and _num(props.get("DesiredCount")) == 1:
            found.append(("service", f"ECS service {name} (desired count 1)", line))
    return found


def _tf_min_one(text: str) -> List[tuple[str, str, int | None]]:
    found: List[tuple[str, str, int | None]] = []
    for match in _TF_MIN_ONE.finditer(text):
        kind, name = match.groups()
        block = _braced(text, match.end() - 1)
        line = _line_of(text, match.start())
        if kind == "aws_autoscaling_group" and _tf_number(block, "min_size") == 1:
            found.append(("fleet", f"Auto Scaling group {name} (minimum 1)", line))
        elif (kind == "aws_appautoscaling_target"
              and _tf_setting(block, "scalable_dimension") == f'"{_ECS_DIMENSION}"'
              and _tf_number(block, "min_capacity") == 1):
            found.append(("fleet", f"ECS scaling target {name} (minimum 1)", line))
        elif kind == "aws_ecs_service" and _tf_number(block, "desired_count") == 1:
            found.append(("service", f"ECS service {name} (desired count 1)", line))
    return found


def _cdk_min_one(text: str) -> List[tuple[str, str, int | None]]:
    found: List[tuple[str, str, int | None]] = []
    for match in _CDK_FLEET.finditer(text):
        cls, name = match.groups()
        args = _braced(text, match.start() + match.group(0).index("("), "(", ")")
        line = _line_of(text, match.start())
        if cls.endswith("AutoScalingGroup"):
            key = "min_?[sS]ize" if cls.startswith("Cfn") else "min_?[cC]apacity"
            has, low = _cdk_literal(args, key)
            if low == 1 or (not has and not cls.startswith("Cfn") and not _SPREAD.search(args)):
                found.append(("fleet", f"Auto Scaling group {name} (minimum 1)", line))
        elif cls.endswith("Service") and _cdk_literal(args, "desired_?[cC]ount") == (True, 1):
            if cls == "CfnService" and "ecs.CfnService" not in match.group(0):
                continue
            found.append(("service", f"ECS service {name} (desired count 1)", line))
    for match in _CDK_TASK_COUNT.finditer(text):
        args = _braced(text, match.end() - 1, "(", ")")
        has, low = _cdk_literal(args, "min_?[cC]apacity")
        if low == 1 or (not has and not _SPREAD.search(args)):
            found.append(("fleet", f"ECS task count of {match.group(1)} (minimum 1)",
                          _line_of(text, match.start())))
    return found


def single_capacity_fleets(repo_path: Path) -> List[tuple[str, str, int | None]]:
    """Production fleets whose literal minimum is one: (fleet, file, line)."""
    candidates: List[tuple[str, str, str, int | None]] = []
    ecs_target = False
    for rel, text in iac_texts(repo_path):
        ecs_target = ecs_target or bool(_ECS_SCALABLE_TARGET.search(text))
        if from_words(rel) in ("dev", "staging"):
            continue
        fleets = _tf_min_one(text) + _cdk_min_one(text)
        if _CF_MIN_ONE.search(text):
            fleets += _cf_min_one(rel, text)
        candidates.extend((check, fleet, rel, line) for check, fleet, line in fleets)
    return [(fleet, rel, line) for check, fleet, rel, line in candidates
            if check == "fleet" or not ecs_target]


class StaticStabilityMissing(_RepoRule):
    id = "REPO-057"
    title = "Capacity has no headroom to survive a failure"
    category = "Reliability"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Run enough capacity that losing one instance, task or Availability Zone does not "
        "need a scale-out first: give production Auto Scaling groups and ECS services a "
        "minimum of at least two, spread across Availability Zones, so the survivors carry "
        "the load while the failed part is replaced (static stability)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        fleets = single_capacity_fleets(repo_path)
        if not fleets:
            return []
        places = [f"{fleet} at {rel}:{line}" if line else f"{fleet} in {rel}"
                  for fleet, rel, line in fleets]
        return [self._finding(
            f"Production fleets that run on one instance or task: {_listed(places, 4)}",
            file=fleets[0][1],
            line=fleets[0][2],
        )]


_SLO = re.compile(
    _cf_type(r"ApplicationSignals::ServiceLevelObjective")
    + r"|resource\s+\"aws_applicationsignals_service_level_objective\""
    r"|\bCfnServiceLevelObjective\("
)


class AvailabilityTargetMissing(_RepoRule):
    id = "REPO-058"
    title = "No availability target on the user-facing edge"
    category = "Reliability"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Turn the availability target into something that fires: alarm on the edge error "
        "and latency metrics at the target (API Gateway 5XXError and Latency, ALB "
        "HTTPCode_Target_5XX_Count and TargetResponseTime, CloudFront 5xxErrorRate), or define "
        "a CloudWatch Application Signals service level objective for the service."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = edges(repo_path)
        if not found or edge_alarm(repo_path) or _in_iac(repo_path, (("SLO", _SLO),)):
            return []
        return [self._finding(
            f"Serves users through {_named(found)}; searched the IaC for an alarm on an "
            "edge 5xx, error or latency metric and an Application Signals service level "
            "objective; found none",
            file=next(iter(found.values())),
        )]


_SNS_ALARM_ACTION = re.compile(
    r"[\"']?(?:AlarmActions|alarm_?[aA]ctions)[\"']?\s*[:=]\s*[^\]]{0,300}?"
    r"(?:arn:aws[\w-]*:sns:|\baws_sns_topic\.\w+\.arn\b|\.topic_?[aA]rn\b)"
    r"|\.add_?[aA]larm_?[aA]ction\(\s*(?:new\s+)?(?:\w+\.)*SnsAction\("
)
_NOTIFIERS = _kinds(
    ("Incident Manager response plan", _cf_type(r"SSMIncidents::ResponsePlan")
     + r"|resource\s+\"aws_ssmincidents_response_plan\"|arn:aws[\w-]*:ssm-incidents:"
     r"|\bCfnResponsePlan\("),
    ("AWS Chatbot configuration", _cf_type(r"Chatbot::\w+")
     + r"|resource\s+\"aws_chatbot_\w+\""
     r"|\bchatbot\.(?:Cfn)?\w*(?:Slack|Teams|Chime)\w*Configuration\("),
)
_HEALTH_EVENT = re.compile(r"\\?[\"']aws\.health\\?[\"']")


def _cf_topic_alarm(rel: str, text: str) -> bool:
    """A template alarm whose AlarmActions Ref or GetAtt an SNS topic in the template."""
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return False
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    if not isinstance(resources, dict):
        return False
    topics = {name for name, body in resources.items()
              if isinstance(body, dict) and body.get("Type") == "AWS::SNS::Topic"}
    for body in resources.values():
        if not isinstance(body, dict) or body.get("Type") != "AWS::CloudWatch::Alarm":
            continue
        props = body.get("Properties")
        actions = props.get("AlarmActions") if isinstance(props, dict) else None
        for action in actions if isinstance(actions, list) else ():
            if isinstance(action, dict):
                target = action.get("Ref") or action.get("Fn::GetAtt")
                target = target[0] if isinstance(target, list) and target else target
                if target in topics:
                    return True
    return False


def availability_notifications(repo_path: Path) -> dict[str, str]:
    """What tells people that availability dropped: kind -> first file."""
    found = _in_iac(repo_path, _NOTIFIERS)
    for rel, text in iac_texts(repo_path):
        if _SNS_ALARM_ACTION.search(text) or (
            _CF_ALARM.search(text) and _cf_topic_alarm(rel, text)
        ):
            found.setdefault("alarm that notifies an SNS topic", rel)
        if (_EVENT_RULE_DECL.search(text) and _HEALTH_EVENT.search(text)
                and _EVENT_TARGET.search(text)):
            found.setdefault("EventBridge rule on AWS Health events", rel)
    return found


class AvailabilityNotificationMissing(_RepoRule):
    id = "REPO-059"
    title = "No one is notified when availability drops"
    category = "Reliability"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Tell people when availability is hit: send the workload alarms to an SNS topic "
        "the on-call team subscribes to, start an Incident Manager response plan, post to a "
        "chat channel through Amazon Q Developer in chat applications (AWS Chatbot), and "
        "route AWS Health events to the same place with an EventBridge rule."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_iac(repo_path, _COMPUTE)
        if not compute or availability_notifications(repo_path):
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched the IaC for an alarm action that notifies an "
            "SNS topic, an Incident Manager response plan, an AWS Chatbot configuration, and "
            "an EventBridge rule on AWS Health events with a target; found none",
            file=next(iter(compute.values())),
        )]


# PERF 2: compute metrics collected (REPO-060), compute that scales dynamically (REPO-061),
# and accelerators whose utilization is watched (REPO-062).


def _metric_named(names: str) -> str:
    """A metric name key (MetricName, metric_name, metricName) set to one of the names."""
    return rf"[\"']?(?:MetricName|metric_?[nN]ame)[\"']?\s*[:=]\s*[\"']?(?:{names})\b"


def _production(rel: str) -> bool:
    return from_words(rel) not in ("dev", "staging")


_COMPUTE_METRIC = re.compile(
    _metric_named(r"CPUUtilization|MemoryUtilization|Duration|ConcurrentExecutions")
    + r"|\.metric_?(?:[cC]pu_?[uU]tilization|[mM]emory_?[uU]tilization|[dD]uration"
    r"|[cC]oncurrent_?[eE]xecutions)\("
)
_COMPUTE_METRIC_COLLECTORS = _kinds(
    ("ECS Container Insights",
     r"\bcontainerInsights\b[\"']?[^{}\[\]]{0,80}?\b[vV]alue[\"']?\s*[:=]\s*[\"']?"
     r"(?:enabled|enhanced)\b"
     r"|\bcontainer_?[iI]nsights(?:_?V2|_v2)?\s*[:=]\s*"
     r"(?:true|True|(?:\w+\.)*ContainerInsights\.(?:ENABLED|ENHANCED))\b"),
    ("EKS CloudWatch observability add-on",
     r"[\"']?(?:AddonName|addon_name|addonName)[\"']?\s*[:=]\s*[\"']?"
     r"amazon-cloudwatch-observability\b"),
    ("CloudWatch agent",
     r"\bamazon-cloudwatch-agent\b|\bCloudWatchAgentServerPolicy\b"
     r"|\bAmazonCloudWatch-[\w-]+\b"),
)


def compute_metric_collection(repo_path: Path) -> dict[str, str]:
    """What collects compute utilization metrics: kind -> first file."""
    found = _in_iac(repo_path, _COMPUTE_METRIC_COLLECTORS)
    for rel, text in iac_texts(repo_path):
        if _TYPED_ALARM.search(text) and _COMPUTE_METRIC.search(text):
            found.setdefault("alarm on a compute utilization metric", rel)
            break
    return found


class ComputeMetricsMissing(_RepoRule):
    id = "REPO-060"
    title = "Compute utilization metrics are not collected"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Collect and watch how busy the compute is: alarm on CPU and memory utilization for "
        "instances and ECS services and on duration and concurrency for Lambda functions, "
        "turn on ECS Container Insights or the EKS CloudWatch observability add-on, and run "
        "the CloudWatch agent on instances for memory and disk metrics."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute: dict[str, str] = {}
        for rel, text in iac_texts(repo_path):
            if _production(rel):
                for name, pattern in _COMPUTE:
                    if pattern.search(text):
                        compute.setdefault(name, rel)
        if not compute or compute_metric_collection(repo_path):
            return []
        places = [f"{kind} in {rel}" for kind, rel in compute.items()]
        return [self._finding(
            f"Runs {_listed(places, 4)}; searched the IaC for an alarm on a CPU, memory, "
            "duration or concurrency metric, ECS Container Insights, the EKS CloudWatch "
            "observability add-on, and the CloudWatch agent; found none",
            file=next(iter(compute.values())),
        )]


def static_fleets(repo_path: Path) -> List[tuple[str, str, int | None, str]]:
    """Production ECS services and Auto Scaling groups with no scaling policy: (fleet, file,
    line, why)."""
    candidates, signals = scan_fleets(repo_path)
    policy = "policy" in signals
    found: List[tuple[str, str, int | None, str]] = []
    for check, name, rel, line, size in candidates:
        if not _production(rel):
            continue
        if check == "ecs" and not ("ecs_target" in signals and policy):
            fleet, why = f"ECS service {name}", "no scaling policy on its task count"
        elif check == "asg" and size is not None:
            fleet, why = f"Auto Scaling group {name}", f"minimum and maximum size both {size}"
        elif check == "asg" and not policy:
            fleet, why = f"Auto Scaling group {name}", "no scaling policy in the repo"
        else:
            continue
        found.append((fleet, rel, line, why))
    return found


class StaticComputeFleet(_RepoRule):
    id = "REPO-061"
    title = "Compute does not scale with demand"
    category = "Performance Efficiency"
    severity = "Medium"
    themes = ("finops",)
    recommendation = (
        "Scale compute with the load instead of a fixed count: register each ECS service's "
        "desired task count with Application Auto Scaling and attach a target tracking "
        "policy, and give each Auto Scaling group a maximum above its minimum and a target "
        "tracking or predictive scaling policy on the metric that tracks demand."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        fleets = static_fleets(repo_path)
        if not fleets:
            return []
        places = [f"{fleet} at {rel}:{line} ({why})" if line else f"{fleet} in {rel} ({why})"
                  for fleet, rel, line, why in fleets]
        return [self._finding(
            f"Production compute that does not scale dynamically: {_listed(places, 4)}",
            file=fleets[0][1],
            line=fleets[0][2],
        )]


# An accelerated instance type: GPU (p, g, gr), Inferentia, Trainium, Gaudi (dl), FPGA (f)
# and video transcoding (vt) families, alone or as a SageMaker ml. type.
_ACCELERATOR_TYPE = re.compile(
    r"(?<![\w.-])(?:ml\.)?((?:p[2-6]|g[3-6]|gr6|inf[12]|trn[12]|dl[12]|f[12]|vt1)[a-z]*"
    r"(?:-[a-z0-9]+)?\.(?:\d*xlarge|large|medium|small|metal(?:-\d+xl)?))(?![\w.-])"
    r"|\bInstanceClass\.((?:P[2-6]|G[3-6]|INF[12]|TRN[12]|DL[12]|F1|VT1)[A-Z0-9_]*)\b"
)
_ACCELERATOR_HOSTS = re.compile(
    _cf_type(r"EC2::Instance|EC2::LaunchTemplate|AutoScaling::LaunchConfiguration"
             r"|AutoScaling::AutoScalingGroup|EKS::Nodegroup|Batch::ComputeEnvironment"
             r"|SageMaker::\w+")
    + r"|resource\s+\"aws_(?:instance|launch_template|launch_configuration|autoscaling_group"
    r"|eks_node_group|batch_compute_environment|sagemaker_\w+)\""
    r"|\b(?:ec2\.)?(?:Cfn)?(?:Instance|LaunchTemplate)\(|\b(?:Cfn)?AutoScalingGroup\("
    r"|\b(?:Cfn)?Nodegroup\(|\.add_?[nN]odegroup_?[cC]apacity\("
    r"|\.add_?[aA]uto_?[sS]caling_?[gG]roup_?[cC]apacity\(|\b(?:Cfn|Managed)?ComputeEnvironment\("
    r"|\bsagemaker\.(?:alpha\.)?(?:Cfn)?\w+\("
)
_ACCELERATOR_ALARM_METRIC = re.compile(_metric_named(
    r"nvidia_smi_utilization_gpu|nvidia_smi_utilization_memory|GPUUtilization"
    r"|GPUMemoryUtilization|neuroncore_utilization|NeuronCoreUtilization"
    r"|node_gpu_utilization|container_gpu_utilization|DCGM_FI_DEV_GPU_UTIL"
))


def accelerators(repo_path: Path) -> dict[str, str]:
    """Accelerated instance types on compute resources: type -> first file."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if not _ACCELERATOR_HOSTS.search(text):
            continue
        for match in _ACCELERATOR_TYPE.finditer(text):
            found.setdefault(match.group(1) or f"InstanceClass.{match.group(2)}", rel)
    return found


def accelerator_alarm(repo_path: Path) -> str | None:
    """The first file with an alarm on a GPU or Neuron core utilization metric."""
    for rel, text in iac_texts(repo_path):
        if _TYPED_ALARM.search(text) and _ACCELERATOR_ALARM_METRIC.search(text):
            return rel
    return None


class AcceleratorUtilizationUnwatched(_RepoRule):
    id = "REPO-062"
    title = "Accelerator utilization is not watched"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Watch how busy the accelerators are: publish GPU metrics with the CloudWatch agent "
        "NVIDIA collector or Container Insights, or Neuron core metrics with the Neuron "
        "monitor, alarm on GPU or Neuron core utilization, and move work that leaves the "
        "accelerators idle to a smaller or a general purpose instance."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = accelerators(repo_path)
        if not found or accelerator_alarm(repo_path):
            return []
        places = [f"{kind} in {rel}" for kind, rel in found.items()]
        return [self._finding(
            f"Runs accelerated instances ({_listed(places, 4)}); searched the IaC for an alarm "
            "on a GPU or Neuron core utilization metric; found none",
            file=next(iter(found.values())),
        )]


# PERF 3: a purpose-built data store rather than data on the instance (REPO-063).

_HOST_DATA_STORAGE = _kinds(
    ("EBS data volume",
     _cf_type(r"EC2::Volume(?:Attachment)?")
     + r"|resource\s+\"aws_(?:ebs_volume|volume_attachment)\""
     r"|\bec2\.(?:Cfn)?Volume(?:Attachment)?\("),
    ("block device on a non-root device name",
     rf"[\"']?(?:DeviceName|deviceName|device_name)[\"']?\s*[:=]\s*[\"']?{_ROOT_DEVICE}"
     r"|\bebs_block_device\s*\{"),
    ("instance store volume",
     r"[\"']?(?:VirtualName|virtual_name)[\"']?\s*[:=]\s*[\"']?ephemeral\d"
     r"|\bephemeral_block_device\s*\{|\bBlockDeviceVolume\.ephemeral\("),
)
# User data or an SSM document: where a host is told to install or run software.
_HOST_SETUP = re.compile(
    r"\bUserData\b|\buser_data\b|\buserData\b|\badd_?[cC]ommands\("
    r"|AWS::SSM::Document\b|resource\s+\"aws_ssm_document\"|\bssm\.CfnDocument\("
)
_DB_ENGINE = (
    r"mysql-server|mariadb\d*-server|postgresql\d*-server|postgresql(?:-\d+)?(?=\s|$|['\";&\\])"
    r"|mongodb-org|mongodb-server|redis\d*(?:-server)?|cassandra|elasticsearch|opensearch"
)
# The rest of one shell command: it stops at a newline (also \n inside a JSON string), ; & |.
_ONE_COMMAND = r"(?:[^\n\\;&|]|\\(?!n))*?"
# A command starts a line, also one written as \n inside a JSON string.
_DB_ON_HOST = re.compile(
    r"(?:\b|(?<=\\n))(?:apt-get|apt|yum|dnf|apk|zypper|amazon-linux-extras)\s+(?:-\S+\s+)*"
    r"(?:install|add)\s+" + _ONE_COMMAND + r"(?<![\w./-])(" + _DB_ENGINE + r")(?![\w.-])"
    r"|(?:\b|(?<=\\n))systemctl\s+(?:enable|start|restart)\s+(?:--now\s+)?"
    r"(mysqld|mariadb|postgresql|mongod|redis(?:-server)?|cassandra|elasticsearch|opensearch)\b"
    r"|(?:\b|(?<=\\n))docker\s+run\s+" + _ONE_COMMAND
    + r"(?<=\s)(?:library/)?(postgres|mysql|mariadb|mongo|redis)(?::[\w.-]+)?(?=\s|$|['\";&\\])",
    re.MULTILINE,
)
_MANAGED_DATA_STORES = (
    *_DATA_STORES,
    *_kinds(
        ("DynamoDB table", _cf_type(r"Serverless::SimpleTable")),
        ("MemoryDB cluster", _cf_type(r"MemoryDB::Cluster")
         + r"|resource\s+\"aws_memorydb_cluster\"|\bmemorydb\.(?:alpha\.)?(?:Cfn)?Cluster\("),
        ("Keyspaces table", _cf_type(r"Cassandra::(?:Keyspace|Table)")
         + r"|resource\s+\"aws_keyspaces_(?:keyspace|table)\""
         r"|\bcassandra\.Cfn(?:Keyspace|Table)\("),
        ("Timestream database", _cf_type(r"Timestream::(?:Database|Table)")
         + r"|resource\s+\"aws_timestreamwrite_(?:database|table)\""
         r"|\btimestream\.Cfn(?:Database|Table)\("),
        ("FSx file system", _cf_type(r"FSx::FileSystem")
         + r"|resource\s+\"aws_fsx_\w+_file_system\"|\bfsx\.(?:Cfn|Lustre)?FileSystem\("),
        ("ElastiCache", r"\belasticache\.(?:alpha\.)?(?:ServerlessCache|ReplicationGroup)\("),
    ),
)


def host_data_storage(repo_path: Path) -> List[tuple[str, str, int]]:
    """Production data kept on the instance: (kind, file, line), first per kind and file."""
    found: List[tuple[str, str, int]] = []
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        for kind, pattern in _HOST_DATA_STORAGE:
            if match := pattern.search(text):
                found.append((kind, rel, _line_of(text, match.start())))
        if _HOST_SETUP.search(text) and (match := _DB_ON_HOST.search(text)):
            engine = next(group for group in match.groups() if group)
            found.append((f"{engine} on the host", rel, _line_of(text, match.start())))
    return found


_MANAGED_SEARCHED = (
    "managed data store (S3, DynamoDB, RDS or Aurora, ElastiCache, MemoryDB, "
    "DocumentDB, Neptune, Keyspaces, OpenSearch Service, Timestream, Redshift, EFS, "
    "FSx)"
)


def unmanaged_host_data(repo_path: Path) -> List[tuple[str, str, int]]:
    """Production data kept on the instance, when the IaC declares no managed data store
    (REPO-063 and REPO-106)."""
    found = host_data_storage(repo_path)
    if not found or _in_iac(repo_path, _MANAGED_DATA_STORES):
        return []
    return found


class PurposeBuiltDataStoreMissing(_RepoRule):
    id = "REPO-063"
    title = "Data lives on the instance, not in a purpose-built store"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("resilience",)
    recommendation = (
        "Pick a managed data store built for the access pattern instead of keeping data on "
        "instance volumes or running a database engine on the host: RDS or Aurora for "
        "relational data, DynamoDB for key-value access, ElastiCache or MemoryDB for "
        "in-memory data, OpenSearch Service for search, S3 for objects, and EFS or FSx for "
        "shared files."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = unmanaged_host_data(repo_path)
        if not found:
            return []
        places = [f"{kind} at {rel}:{line}" for kind, rel, line in found]
        return [self._finding(
            f"Keeps data on the instance: {_listed(places, 4)}; searched the IaC for a "
            f"{_MANAGED_SEARCHED}; found none",
            file=found[0][1],
            line=found[0][2],
        )]


# PERF 4: networking. Edge latency watched (REPO-064), redundant dedicated connectivity
# (REPO-066), load balancing (REPO-067), modern protocols (REPO-068), and network
# configuration tuned on metrics (REPO-065).


def _cf_resources(rel: str, text: str) -> dict[str, dict]:
    """The Resources of a readable CloudFormation template: logical id -> body."""
    try:
        doc = parse_template_text(Path(rel), text)
    except Exception:  # noqa: BLE001 - not a readable template
        return {}
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    if not isinstance(resources, dict):
        return {}
    return {name: body for name, body in resources.items() if isinstance(body, dict)}


def _props(body: dict) -> dict:
    props = body.get("Properties")
    return props if isinstance(props, dict) else {}


def production_edges(repo_path: Path) -> dict[str, str]:
    """User-facing endpoints (as edges()) in files whose path does not read as dev or
    staging: kind -> first file."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        for name, pattern in _EDGES:
            if pattern.search(text):
                found.setdefault(name, rel)
        if _SAM_TRANSFORM.search(text) and _SAM_API_EVENT.search(text):
            found.setdefault("API Gateway", rel)
    return found


_LATENCY_NAMES = r"TargetResponseTime|Latency|IntegrationLatency|OriginLatency"
_CDK_LATENCY_METRIC = (
    r"\.metric(?:Latency|IntegrationLatency|OriginLatency|TargetResponseTime)\("
    r"|\.metric_(?:latency|integration_latency|origin_latency|target_response_time)\("
    r"|\.metrics\.(?:targetResponseTime|target_response_time)\("
)
_LATENCY_METRIC = re.compile(_metric_named(_LATENCY_NAMES) + "|" + _CDK_LATENCY_METRIC)
_TF_ALARM_BLOCK = re.compile(
    r"resource\s+\"aws_cloudwatch_metric_alarm\"\s+\"[^\"]+\"\s*\{"
)
_CDK_ALARM_CALL = re.compile(
    r"\bcloudwatch\.Alarm\(|\bnew\s+Alarm\(|\.create_?[Aa]larm\("
)
# A threshold set to a number; a variable, parameter or anomaly band is not one.
_NUMERIC_THRESHOLD = re.compile(
    r"(?<![\w.])[\"']?(?:Threshold|threshold)[\"']?\s*[:=]\s*[\"']?-?\d+(?:\.\d+)?[\"']?"
    r"(?![\w.])"
)
_LATENCY_NAME_SET = frozenset(_LATENCY_NAMES.split("|"))
_CF_ALARM_TYPE = re.compile(_cf_type(r"CloudWatch::Alarm"))


def _number(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    return isinstance(value, str) and re.fullmatch(r"-?\d+(?:\.\d+)?", value) is not None


def _cf_latency_threshold(rel: str, text: str) -> bool:
    """A CloudFormation alarm on an edge latency metric with a numeric Threshold."""
    for body in _cf_resources(rel, text).values():
        if body.get("Type") != "AWS::CloudWatch::Alarm":
            continue
        props = _props(body)
        names = {props.get("MetricName")}
        for query in props.get("Metrics") or ():
            stat = query.get("MetricStat") if isinstance(query, dict) else None
            metric = stat.get("Metric") if isinstance(stat, dict) else None
            if isinstance(metric, dict):
                names.add(metric.get("MetricName"))
        if names & _LATENCY_NAME_SET and _number(props.get("Threshold")):
            return True
    return False


def _latency_threshold(rel: str, text: str) -> bool:
    """An alarm in the text on an edge latency metric with a literal numeric threshold."""
    if _CF_ALARM_TYPE.search(text) and _cf_latency_threshold(rel, text):
        return True
    for match in _TF_ALARM_BLOCK.finditer(text):
        body = _braced(text, match.end() - 1)
        if _LATENCY_METRIC.search(body) and _NUMERIC_THRESHOLD.search(body):
            return True
    # A CDK alarm often takes its metric from a variable: the caller found a latency metric
    # in the file, so a number in the alarm's own arguments is enough.
    for match in _CDK_ALARM_CALL.finditer(text):
        if _NUMERIC_THRESHOLD.search(_braced(text, match.end() - 1, "(", ")")):
            return True
    return False


def latency_alarms(repo_path: Path) -> tuple[str | None, str | None]:
    """The first file with an alarm on an edge latency metric, and the first file where such
    an alarm has a literal numeric threshold."""
    alarm = fixed = None
    for rel, text in iac_texts(repo_path):
        if not _TYPED_ALARM.search(text) or not _LATENCY_METRIC.search(text):
            continue
        alarm = alarm or rel
        if fixed is None and _latency_threshold(rel, text):
            fixed = rel
            break
    return alarm, fixed


class EdgeLatencyUnwatched(_RepoRule):
    id = "REPO-064"
    title = "Network latency at the edge is not watched"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Alarm on the latency users see at the edge: TargetResponseTime on an Application "
        "Load Balancer, Latency and IntegrationLatency on API Gateway, and OriginLatency on "
        "CloudFront, so a slow network path or origin shows up before users report it."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = production_edges(repo_path)
        if not found or latency_alarms(repo_path)[0]:
            return []
        places = [f"{kind} in {rel}" for kind, rel in found.items()]
        return [self._finding(
            f"Serves users through {_listed(places)}; searched the IaC for an alarm on "
            "TargetResponseTime, Latency, IntegrationLatency or OriginLatency; found none",
        )]


_FLOW_LOGS = _kinds(
    ("VPC Flow Logs", _cf_type(r"EC2::FlowLog") + r"|resource\s+\"aws_flow_log\""
     r"|\bec2\.(?:Cfn)?FlowLog\(|\.add_?[fF]low_?[lL]og\("
     r"|\bflow_?[lL]ogs[\"']?\s*[:=]\s*[{\[(]"),
)


class NetworkMetricsUnused(_RepoRule):
    id = "REPO-065"
    title = "Network configuration is not tuned on metrics"
    category = "Performance Efficiency"
    severity = "Low"
    themes = ("observability",)
    recommendation = (
        "Collect the network metrics needed to tune the configuration: turn on VPC Flow Logs "
        "to see traffic patterns, and alarm on edge latency (TargetResponseTime, Latency, "
        "OriginLatency) with a fixed threshold taken from the performance target, then "
        "revisit the network design when it is breached."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = production_edges(repo_path)
        if not found or _in_iac(repo_path, _FLOW_LOGS):
            return []
        alarm, fixed = latency_alarms(repo_path)
        if fixed:
            return []
        latency = (
            f"the latency alarm in {alarm} has no numeric threshold" if alarm
            else "no alarm on an edge latency metric"
        )
        places = [f"{kind} in {rel}" for kind, rel in found.items()]
        return [self._finding(
            f"Serves users through {_listed(places)}; {latency}, and no VPC Flow Logs "
            "(AWS::EC2::FlowLog, aws_flow_log, CDK FlowLog or addFlowLog)",
        )]


def _counted(text: str, pattern: re.Pattern[str]) -> int:
    """Declarations of a resource; a Terraform block with count or for_each counts as two."""
    total = 0
    for match in pattern.finditer(text):
        total += 1
        if match.group(0).rstrip().endswith("{") and re.search(
            r"^\s*(?:count|for_each)\s*=", _braced(text, match.end() - 1), re.MULTILINE
        ):
            total += 1
    return total


_DX_CONNECTION = re.compile(
    _cf_type(r"DirectConnect::Connection")
    + r"|resource\s+\"aws_dx_connection\"\s+\"[^\"]+\"\s*\{"
)
_DX_LAG = re.compile(_cf_type(r"DirectConnect::Lag") + r"|resource\s+\"aws_dx_lag\"")
_DX_INTERFACE = re.compile(
    _cf_type(r"DirectConnect::\w*VirtualInterface")
    + r"|resource\s+\"aws_dx_(?:hosted_)?(?:private|public|transit)_virtual_interface\""
    r"\s+\"[^\"]+\"\s*\{"
)
_VPN_CONNECTION = re.compile(
    _cf_type(r"EC2::VPNConnection") + r"|resource\s+\"aws_vpn_connection\"\s+\"[^\"]+\"\s*\{"
    r"|\bec2\.(?:Cfn)?VpnConnection\(|\.add_?[vV]pn_?[cC]onnection\("
)
_CUSTOMER_GATEWAY = re.compile(
    _cf_type(r"EC2::CustomerGateway") + r"|resource\s+\"aws_customer_gateway\"\s+\"[^\"]+\"\s*\{"
)
_CDK_VPN_OPTIONS = re.compile(r"\bvpn_?[cC]onnections[\"']?\s*[:=]\s*\{")
_CDK_VPN_IP = re.compile(r"[\"']?\bip[\"']?\s*[:=]")


def hybrid_links(repo_path: Path) -> dict[str, tuple[int, str]]:
    """Dedicated and VPN links in production IaC: kind -> (declarations, first file)."""
    counts: dict[str, tuple[int, str]] = {}

    def add(kind: str, n: int, rel: str) -> None:
        if n:
            old = counts.get(kind, (0, rel))
            counts[kind] = (old[0] + n, old[1])

    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        add("Direct Connect connection", _counted(text, _DX_CONNECTION), rel)
        add("Direct Connect LAG", len(_DX_LAG.findall(text)), rel)
        add("Direct Connect virtual interface", _counted(text, _DX_INTERFACE), rel)
        add("VPN connection", _counted(text, _VPN_CONNECTION), rel)
        add("customer gateway", _counted(text, _CUSTOMER_GATEWAY), rel)
        for match in _CDK_VPN_OPTIONS.finditer(text):
            add("VPN connection", len(_CDK_VPN_IP.findall(_braced(text, match.end() - 1))), rel)
    return counts


def single_hybrid_link(repo_path: Path) -> tuple[str, str] | None:
    """(what, file) when the production IaC declares exactly one link to an on-premises
    network and no second path: one Direct Connect connection or virtual interface with no
    LAG and no VPN, or one VPN connection on one customer gateway with no Direct Connect."""
    links = hybrid_links(repo_path)

    def n(kind: str) -> int:
        return links.get(kind, (0, ""))[0]

    dx, vif = n("Direct Connect connection"), n("Direct Connect virtual interface")
    vpn, lag = n("VPN connection"), n("Direct Connect LAG")
    if (dx or vif) and dx <= 1 and vif <= 1 and not lag and not vpn:
        kind = "Direct Connect connection" if dx else "Direct Connect virtual interface"
        return kind, links[kind][1]
    if vpn == 1 and not (dx or vif or lag) and n("customer gateway") <= 1:
        return "VPN connection", links["VPN connection"][1]
    return None


class SingleHybridLink(_RepoRule):
    id = "REPO-066"
    title = "Dedicated connectivity or VPN has no redundant link"
    category = "Performance Efficiency"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Give the link to the on-premises network a second path: a second Direct Connect "
        "connection at another location or a LAG, or a Site-to-Site VPN as backup to Direct "
        "Connect, and a second VPN connection on a second customer gateway device."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        single = single_hybrid_link(repo_path)
        if not single:
            return []
        kind, rel = single
        if kind == "VPN connection":
            return [self._finding(
                f"Declares one VPN connection in {rel}; searched the IaC for a second VPN "
                "connection on another customer gateway and for Direct Connect; found none",
                file=rel,
            )]
        return [self._finding(
            f"Declares one {kind} in {rel}; searched the IaC for a second Direct Connect "
            "connection or virtual interface, a LAG, and a Site-to-Site VPN backup; found "
            "none",
            file=rel,
        )]


_LOAD_BALANCERS = _kinds(
    ("load balancer",
     _cf_type(r"ElasticLoadBalancing(?:V2)?::LoadBalancer")
     + r"|resource\s+\"aws_(?:lb|alb|elb)\""
     r"|\b(?:Application|Network)LoadBalancer\(|\belb\.(?:Cfn)?LoadBalancer\("
     r"|\b(?:Application|Network)LoadBalanced\w+\(|\belbv2\.CfnLoadBalancer\("),
)
_TF_INSTANCE = re.compile(r"resource\s+\"aws_instance\"\s+\"([^\"]+)\"\s*\{")
_TF_PUBLIC_IP = re.compile(r"\bassociate_public_ip_address\s*=\s*true\b")
_TF_EIP = re.compile(r"resource\s+\"aws_eip(?:_association)?\"\s+\"[^\"]+\"\s*\{")
_TF_EIP_INSTANCE = re.compile(r"\binstance(?:_id)?\s*=\s*aws_instance\.([\w-]+)\.id\b")
_CDK_INSTANCE = re.compile(r"\bec2\.Instance\(")
_CDK_PUBLIC = re.compile(
    r"\bassociate_?[pP]ublic_?[iI]p_?[aA]ddress\s*[:=]\s*(?:true|True)\b"
    r"|\bsubnet_?[tT]ype\s*[:=]\s*(?:\w+\.)*SubnetType\.PUBLIC\b"
)
_CDK_EIP = re.compile(r"\bec2\.CfnEIP(?:Association)?\(")
_CF_INSTANCE_TYPE = re.compile(_cf_type(r"EC2::Instance"))


def _cf_public_instances(rel: str, text: str) -> List[str]:
    resources = _cf_resources(rel, text)
    public: List[str] = []
    for name, body in resources.items():
        if body.get("Type") != "AWS::EC2::Instance":
            continue
        enis = _props(body).get("NetworkInterfaces")
        if any(isinstance(eni, dict) and str(eni.get("AssociatePublicIpAddress")).lower()
               == "true" for eni in (enis if isinstance(enis, list) else ())):
            public.append(name)
    for body in resources.values():
        if body.get("Type") in ("AWS::EC2::EIP", "AWS::EC2::EIPAssociation"):
            target = _props(body).get("InstanceId")
            ref = target.get("Ref") if isinstance(target, dict) else None
            if ref in resources and ref not in public:
                public.append(ref)
    return public


def public_instances(repo_path: Path) -> List[tuple[str, str]]:
    """Production EC2 instances with a public IP or an Elastic IP: (instance, file)."""
    found: List[tuple[str, str]] = []
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        if _CF_INSTANCE_TYPE.search(text):
            found.extend((name, rel) for name in _cf_public_instances(rel, text))
        eip_targets = {
            m.group(1) for e in _TF_EIP.finditer(text)
            for m in [_TF_EIP_INSTANCE.search(_braced(text, e.end() - 1))] if m
        }
        for match in _TF_INSTANCE.finditer(text):
            name = match.group(1)
            if name in eip_targets or _TF_PUBLIC_IP.search(_braced(text, match.end() - 1)):
                found.append((f"aws_instance.{name}", rel))
        eip = _CDK_EIP.search(text)
        for match in _CDK_INSTANCE.finditer(text):
            if eip or _CDK_PUBLIC.search(_braced(text, match.end() - 1, "(", ")")):
                found.append((f"ec2.Instance at line {_line_of(text, match.start())}", rel))
    return found


_CF_TARGET_GROUP = re.compile(_cf_type(r"ElasticLoadBalancingV2::TargetGroup"))
_TF_TG_ATTACHMENT = re.compile(
    r"resource\s+\"aws_lb_target_group_attachment\"\s+\"[^\"]+\"\s*\{"
)
_TF_TG_REF = re.compile(r"\btarget_group_arn\s*=\s*(aws_lb_target_group\.[\w-]+)\.arn\b")
_CDK_TARGETS_LIST = re.compile(r"\btargets[\"']?\s*[:=]\s*\[")
_CDK_LITERAL_TARGET = re.compile(
    r"(?:new\s+)?(?:\w+\.)*(?:InstanceIdTarget|InstanceTarget|IpTarget)\("
)


def _cf_single_targets(rel: str, text: str) -> List[str]:
    resources = _cf_resources(rel, text)
    fleets = json.dumps([
        _props(body) for body in resources.values()
        if body.get("Type") in ("AWS::AutoScaling::AutoScalingGroup", "AWS::ECS::Service")
    ], default=str)
    return [
        name for name, body in resources.items()
        if body.get("Type") == "AWS::ElasticLoadBalancingV2::TargetGroup"
        and isinstance(_props(body).get("Targets"), list)
        and len(_props(body)["Targets"]) == 1
        and f'"{name}"' not in fleets
    ]


def single_targets(repo_path: Path) -> List[tuple[str, str]]:
    """Production target groups with exactly one literal target: (target group, file)."""
    found: List[tuple[str, str]] = []
    texts = [(rel, text) for rel, text in iac_texts(repo_path) if _production(rel)]
    tf_attachments: dict[str, tuple[int, str]] = {}
    fleets = "\n".join(
        _braced(text, m.end() - 1) for _, text in texts for m in re.finditer(
            r"resource\s+\"aws_(?:autoscaling_group|autoscaling_attachment|ecs_service)\""
            r"\s+\"[^\"]+\"\s*\{", text)
    )
    for rel, text in texts:
        if _CF_TARGET_GROUP.search(text):
            found.extend((name, rel) for name in _cf_single_targets(rel, text))
        for match in _TF_TG_ATTACHMENT.finditer(text):
            body = _braced(text, match.end() - 1)
            ref = _TF_TG_REF.search(body)
            if ref:
                many = 2 if re.search(r"^\s*(?:count|for_each)\s*=", body, re.MULTILINE) else 1
                n, first = tf_attachments.get(ref.group(1), (0, rel))
                tf_attachments[ref.group(1)] = (n + many, first)
        for match in _CDK_TARGETS_LIST.finditer(text):
            body = _braced(text, match.end() - 1, "[", "]")
            targets = list(_CDK_LITERAL_TARGET.finditer(body))
            if len(targets) != 1:
                continue
            call = targets[0]
            close = call.end() + len(_braced(body, call.end() - 1, "(", ")")) + 1
            rest = body[:call.start()] + body[close:]
            if not rest.strip(" \t\r\n,"):
                found.append((f"target list at line {_line_of(text, match.start())}", rel))
    for group, (n, rel) in tf_attachments.items():
        if n == 1 and f"{group}.arn" not in fleets:
            found.append((group, rel))
    return found


class LoadBalancingMissing(_RepoRule):
    id = "REPO-067"
    title = "Traffic is not spread by a load balancer"
    category = "Performance Efficiency"
    severity = "Medium"
    themes = ("resilience",)
    recommendation = (
        "Put an Application or Network Load Balancer in front of the compute and register "
        "more than one target (an Auto Scaling group or ECS service rather than one "
        "instance), so load spreads across targets and Availability Zones instead of "
        "landing on one public instance."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places: List[str] = []
        public = public_instances(repo_path)
        if public and not _in_iac(repo_path, _LOAD_BALANCERS):
            places += [f"internet-facing EC2 instance {name} in {rel}" for name, rel in public]
        places += [f"target group {name} with one target in {rel}"
                   for name, rel in single_targets(repo_path)]
        if not places:
            return []
        return [self._finding(
            f"Serves traffic from {_listed(places, 4)}; a load balancer with more than one "
            "target spreads load, and none was found for these",
        )]


_OLD_PROTOCOLS = _kinds(
    ("CloudFront HTTP/1.1 only",
     r"[\"']?(?:HttpVersion|http_?[vV]ersion)[\"']?\s*[:=]\s*"
     r"(?:[\"']?http1\.1[\"']?(?![\w.])|(?:\w+\.)*HttpVersion\.HTTP1_1\b)"),
    ("CloudFront viewer TLS below 1.2",
     r"[\"']?(?:MinimumProtocolVersion|minimum_?[pP]rotocol_?[vV]ersion)[\"']?\s*[:=]\s*"
     r"(?:[\"']?(?:SSLv3|TLSv1\.1_2016|TLSv1_2016|TLSv1)[\"']?(?![\w.])"
     r"|(?:\w+\.)*SecurityPolicyProtocol\.(?:SSL_V3|TLS_V1|TLS_V1_2016|TLS_V1_1_2016)\b)"),
    ("load balancer TLS policy below 1.2",
     r"[\"']?(?:SslPolicy|ssl_?[pP]olicy)[\"']?\s*[:=]\s*"
     r"(?:[\"']?ELBSecurityPolicy-(?:2015-05|2016-08|FS-2018-06|TLS-1-[01]-[\w-]+"
     r"|FS-1-1-[\w-]+|TLS13-1-[01]-[\w-]+)(?![\w-])"
     r"|(?:\w+\.)*SslPolicy\.(?:LEGACY|RECOMMENDED|TLS11|TLS13_10|TLS13_11|FORWARD_SECRECY"
     r"|FORWARD_SECRECY_TLS11)\b)"),
    ("API Gateway domain on TLS 1.0",
     r"[\"']?(?:SecurityPolicy|security_?[pP]olicy)[\"']?\s*[:=]\s*"
     r"(?:[\"']?TLS_1_0\b|(?:\w+\.)*SecurityPolicy\.TLS_1_0\b)"),
)
_CF_LISTENER_TYPE = re.compile(_cf_type(r"ElasticLoadBalancingV2::Listener"))
_TF_LISTENER = re.compile(r"resource\s+\"aws_(?:lb|alb)_listener\"\s+\"[^\"]+\"\s*\{")
_TF_LB = re.compile(r"resource\s+\"aws_(?:lb|alb)\"\s+\"([^\"]+)\"\s*\{")
_CDK_PUBLIC_ALB = re.compile(r"\binternet_?[fF]acing\s*[:=]\s*(?:true|True)\b")
_CDK_ADD_LISTENER = re.compile(r"\.add_?[lL]istener\(")
_CDK_HTTP_LISTENER = re.compile(
    r"\bport\s*[:=]\s*80\b|\bApplicationProtocol\.HTTP\b(?!S)"
)
_REDIRECT = re.compile(r"\bredirect\b|\.add_?[rR]edirect\(", re.IGNORECASE)


def _cf_http_forwards(rel: str, text: str) -> List[str]:
    resources = _cf_resources(rel, text)
    found: List[str] = []
    for name, body in resources.items():
        if body.get("Type") != "AWS::ElasticLoadBalancingV2::Listener":
            continue
        props = _props(body)
        actions = props.get("DefaultActions")
        if props.get("Protocol") != "HTTP" or not isinstance(actions, list):
            continue
        if not any(isinstance(a, dict) and a.get("Type") == "forward" for a in actions):
            continue
        arn = props.get("LoadBalancerArn")
        lb = resources.get(str(arn.get("Ref"))) if isinstance(arn, dict) else None
        if not lb:
            continue
        lb_props = _props(lb)
        if lb_props.get("Scheme") == "internal" or lb_props.get("Type") in (
            "network", "gateway"
        ):
            continue
        found.append(name)
    return found


def _tf_http_forwards(text: str) -> List[str]:
    lbs = {m.group(1): _braced(text, m.end() - 1) for m in _TF_LB.finditer(text)}
    found: List[str] = []
    for match in _TF_LISTENER.finditer(text):
        body = _braced(text, match.end() - 1)
        if not re.search(r"\bprotocol\s*=\s*\"HTTP\"", body) or "redirect" in body:
            continue
        if not re.search(r"\btype\s*=\s*\"forward\"", body):
            continue
        ref = re.search(r"\bload_balancer_arn\s*=\s*aws_(?:lb|alb)\.([\w-]+)\.arn\b", body)
        lb = lbs.get(ref.group(1)) if ref else None
        if lb is None or re.search(r"\binternal\s*=\s*true\b", lb) or re.search(
            r"\bload_balancer_type\s*=\s*\"(?:network|gateway)\"", lb
        ):
            continue
        found.append(f"listener at line {_line_of(text, match.start())}")
    return found


def old_protocols(repo_path: Path) -> List[tuple[str, str, int]]:
    """Production edges on older protocols: (kind, file, line)."""
    found: List[tuple[str, str, int]] = []
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        for kind, pattern in _OLD_PROTOCOLS:
            if match := pattern.search(text):
                found.append((kind, rel, _line_of(text, match.start())))
        http = "internet-facing load balancer forwarding plain HTTP"
        if _CF_LISTENER_TYPE.search(text) and _cf_http_forwards(rel, text):
            found.append((http, rel, 0))
        if _TF_LISTENER.search(text) and _tf_http_forwards(text):
            found.append((http, rel, 0))
        if _CDK_PUBLIC_ALB.search(text) and not _REDIRECT.search(text):
            for match in _CDK_ADD_LISTENER.finditer(text):
                if _CDK_HTTP_LISTENER.search(_braced(text, match.end() - 1, "(", ")")):
                    found.append((http, rel, _line_of(text, match.start())))
                    break
    return found


class OldNetworkProtocol(_RepoRule):
    id = "REPO-068"
    title = "Edge uses an older network protocol"
    category = "Performance Efficiency"
    severity = "Medium"
    themes = ("network-exposure",)
    recommendation = (
        "Serve users over current protocols: let CloudFront use HTTP/2 or HTTP/3 (http2and3), "
        "set the viewer minimum protocol to TLSv1.2_2021, use a TLS 1.2 or 1.3 load balancer "
        "policy such as ELBSecurityPolicy-TLS13-1-2-2021-06, set API Gateway domains to "
        "TLS_1_2, and redirect HTTP listeners on public load balancers to HTTPS."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = old_protocols(repo_path)
        if not found:
            return []
        places = [f"{kind} at {rel}:{line}" if line else f"{kind} in {rel}"
                  for kind, rel, line in found]
        return [self._finding(
            f"Uses older protocols: {_listed(places, 4)}",
        )]


# COST 3: a detailed cost and usage source (REPO-069), cost attribution tags (REPO-070), a
# unit-cost metric (REPO-071), and costs allocated through workload metrics (REPO-072).

_COST_REPORTS = _kinds(
    ("cost and usage report", _cf_type(r"CUR::ReportDefinition|BCMDataExports::Export")
     + r"|resource\s+\"aws_(?:cur_report_definition|bcmdataexports_export)\""
     r"|\bCfnReportDefinition\(|bcmdataexports\.CfnExport\("),
)
_WORKLOAD = _COMPUTE + _DATA_STORES + _EDGES
_COST_KEY = (
    r"(?:cost[-_ ]?cent(?:er|re)|business[-_ ]?unit|project|product|cost[-_ ]?category)"
)
_COST_TAG = _tag_key(_COST_KEY)
_COST_CATEGORY = _kinds(
    ("cost category", _cf_type(r"CE::CostCategory") + r"|resource\s+\"aws_ce_cost_category\""
     r"|\bce\.CfnCostCategory\("),
)
# A metric name that reads as a unit cost: CostPerRequest, cost_per_tenant, UnitCost.
_UNIT_COST = r"(?i:[\w-]*(?:cost[_-]?per[_-]?\w+|unit[_-]?cost)[\w-]*)"
_UNIT_COST_NAME = re.compile(_UNIT_COST)
_UNIT_COST_METRIC = re.compile(
    rf"[\"']?(?:MetricName|metric_?[nN]ame|[lL]abel|[iI]d)[\"']?\s*[:=]\s*[\"']?{_UNIT_COST}"
    rf"[\"']?\s*(?:[,;)}}\]]|$)"
    rf"|\bmetric_transformation\s*\{{[^{{}}]*?\bname\s*=\s*\"{_UNIT_COST}\""
    rf"|\.(?:add_?[mM]etric|put_?[mM]etric)\(\s*(?:name\s*=\s*)?[\"']{_UNIT_COST}[\"']",
    re.MULTILINE,
)
# Embedded metric format: the metric's Name inside a CloudWatchMetrics directive.
_EMF_UNIT_COST = re.compile(rf"[\"']Name[\"']\s*:\s*[\"']{_UNIT_COST}[\"']")
_COST_METRIC_NAMES = frozenset({"EstimatedCharges"})
_METRIC_NAME_VALUE = re.compile(
    r"[\"']?(?:MetricName|metric_?[nN]ame)\\?[\"']?\s*[:=]\s*\\?[\"']?([\w.-]+)"
)
# A dashboard metric array: ["AWS/Billing", "EstimatedCharges", ...].
_NAMESPACE_PAIR = re.compile(
    r"\\?[\"'][A-Za-z0-9]+/[\w/.-]+\\?[\"']\s*,\s*\\?[\"']([\w.-]+)\\?[\"']"
)
_CDK_METRIC_HELPER = re.compile(r"\.metric(?:[A-Z]|_[a-z])\w*\(")
_MATH = re.compile(r"[eE]xpression\\?[\"']?\s*[:=]|\bMathExpression\(")
_TF_MATH_BLOCK = re.compile(
    r"resource\s+\"aws_cloudwatch_(?:metric_alarm|dashboard)\"\s+\"[^\"]+\"\s*\{"
)
_CF_MATH_TYPE = re.compile(_cf_type(r"CloudWatch::(?:Alarm|Dashboard)"))
_CF_MATH_TYPES = frozenset({"AWS::CloudWatch::Alarm", "AWS::CloudWatch::Dashboard"})


def _in_production_iac(
    repo_path: Path, kinds: tuple[tuple[str, re.Pattern[str]], ...]
) -> dict[str, str]:
    """Each kind declared in IaC whose path does not read as dev or staging: kind -> file."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _production(rel):
            for name, pattern in kinds:
                if pattern.search(text):
                    found.setdefault(name, rel)
    return found


def _cost_name(name: str) -> bool:
    return name in _COST_METRIC_NAMES or _UNIT_COST_NAME.fullmatch(name) is not None


def unit_cost_metric(repo_path: Path) -> str | None:
    """The first file that names a unit-cost metric in a metric-name position."""
    for rel, text in iac_texts(repo_path):
        if _UNIT_COST_METRIC.search(text) or (
            "CloudWatchMetrics" in text and _EMF_UNIT_COST.search(text)
        ):
            return rel
    return None


def _ties_cost_to_workload(block: str) -> bool:
    """A metric math block that reads a cost metric and a workload metric."""
    if not _MATH.search(block):
        return False
    names = set(_METRIC_NAME_VALUE.findall(block)) | set(_NAMESPACE_PAIR.findall(block))
    cost = {name for name in names if _cost_name(name)}
    if not cost and not _UNIT_COST_METRIC.search(block):
        return False
    return bool(names - cost) or _CDK_METRIC_HELPER.search(block) is not None


def _math_blocks(rel: str, text: str) -> Iterator[str]:
    """CloudFormation alarms and dashboards, Terraform alarms and dashboards, and a CDK
    file that builds a MathExpression (its metrics often come from variables)."""
    if _CF_MATH_TYPE.search(text):
        for body in _cf_resources(rel, text).values():
            if body.get("Type") in _CF_MATH_TYPES:
                yield json.dumps(body)
    for match in _TF_MATH_BLOCK.finditer(text):
        yield _braced(text, match.end() - 1)
    if "MathExpression(" in text:
        yield text


def cost_allocation_math(repo_path: Path) -> str | None:
    """The first file with metric math over a cost metric and a workload metric."""
    for rel, text in iac_texts(repo_path):
        if any(_ties_cost_to_workload(block) for block in _math_blocks(rel, text)):
            return rel
    return None


class CostReportMissing(_RepoRule):
    id = "REPO-069"
    title = "No Cost and Usage Report or data export"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Turn on a detailed cost source in the management (payer) account: an AWS Data "
        "Exports export of CUR 2.0 (or a legacy Cost and Usage Report) with hourly "
        "granularity and resource IDs, delivered to S3 and queryable with Athena."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        workload = _in_production_iac(repo_path, _WORKLOAD)
        if not workload or _in_iac(repo_path, _COST_REPORTS):
            return []
        places = [f"{kind} in {rel}" for kind, rel in workload.items()]
        return [self._finding(
            f"Declares {_listed(places)}; searched the IaC for a Cost and Usage Report "
            "(AWS::CUR::ReportDefinition, aws_cur_report_definition) or a data export "
            "(AWS::BCMDataExports::Export, aws_bcmdataexports_export); found none",
        )]


class CostAttributionTagMissing(_RepoRule):
    id = "REPO-070"
    title = "No cost attribution tag or cost category"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Decide how cost is attributed and tag for it: put a CostCenter, BusinessUnit or "
        "Project tag on every resource (CDK Tags.of(app), Terraform provider default_tags, "
        "CloudFormation stack tags), activate it as a cost allocation tag, or group costs "
        "with an AWS Cost Categories rule."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        workload = _in_production_iac(repo_path, _WORKLOAD)
        if not workload or _in_iac(repo_path, _COST_CATEGORY):
            return []
        if any(_COST_TAG.search(text) for _rel, text in iac_texts(repo_path)):
            return []
        places = [f"{kind} in {rel}" for kind, rel in workload.items()]
        return [self._finding(
            f"Declares {_listed(places)}; searched the IaC for a tag keyed CostCenter, "
            "BusinessUnit, Project, Product or CostCategory and for a cost category "
            "(AWS::CE::CostCategory, aws_ce_cost_category); found none",
        )]


class UnitCostMetricMissing(_RepoRule):
    id = "REPO-071"
    title = "No unit-cost metric for the workload"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Publish an organization metric that relates cost to the value the workload "
        "delivers, such as CostPerRequest, CostPerTenant or CostPerOrder, as a CloudWatch "
        "metric, metric filter or metric math label, and review it with the business."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_production_iac(repo_path, _COMPUTE)
        if not compute or unit_cost_metric(repo_path):
            return []
        places = [f"{kind} in {rel}" for kind, rel in compute.items()]
        return [self._finding(
            f"Runs {_listed(places, 4)}; searched the IaC and code for a metric name, metric "
            "filter, metric math label or embedded metric named like CostPerRequest or "
            "UnitCost; found none",
        )]


class CostNotAllocatedByWorkload(_RepoRule):
    id = "REPO-072"
    title = "Costs are not allocated by workload metrics"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Allocate cost by what the workload does: a CloudWatch metric math expression that "
        "divides a cost metric (EstimatedCharges or a published unit cost) by a workload "
        "metric such as RequestCount, Invocations or orders, on an alarm or dashboard."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_production_iac(repo_path, _COMPUTE)
        if not compute or cost_allocation_math(repo_path):
            return []
        places = [f"{kind} in {rel}" for kind, rel in compute.items()]
        return [self._finding(
            f"Runs {_listed(places, 4)}; searched the IaC for metric math that combines a "
            "cost metric (EstimatedCharges or a unit cost) with a workload metric; found none",
        )]


# COST 1: cloud financial management. Budget ownership (REPO-073), proactive cost monitoring
# (REPO-074), keeping up with new releases (REPO-075), business value per unit (REPO-076),
# and a cost-owner note for finance and technology (REPO-077), organizational processes
# (REPO-078) and culture (REPO-079).

_BUDGET_TYPE = "AWS::Budgets::Budget"
_CF_BUDGET = re.compile(_cf_type(r"Budgets::Budget"))
_TF_BUDGET = re.compile(r"resource\s+\"aws_budgets_budget\"\s+\"([^\"]+)\"\s*\{")
_CDK_BUDGET = re.compile(r"\bCfnBudget\(\s*\w+\s*,\s*['\"]([^'\"]+)['\"]")
_OWNER_KEY = r"(?:owner|cost[-_ ]?owner|team)"
_OWNER_TAG = re.compile(
    _tag_key(_OWNER_KEY).pattern + rf"|\bkey\s*=\s*['\"]{_OWNER_KEY}['\"]",
    re.IGNORECASE | re.MULTILINE,
)
_CDK_OWNER_TAG = re.compile(
    rf"\bTags\.of\([^()]*\)\.add\(\s*['\"]{_OWNER_KEY}['\"]", re.IGNORECASE
)
_SUBSCRIBER = re.compile(
    r"\bsubscriber_(?:email_addresses|sns_topic_arns)\s*=\s*(?!\[\s*\])\S"
    r"|\bsubscribers\s*[:=]\s*(?!\[\s*\])\S|\baddress\s*[:=]\s*\S"
)
_FORECASTED = re.compile(r"notification_?[tT]ype\s*[:=]\s*['\"]FORECASTED['\"]")
_ABSOLUTE = re.compile(r"threshold_?[tT]ype\s*[:=]\s*['\"]ABSOLUTE_VALUE['\"]")
_THRESHOLD_VALUE = re.compile(r"(?<![\w.])threshold\s*[:=]\s*([^\s,;)}\]]+)")
_ANOMALY_DETECTION = _kinds(
    ("Cost Anomaly Detection", _cf_type(r"CE::Anomaly(?:Monitor|Subscription)")
     + r"|resource\s+\"aws_ce_anomaly_(?:monitor|subscription)\""
     r"|\bCfnAnomaly(?:Monitor|Subscription)\("),
)
# A unit of business value: per request, tenant, order, user, customer or transaction.
_VALUE_UNIT = re.compile(
    r"(?:(?<![A-Za-z0-9])[Pp]er|(?<=[a-z])Per|PER)[-_ ]?"
    r"(?i:requests?|tenants?|orders?|users?|customers?|transactions?)(?![a-z])"
)


class _Budget:
    """A budget declared in IaC: where, whether it names an owner, whether it warns before
    spend reaches the limit, and its text (name, tags) for a unit of value."""

    def __init__(self, rel: str, name: str, line: int | None, owner: bool, early: bool,
                 text: str) -> None:
        self.rel, self.name, self.line = rel, name, line
        self.owner, self.early, self.text = owner, early, text


def _early_threshold(token: object, absolute: bool) -> bool:
    """A threshold that warns before 100 percent; one that is not a literal percentage
    (a parameter, or an absolute amount) is taken as an early warning."""
    if absolute:
        return True
    try:
        return float(str(token).strip("\"'")) < 100
    except ValueError:
        return True


def _cf_budget(rel: str, text: str, name: str, body: dict) -> _Budget:
    props = _props(body)
    tags = props.get("ResourceTags")
    owner = isinstance(tags, list) and any(
        isinstance(t, dict) and re.fullmatch(_OWNER_KEY, str(t.get("Key", "")), re.I)
        for t in tags
    )
    early = False
    entries = props.get("NotificationsWithSubscribers")
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        if entry.get("Subscribers"):
            owner = True
        note = entry.get("Notification")
        if not isinstance(note, dict):
            continue
        if note.get("NotificationType") == "FORECASTED" or _early_threshold(
            note.get("Threshold", 100), note.get("ThresholdType") == "ABSOLUTE_VALUE"
        ):
            early = True
    at = text.find(name)
    data = props.get("Budget")
    shown = data.get("BudgetName") if isinstance(data, dict) else None
    return _Budget(rel, shown if isinstance(shown, str) else name,
                   _line_of(text, at) if at >= 0 else None, owner, early, json.dumps(body))


def _text_budget(rel: str, text: str, name: str, at: int, block: str) -> _Budget:
    owner = bool(_OWNER_TAG.search(block) or _SUBSCRIBER.search(block)
                 or _CDK_OWNER_TAG.search(text))
    absolute = _ABSOLUTE.search(block) is not None
    early = bool(_FORECASTED.search(block)) or any(
        _early_threshold(token, absolute) for token in _THRESHOLD_VALUE.findall(block)
    )
    return _Budget(rel, name, _line_of(text, at), owner, early, block)


def budgets(repo_path: Path) -> List[_Budget]:
    """Every budget the IaC declares: CloudFormation AWS::Budgets::Budget, Terraform
    aws_budgets_budget and CDK CfnBudget."""
    found: List[_Budget] = []
    for rel, text in iac_texts(repo_path):
        if _CF_BUDGET.search(text):
            for name, body in _cf_resources(rel, text).items():
                if body.get("Type") == _BUDGET_TYPE:
                    found.append(_cf_budget(rel, text, name, body))
        for match in _TF_BUDGET.finditer(text):
            block = _braced(text, match.end() - 1)
            found.append(_text_budget(rel, text, match.group(1), match.start(), block))
        for match in _CDK_BUDGET.finditer(text):
            block = _braced(text, text.index("(", match.start()), "(", ")")
            found.append(_text_budget(rel, text, match.group(1), match.start(), block))
    return found


# Previous-generation types SUST-007 does not report (it reads t2, m3, m4, c3, c4, r3 and r4
# anywhere in a line), and Lambda runtimes past their deprecation date.
_SUST_LEGACY = re.compile(r"t2\.|m3\.|m4\.|c3\.|c4\.|r3\.|r4\.")
_SIZE = r"(?:nano|micro|small|medium|\d*x?large|metal)\b"
_OLD_TYPE = re.compile(
    rf"(?<![\w.-])(?:m1|m2|c1|t1|cc2|cg1|cr1|hi1|hs1|i2|d2|g2|g3s?|p2|x1e?)\.{_SIZE}"
    rf"|\bdb\.(?:m1|m2|m3|m4|r3|r4|t2)\.{_SIZE}"
    rf"|\bcache\.(?:m1|m2|m3|m4|r3|r4|t1|t2|c1)\.{_SIZE}"
    r"|\bInstanceClass\.(?:M1|M2|C1|T1|I2|D2|G2|G3S?|P2|X1E?)\b"
)
_OLD_RUNTIME = re.compile(
    r"\b[rR]untime[\"']?\s*[:=]\s*[\"']?"
    r"((?:nodejs1[246]\.x|python3\.[678]|java8|dotnetcore3\.1|go1\.x|ruby2\.7))(?![\w.])"
    r"|\bRuntime\.((?:NODEJS_1[246]_X|PYTHON_3_[678]|JAVA_8|DOTNET_CORE_3_1|GO_1_X"
    r"|RUBY_2_7))\b"
)


def old_generation(repo_path: Path) -> List[tuple[str, str, int]]:
    """(type or runtime, file, line) of each older instance type or deprecated runtime in
    production IaC that SUST-007 does not already report."""
    found: List[tuple[str, str, int]] = []
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        for match in _OLD_TYPE.finditer(text):
            if not _SUST_LEGACY.search(match.group(0)):
                found.append((match.group(0), rel, _line_of(text, match.start())))
        for match in _OLD_RUNTIME.finditer(text):
            found.append((match.group(1) or match.group(2), rel,
                          _line_of(text, match.start())))
    return found


# Notes: markdown and text files outside build output, tests and this tool's reports.
_NOTE_SUFFIXES = frozenset({".md", ".markdown", ".txt", ".rst", ".adoc"})
_REPORT_TITLE = "# AWS Architecture Review Report"
_HEADING = re.compile(r"^(#{1,6})[ \t]+(.+?)[ \t#]*$", re.MULTILINE)
_COST_NAME = re.compile(r"(?:^|[-_. ])(?:costs?|finops|spend(?:ing)?|budgets?)(?:$|[-_. ])")
_COST_HEADING = re.compile(
    r"(?i)(?:costs?|finops|cost (?:ownership|owners?|management)|budgets?)"
)
_OWNER_NAMED = re.compile(
    r"(?i)\b(?:owner|contact|responsible|accountable)s?\b[*_ \t]*"
    r"(?::|\||=|[ \t]-[ \t]|\bis\b|\bare\b)[*_ \t|]*"
    r"(?P<who>@[\w-]+|[\w.+-]+@[\w-]+\.\w[\w.]*|[A-Za-z][\w.-]*)"
)
_NOT_A_NAME = frozenset({
    "tbd", "todo", "none", "unknown", "n", "nobody", "unassigned", "not", "missing", "x",
    "xxx", "na", "pending",
})
_REVIEW_NAME = re.compile(
    r"(?:service|architecture|arch|well[-_ ]?architected|tech(?:nology)?)[-_ ]?reviews?"
)
_REVIEW_HEADING = re.compile(
    r"(?i)\b(?:service|architecture|well-architected|technology)\s+reviews?\b"
)
_DATE = re.compile(
    r"\b20\d\d-[01]\d-[0-3]\d\b|\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May"
    r"|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
    r"\s+20\d\d\b"
)
_PR_TEMPLATE_DIRS = (
    (".github", "pull_request_template"), (".gitlab", "merge_request_templates"),
)
_COST_CHECKBOX = re.compile(
    r"(?im)^\s*(?:[-*+]|\d+\.)\s+\[[ xX]\][^\n]*\b(?:costs?|budgets?|spend|finops)\b"
)


def note_texts(repo_path: Path) -> Iterator[tuple[str, str]]:
    """(repo-relative path, text) of each markdown or text note outside tests, skipping
    reports this tool saved."""
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if path.suffix.lower() not in _NOTE_SUFFIXES or _in_test_dir(parts):
            continue
        text = read_text_safe(path)
        if text.lstrip().startswith(_REPORT_TITLE) or _saved_report(text):
            continue
        yield "/".join(parts), text


def _sections(text: str, wanted: re.Pattern[str]) -> Iterator[str]:
    """The body under each heading that matches wanted, up to the next heading of the same
    or a higher level."""
    heads = list(_HEADING.finditer(text))
    for i, head in enumerate(heads):
        if not wanted.fullmatch(head.group(2).strip()):
            continue
        end = len(text)
        for nxt in heads[i + 1:]:
            if len(nxt.group(1)) <= len(head.group(1)):
                end = nxt.start()
                break
        yield text[head.end():end]


def _names_owner(text: str) -> bool:
    return any(
        match.group("who").lower().rstrip(".") not in _NOT_A_NAME
        for match in _OWNER_NAMED.finditer(text)
    )


def _cost_named(parts: tuple[str, ...]) -> bool:
    stem = parts[-1].lower().rsplit(".", 1)[0]
    return any(_COST_NAME.search(p) for p in (*(d.lower() for d in parts[:-1]), stem))


def cost_owner_note(repo_path: Path) -> str | None:
    """The first note that is about cost (COST.md, FINOPS.md, docs/cost*.md, or a README or
    docs heading "Cost", "FinOps" or "Cost ownership") and names an owner."""
    for rel, text in note_texts(repo_path):
        parts = tuple(rel.split("/"))
        if _cost_named(parts) and _names_owner(text):
            return rel
        docs = parts[-1].lower().startswith("readme") or any(
            d.lower() in ("docs", "doc") for d in parts[:-1]
        )
        if docs and any(_names_owner(s) for s in _sections(text, _COST_HEADING)):
            return rel
    return None


def service_review_note(repo_path: Path) -> str | None:
    """The first dated note whose name or heading reads as a service or architecture
    review."""
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        titled = _REVIEW_NAME.search(stem) or any(
            _REVIEW_HEADING.search(h.group(2)) for h in _HEADING.finditer(text)
        )
        if titled and _DATE.search(text):
            return rel
    return None


def cost_checklist(repo_path: Path) -> str | None:
    """The first pull or merge request template with a cost checklist item."""
    for rel, text in note_texts(repo_path):
        lowered = rel.lower()
        template = lowered.rsplit("/", 1)[-1].startswith("pull_request_template") or any(
            lowered.startswith(f"{root}/{sub}") for root, sub in _PR_TEMPLATE_DIRS
        )
        if template and _COST_CHECKBOX.search(text):
            return rel
    return None


_NOTE_SEARCH = (
    "searched the repo for a cost note (COST.md, FINOPS.md, docs/cost*.md, or a README or "
    "docs section headed Cost, FinOps or Cost ownership) that names an owner, contact, "
    "responsible or accountable person or team; found none"
)


def _workload_places(repo_path: Path) -> List[str]:
    return [f"{kind} in {rel}"
            for kind, rel in _in_production_iac(repo_path, _WORKLOAD).items()]


class BudgetOwnerMissing(_RepoRule):
    id = "REPO-073"
    title = "Budget has no named owner"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Give each budget an owner who acts on it: tag the budget with Owner, CostOwner or "
        "Team (CloudFormation ResourceTags, Terraform tags, CDK resourceTags or Tags.of) and "
        "subscribe that person or team to its notifications by email or SNS topic."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        unowned = [b for b in budgets(repo_path) if not b.owner]
        if not unowned:
            return []
        first = unowned[0]
        places = [f"{b.name} in {b.rel}" for b in unowned]
        return [self._finding(
            f"Budget {_listed(places)} has no Owner, CostOwner or Team tag and no "
            "notification subscriber, so no one is named to act on its spend",
            file=first.rel, line=first.line,
        )]


class ReactiveCostMonitoring(_RepoRule):
    id = "REPO-074"
    title = "Cost is only watched after the budget is spent"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Watch cost before it is spent: add a FORECASTED budget notification or an ACTUAL "
        "one below 100 percent (80 percent is common), and turn on Cost Anomaly Detection "
        "with an anomaly monitor and subscription."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = budgets(repo_path)
        if not found or any(b.early for b in found):
            return []
        if _in_iac(repo_path, _ANOMALY_DETECTION):
            return []
        first = found[0]
        places = [f"{b.name} in {b.rel}" for b in found]
        return [self._finding(
            f"Budget {_listed(places)} notifies only at 100 percent or more of actual spend "
            "(no FORECASTED notification, no threshold below 100); searched the IaC for "
            "Cost Anomaly Detection (AWS::CE::AnomalyMonitor, aws_ce_anomaly_monitor); "
            "found none",
            file=first.rel, line=first.line,
        )]


class OldGenerationResources(_RepoRule):
    id = "REPO-075"
    title = "Workload uses a previous-generation type or deprecated runtime"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Review new AWS releases on a schedule and move off previous-generation instance, "
        "database and cache types and deprecated Lambda runtimes; record each review in a "
        "dated service review note."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = old_generation(repo_path)
        if not found or service_review_note(repo_path):
            return []
        _kind, rel, line = found[0]
        places = [f"{kind} in {where}:{at}" for kind, where, at in found]
        return [self._finding(
            f"Uses {_listed(places, 4)}; searched the repo for a dated service or "
            "architecture review note; found none",
            file=rel, line=line,
        )]


class BusinessValueUnquantified(_RepoRule):
    id = "REPO-076"
    title = "Spend is not tied to a unit of business value"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "State what the spend buys: name a budget per unit of value (per request, tenant, "
        "order or user) or publish a unit-cost metric such as CostPerOrder, and report it "
        "with the business outcome it supports."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute = _in_production_iac(repo_path, _COMPUTE)
        if not compute or unit_cost_metric(repo_path):
            return []
        if any(_VALUE_UNIT.search(b.text) for b in budgets(repo_path)):
            return []
        places = [f"{kind} in {rel}" for kind, rel in compute.items()]
        return [self._finding(
            f"Runs {_listed(places, 4)}; searched the IaC for a budget named per request, "
            "tenant, order, user or transaction and for a unit-cost metric; found none",
        )]


class FinanceTechPartnershipMissing(_RepoRule):
    id = "REPO-077"
    title = "No named cost owner links finance and engineering"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Write down who owns this workload's cost with finance: a COST.md or a Cost section "
        "in the README that names the engineering owner and the finance contact, and how "
        "often they review spend together."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places = _workload_places(repo_path)
        if not places or cost_owner_note(repo_path):
            return []
        return [self._finding(
            f"Declares {_listed(places)}; no finance or engineering contact is named: "
            f"{_NOTE_SEARCH}",
        )]


class CostAwareProcessMissing(_RepoRule):
    id = "REPO-078"
    title = "Cost is not part of the change process"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Make cost a step in how changes are made: add a cost checklist item to the pull "
        "request template (expected cost impact, budget checked) or a COST.md that names "
        "who reviews cost for changes."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places = _workload_places(repo_path)
        if not places or cost_checklist(repo_path) or cost_owner_note(repo_path):
            return []
        return [self._finding(
            f"Declares {_listed(places)}; searched pull and merge request templates for a "
            f"cost checklist item; found none; {_NOTE_SEARCH}",
        )]


class CostAwareCultureMissing(_RepoRule):
    id = "REPO-079"
    title = "No cost guidance for the team"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Give the team a place to learn what the workload costs: a COST.md or FINOPS.md "
        "that names the cost owner, links the cost dashboards and budgets, and shares cost "
        "wins and goals."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places = _workload_places(repo_path)
        if not places or cost_owner_note(repo_path):
            return []
        return [self._finding(
            f"Declares {_listed(places)}; the team has no shared cost guidance: "
            f"{_NOTE_SEARCH}",
        )]


# COST 2: usage governance. Cost policies (REPO-080, account-level), cost controls
# (REPO-081), goals and targets (REPO-082), account structure (REPO-083), billing access
# through groups and roles (REPO-084), and project lifecycle tags (REPO-085).

_DENY = re.compile(
    r"[\"']?[eE]ffect[\"']?\s*[:=]\s*[\"']Deny[\"']|\bEffect\.DENY\b"
)
_EXPENSIVE = re.compile(
    r"[\"']?(?:ec2:RunInstances|sagemaker:Create[\w*]*|ec2:InstanceType|sagemaker:InstanceTypes"
    r"|rds:DatabaseClass|aws:RequestedRegion)[\"']?"
)
# How far around a Deny the action or condition key may sit: one policy statement.
_DENY_WINDOW = 600
_BUDGET_ACTION = re.compile(
    _cf_type(r"Budgets::BudgetsAction") + r"|resource\s+\"aws_budgets_budget_action\""
    r"|\bCfnBudgetsAction\("
)
_COST_POLICY_SEARCH = (
    "a service control policy or a policy that Denies ec2:RunInstances or "
    "sagemaker:Create* or sets a condition on ec2:InstanceType, sagemaker:InstanceTypes, "
    "rds:DatabaseClass or aws:RequestedRegion"
)


def cost_policies(repo_path: Path) -> dict[str, str]:
    """Policies that govern what may be spent: kind -> first file. A service control
    policy, or any policy that Denies an expensive choice (instance types, regions)."""
    found: dict[str, str] = {}
    scp = org_guardrails(repo_path).get("service control policy")
    if scp:
        found["service control policy"] = scp
    for rel, text in iac_texts(repo_path):
        for match in _DENY.finditer(text):
            near = text[max(match.start() - _DENY_WINDOW, 0):match.end() + _DENY_WINDOW]
            if _EXPENSIVE.search(near):
                found.setdefault("cost deny policy", rel)
                break
    return found


class CostPolicyMissing(_RepoRule):
    id = "REPO-080"
    title = "No policy governs what the organization may spend"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Turn the organization's cost rules into policy: a service control policy or a "
        "permissions boundary that Denies instance types, database classes and Regions the "
        "organization has not approved (conditions on ec2:InstanceType, rds:DatabaseClass, "
        "sagemaker:InstanceTypes and aws:RequestedRegion)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places = _workload_places(repo_path)
        if not places or cost_policies(repo_path):
            return []
        return [self._finding(
            f"Declares {_listed(places)}; searched the IaC for {_COST_POLICY_SEARCH}; "
            "found none",
        )]


class CostControlMissing(_RepoRule):
    id = "REPO-081"
    title = "Nothing limits what the workload can spend"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Put a control in front of spend: a permissions boundary on the workload's roles "
        "or a service control policy that Denies unapproved instance types and Regions, or "
        "an AWS Budgets action that applies a deny policy or stops instances when a budget "
        "is exceeded."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places = _workload_places(repo_path)
        if not places or cost_policies(repo_path):
            return []
        for _rel, text in iac_texts(repo_path):
            if _BOUNDARY.search(text) or _BUDGET_ACTION.search(text):
                return []
        return [self._finding(
            f"Declares {_listed(places)}; searched the IaC for {_COST_POLICY_SEARCH}, a "
            "permissions boundary (PermissionsBoundary, permissions_boundary, CDK "
            "PermissionsBoundary.of) and an AWS Budgets action (AWS::Budgets::BudgetsAction, "
            "aws_budgets_budget_action, CfnBudgetsAction); found none",
        )]


_BUDGET_TARGET = re.compile(
    r"\b(?:budget_?limit|limit_amount|planned_?budget_?limits|planned_limit)\b", re.IGNORECASE
)


class BudgetTargetMissing(_RepoRule):
    id = "REPO-082"
    title = "Budget sets no target amount"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Give each budget a goal: set a limit amount (BudgetLimit, limit_amount, "
        "budgetLimit) or planned limits per period, agreed with the cost owner, and review "
        "it as usage changes."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = budgets(repo_path)
        if not found or any(_BUDGET_TARGET.search(b.text) for b in found):
            return []
        first = found[0]
        places = [f"{b.name} in {b.rel}" for b in found]
        return [self._finding(
            f"Budget {_listed(places)} sets no limit amount (BudgetLimit, limit_amount, "
            "budgetLimit) and no planned limits (PlannedBudgetLimits, planned_limit)",
            file=first.rel, line=first.line,
        )]


_ACCOUNT_ID = re.compile(
    r"\b(?i:account(?:_?id)?)[\"']?\s*[:=]\s*[\"'](\d{12})[\"']"
    r"|\barn:aws[\w-]*:iam::(\d{12}):role/"
)
_ALLOWED_ACCOUNTS = re.compile(r"\ballowed_account_ids\s*=\s*\[([^\]]*)\]")
_STACKSET_TARGETS = re.compile(
    r"[\"']?(?:DeploymentTargets|deploymentTargets|deployment_targets)[\"']?\s*[:=]"
)
_TF_WORKSPACE = re.compile(r"\bterraform\.workspace\s*==\s*\"([\w-]+)\"")


def account_split(repo_path: Path) -> str | None:
    """What shows that environments run in separate accounts, or None."""
    ids: set[str] = set()
    texts = list(iac_texts(repo_path))
    for path in walk(repo_path):
        if path.name.lower().endswith((".tfvars", ".tfvars.json")):
            parts = _rel_parts(path, repo_path)
            if not _in_test_dir(parts):
                texts.append(("/".join(parts), read_text_safe(path)))
    for rel, text in texts:
        if _ORG_UNITS.search(text):
            return f"Organizations account or OU in {rel}"
        if _STACKSET_TARGETS.search(text):
            return f"StackSets deployment targets in {rel}"
        for match in _ACCOUNT_ID.finditer(text):
            ids.add(match.group(1) or match.group(2))
        for match in _ALLOWED_ACCOUNTS.finditer(text):
            ids.update(re.findall(r"\d{12}", match.group(1)))
    if len(ids) >= 2:
        return f"{len(ids)} account ids"
    return None


def deployed_environments(repo_path: Path) -> dict[str, str]:
    """Environments as REPO-003 finds them, plus Terraform workspace names compared in code."""
    found = environments_found(repo_path)
    for rel, text in iac_texts(repo_path):
        if rel.endswith(".tf"):
            for match in _TF_WORKSPACE.finditer(text):
                env = from_words(match.group(1))
                if env is not None:
                    found.setdefault(env, f"{rel} workspace {match.group(1)}")
    return found


class SharedAccountEnvironments(_RepoRule):
    id = "REPO-083"
    title = "Production and non-production share an account"
    category = "Cost"
    severity = "Medium"
    themes = ("finops",)
    recommendation = (
        "Run production and non-production in separate AWS accounts under AWS "
        "Organizations, with one OU per environment, so cost, quotas and access are kept "
        "apart: set a literal account per CDK stage, a provider assume_role or "
        "allowed_account_ids per Terraform environment, or StackSets deployment targets."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = deployed_environments(repo_path)
        if "prod" not in found or not ({"dev", "staging"} & found.keys()):
            return []
        if not _in_iac(repo_path, _WORKLOAD):
            return []
        if account_split(repo_path):
            return []
        seen = ", ".join(f"{env} ({where})" for env, where in sorted(found.items()))
        return [self._finding(
            f"Deploys {seen}; searched the IaC for Organizations accounts or OUs, StackSets "
            "deployment targets, and distinct literal account ids (CDK env account, "
            "Terraform assume_role role_arn or allowed_account_ids); found fewer than two",
        )]


_BILLING = re.compile(
    r"[\"'](?:aws-portal|billing|ce|budgets|cur):[\w*]+[\"']"
    r"|[\"']account:\w*Billing\w*[\"']"
    r"|\bjob-function/Billing\b|\bAWSBillingReadOnlyAccess\b"
)
_CDK_USER = re.compile(
    r"\b(\w+)\s*=\s*(?:new\s+)?iam\.User\(|(?<![\w.])(?:new\s+)?iam\.User\("
)
_CDK_USER_GRANT = r"\b{var}\.(?:add_?[mM]anaged_?[pP]olicy|add_?[tT]o_?(?:[pP]rincipal_?)?" \
    r"[pP]olicy|attach_?[iI]nline_?[pP]olicy)\("
_TF_USER_GRANT = re.compile(
    r"resource\s+\"(aws_iam_user_policy(?:_attachment)?)\"\s+\"([^\"]+)\"\s*\{"
)
_TF_IAM_POLICY_REF = re.compile(
    r"\b(data\.aws_iam_policy_document|aws_iam_policy)\.([\w-]+)\."
)


def _tf_named_block(text: str, ref: str, name: str) -> str:
    kind = "data" if ref.startswith("data.") else "resource"
    block_type = ref.split(".")[-1]
    match = re.search(rf"{kind}\s+\"{block_type}\"\s+\"{re.escape(name)}\"\s*\{{", text)
    return _braced(text, match.end() - 1) if match else ""


def _cdk_named(text: str, ident: str) -> str:
    """The constructor call a CDK variable is assigned, e.g. a Policy for attachInlinePolicy."""
    match = re.search(rf"\b{re.escape(ident)}\s*=\s*(?:new\s+)?[\w.]+\(", text)
    return _braced(text, match.end() - 1, "(", ")") if match else ""


def user_billing_grants(repo_path: Path) -> List[tuple[str, str, int]]:
    """(IAM user, file, line) for each user granted billing access directly."""
    found: List[tuple[str, str, int]] = []
    for rel, text in iac_texts(repo_path):
        for name, body in _cf_resources(rel, text).items():
            kind, props = body.get("Type"), _props(body)
            granted = (
                kind == "AWS::IAM::User"
                and _BILLING.search(json.dumps([props.get("Policies"),
                                                props.get("ManagedPolicyArns")]))
            ) or (
                kind in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy") and props.get("Users")
                and _BILLING.search(json.dumps(props.get("PolicyDocument")))
            )
            if granted:
                at = text.find(f'"{name}"')
                at = at if at >= 0 else text.find(name)
                found.append((name, rel, _line_of(text, at)))
        for match in _TF_USER_GRANT.finditer(text):
            block = _braced(text, match.end() - 1)
            linked = "".join(_tf_named_block(text, ref, name)
                             for ref, name in _TF_IAM_POLICY_REF.findall(block))
            if _BILLING.search(block + linked):
                found.append((f"{match.group(1)}.{match.group(2)}", rel,
                              _line_of(text, match.start())))
        for match in _CDK_USER.finditer(text):
            args = _braced(text, text.index("(", match.start()), "(", ")")
            grants = [args]
            var = match.group(1)
            if var:
                for call in re.finditer(_CDK_USER_GRANT.format(var=re.escape(var)), text):
                    arg = _braced(text, call.end() - 1, "(", ")")
                    grants.append(arg + _cdk_named(text, arg.strip()))
            if any(_BILLING.search(g) for g in grants):
                found.append((var or "iam.User", rel, _line_of(text, match.start())))
    return found


class BillingAccessOnUser(_RepoRule):
    id = "REPO-084"
    title = "Billing access is granted to an IAM user"
    category = "Cost"
    severity = "Low"
    themes = ("identity",)
    recommendation = (
        "Grant billing and cost access through groups or roles, not to individual IAM "
        "users: put the Billing or AWSBillingReadOnlyAccess policy on an IAM group or an "
        "IAM Identity Center permission set for the finance and cost owner roles."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = user_billing_grants(repo_path)
        if not found:
            return []
        _user, rel, line = found[0]
        places = [f"{user} in {where}:{at}" for user, where, at in found]
        return [self._finding(
            f"Grants billing access (aws-portal, billing, ce, budgets or cur actions, or a "
            f"Billing managed policy) directly to {_listed(places)}",
            file=rel, line=line,
        )]


# Long-lived dev and staging environments are not temporary; these names are.
_TEMP_WORDS = frozenset({
    "preview", "ephemeral", "feature", "sandbox", "test", "tmp", "temp", "scratch", "demo",
    "poc", "spike", "experiment",
})
_DECLARES = re.compile(
    _cf_type(r"\w+::\w+") + r"|resource\s+\"aws_\w+\"|\b\w*(?:Stack|Stage)\("
    # A CDK construct: new s3.Bucket(this, ...), s3.Bucket(self, ...).
    r"|\b\w+\.[A-Z]\w*\(\s*(?:this|self|scope)\s*,"
)
_END_DATE_TAG = _tag_key(
    r"(?:expiry[-_ ]?date|expiry|expires|expiration|end[-_ ]?date|delete[-_ ]?after|ttl)"
)
_ENV_TAG = _tag_key(r"(?:environment|env|stage)")


def _temporary(name: str) -> bool:
    env = from_words(name)
    if env == "prod":
        return False
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).lower()
    if _TEMP_WORDS & set(re.split(r"[^a-z0-9]+", spaced)):
        return True
    # A pull request preview: pr-12, pr12, PR_12.
    return re.search(r"(?:^|[^a-z0-9])pr[-_]?\d+(?![a-z])", spaced) is not None


def temporary_stacks(repo_path: Path) -> List[tuple[str, bool, bool]]:
    """(place, has end-date tag, has environment tag) for each temporary stack. Tags count
    when set in the stack's file or in an IaC file in the same directory."""
    texts = list(iac_texts(repo_path))
    by_dir: dict[str, str] = {}
    for rel, text in texts:
        by_dir[rel.rpartition("/")[0]] = by_dir.get(rel.rpartition("/")[0], "") + "\n" + text
    found: List[tuple[str, bool, bool]] = []
    for rel, text in texts:
        if not _DECLARES.search(text):
            continue
        places = [rel] if _temporary(rel) else [
            f"{rel} stack {m.group(2)}" for m in _STACK_ID.finditer(text)
            if rel.endswith((".ts", ".js", ".py")) and _temporary(m.group(2))
        ]
        if not places:
            continue
        tags = text if not _temporary(rel) else by_dir[rel.rpartition("/")[0]]
        end, env = bool(_END_DATE_TAG.search(tags)), bool(_ENV_TAG.search(tags))
        found.extend((place, end, env) for place in places)
    return found


class ProjectLifecycleUntracked(_RepoRule):
    id = "REPO-085"
    title = "Temporary stacks have no end date"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Tag every temporary stack (sandbox, test, preview, feature branch, pull request) with an "
        "end date (ExpiryDate or DeleteAfter) and its environment, and remove or review "
        "stacks past that date on a schedule."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        untracked = []
        for place, end, env in temporary_stacks(repo_path):
            missing = [what for what, has in (("end-date", end), ("environment", env))
                       if not has]
            if missing:
                untracked.append(f"{place} (no {' or '.join(missing)} tag)")
        if not untracked:
            return []
        return [self._finding(
            f"Temporary stack {_listed(untracked, 4)}; an end-date tag is keyed ExpiryDate, "
            "Expiry, Expires, Expiration, EndDate, DeleteAfter or ttl, an environment tag "
            "Environment, Env or Stage",
        )]


# COST 4: decommissioning. Tracking resources over their lifetime (REPO-086) and a
# decommissioning process for temporary environments (REPO-087).

_CREATED_BY_TAG = _tag_key(r"(?:created[-_ ]?by|managed[-_ ]?by|creator|iac)")
# Terraform modules and some resources take source, repository and repo arguments, so a
# lowercase unquoted one is not a tag; a quoted or capitalized key is.
_SOURCE_KEY = r"(?i:source|repository|repo)"
_SOURCE_TAG = re.compile(
    rf"[\"']?Key[\"']?\s*:\s*[\"']?{_SOURCE_KEY}[\"']?\s*(?:,|$)"
    rf"|^\s*(?:[\"']{_SOURCE_KEY}[\"']|Source|Repository|Repo|SOURCE|REPOSITORY|REPO)"
    r"\s*=\s*\S"
    rf"|\.add\(\s*['\"]{_SOURCE_KEY}['\"]"
    rf"|[{{,]\s*[\"']?{_SOURCE_KEY}[\"']?\s*:\s*['\"]",
    re.MULTILINE,
)
_PR_TRIGGER = re.compile(
    r"^\s*(?:-\s*)?[\"']?pull_request(?:_target)?[\"']?\s*:?\s*(?:#.*)?$"
    r"|^\s*[\"']?on[\"']?\s*:[^\n]*\bpull_request",
    re.MULTILINE,
)
_ENV_DEPLOY = re.compile(
    r"\bcdk\s+deploy\b|\bterraform(?:\s+-chdir=\S+)?\s+apply\b(?![^\n]*\s-destroy\b)"
    r"|\bsam\s+deploy\b|\baws\s+cloudformation\s+(?:deploy|create-stack)\b"
    r"|\b(?:serverless|sls)\s+deploy\b"
)
# A deploy limited to pushes or to one branch is not a per-pull-request environment.
_MAIN_ONLY = re.compile(
    r"github\.event_name\s*==\s*['\"]push['\"]|github\.ref\s*==\s*['\"]refs/heads/"
)
_REVIEW_ENV = re.compile(r"^\s*(?:environment|name)\s*:\s*[\"']?review/", re.MULTILINE)
_TEARDOWN = _kinds(
    ("cdk destroy", r"\bcdk\s+destroy\b"),
    ("terraform destroy",
     r"\bterraform(?:\s+-chdir=\S+)?\s+(?:destroy\b|apply\b[^\n]*\s-destroy\b)"
     r"|\bterragrunt\s+(?:run-all\s+)?destroy\b"),
    ("sam delete", r"\bsam\s+delete\b"),
    ("aws cloudformation delete-stack", r"\baws\s+cloudformation\s+delete-stack\b"),
    ("serverless remove", r"\b(?:serverless|sls)\s+remove\b"),
    ("GitLab stop job", r"\bon_stop\s*:|\baction\s*:\s*[\"']?stop\b"),
)
_CLEANUP_WORD = re.compile(
    r"(?i)(?:clean[-_ ]?up|tear[-_ ]?down|decommission|expire[ds]?(?![a-z])|nuke)"
)
_NUKE_CONFIG = re.compile(r"(?:aws[-_.])?nuke[\w.-]*\.ya?ml")
_DECOMMISSION_NAME = re.compile(
    r"(?:^|[-_. ])(?:decommission\w*|tear[-_]?down|clean[-_]?up|offboarding)(?:$|[-_. ])"
)
_DECOMMISSION_HEADING = re.compile(
    r"(?i).*\b(?:decommission\w*|tear[- ]?down|clean[- ]?up|offboarding)\b.*"
)
# A note describes the process when it says what is removed and how.
_DECOMMISSION_STEP = re.compile(
    r"(?i)\b(?:destroy|delete|remove|tear[- ]?down|terminate|nuke|decommission)\w*"
)


def created_environments(repo_path: Path) -> List[str]:
    """Places that create review or temporary environments: temporary stacks (as REPO-085),
    GitHub workflows that deploy on pull requests, and GitLab review environments."""
    places = [place for place, _end, _env in temporary_stacks(repo_path)]
    for rel, text in build_texts(repo_path):
        lowered = rel.lower()
        if lowered.startswith(".github/workflows/"):
            if (_PR_TRIGGER.search(text) and _ENV_DEPLOY.search(text)
                    and not _MAIN_ONLY.search(text)):
                places.append(f"{rel} (deploys on pull requests)")
        elif lowered.endswith(".gitlab-ci.yml") and _REVIEW_ENV.search(text):
            places.append(f"{rel} (review/ environment)")
    return places


def decommissioning(repo_path: Path) -> dict[str, str]:
    """Each way the repo tears environments down: kind -> first place."""
    _builds, found = _tools_in_builds(repo_path, _TEARDOWN)
    scheduled = [(rel, text) for rel, text in iac_texts(repo_path) if _SCHEDULE.search(text)]
    cleanup = next((rel for rel, text in scheduled if _CLEANUP_WORD.search(text)), None)
    if cleanup is None and scheduled and any(
        _CLEANUP_WORD.search(text) for _rel, _name, text in _function_code(repo_path)
    ):
        cleanup = scheduled[0][0]
    if cleanup:
        found.setdefault("scheduled cleanup", cleanup)
    for path in walk(repo_path):
        if _NUKE_CONFIG.fullmatch(path.name.lower()):
            found.setdefault("aws-nuke config", "/".join(_rel_parts(path, repo_path)))
            break
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        if (_DECOMMISSION_NAME.search(stem) and _DECOMMISSION_STEP.search(text)) or any(
            _DECOMMISSION_STEP.search(s) for s in _sections(text, _DECOMMISSION_HEADING)
        ):
            found.setdefault("decommissioning note", rel)
            break
    return found


class ResourceLifetimeUntracked(_RepoRule):
    id = "REPO-086"
    title = "Resources are not tagged with who created and owns them"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Tag every resource with where it came from and who owns it, so you can find "
        "and remove what is no longer used: a CreatedBy, ManagedBy or Repository tag and an "
        "Owner or Team tag (CDK Tags.of(app), Terraform provider default_tags, "
        "CloudFormation stack tags)."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places = _workload_places(repo_path)
        if not places:
            return []
        texts = [text for _rel, text in iac_texts(repo_path)]
        created = any(_CREATED_BY_TAG.search(t) or _SOURCE_TAG.search(t) for t in texts)
        owner = any(_OWNER_TAG.search(t) for t in texts)
        missing = [what for what, has in (("created-by", created), ("owner", owner))
                   if not has]
        if not missing:
            return []
        return [self._finding(
            f"Declares {_listed(places)}; no {' or '.join(missing)} tag in the IaC. A "
            "created-by tag is keyed CreatedBy, ManagedBy, Creator, Source, Repository, Repo "
            "or IaC, an owner tag Owner, CostOwner or Team",
        )]


class DecommissioningMissing(_RepoRule):
    id = "REPO-087"
    title = "Nothing tears down temporary environments"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Remove review and temporary environments when they are done: a CI job that runs "
        "cdk destroy, terraform destroy, sam delete or aws cloudformation delete-stack when "
        "the pull request closes (a GitLab environment with on_stop), a scheduled cleanup "
        "of stacks past their end date, or a written decommissioning procedure."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        created = created_environments(repo_path)
        if not created or decommissioning(repo_path):
            return []
        return [self._finding(
            f"Creates temporary environments: {_listed(created, 4)}; searched CI for cdk "
            "destroy, terraform destroy, sam delete, aws cloudformation delete-stack, "
            "serverless remove or a GitLab on_stop job, the IaC for a scheduled cleanup, "
            "the repo for an aws-nuke config and a decommissioning note; found none",
        )]


# COST 6: resource type, size and number. Cost modeling (REPO-088) and shared resources
# (REPO-089).

_INFRACOST_CI = _kinds(("infracost", r"\binfracost\s+(?:breakdown|diff|comment)\b"))
_INFRACOST_CONFIG = re.compile(r"infracost(?:-usage)?\.ya?ml")
_COST_TOOL_CONFIG = re.compile(
    r"cdk-cost[\w.-]*\.(?:json|ya?ml)|\.?cost[-_]estimate[\w.-]*\.(?:json|ya?ml)"
)
_ESTIMATE_NAME = re.compile(
    r"(?:^|[-_. ])(?:cost[-_]?(?:estimates?|models?|modell?ing)|pricing|estimates?)(?:$|[-_. ])"
)
_ESTIMATE_HEADING = re.compile(
    r"(?i).*\b(?:cost[- ](?:estimates?|models?|modell?ing)|estimated[- ]costs?|pricing)\b.*"
)
# An estimate states an amount or links the AWS Pricing Calculator.
_CURRENCY_AMOUNT = re.compile(
    r"[$€£]\s?\d[\d,]*(?:\.\d+)?"
    r"|\b(?:USD|EUR|GBP)\s?\d[\d,]*(?:\.\d+)?"
    r"|\b\d[\d,]*(?:\.\d+)?\s?(?:USD|EUR|GBP)\b"
    r"|\bcalculator\.aws\b"
)


def cost_estimates(repo_path: Path) -> dict[str, str]:
    """Each kind of cost estimate the repo holds: kind -> first place."""
    _builds, found = _tools_in_builds(repo_path, _INFRACOST_CI)
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        name = path.name.lower()
        rel = "/".join(parts)
        if _INFRACOST_CONFIG.fullmatch(name) or ".infracost" in parts[:-1]:
            found.setdefault("Infracost config", rel)
        elif _COST_TOOL_CONFIG.fullmatch(name):
            found.setdefault("cost-estimate config", rel)
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        if (_ESTIMATE_NAME.search(stem) and _CURRENCY_AMOUNT.search(text)) or any(
            _CURRENCY_AMOUNT.search(s) for s in _sections(text, _ESTIMATE_HEADING)
        ):
            found.setdefault("cost estimate note", rel)
            break
    return found


_OWN_SHAREABLE = _kinds(
    ("VPC", _cf_type(r"EC2::VPC") + r"|resource\s+\"aws_vpc\""
     r"|\bec2\.(?:Vpc|CfnVPC)\(|\bnew\s+(?:Vpc|CfnVPC)\("),
    ("ECS cluster", _cf_type(r"ECS::Cluster") + r"|resource\s+\"aws_ecs_cluster\""
     r"|\becs\.(?:Cfn)?Cluster\("),
    ("EKS cluster", _cf_type(r"EKS::Cluster") + r"|resource\s+\"aws_eks_cluster\""
     r"|\beks\.(?:Cfn)?Cluster\("),
)
_SHARED = _kinds(
    ("looked-up or imported resource",
     r"\bVpc\.(?:fromLookup|fromVpcAttributes|from_lookup|from_vpc_attributes)\("
     r"|\bCluster\.(?:fromClusterAttributes|fromClusterArn|from_cluster_attributes"
     r"|from_cluster_arn)\("
     r"|\bBucket\.(?:fromBucket(?:Name|Arn|Attributes)|from_bucket_(?:name|arn|attributes))\("
     r"|\bSubnet\.(?:fromSubnetId|from_subnet_id)\("
     r"|\bdata\s+\"aws_(?:vpc|subnets?|ecs_cluster|eks_cluster|s3_bucket)\""
     r"|\bterraform_remote_state\b"
     r"|Fn::ImportValue|!ImportValue\b"
     r"|AWS::SSM::Parameter::Value<\s*AWS::EC2::VPC::Id\s*>"),
    ("AWS RAM share", _cf_type(r"RAM::ResourceShare")
     + r"|resource\s+\"aws_ram_resource_(?:share|association)\""
     r"|\bram\.CfnResourceShare\("),
)
_TENANCY_TAG = _tag_key(r"(?:tenancy|tenant[-_ ]?model)")
_SINGLE_VALUE = re.compile(r"(?i)\b(?:single|dedicated)\b")
_SINGLE_TENANT_COMMENT = re.compile(
    r"(?i)(?://|#|/\*|^\s*\*)[^\n]*\b(?:single[- ]tenant|dedicated by design)\b",
    re.MULTILINE,
)


def _single_tenant(text: str) -> bool:
    """A Tenancy or tenant-model tag set to single or dedicated, or a comment that says the
    workload is single-tenant on purpose."""
    if _SINGLE_TENANT_COMMENT.search(text):
        return True
    for match in _TENANCY_TAG.finditer(text):
        value = "\n".join(text[match.end():match.end() + 120].split("\n")[:2])
        if _SINGLE_VALUE.search(value):
            return True
    return False


def shared_resources(repo_path: Path) -> dict[str, str]:
    """What the IaC shares or says about single tenancy: kind -> first file."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        for name, pattern in _SHARED:
            if pattern.search(text):
                found.setdefault(name, rel)
        if _single_tenant(text):
            found.setdefault("single tenancy", rel)
    return found


class CostModelMissing(_RepoRule):
    id = "REPO-088"
    title = "No cost estimate for the workload"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Estimate what the workload costs before you choose types, sizes and counts: run "
        "Infracost in CI (infracost breakdown or diff) or write a cost estimate in the repo "
        "with the expected monthly amount or an AWS Pricing Calculator link, and update it "
        "when the architecture changes."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places = _workload_places(repo_path)
        if not places or cost_estimates(repo_path):
            return []
        return [self._finding(
            f"Declares {_listed(places)}; searched CI for infracost breakdown, diff or "
            "comment, the repo for an Infracost or cost-estimate config, and notes named or "
            "headed cost estimate, cost model, estimated cost or pricing that give an amount "
            "or a Pricing Calculator link; found none",
        )]


class SharedResourcesUnused(_RepoRule):
    id = "REPO-089"
    title = "Workload creates its own network or cluster instead of sharing"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Share what several workloads can use: look up a shared VPC or cluster "
        "(Vpc.fromLookup, Terraform data sources or remote state, CloudFormation "
        "ImportValue) or share it through AWS RAM. If the workload must be single-tenant, "
        "say so with a Tenancy tag of single or dedicated."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        own = _in_production_iac(repo_path, _OWN_SHAREABLE)
        if not own or shared_resources(repo_path):
            return []
        created = [f"{kind} in {rel}" for kind, rel in own.items()]
        return [self._finding(
            f"Creates its own {_listed(created)}; searched the IaC for a looked-up or "
            "imported VPC, subnet, cluster or bucket (fromLookup, from*Attributes, Terraform "
            "data sources or remote state, ImportValue, an SSM VPC id parameter), an AWS RAM "
            "share, and a Tenancy tag or single-tenant comment; found none",
        )]


# COST 7: pricing models. Pricing model analysis (REPO-090), Region by cost (REPO-091),
# third-party terms (REPO-092) and management-account pricing (REPO-093).

_CF_PRICED_FLEET = {
    "AWS::EKS::Nodegroup": "EKS node group",
    "AWS::Batch::ComputeEnvironment": "Batch compute environment",
}
_CF_PRICED_FLEET_TYPE = re.compile(_cf_type(r"EKS::Nodegroup|Batch::ComputeEnvironment"))
_TF_PRICED_FLEET = re.compile(
    r"resource\s+\"(aws_eks_node_group|aws_batch_compute_environment)\"\s+\"([^\"]+)\""
)
_CDK_PRICED_FLEET = re.compile(
    r"\b(?:new\s+)?(?:\w+\.)?(Nodegroup|CfnNodegroup|ManagedEc2EcsComputeEnvironment"
    r"|ManagedEc2EksComputeEnvironment|FargateComputeEnvironment|CfnComputeEnvironment)"
    + _CDK_ID
    + r"|\.add_?[nN]odegroup_?[cC]apacity\(\s*['\"]([^'\"]+)['\"]"
)
_FLEET_KIND = {
    "ecs": "ECS service", "asg": "Auto Scaling group",
    "aws_eks_node_group": "EKS node group", "Nodegroup": "EKS node group",
    "CfnNodegroup": "EKS node group",
}
# A Spot setting anywhere in production IaC: mixed instances below 100 percent on demand, a
# Spot allocation strategy, a launch template market type of spot, a Spot price, a
# FARGATE_SPOT capacity provider, an EKS or Batch SPOT capacity type, or Spot draining.
_SPOT = re.compile(
    r"(?i:on_?demand_?percentage_?above_?base_?capacity)[\"']?\s*[:=]\s*[\"']?"
    r"(?!100\b)\d{1,2}\b"
    r"|(?i:spot_?allocation_?strategy)[\"']?\s*[:=]"
    r"|(?i:market_?type)[\"']?\s*[:=]\s*[\"']?(?i:spot)\b"
    r"|(?i:spot_?price)[\"']?\s*[:=]"
    r"|(?:[\"']|[:=]\s*)FARGATE_SPOT\b"
    r"|(?i:capacity_?type)[\"']?\s*[:=]\s*(?:[\"']|(?:\w+\.)?CapacityType\.)?SPOT\b"
    r"|\b[tT]ype[\"']?\s*[:=]\s*[\"']?SPOT[\"']?\s*(?:,|$)"
    r"|\bspot\s*[:=]\s*(?:true|True)\b"
    r"|(?i:spot_?instance_?draining)\s*[:=]\s*(?:true|True)\b",
    re.MULTILINE,
)
_COMMITMENT_TAG = _tag_key(r"(?:pricing[-_ ]?model|commitment|savings[-_ ]?plans?)")
_PRICING_NAME = re.compile(
    r"pricing[-_ ]?models?|savings[-_ ]?plans?|reserved[-_ ]?instances?|commitments?"
)
_PRICING_HEADING = re.compile(
    r"(?i)\b(?:pricing[- ]models?|savings[- ]plans?|reserved[- ]instances?|commitments?)\b"
)
_COMMITMENT_NAME = re.compile(r"savings[-_ ]?plans?|reserved[-_ ]?instances?|commitments?")
_COMMITMENT_HEADING = re.compile(
    r"(?i)\b(?:savings[- ]plans?|reserved[- ]instances?|commitments?)\b"
)


def _titled_note(repo_path: Path, name: re.Pattern[str],
                 heading: re.Pattern[str]) -> str | None:
    """The first note whose file name or a heading matches."""
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        if name.search(stem) or any(heading.search(h.group(2)) for h in _HEADING.finditer(text)):
            return rel
    return None


def _priced_fleets(rel: str, text: str) -> List[tuple[str, str, int | None]]:
    """(kind, name, line) of EKS node groups and Batch compute environments."""
    found: List[tuple[str, str, int | None]] = []
    if _CF_PRICED_FLEET_TYPE.search(text):
        for name, body in _cf_resources(rel, text).items():
            kind = _CF_PRICED_FLEET.get(str(body.get("Type")))
            if kind:
                found.append((kind, str(name), _cf_logical_line(text, str(name))))
    for match in _TF_PRICED_FLEET.finditer(text):
        kind = _FLEET_KIND.get(match.group(1), "Batch compute environment")
        found.append((kind, match.group(2), _line_of(text, match.start())))
    for match in _CDK_PRICED_FLEET.finditer(text):
        cls, name, added = match.groups()
        kind = _FLEET_KIND.get(cls or "Nodegroup", "Batch compute environment")
        found.append((kind, name or added, _line_of(text, match.start())))
    return found


def unpriced_fleets(repo_path: Path) -> List[str]:
    """Production fleets, as "kind name in file:line", when production IaC has no Spot
    setting and no commitment tag and no note records a pricing model; else empty."""
    fleets, _signals = scan_fleets(repo_path)
    places = [f"{_FLEET_KIND[check]} {name} in {rel}:{line}" if line else
              f"{_FLEET_KIND[check]} {name} in {rel}"
              for check, name, rel, line, _size in fleets
              if check in ("ecs", "asg") and _production(rel)]
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        if _SPOT.search(text) or _COMMITMENT_TAG.search(text):
            return []
        places.extend(f"{kind} {name} in {rel}:{line}" if line else f"{kind} {name} in {rel}"
                      for kind, name, line in _priced_fleets(rel, text))
    if not places or _titled_note(repo_path, _PRICING_NAME, _PRICING_HEADING):
        return []
    return places


class PricingModelUnanalysed(_RepoRule):
    id = "REPO-090"
    title = "No pricing model chosen for the compute fleet"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Decide the pricing model for each fleet: run interruption-tolerant capacity on Spot "
        "(mixed instances, FARGATE_SPOT, an EKS or Batch SPOT capacity type) and cover the "
        "steady baseline with Savings Plans or Reserved Instances. Record the choice in a "
        "pricing model note or a PricingModel tag."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places = unpriced_fleets(repo_path)
        if not places:
            return []
        return [self._finding(
            f"Fleets on demand: {_listed(places)}; searched production IaC for a Spot setting "
            "(mixed instances below 100 percent on demand, Spot allocation strategy or price, "
            "spot market type, FARGATE_SPOT, SPOT capacity type) and a PricingModel, "
            "Commitment or SavingsPlan tag, and the repo for a note named or headed pricing "
            "model, savings plan, reserved instance or commitment; found none",
        )]


# Regions priced above us-east-1, us-west-2 and eu-west-1 for common compute (EC2
# on-demand, Fargate) in the AWS Price List.
HIGHER_PRICED_REGIONS = (
    "sa-east-1", "ap-east-1", "af-south-1", "me-south-1", "me-central-1", "ap-northeast-1",
    "ap-northeast-3", "ap-southeast-2", "ap-southeast-4", "ap-southeast-5", "eu-central-2",
    "eu-south-2", "il-central-1", "mx-central-1", "ca-west-1",
)
_HIGH = "|".join(re.escape(r) for r in HIGHER_PRICED_REGIONS)
_CODE_REGION = re.compile(rf"\b\w*(?:region|Region|REGION)\s*[:=]\s*['\"]({_HIGH})['\"]")
_TF_REGION_BLOCK = re.compile(r"(?:provider\s+\"aws\"|variable\s+\"[^\"]+\")\s*\{")
_TF_REGION = re.compile(rf"(?m)^\s*(?:region|default)\s*=\s*\"({_HIGH})\"")
_STACKSET_TYPE = re.compile(_cf_type(r"CloudFormation::StackSet"))
_REGION_REASON = re.compile(
    r"(?i)\b(?:costs?|prices?|pricing|latency|residency|sovereignty|compliance)\b"
)
_REASON_COMMENT = re.compile(
    r"(?i)(?://|#|/\*|^\s*\*)[^\n]*\b(?:costs?|prices?|pricing|latency|residency"
    r"|sovereignty|compliance)\b"
)
_REGION_HEADING = re.compile(r"(?i).*\bregions?\b.*")


def _stackset_regions(rel: str, text: str) -> Iterator[tuple[str, int]]:
    for body in _cf_resources(rel, text).values():
        if body.get("Type") != "AWS::CloudFormation::StackSet":
            continue
        groups = _props(body).get("StackInstancesGroup")
        for group in groups if isinstance(groups, list) else ():
            regions = group.get("Regions") if isinstance(group, dict) else None
            for region in regions if isinstance(regions, list) else ():
                if region in HIGHER_PRICED_REGIONS:
                    yield region, _line_of(text, text.find(str(region)))


def _region_literals(rel: str, text: str) -> Iterator[tuple[str, int]]:
    """(region, line) of each higher-priced Region literal: CDK env or region props,
    Terraform provider or variable defaults, CloudFormation StackSet Regions."""
    suffix = rel.rsplit(".", 1)[-1].lower()
    if suffix in ("ts", "js", "py"):
        for match in _CODE_REGION.finditer(text):
            yield match.group(1), _line_of(text, match.start(1))
    elif suffix == "tf":
        for block in _TF_REGION_BLOCK.finditer(text):
            start = block.end() - 1
            for match in _TF_REGION.finditer(_braced(text, start)):
                yield match.group(1), _line_of(text, start + 1 + match.start(1))
    elif _STACKSET_TYPE.search(text):
        yield from _stackset_regions(rel, text)


def _commented(text: str, line: int) -> bool:
    lines = text.splitlines()
    near = lines[max(line - 2, 0):line]
    return any(_REASON_COMMENT.search(item) for item in near)


def _region_noted(repo_path: Path) -> set[str]:
    """Regions a note names under a Region heading or in a Region-named note, with a
    reason (cost, price, latency, residency, sovereignty or compliance)."""
    noted: set[str] = set()
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        bodies = [text] if "region" in stem else []
        bodies += [m.group(0) + body for m, body in zip(
            (h for h in _HEADING.finditer(text) if _REGION_HEADING.fullmatch(h.group(2))),
            _sections(text, _REGION_HEADING),
        )]
        for body in bodies:
            if _REGION_REASON.search(body):
                noted.update(r for r in HIGHER_PRICED_REGIONS if r in body)
    return noted


def costly_regions(repo_path: Path) -> List[tuple[str, str, int]]:
    """(region, file, line) of each higher-priced Region hardcoded in production IaC with
    no reason given in a comment beside it or in a Region note."""
    found = [
        (region, rel, line)
        for rel, text in iac_texts(repo_path) if _production(rel)
        for region, line in _region_literals(rel, text) if not _commented(text, line)
    ]
    if not found:
        return []
    noted = _region_noted(repo_path)
    return [hit for hit in found if hit[0] not in noted]


class RegionNotChosenByCost(_RepoRule):
    id = "REPO-091"
    title = "Higher-priced Region with no recorded reason"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Compare Region prices before you pin a workload: us-east-1, us-west-2 and eu-west-1 "
        "cost less for most compute. If latency, data residency or compliance needs the "
        "Region, say so in a comment beside it or in a Region note, or take the Region from "
        "a parameter or variable."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        hits = costly_regions(repo_path)
        if not hits:
            return []
        places = [f"{region} at {rel}:{line}" for region, rel, line in hits]
        return [self._finding(
            f"Hardcodes {_listed(places)}, priced above us-east-1, us-west-2 and eu-west-1; "
            "searched for a cost, price, latency, residency, sovereignty or compliance comment "
            "on or above the line and a Region note that names it with a reason; found none",
        )]


_MARKETPLACE_OWNER = re.compile(r"[\"']aws-marketplace[\"']")
_TF_AMI = re.compile(r"data\s+\"aws_ami\"\s+\"([^\"]+)\"\s*\{")
_CDK_LOOKUP = re.compile(r"\b(?:MachineImage\.lookup|machine_image\.lookup|LookupMachineImage)\(")
_PRODUCT_CODE = re.compile(
    r"[\"']?\b(?:ProductCodes?|product_codes?|productCodes?)[\"']?\s*[:=]\s*[\[{\"'\w]"
    r"|\bname\s*=\s*\"product-code(?:\.type)?\""
)
_MARKETPLACE_PRODUCT = re.compile(
    _cf_type(r"ServiceCatalog::CloudFormationProvisionedProduct")
)
_PROD_ID = re.compile(r"[\"']?ProductId[\"']?\s*:\s*[\"']?prod-\w")
_TERM_TAG = _tag_key(
    r"(?:(?:marketplace|contract|licen[cs]e|subscription)[-_ ]?term|contract[-_ ]?end)"
)
_VENDOR_NAME = re.compile(r"marketplace|third[-_ ]?party|vendors?|licen[cs]es?")
_VENDOR_HEADING = re.compile(
    r"(?i).*\b(?:marketplace|third[- ]party|vendors?|licen[cs](?:es?|ing))\b.*"
)
_TERM_WORDS = re.compile(
    r"(?i)\b(?:terms?|contracts?|renewals?|renews?|annual(?:ly)?|12-month|36-month)\b"
)


def marketplace_uses(repo_path: Path) -> List[str]:
    """Each AWS Marketplace image or product in the IaC, as "what in file:line"."""
    found: List[str] = []
    for rel, text in iac_texts(repo_path):
        for match in _TF_AMI.finditer(text):
            block = _braced(text, match.end() - 1)
            if _MARKETPLACE_OWNER.search(block) or _PRODUCT_CODE.search(block):
                found.append(f"Marketplace AMI {match.group(1)} in {rel}:"
                             f"{_line_of(text, match.start())}")
        for match in _CDK_LOOKUP.finditer(text):
            args = _braced(text, match.end() - 1, "(", ")")
            if _MARKETPLACE_OWNER.search(args):
                found.append(f"Marketplace AMI lookup in {rel}:{_line_of(text, match.start())}")
        if not _TF_AMI.search(text):
            for match in _PRODUCT_CODE.finditer(text):
                found.append(f"product code in {rel}:{_line_of(text, match.start())}")
        if _MARKETPLACE_PRODUCT.search(text):
            for match in _PROD_ID.finditer(text):
                found.append(f"Marketplace product in {rel}:{_line_of(text, match.start())}")
    return found


def marketplace_terms(repo_path: Path) -> str | None:
    """The first place that records a third-party term: a term tag in the IaC, or a
    marketplace, third-party, vendor or licence note that gives a term or a date."""
    for rel, text in iac_texts(repo_path):
        if _TERM_TAG.search(text):
            return rel
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        bodies = [text] if _VENDOR_NAME.search(stem) else []
        bodies += list(_sections(text, _VENDOR_HEADING))
        if any(_TERM_WORDS.search(b) or _DATE.search(b) for b in bodies):
            return rel
    return None


class ThirdPartyTermsMissing(_RepoRule):
    id = "REPO-092"
    title = "Marketplace product with no recorded agreement term"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Record the agreement for each AWS Marketplace product: the contract or subscription "
        "term, renewal date and pricing (hourly, annual or a private offer) in a "
        "MarketplaceTerm or ContractEnd tag or a vendor note, and review it before renewal."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        uses = marketplace_uses(repo_path)
        if not uses or marketplace_terms(repo_path):
            return []
        return [self._finding(
            f"Uses {_listed(uses)}; searched the IaC for a MarketplaceTerm, ContractTerm, "
            "ContractEnd, LicenseTerm or SubscriptionTerm tag and the repo for a marketplace, "
            "third-party, vendor or licence note that gives a term, renewal or date; found "
            "none",
        )]


_COMMITMENT_BUDGET = re.compile(
    r"(?i:budget_?type)[\"']?\s*[:=]\s*[\"']?"
    r"(?:SAVINGS_PLANS_(?:UTILIZATION|COVERAGE)|RI_(?:UTILIZATION|COVERAGE))\b"
)
_DISCOUNT_SHARING = re.compile(
    r"(?i)\b(?:discount|ri|sp|ri[-_/]?sp|savings[-_ ]?plans?|reserved[-_ ]?instances?)"
    r"[-_ ]?sharing[\"']?\s*[:=]"
)
# An organization stack: Organizations accounts, OUs or service control policies. The
# CloudFormation type must sit in a Type key, so a file that only names it is not one.
_ORG_STACK_UNITS = re.compile(
    _cf_type(r"Organizations::(?:Account|OrganizationalUnit)")
    + r"|resource\s+\"aws_organizations_(?:account|organizational_unit)\""
    r"|organizations\.Cfn(?:Account|OrganizationalUnit)\("
)
_ORG_STACK_POLICY = re.compile(
    _cf_type(r"Organizations::Policy")
    + r"|resource\s+\"aws_organizations_policy\"|organizations\.CfnPolicy\("
)


def org_stack(repo_path: Path) -> List[str]:
    """Where the IaC declares Organizations accounts or OUs or a service control policy, as
    "kind in file"; empty for an application stack."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if _ORG_STACK_UNITS.search(text):
            found.setdefault("Organizations account or OU", rel)
        if _ORG_STACK_POLICY.search(text) and (
            "SERVICE_CONTROL_POLICY" in text or not _OTHER_POLICY_TYPE.search(text)
        ):
            found.setdefault("service control policy", rel)
    return [f"{kind} in {rel}" for kind, rel in found.items()]


def tracked_commitments(repo_path: Path) -> str | None:
    """The first place that tracks shared commitments: a Savings Plans or RI utilization or
    coverage budget, a discount sharing setting, or a commitment note."""
    for rel, text in iac_texts(repo_path):
        if _COMMITMENT_BUDGET.search(text) or _DISCOUNT_SHARING.search(text):
            return rel
    return _titled_note(repo_path, _COMMITMENT_NAME, _COMMITMENT_HEADING)


class ManagementPricingMissing(_RepoRule):
    id = "REPO-093"
    title = "Organization tracks no shared Savings Plans or Reserved Instances"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Analyse commitments in the management account: buy Savings Plans and Reserved "
        "Instances there so discounts are shared across accounts, and add an AWS Budgets "
        "budget of type SAVINGS_PLANS_UTILIZATION or RI_COVERAGE (or the other two) to "
        "watch them."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places = org_stack(repo_path)
        if not places or tracked_commitments(repo_path):
            return []
        return [self._finding(
            f"Organization stack ({_listed(places)}); searched the IaC for a budget of type "
            "SAVINGS_PLANS_UTILIZATION, SAVINGS_PLANS_COVERAGE, RI_UTILIZATION or RI_COVERAGE "
            "and an RI or Savings Plans sharing setting, and the repo for a note named or "
            "headed savings plan, reserved instance or commitment; found none",
        )]


# COST 8: data transfer. Data transfer modeling (REPO-094) and components chosen for
# transfer cost (REPO-095).

_TRANSFER_TAG = _tag_key(r"(?:data[-_ ]?transfer|transfer[-_ ]?costs?|cross[-_ ]?az[-_ ]?traffic)")
_TRANSFER_NAME = re.compile(
    r"data[-_ ]?transfer|egress|cross[-_ ]?az|network[-_ ]?costs?|transfer[-_ ]?costs?"
)
_TRANSFER_HEADING = re.compile(
    r"(?i)\b(?:data[- ]transfer|egress|cross[- ]az|network costs?|transfer costs?)\b"
)
_TRANSFER_DETAIL = re.compile(
    r"(?i)\b\d+(?:\.\d+)?\s*(?:[KMGTP]B)\b|per month|/\s*month|\$\s*\d"
    r"|\b(?:S3|RDS|Aurora|DynamoDB|ElastiCache|OpenSearch|MSK|Kafka|EFS|EBS|NAT|CloudFront"
    r"|Lambda|ECS|EKS|EC2|Backup)\b"
)
_TRANSFER_COMMENT = re.compile(
    r"(?i)(?://|#|/\*|^\s*\*)[^\n]*\b(?:data[- ]transfer|cross[- ]?az|egress)\b"
)
_CROSS_AZ_PATTERNS = _kinds(
    ("Multi-AZ database or cache",
     r"(?i:[\"']?multi_?az(?:_?enabled)?[\"']?)\s*[:=]\s*[\"']?(?i:true)\b"),
    ("replicated ElastiCache group",
     r"(?i:replicas_?per_?(?:node_?group|shard)|num_?cache_?(?:clusters|nodes))[\"']?"
     r"\s*[:=]\s*[\"']?(?:[2-9]|[1-9]\d)\b"
     r"|(?i:replicas_?per_?(?:node_?group|shard))[\"']?\s*[:=]\s*[\"']?1\b"
     r"|(?i:num_?node_?groups)[\"']?\s*[:=]\s*[\"']?(?:[2-9]|[1-9]\d)\b"),
    ("zone-aware OpenSearch domain",
     r"(?i:zone_?awareness_?enabled)[\"']?\s*[:=]\s*[\"']?(?i:true)\b"),
    ("MSK cluster", _cf_type(r"MSK::(?:Cluster|ServerlessCluster)")
     + r"|resource\s+\"aws_msk_(?:serverless_)?cluster\"|\bmsk\.(?:Cfn)?Cluster\("),
    ("Aurora cluster with readers",
     r"\breaders\s*[:=]\s*\[|\bcluster_?instances\s*[:=]\s*[2-9]\b"
     r"|\bnew\s+rds\.DatabaseCluster\([^)]*\binstances\s*:\s*[2-9]\b"),
)
_CROSS_REGION_PATTERNS = _kinds(
    *((name, pattern.pattern) for name, pattern in _DR_REPLICATION
      if name != "Elastic Disaster Recovery"),
    ("snapshot copy to another Region",
     r"resource\s+\"aws_(?:ebs_snapshot_copy|db_snapshot_copy|ec2_snapshot_copy"
     r"|db_instance_automated_backups_replication)\""),
    ("EFS replication", r"resource\s+\"aws_efs_replication_configuration\""
     r"|\befs\.CfnReplicationConfiguration\(|[\"']?ReplicationConfiguration[\"']?\s*:\s*"
     r"(?:\{|efs\.)"),
)
_FLEET_RESOURCES = {
    "AWS::AutoScaling::AutoScalingGroup": ("Auto Scaling group", ("VPCZoneIdentifier",)),
    "AWS::ECS::Service": ("ECS service", ("NetworkConfiguration",)),
    "AWS::EKS::Nodegroup": ("EKS node group", ("Subnets",)),
}
_TF_FLEET_XFER = re.compile(
    r"resource\s+\"(aws_autoscaling_group|aws_ecs_service|aws_eks_node_group)\"\s+\"([^\"]+)\""
)
_TF_FLEET_KIND = {"aws_autoscaling_group": "Auto Scaling group",
                  "aws_ecs_service": "ECS service", "aws_eks_node_group": "EKS node group"}
_TF_SUBNET_LIST = re.compile(
    r"\b(?:vpc_zone_identifier|subnet_ids|subnets)\s*=\s*\[([^\]]*)\]"
)
_CDK_FLEET_XFER = re.compile(
    r"\b(?:autoscaling|ecs|eks)\.(AutoScalingGroup|FargateService|Ec2Service|Nodegroup)\s*\("
)
_CDK_FLEET_KIND = {"AutoScalingGroup": "Auto Scaling group", "FargateService": "ECS service",
                   "Ec2Service": "ECS service", "Nodegroup": "EKS node group"}
_ONE_AZ = re.compile(
    r"\bmax_?[aA]zs\s*[:=]\s*1\b"
    r"|\bavailability_?[zZ]ones\s*[:=]\s*\[\s*['\"][^'\",\]]+['\"]\s*\]"
)


_TRIPLE_QUOTED = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.DOTALL)


def _blank_strings(rel: str, text: str) -> str:
    """Python source without its triple-quoted strings (snippets and docs, not constructs),
    line numbers kept."""
    if not rel.endswith(".py"):
        return text
    return _TRIPLE_QUOTED.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def _hits(pattern: re.Pattern[str], rel: str, text: str) -> Iterator[re.Match[str]]:
    """Matches of pattern; in Python source only a keyword argument or a constructor call,
    not a quoted dict key, a template line or text in a message."""
    for match in pattern.finditer(text):
        if rel.endswith(".py"):
            hit = match.group(0)
            if hit.startswith(("resource", '"', "'")) or ("=" not in hit and "(" not in hit):
                continue
        yield match


def _list_len(value: object) -> int:
    return len(value) if isinstance(value, list) else 0


def _cf_fleet_spans_subnets(kind_key: str, props: dict) -> bool:
    if kind_key == "NetworkConfiguration":
        net = props.get("NetworkConfiguration")
        vpc = net.get("AwsvpcConfiguration") if isinstance(net, dict) else None
        return isinstance(vpc, dict) and _list_len(vpc.get("Subnets")) > 1
    return _list_len(props.get(kind_key)) > 1


def _cross_az_sites(rel: str, text: str) -> List[tuple[str, int | None]]:
    """(kind, line) of each resource in the file that moves data across Availability Zones."""
    found: List[tuple[str, int | None]] = []
    text = _blank_strings(rel, text)
    for kind, pattern in _CROSS_AZ_PATTERNS:
        for match in _hits(pattern, rel, text):
            found.append((kind, _line_of(text, match.start())))
    if len(re.findall(r"[\"']?DBClusterIdentifier[\"']?\s*:", text)) > 1 \
            or len(re.findall(r"resource\s+\"aws_rds_cluster_instance\"", text)) > 1:
        first = re.search(r"[\"']?DBClusterIdentifier[\"']?\s*:|aws_rds_cluster_instance", text)
        found.append(("Aurora cluster with readers",
                      _line_of(text, first.start()) if first else None))
    if _CF_FLEET_TYPE.search(text):
        for name, body in _cf_resources(rel, text).items():
            kind, key = _FLEET_RESOURCES.get(str(body.get("Type")), ("", ("",)))
            if kind and _cf_fleet_spans_subnets(key[0], _props(body)):
                found.append((f"{kind} {name} over several subnets",
                              _cf_logical_line(text, str(name))))
    for match in _TF_FLEET_XFER.finditer(text):
        brace = text.find("{", match.end())
        block = _braced(text, brace) if brace >= 0 else ""
        for lst in _TF_SUBNET_LIST.finditer(block):
            if len([i for i in lst.group(1).split(",") if i.strip()]) > 1:
                found.append((f"{_TF_FLEET_KIND[match.group(1)]} {match.group(2)} over "
                              "several subnets", _line_of(text, match.start())))
                break
    if not _ONE_AZ.search(text):
        for match in _CDK_FLEET_XFER.finditer(text):
            found.append((f"{_CDK_FLEET_KIND[match.group(1)]} over the VPC's Availability "
                          "Zones", _line_of(text, match.start())))
    return found


def _cross_region_sites(rel: str, text: str) -> List[tuple[str, int | None]]:
    """(kind, line) of each copy of data to another Region the file declares."""
    text = _blank_strings(rel, text)
    return [(kind, _line_of(text, match.start()))
            for kind, pattern in _CROSS_REGION_PATTERNS for match in _hits(pattern, rel, text)]


_CF_FLEET_TYPE = re.compile(_cf_type(r"AutoScaling::AutoScalingGroup|ECS::Service|EKS::Nodegroup"))


def _has_transfer_comment(text: str, line: int | None) -> bool:
    """A data-transfer comment on the line or the one before it."""
    if not line:
        return False
    lines = text.split("\n")
    nearby = "\n".join(lines[max(line - 2, 0):line])
    return _TRANSFER_COMMENT.search(nearby) is not None


def transfer_recorded(repo_path: Path) -> str | None:
    """Where the repo records data transfer: a tag in production IaC or a note named or
    headed for data transfer that gives a size, unit or service. None when absent."""
    for rel, text in iac_texts(repo_path):
        if _production(rel) and _TRANSFER_TAG.search(text):
            return rel
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        if (_TRANSFER_NAME.search(stem)
                or any(_TRANSFER_HEADING.search(h.group(2)) for h in _HEADING.finditer(text))) \
                and _TRANSFER_DETAIL.search(text):
            return rel
    return None


def _uncommented(sites: List[tuple[str, int | None]], rel: str, text: str) -> List[str]:
    return [f"{kind} in {rel}:{line}" if line else f"{kind} in {rel}"
            for kind, line in sites if not _has_transfer_comment(text, line)]


def unrecorded_cross_az(repo_path: Path) -> List[str]:
    """Production resources that move data across Availability Zones or Regions, as
    "kind in file:line", when nothing records the transfer; else empty."""
    places: List[str] = []
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        sites = _cross_az_sites(rel, text) + _cross_region_sites(rel, text)
        places.extend(_uncommented(sites, rel, text))
    if not places or transfer_recorded(repo_path):
        return []
    return places


class DataTransferUnmodelled(_RepoRule):
    id = "REPO-094"
    title = "Data transfer between Availability Zones or Regions is not modeled"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Model what the workload sends across Availability Zones and Regions before it costs "
        "money: write the expected volume (GB per month) and the price per GB in a "
        "data-transfer note, or tag the resources with DataTransfer, TransferCost or "
        "CrossAZTraffic, or leave a data-transfer comment next to each resource."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        places = unrecorded_cross_az(repo_path)
        if not places:
            return []
        return [self._finding(
            f"Moves data across Availability Zones or Regions: {_listed(places)}; searched "
            "production IaC for a DataTransfer, TransferCost or CrossAZTraffic tag and a "
            "data-transfer, cross-AZ or egress comment next to each resource, and notes named "
            "or headed data transfer, egress, cross-AZ or network cost that give a size, "
            "unit or service; found none",
        )]


_VPC_ENDPOINT = re.compile(
    _cf_type(r"EC2::VPCEndpoint(?:Service)?") + r"|resource\s+\"aws_vpc_endpoint\""
    r"|\bec2\.(?:Cfn)?(?:Gateway|Interface)?VpcEndpoint\(|\b(?:Gateway|Interface)VpcEndpoint\("
    r"|\.add_?(?:[gG]ateway|[iI]nterface)_?[eE]ndpoint\("
)
_ENDPOINT_SERVICE = {
    "S3": re.compile(
        r"(?i)(?:ServiceName|service_name)[\"']?\s*[:=][^\n]*\.s3\b"
        r"|GatewayVpcEndpointAwsService\.S3\b|InterfaceVpcEndpointAwsService\.S3\b"
        r"|add_?(?:gateway|interface)_?endpoint\([^)]*\bS3\b"
    ),
    "DynamoDB": re.compile(
        r"(?i)(?:ServiceName|service_name)[\"']?\s*[:=][^\n]*\.dynamodb\b"
        r"|GatewayVpcEndpointAwsService\.DYNAMODB\b"
        r"|add_?(?:gateway|interface)_?endpoint\([^)]*\bDYNAMODB\b"
    ),
}
_ENDPOINT_UNREADABLE = re.compile(
    r"(?:ServiceName|service_name)[\"']?\s*[:=]\s*(?:var\.|local\.|data\.|!Ref\b|!Sub\b"
    r"|\{\s*[\"']?Ref\b|[A-Za-z_]\w*\.)"
)
_S3_USE = re.compile(
    _cf_type(r"S3::Bucket") + r"|resource\s+\"aws_s3_bucket\"|\bs3\.(?:Cfn)?Bucket\("
    r"|\bBucket\.from\w+\(|[\"']s3:"
)
_DDB_USE = re.compile(
    _cf_type(r"DynamoDB::(?:Table|GlobalTable)") + r"|resource\s+\"aws_dynamodb_table\""
    r"|\bdynamodb\.(?:Cfn)?(?:Table|TableV2|GlobalTable)\(|\bTable\.from\w+\(|[\"']dynamodb:"
)
_NAT = re.compile(
    _cf_type(r"EC2::NatGateway") + r"|resource\s+\"aws_nat_gateway\""
    r"|\bnat_?[gG]ateways\s*[:=]\s*[1-9]|NatProvider\.gateway|\bnat_gateway_provider\b"
)
_CDK_VPC_XFER = re.compile(r"\bec2\.Vpc\(")
_NO_NAT_XFER = re.compile(r"\bnat_?[gG]ateways\s*[:=]\s*0\b")
_CF_MOVERS = {
    "AWS::Lambda::Function": ("Lambda function", "VpcConfig"),
    "AWS::ECS::Service": ("ECS service", "NetworkConfiguration"),
    "AWS::EC2::Instance": ("EC2 instance", "SubnetId"),
}
_CF_MOVER_TYPE = re.compile(_cf_type(r"Lambda::Function|ECS::Service|EC2::Instance"))
_TF_MOVER = re.compile(
    r"resource\s+\"(aws_lambda_function|aws_ecs_service|aws_instance)\"\s+\"([^\"]+)\""
)
_TF_MOVER_KIND = {
    "aws_lambda_function": ("Lambda function", re.compile(r"\bvpc_config\s*\{")),
    "aws_ecs_service": ("ECS service", re.compile(r"\bnetwork_configuration\s*\{")),
    "aws_instance": ("EC2 instance", re.compile(r"\bsubnet_id\s*=")),
}
_CDK_MOVER = re.compile(
    r"\b(?:_?lambda_?|lambda_nodejs|nodejs|ec2|ecs|ecs_patterns|ecsPatterns)\."
    r"(Function|NodejsFunction|PythonFunction|DockerImageFunction|Instance|FargateService"
    r"|Ec2Service|ApplicationLoadBalancedFargateService|QueueProcessingFargateService)\s*\("
)
_CDK_MOVER_KIND = {
    "Instance": "EC2 instance", "FargateService": "ECS service", "Ec2Service": "ECS service",
    "ApplicationLoadBalancedFargateService": "ECS service",
    "QueueProcessingFargateService": "ECS service",
}
_CDK_FIRST_ID = re.compile(r"\s*(?:this|self)\s*,\s*['\"]([^'\"]+)['\"]")
_CDK_VPC_PROP = re.compile(r"\bvpc(?:_?[sS]ubnets)?\b\s*(?:[:=,}]|$)", re.MULTILINE)


def _vpc_movers(rel: str, text: str) -> List[tuple[str, str, int | None]]:
    """(kind, name, line) of each Lambda function, ECS service or EC2 instance in a VPC."""
    found: List[tuple[str, str, int | None]] = []
    if _CF_MOVER_TYPE.search(text):
        for name, body in _cf_resources(rel, text).items():
            mover = _CF_MOVERS.get(str(body.get("Type")))
            if mover and _props(body).get(mover[1]):
                found.append((mover[0], str(name), _cf_logical_line(text, str(name))))
    for match in _TF_MOVER.finditer(text):
        brace = text.find("{", match.end())
        kind, marker = _TF_MOVER_KIND[match.group(1)]
        if brace >= 0 and marker.search(_braced(text, brace)):
            found.append((kind, match.group(2), _line_of(text, match.start())))
    for match in _CDK_MOVER.finditer(text):
        cls = match.group(1)
        args = _braced(text, match.end() - 1, "(", ")")
        named = _CDK_FIRST_ID.match(args)
        name = named.group(1) if named else cls
        kind = _CDK_MOVER_KIND.get(cls, "Lambda function")
        if cls in ("Function", "NodejsFunction", "PythonFunction", "DockerImageFunction",
                   "Instance") and not _CDK_VPC_PROP.search(args):
            continue
        found.append((kind, name, _line_of(text, match.start())))
    return found


def unavoidable_transfer(repo_path: Path) -> List[str]:
    """Findings for COST08-BP02, as text: VPC data movers behind a NAT gateway with no
    gateway endpoint for the S3 or DynamoDB they use, and cross-Region copies with no
    recorded reason and no VPC endpoint."""
    movers: List[str] = []
    copies: List[str] = []
    uses: set[str] = set()
    nat = endpoint = one_az = False
    covered: set[str] = set()
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        text = _blank_strings(rel, text)
        if _S3_USE.search(text):
            uses.add("S3")
        if _DDB_USE.search(text):
            uses.add("DynamoDB")
        nat = nat or _NAT.search(text) is not None
        if _CDK_VPC_XFER.search(text) and not _NO_NAT_XFER.search(text):
            nat = True
        one_az = one_az or _ONE_AZ.search(text) is not None
        if _VPC_ENDPOINT.search(text):
            endpoint = True
            if _ENDPOINT_UNREADABLE.search(text):
                covered |= {"S3", "DynamoDB"}
        for service, pattern in _ENDPOINT_SERVICE.items():
            if pattern.search(text):
                covered.add(service)
        movers.extend(f"{kind} {name} in {rel}:{line}" if line else f"{kind} {name} in {rel}"
                      for kind, name, line in _vpc_movers(rel, text))
        copies.extend(_uncommented(_cross_region_sites(rel, text), rel, text))
    parts: List[str] = []
    missing = sorted(uses - covered)
    if movers and nat and missing and not one_az:
        parts.append(f"{_listed(movers)} in a VPC with a NAT gateway reach "
                     f"{' and '.join(missing)} with no gateway endpoint for it")
    if copies and not endpoint and not transfer_recorded(repo_path):
        parts.append(f"copies data to another Region with no recorded reason: "
                     f"{_listed(copies)}")
    return parts


class DataTransferNotOptimised(_RepoRule):
    id = "REPO-095"
    title = "Data movers pay for transfer they could avoid"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Keep data movers off paid paths: add a gateway VPC endpoint for S3 and DynamoDB so "
        "VPC workloads skip the NAT gateway, or keep the movers in one Availability Zone. "
        "For a copy to another Region, record the reason (a data-transfer note, tag or "
        "comment) or reach the service through a VPC endpoint."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        parts = unavoidable_transfer(repo_path)
        if not parts:
            return []
        return [self._finding(
            "; ".join(parts) + "; searched production IaC for an S3 or DynamoDB gateway "
            "VPC endpoint (AWS::EC2::VPCEndpoint, aws_vpc_endpoint, addGatewayEndpoint), "
            "any VPC endpoint, a single-AZ VPC, and the data-transfer tag, note or comment "
            "of REPO-094; found none",
        )]


# COST 9: demand management. Demand analysis (REPO-096) and a buffer or throttle on what
# takes demand (REPO-097).

_SCHEDULED_SCALING = re.compile(
    _cf_type(r"AutoScaling::ScheduledAction") + r"|resource\s+\"aws_(?:autoscaling_schedule"
    r"|appautoscaling_scheduled_action)\""
    r"|[\"']?ScheduledActions[\"']?\s*[:=]|\bscheduled_action\s*\{"
    r"|\.(?:scaleOnSchedule|scale_on_schedule)\(|\b(?:autoscaling|appscaling|applicationautoscaling)"
    r"\.Schedule\.|\b(?:SetDesiredCapacity|PutScheduledUpdateGroupAction"
    r"|RegisterScalableTarget)\b|(?m:^\s*type\s*:\s*[\"']?cron\b)"
)
_DEMAND_METRICS = (
    r"ApproximateNumberOfMessagesVisible|ApproximateAgeOfOldestMessage|RequestCount"
    r"|RequestCountPerTarget|ALBRequestCountPerTarget|Invocations|ConcurrentExecutions"
    r"|IncomingRequests|NumberOfMessagesSent"
)
_DEMAND_SIGNAL = re.compile(
    _metric_named(_DEMAND_METRICS)
    + r"|[\"']?PredefinedMetricType[\"']?\s*[:=]\s*[\"']?ALBRequestCountPerTarget\b"
    r"|\bpredefined_metric_type\s*=\s*\"ALBRequestCountPerTarget\""
    r"|\.(?:metric_?(?:[aA]pproximate_?(?:[nN]umber_?[oO]f_?[mM]essages_?[vV]isible"
    r"|[aA]ge_?[oO]f_?[oO]ldest_?[mM]essage)|[rR]equest_?[cC]ount|[iI]nvocations"
    r"|[cC]oncurrent_?[eE]xecutions|[cC]ount)"
    r"|scaleOnRequestCount|scale_on_request_count)\("
    r"|\bQueueProcessing(?:Fargate|Ec2)Service\("
)
_DEMAND_NAME = re.compile(
    r"(?i)(?:demand|traffic|usage[-_ ]?patterns?|load[-_ ]?profiles?|capacity[-_ ]?plan(?:ning)?)"
)
_DEMAND_HEADING = re.compile(
    r"(?i).*\b(?:demand|traffic|usage[-_ ]?patterns?|load[-_ ]?profiles?"
    r"|capacity[-_ ]?plan(?:ning)?)\b.*"
)
_DEMAND_FACT = re.compile(
    r"(?i)\d[\d,.]*\s*(?:k|m)?\s*(?:requests?|reqs?|rps|rpm|tps|users?|visitors|messages"
    r"|events|invocations|peak\b|per[ \t]+(?:day|hour|second|minute|month)\b"
    r"|/(?:day|hour|s|sec|min|month)\b)"
    r"|\bpeaks?\b[^\n]{0,40}\d|\b(?:weekdays?|weekends?|month-end|seasonal|seasons?"
    r"|business[ \t]+hours)\b"
)


def _live(pattern: re.Pattern[str], rel: str, text: str) -> bool:
    """Whether pattern matches; in Python source not inside a quoted string on its line."""
    for match in pattern.finditer(text):
        if not rel.endswith(".py"):
            return True
        prefix = text[text.rfind("\n", 0, match.start()) + 1:match.start()]
        if prefix.count("'") % 2 == 0 and prefix.count('"') % 2 == 0:
            return True
    return False


def _demand_note(repo_path: Path) -> str | None:
    """The first note about demand that gives a rate, a volume or a calendar pattern."""
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        if _DEMAND_NAME.search(stem) and _DEMAND_FACT.search(text):
            return rel
        if any(_DEMAND_FACT.search(body) for body in _sections(text, _DEMAND_HEADING)):
            return rel
    return None


def demand_gaps(repo_path: Path) -> tuple[dict[str, str], bool]:
    """Production compute (kind -> first file), and whether any demand signal exists."""
    compute: dict[str, str] = {}
    signal = False
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        text = _blank_strings(rel, text)
        for kind, pattern in _COMPUTE:
            if _live(pattern, rel, text):
                compute.setdefault(kind, rel)
        signal = signal or _live(_SCHEDULED_SCALING, rel, text) or _live(_DEMAND_SIGNAL, rel, text)
    return compute, signal or _demand_note(repo_path) is not None


class DemandNotAnalysed(_RepoRule):
    id = "REPO-096"
    title = "Workload demand is not analysed"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Analyse the demand the workload serves: scale on it (a scheduled scaling action for "
        "a known peak, or target tracking on request count per target or queue depth), alarm "
        "or chart request rate, queue depth or concurrency, or write a demand note with "
        "requests per second, peak hours and the weekday, month-end or seasonal pattern."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        compute, signal = demand_gaps(repo_path)
        if not compute or signal:
            return []
        return [self._finding(
            f"Runs {_named(compute)}; searched production IaC for a scheduled scaling action, "
            "a demand metric (queue depth, request count, invocations, concurrency) used to "
            "scale or alarm, and notes named or headed demand, traffic, usage pattern, load "
            "profile or capacity plan that give a rate, volume or calendar pattern; found none",
            file=next(iter(compute.values())),
        )]


_API_THROTTLE = dict(_LEVERS)
_LIMITERS = (
    _API_THROTTLE["Lambda reserved concurrency"], _API_THROTTLE["API Gateway throttle"],
    _API_THROTTLE["WAF rate-based rule"],
)
_PROVISIONED = re.compile(
    r"[\"']?Provisioned(?:Concurrent|Concurrency)\w*[\"']?\s*[:=]"
    r"|\bprovisioned_(?:concurrent_executions|concurrency)\w*\s*[={]"
    r"|\bprovisioned(?:Concurrent|Concurrency)\w*\s*:"
)
_BUFFERS = (
    _API_THROTTLE["Lambda reserved concurrency"], _PROVISIONED,
    re.compile(
        _cf_type(r"SQS::Queue|Kinesis::Stream|Events::EventBus|Pipes::Pipe")
        + r"|resource\s+\"aws_(?:sqs_queue|kinesis_stream|cloudwatch_event_bus)\""
        r"|\b(?:sqs\.(?:Cfn)?Queue|kinesis\.(?:Cfn)?Stream|events\.EventBus)\("
        r"|\bQueue\(|\bSqsEventSource\("
    ),
)
_API_GATEWAY = dict(_EDGES)["API Gateway"]
_DIRECT_TRIGGERS = _kinds(
    ("SNS subscription to Lambda",
     r"[\"']?[pP]rotocol[\"']?\s*[:=]\s*[\"']?lambda\b|\bLambdaSubscription\("
     r"|\bSnsEventSource\(|[pP]rincipal[\"']?\s*[:=]\s*[\"']sns\.amazonaws\.com"),
    ("S3 notification to Lambda",
     r"\bs3n\.LambdaDestination\(|\bS3EventSource(?:V2)?\(|LambdaFunctionConfigurations"
     r"|\blambda_function\s*\{"),
)


def unbuffered_demand(repo_path: Path) -> tuple[List[str], bool]:
    """What takes demand with nothing to absorb or limit it, as "kind in file", and whether
    anything was found that takes demand."""
    apis: List[str] = []
    triggers: List[str] = []
    limiter = buffer = False
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        text = _blank_strings(rel, text)
        if _live(_API_GATEWAY, rel, text) or (
            _SAM_TRANSFORM.search(text) and _SAM_API_EVENT.search(text)
        ):
            apis.append(f"API Gateway API in {rel}")
        triggers.extend(f"{kind} in {rel}" for kind, pattern in _DIRECT_TRIGGERS
                        if _live(pattern, rel, text))
        limiter = limiter or any(_live(p, rel, text) for p in _LIMITERS)
        buffer = buffer or any(_live(p, rel, text) for p in _BUFFERS)
    found: List[str] = []
    if apis and not limiter:
        found.extend(apis)
    if triggers and not buffer:
        found.extend(triggers)
    return found, bool(apis or triggers)


class DemandUnbuffered(_RepoRule):
    id = "REPO-097"
    title = "Demand has no buffer or throttle"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Smooth demand before it sets the bill: throttle the API (a stage or usage plan "
        "throttle, or a WAF rate-based rule), put an SQS queue, Kinesis stream or EventBridge "
        "bus between a trigger and the Lambda function that handles it, or cap the function "
        "with reserved concurrency."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found, _ = unbuffered_demand(repo_path)
        if not found:
            return []
        return [self._finding(
            f"Takes demand with nothing to absorb or limit it: {_listed(found)}; searched "
            "production IaC for an API Gateway throttle or usage plan, a WAF rate-based rule, "
            "Lambda reserved or provisioned concurrency, and an SQS queue, Kinesis stream or "
            "EventBridge bus; found none",
        )]


# SUS 2: aligning cloud resources to demand. SLAs (REPO-098), unused assets (REPO-099),
# geographic placement (REPO-100), team resources (REPO-101), and flattening the demand curve
# (REPO-102, which shares its detection with REPO-097).


def production_workload(repo_path: Path) -> dict[str, str]:
    """Compute, data stores and user-facing endpoints in production IaC: kind -> first file.
    In Python source, text inside a quoted string does not count."""
    found: dict[str, str] = {}
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        text = _blank_strings(rel, text)
        for kind, pattern in _WORKLOAD:
            if _live(pattern, rel, text):
                found.setdefault(kind, rel)
        if _SAM_TRANSFORM.search(text) and _SAM_API_EVENT.search(text):
            found.setdefault("API Gateway", rel)
    return found


def _note_with(
    repo_path: Path, name: re.Pattern[str], heading: re.Pattern[str], body: re.Pattern[str]
) -> str | None:
    """The first note that is named (file stem) or headed (section) for a topic and whose
    text, or section, matches body."""
    for rel, text in note_texts(repo_path):
        stem = rel.rsplit("/", 1)[-1].lower().rsplit(".", 1)[0]
        if name.search(stem) and body.search(text):
            return rel
        if any(body.search(section) for section in _sections(text, heading)):
            return rel
    return None


_SLA_NAME = re.compile(
    r"(?:^|[-_. ])(?:slas?|slos?|service[-_ ]?levels?|availability[-_ ]?targets?"
    r"|reliability[-_ ]?targets?)(?:$|[-_. ])"
)
_SLA_HEADING = re.compile(
    r"(?i).*\b(?:slas?|slos?|service[- ]levels?(?:[- ](?:agreements?|objectives?))?"
    r"|availability[- ]targets?|reliability[- ]targets?)\b.*"
)
_SUSTAINABILITY_WORD = re.compile(
    r"(?i)sustainab|carbon|energy|emissions?|\bidle\b|utili[sz]ation|right-?siz"
    r"|scale[- ]to[- ]zero|off-hours"
)


class SlaIgnoresSustainability(_RepoRule):
    id = "REPO-098"
    title = "Service levels are not aligned with sustainability goals"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Write the service-level or availability target down in a note (an SLA, SLO or "
        "availability target) and record what it costs in resources: which tiers can scale to "
        "zero or run smaller off-hours, and where a lower target lets you cut idle capacity "
        "and energy use."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        workload = production_workload(repo_path)
        if not workload:
            return []
        if _note_with(repo_path, _SLA_NAME, _SLA_HEADING, _SUSTAINABILITY_WORD):
            return []
        return [self._finding(
            f"Runs {_named(workload)}; searched notes named or headed SLA, SLO, service level, "
            "availability target or reliability target for a sustainability tradeoff (carbon, "
            "energy, idle capacity, utilization, right-sizing, scale to zero, off-hours); "
            "found none",
        )]


# Assets that cost to keep and that nothing in the repo refers to. Elastic IPs are COST-012
# and CF-EIP-001.
_UNUSED_KINDS = (
    ("EBS volume", "EC2::Volume", ("aws_ebs_volume",), r"ec2\.(?:Cfn)?Volume"),
    ("load balancer", "ElasticLoadBalancingV2::LoadBalancer", ("aws_lb", "aws_alb"),
     r"(?:elbv2|elb|elasticloadbalancingv2)\.(?:Cfn)?(?:Application|Network)?LoadBalancer"),
    ("target group", "ElasticLoadBalancingV2::TargetGroup", ("aws_lb_target_group",
                                                            "aws_alb_target_group"),
     r"(?:elbv2|elb|elasticloadbalancingv2)\.(?:Cfn)?(?:Application|Network)?TargetGroup"),
    ("NAT gateway", "EC2::NatGateway", ("aws_nat_gateway",), r"ec2\.CfnNatGateway"),
    ("network interface", "EC2::NetworkInterface", ("aws_network_interface",),
     r"ec2\.(?:Cfn)?NetworkInterface"),
)
_CFN_SUFFIXES = (".json", ".yaml", ".yml", ".template")
_CDK_ASSIGNED = re.compile(
    r"^\s*(?:(?:export\s+)?(?:const|let|var)\s+|(?:this|self)\.|(?:public|private|protected"
    r"|readonly)\s+)*(\w+)\s*(?::[^=\n]+)?=\s*$"
)


def _word_count(name: str, text: str) -> int:
    return len(re.findall(rf"(?<![\w$.-]){re.escape(name)}(?![\w-])", text))


def _cdk_unused(rel: str, text: str, kind: str, pattern: str) -> Iterator[tuple[str, int]]:
    for match in re.finditer(rf"\b{pattern}\(", text):
        if rel.endswith(".py") and not _live(re.compile(re.escape(match.group(0))), rel, text):
            continue
        start = text.rfind("\n", 0, match.start()) + 1
        prefix = re.sub(r"\bnew\s+$", "", text[start:match.start()])
        assigned = _CDK_ASSIGNED.match(prefix)
        if assigned:
            if _word_count(assigned.group(1), text) <= 1:
                yield assigned.group(1), _line_of(text, match.start())
        elif not prefix.strip():
            before = text[:start].rstrip()
            if not before or before[-1] not in "=(,[:?|&+":
                yield "created and not assigned", _line_of(text, match.start())


def unused_assets(repo_path: Path) -> List[str]:
    """Provisioned assets in production IaC whose name nothing refers to, as
    "kind name (file:line)"."""
    files = [(rel, _blank_strings(rel, text)) for rel, text in iac_texts(repo_path)
             if _production(rel)]
    corpus = "\n".join(text for _, text in files)
    found: List[str] = []
    for rel, text in files:
        suffix = "." + rel.rsplit(".", 1)[-1].lower()
        for kind, cfn_type, tf_types, cdk in _UNUSED_KINDS:
            if suffix in _CFN_SUFFIXES:
                for name, body in _cf_resources(rel, text).items():
                    if body.get("Type") == f"AWS::{cfn_type}" and _word_count(name, text) <= 1:
                        found.append(f"{kind} {name} ({rel}:{_line_of(text, text.find(name))})")
            elif suffix == ".tf":
                for match in re.finditer(
                    rf"resource\s+\"({'|'.join(tf_types)})\"\s+\"(\w+)\"", text
                ):
                    ref = rf"\b{match.group(1)}\.{match.group(2)}\b"
                    if not re.search(ref, corpus):
                        found.append(f"{kind} {match.group(2)} "
                                     f"({rel}:{_line_of(text, match.start())})")
            elif suffix in (".ts", ".js", ".py"):
                found.extend(f"{kind} {name} ({rel}:{line})"
                             for name, line in _cdk_unused(rel, text, kind, cdk))
    return found


class UnusedAssets(_RepoRule):
    id = "REPO-099"
    title = "Provisioned assets nothing uses"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Remove assets nothing refers to, or wire them in: attach or delete the volume, add "
        "a listener or delete the load balancer, register or delete the target group, add a "
        "route or delete the NAT gateway, and attach or delete the network interface."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = unused_assets(repo_path)
        if not found:
            return []
        return [self._finding(
            f"Provisions {_listed(found, 4)} and no other IaC in the repo refers to the name "
            "(no attachment, listener, route or reference); an idle asset still draws "
            "resources and energy"
        )]


_PRICE_CLASS = re.compile(
    r"(?:PriceClass|price_class|priceClass)[\"']?\s*[:=]\s*[\"']?(?:[\w.]*?\.)?"
    r"(?:PriceClass_|PRICE_CLASS_)(100|200|All|ALL)\b"
)
_REGION_NAME = r"[a-z]{2}-[a-z]+-\d"
_CODE_STACK_REGION = re.compile(rf"\bregion[\"']?\s*[:=]\s*[\"']({_REGION_NAME})[\"']")
_TF_PROVIDER = re.compile(r"provider\s+\"aws\"\s*\{")
_TF_STACK_REGION = re.compile(rf"(?m)^\s*region\s*=\s*\"({_REGION_NAME})\"")
_ORIGIN_REGION = re.compile(
    rf"\.s3(?:-website)?[.-]({_REGION_NAME})\.amazonaws\.com"
    rf"|\.({_REGION_NAME})\.elb\.amazonaws\.com"
    rf"|\.execute-api\.({_REGION_NAME})\.amazonaws\.com"
)
_OCEANIA = ("ap-southeast-2", "ap-southeast-4", "ap-southeast-6")
_PLACEMENT_REASON = (
    r"\b(?:latency|audience|users?|customers?|viewers?|traffic|placement|geograph\w*"
    r"|residency|sovereignty|compliance|costs?|because|since|due to)\b"
)
_PLACEMENT_COMMENT = re.compile(rf"(?i)(?://|#|/\*|^\s*\*)[^\n]*{_PLACEMENT_REASON}")
_PLACEMENT_BODY = re.compile(f"(?i){_PLACEMENT_REASON}")
_PLACEMENT_NAME = re.compile(
    r"(?:placement|latency|edge|regions?|geograph\w*|price[-_ ]?class|cloudfront)"
)
_PLACEMENT_HEADING = re.compile(
    r"(?i).*\b(?:placement|latency|edge|regions?|geograph\w*|price[- ]class|cloudfront)\b.*"
)
_PRICE_CLASS_AREAS = {
    "100": "North America, Europe and Israel", "200": "North America, Europe, Israel, Asia, "
    "the Middle East and Africa",
}


def _price_class_covers(price_class: str, region: str) -> bool:
    if price_class == "ALL":
        return True
    if region.startswith(("us-", "ca-", "mx-", "eu-", "il-")):
        return True
    if price_class == "200":
        return not region.startswith("sa-") and region not in _OCEANIA
    return False


def _commented_with_reason(text: str, line: int) -> bool:
    lines = text.splitlines()
    return any(_PLACEMENT_COMMENT.search(item) for item in lines[max(line - 2, 0):line])


def _placement_regions(rel: str, text: str) -> Iterator[tuple[str, int]]:
    """(region, line) of each literal Region: a CDK env or region prop, a Terraform provider
    without an alias, and a Region inside an S3, load balancer or API Gateway domain."""
    suffix = rel.rsplit(".", 1)[-1].lower()
    if suffix in ("ts", "js", "py"):
        for match in _CODE_STACK_REGION.finditer(text):
            if _live(re.compile(re.escape(match.group(0))), rel, text):
                yield match.group(1), _line_of(text, match.start(1))
    elif suffix == "tf":
        for block in _TF_PROVIDER.finditer(text):
            body = _braced(text, block.end() - 1)
            if re.search(r"\balias\s*=", body):
                continue
            for match in _TF_STACK_REGION.finditer(body):
                yield match.group(1), _line_of(text, block.end() + match.start(1))
    for match in _ORIGIN_REGION.finditer(text):
        yield next(g for g in match.groups() if g), _line_of(text, match.start())


def placement_mismatches(repo_path: Path) -> List[str]:
    """Each literal Region outside the CloudFront price class of the same repo, with no
    comment or note giving a reason, as a sentence part."""
    classes: List[tuple[str, str, int]] = []
    regions: List[tuple[str, str, int, bool]] = []
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        text = _blank_strings(rel, text)
        for match in _PRICE_CLASS.finditer(text):
            line = _line_of(text, match.start())
            if not _commented_with_reason(text, line):
                classes.append((match.group(1).upper(), rel, line))
        for region, line in _placement_regions(rel, text):
            regions.append((region, rel, line, _commented_with_reason(text, line)))
    found = [
        f"PriceClass_{'All' if pc == 'ALL' else pc} at {crel}:{cline} serves "
        f"{_PRICE_CLASS_AREAS[pc]}, but the stack uses {region} at {rrel}:{rline}"
        for pc, crel, cline in classes
        for region, rrel, rline, explained in regions
        if not explained and not _price_class_covers(pc, region)
    ]
    if found and _note_with(
        repo_path, _PLACEMENT_NAME, _PLACEMENT_HEADING, _PLACEMENT_BODY
    ):
        return []
    return found


class GeographicPlacementMismatch(_RepoRule):
    id = "REPO-100"
    title = "CloudFront price class and stack Region disagree"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Place the workload close to the users and match the edge to it: pick the price class "
        "that covers the Region the origin runs in (PriceClass_All for South America or "
        "Oceania), or move the stack to a Region near its users. If the split is deliberate, "
        "say why in a comment beside it or in a placement note."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = placement_mismatches(repo_path)
        if not found:
            return []
        return [self._finding(
            f"{_listed(found, 2)}; searched for a comment on or above either line and a note "
            "named or headed placement, latency, edge or region that gives a reason; found "
            "none. Traffic from outside the covered areas travels farther than it needs to"
        )]


_TEAM_NAME = re.compile(
    r"(?:dev(?:eloper)?[-_ ]?(?:env(?:ironment)?s?|tooling|workstations?)|workstations?"
    r"|ci[-_ ]?runners?|build[-_ ]?agents?|team[-_ ]?resources?)"
)
_TEAM_HEADING = re.compile(
    r"(?i).*\b(?:dev(?:eloper)?[- ]env(?:ironment)?s?|developer[- ]tooling|workstations?"
    r"|ci[- ]runners?|build[- ]agents?|team[- ]resources?|cloud[- ]dev\w*)\b.*"
)
_TEAM_SIZING = re.compile(
    r"(?i)right-?siz|auto-?[- ]?stop|\bidle\b|shut[- ]?(?:s )?down|scale[- ]down|schedul"
    r"|hibernat|on-demand|\bspot\b"
)


class TeamResourcesUnsized(_RepoRule):
    id = "REPO-101"
    title = "Team resources are not sized for the work"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Add a note named or headed developer environments, workstations, CI runners or build "
        "agents that says how they are sized for the work and when they shut down: "
        "right-sized instances, auto-stop or hibernation when idle, a schedule, on-demand "
        "or Spot runners."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        workload = production_workload(repo_path)
        if not workload:
            return []
        if _note_with(repo_path, _TEAM_NAME, _TEAM_HEADING, _TEAM_SIZING):
            return []
        return [self._finding(
            f"Runs {_named(workload)}; searched notes named or headed developer environment, "
            "workstation, CI runners, build agents or team resources for how they are sized "
            "and shut down (right-sizing, auto-stop, idle, schedule, hibernation, on-demand, "
            "Spot); found none",
        )]


class DemandCurveNotFlattened(_RepoRule):
    id = "REPO-102"
    title = "Demand spikes reach the workload unflattened"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Flatten the demand curve so you do not provision for the spike: throttle the API (a "
        "stage or usage plan throttle, or a WAF rate-based rule), put an SQS queue, Kinesis "
        "stream or EventBridge bus between a trigger and the Lambda function, or cap the "
        "function with reserved concurrency."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found, _ = unbuffered_demand(repo_path)
        if not found:
            return []
        return [self._finding(
            f"Takes demand straight to the workload: {_listed(found)}; searched production "
            "IaC for a throttle, usage plan, WAF rate-based rule, reserved or provisioned "
            "concurrency, and a queue, stream or event bus; found none. Unflattened spikes "
            "drive over-provisioned, idle capacity"
        )]


# SUS 3: software and architecture patterns. Components nothing uses (REPO-103), code at its
# resource ceiling with no profile (REPO-104), end-user devices (REPO-105), and data access
# patterns (REPO-106, which shares its detection with REPO-063).


def _refs(name: str, text: str) -> int:
    """How often name appears as a whole word (a dotted reference such as self.name counts)."""
    return len(re.findall(rf"(?<![\w$-]){re.escape(name)}(?![\w-])", text))


def _is_zero(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, str)) and str(value) == "0"


def _named_once(name: str, literal: object, corpus: str) -> bool:
    """Whether the logical id and a literal resource name (when there is a plain one) each
    appear only where they are defined."""
    if _refs(name, corpus) > 1:
        return False
    return (not isinstance(literal, str) or "$" in literal or literal == name
            or _refs(literal, corpus) <= 1)


def _tf_resources(text: str, types: str) -> Iterator[tuple[str, str, str, int]]:
    """(type, name, body, line) of each Terraform resource of the types (a regex)."""
    for match in re.finditer(rf"resource\s+\"({types})\"\s+\"(\w+)\"\s*\{{", text):
        yield (match.group(1), match.group(2), _braced(text, match.end() - 1),
               _line_of(text, match.start()))


def _cdk_constructs(rel: str, text: str, pattern: str) -> Iterator[tuple[str, str, str, int]]:
    """(variable it is assigned to or "", construct id, arguments, line) of each live call
    of a CDK construct."""
    for match in re.finditer(pattern, text):
        if rel.endswith(".py") and not _live(re.compile(re.escape(match.group(0))), rel, text):
            continue
        start = text.rfind("\n", 0, match.start()) + 1
        prefix = re.sub(r"(?:\bnew\s+)?[\w.]*$", "", text[start:match.start()])
        assigned = _CDK_ASSIGNED.match(prefix)
        args = _braced(text, match.end() - 1, "(", ")")
        ident = re.match(r"\s*[\w.]+\s*,\s*['\"]([^'\"]+)['\"]", args)
        yield (assigned.group(1) if assigned else "", ident.group(1) if ident else "",
               args, _line_of(text, match.start()))


def _cdk_zero(keys: str, args: str) -> bool:
    return bool(re.search(rf"\b(?:{keys})[\"']?\s*[:=]\s*[\"']?0[\"']?(?![\w.])", args))


def _arg_literal(keys: str, args: str) -> str | None:
    match = re.search(rf"\b(?:{keys})[\"']?\s*[:=]\s*['\"]([^'\"$]+)['\"]", args)
    return match.group(1) if match else None


_CDK_DISUSED = (
    ("ECS service", r"\b\w*(?:Fargate|Ec2)Service\(|\becs\.CfnService\("),
    ("Auto Scaling group", r"\b(?:\w+\.)?(?:Cfn)?AutoScalingGroup\("),
    ("Lambda function", r"\b\w*lambda\w*\.(?:Cfn)?Function\(|\b(?:Nodejs|Python|Go|DockerImage)"
     r"Function\("),
    ("EventBridge rule", r"\b\w*events\.(?:Cfn)?Rule\("),
    ("SNS topic", r"\b\w*sns\.(?:Cfn)?Topic\("),
)
_CF_DISUSED_TYPES = {
    "AWS::ECS::Service": "ECS service", "AWS::AutoScaling::AutoScalingGroup": "Auto Scaling group",
    "AWS::Lambda::Function": "Lambda function", "AWS::Events::Rule": "EventBridge rule",
    "AWS::SNS::Topic": "SNS topic",
}
_TF_DISUSED_TYPES = (
    "aws_ecs_service|aws_autoscaling_group|aws_lambda_function|aws_cloudwatch_event_rule"
    "|aws_sns_topic"
)
_TF_KIND = {
    "aws_ecs_service": "ECS service", "aws_autoscaling_group": "Auto Scaling group",
    "aws_lambda_function": "Lambda function", "aws_cloudwatch_event_rule": "EventBridge rule",
    "aws_sns_topic": "SNS topic",
}
_UNTRIGGERED = "nothing triggering or referring to it"


def _cf_disused(rel: str, text: str, corpus: str) -> Iterator[str]:
    for name, body in _cf_resources(rel, text).items():
        kind = _CF_DISUSED_TYPES.get(str(body.get("Type")))
        if not kind:
            continue
        props = _props(body)
        why = None
        if kind == "ECS service" and _is_zero(props.get("DesiredCount")):
            why = "desired count 0"
        elif kind == "Auto Scaling group" and _is_zero(props.get("MaxSize")):
            why = "maximum size 0"
        elif kind == "Lambda function":
            if _is_zero(props.get("ReservedConcurrentExecutions")):
                why = "reserved concurrency 0"
            elif _named_once(name, props.get("FunctionName"), corpus):
                why = _UNTRIGGERED
        elif kind == "EventBridge rule":
            if props.get("State") == "DISABLED":
                why = "state DISABLED"
            elif not props.get("Targets"):
                why = "no targets"
        elif kind == "SNS topic" and not props.get("Subscription") and _named_once(
            name, props.get("TopicName"), corpus
        ):
            why = "no subscription and no reference"
        if why:
            yield f"{kind} {name} with {why} ({rel}:{_line_of(text, text.find(name))})"


def _tf_disused(rel: str, text: str, corpus: str) -> Iterator[str]:
    for rtype, name, body, line in _tf_resources(text, _TF_DISUSED_TYPES):
        kind = _TF_KIND[rtype]
        referenced = bool(re.search(rf"\b{rtype}\.{name}\b", corpus))
        found_name = re.search(r"(?m)^\s*(?:function_name|name)\s*=\s*\"([^\"$]+)\"", body)
        literal = found_name if found_name and found_name.group(1) != name else None
        why = None
        if kind == "ECS service" and re.search(r"(?m)^\s*desired_count\s*=\s*0\s*$", body):
            why = "desired count 0"
        elif kind == "Auto Scaling group" and re.search(r"(?m)^\s*max_size\s*=\s*0\s*$", body):
            why = "maximum size 0"
        elif kind == "Lambda function":
            if re.search(r"(?m)^\s*reserved_concurrent_executions\s*=\s*0\s*$", body):
                why = "reserved concurrency 0"
            elif not referenced and (not literal or _refs(literal.group(1), corpus) <= 1):
                why = _UNTRIGGERED
        elif kind == "EventBridge rule":
            if re.search(r"(?m)^\s*is_enabled\s*=\s*false\b|^\s*state\s*=\s*\"DISABLED\"", body):
                why = "state DISABLED"
            elif not referenced:
                why = "no targets"
        elif kind == "SNS topic" and not referenced and (
            not literal or _refs(literal.group(1), corpus) <= 1
        ):
            why = "no subscription and no reference"
        if why:
            yield f"{kind} {name} with {why} ({rel}:{line})"


def _cdk_disused(rel: str, text: str, corpus: str) -> Iterator[str]:
    for kind, pattern in _CDK_DISUSED:
        for var, ident, args, line in _cdk_constructs(rel, text, pattern):
            name = var or ident or "(unnamed)"
            why = None
            if kind == "ECS service" and _cdk_zero("desiredCount|desired_count", args):
                why = "desired count 0"
            elif kind == "Auto Scaling group" and _cdk_zero(
                "maxCapacity|max_capacity|maxSize|max_size", args
            ):
                why = "maximum size 0"
            elif kind == "Lambda function":
                literal = _arg_literal("functionName|function_name", args)
                if _cdk_zero("reservedConcurrentExecutions|reserved_concurrent_executions", args):
                    why = "reserved concurrency 0"
                elif (not var or _refs(var, corpus) == 1) and (
                    not ident or _refs(ident, corpus) <= 1
                ) and (not literal or _refs(literal, corpus) <= 1):
                    why = _UNTRIGGERED
            elif kind == "EventBridge rule":
                if re.search(r"\benabled[\"']?\s*[:=]\s*(?:false|False)\b|DISABLED", args):
                    why = "disabled"
                elif not re.search(r"\btargets[\"']?\s*[:=]", args) and (
                    not var or _refs(var, corpus) == 1
                ):
                    why = "no targets"
            elif kind == "SNS topic" and var and _refs(var, corpus) == 1:
                literal = _arg_literal("topicName|topic_name", args)
                if not literal or _refs(literal, corpus) <= 1:
                    why = "no subscription and no reference"
            if why:
                yield f"{kind} {name} with {why} ({rel}:{line})"


def disused_components(repo_path: Path) -> List[str]:
    """Components in production IaC with a clear no-use signal, as "kind name with reason
    (file:line)". REPO-099's assets are not repeated here."""
    everything = list(iac_texts(repo_path))
    corpus = "\n".join(text for _, text in everything)
    found: List[str] = []
    for rel, text in everything:
        if not _production(rel):
            continue
        text = _blank_strings(rel, text)
        suffix = "." + rel.rsplit(".", 1)[-1].lower()
        if suffix in _CFN_SUFFIXES:
            found.extend(_cf_disused(rel, text, corpus))
        elif suffix == ".tf":
            found.extend(_tf_disused(rel, text, corpus))
        else:
            found.extend(_cdk_disused(rel, text, corpus))
    return found


class UnusedComponents(_RepoRule):
    id = "REPO-103"
    title = "Workload components with no use"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Remove components that do nothing, or wire them in: delete an ECS service at desired "
        "count 0, an Auto Scaling group with a maximum of 0, a function with reserved "
        "concurrency 0, a disabled or target-less EventBridge rule, a topic with no "
        "subscriber and a function nothing triggers; or give each a trigger, target or "
        "subscriber and a use."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = disused_components(repo_path)
        if not found:
            return []
        return [self._finding(
            f"Declares {_listed(found, 4)}; nothing in the IaC gives it work, so it only adds "
            "to what the workload runs and maintains"
        )]


_PROFILER_IN_IAC = _kinds(
    ("CodeGuru Profiler", _cf_type(r"CodeGuruProfiler::ProfilingGroup")
     + r"|resource\s+\"aws_codeguruprofiler_profiling_group\"|\bcodeguruprofiler\."),
    ("Lambda Insights", r"\b(?:lambdaInsightsVersion|LambdaInsightsVersion|insights_version"
     r"|LambdaInsightsExtension(?:-Arm64)?|lambda_insights_extension)\b"),
    ("AWS Lambda Power Tuning", r"aws-lambda-power-tuning"),
)
_LOAD_NAME = re.compile(
    r"(?:^|[-_. ])(?:load[-_ ]?tests?|(?:performance|perf)[-_ ]?(?:profiles?|profiling|tests?)"
    r"|profiling|benchmarks?|capacity[-_ ]?tests?)(?:$|[-_. ])"
)
_LOAD_HEADING = re.compile(
    r"(?i).*\b(?:load[- ]test\w*|(?:performance|perf)[- ]profil\w*|profiling|benchmark\w*"
    r"|capacity[- ]test\w*)\b.*"
)
_NUMBER_UNIT = re.compile(
    r"(?i)\b\d[\d,.]*\s*(?:ms|milliseconds?|seconds?|secs?|MB|GB|MiB|GiB|rps|req/s"
    r"|requests?)(?![a-z])"
)
# Fargate task sizes: vCPU units -> the largest memory (MiB) that size takes.
_FARGATE_MAX = {256: 2048, 512: 4096, 1024: 8192, 2048: 16384, 4096: 30720, 8192: 61440,
                16384: 122880}
_MEM_KEY = r"(?:MemorySize|memorySize|memory_size)"
_TASK_MEM_KEY = r"(?:Memory|memory|memoryLimitMiB|memory_limit_mib)"
_NUM = r"[\"']?\s*[:=]\s*[\"']?(\d+)"


def _lambda_ceiling(memory: int | None, timeout: int | None) -> str | None:
    if memory == 10240:
        return "memory 10240 MB"
    if timeout == 900 and memory is not None and memory >= 3008:
        return f"timeout 900 s with memory {memory} MB"
    return None


def _task_ceiling(cpu: int | None, memory: int | None) -> str | None:
    if cpu == 16384 or (cpu in _FARGATE_MAX and memory == _FARGATE_MAX[cpu]):
        return f"cpu {cpu} with memory {memory} MiB"
    if memory == 122880:
        return f"memory 122880 MiB with cpu {cpu}"
    return None


def _int(match: re.Match[str] | None) -> int | None:
    return int(match.group(1)) if match else None


def _timeout_seconds(text: str) -> int | None:
    match = re.search(
        r"\b(?:Timeout|timeout)[\"']?\s*[:=]\s*(?:[\"']?(\d+)[\"']?(?![\w.(])"
        r"|[\w.]*Duration\.(seconds|minutes)\((\d+)\))", text
    )
    if not match:
        return None
    if match.group(1):
        return int(match.group(1))
    return int(match.group(3)) * (60 if match.group(2) == "minutes" else 1)


def _ceilings_in_body(body: str, lambda_like: bool) -> str | None:
    if lambda_like:
        return _lambda_ceiling(_int(re.search(rf"\b{_MEM_KEY}{_NUM}", body)),
                               _timeout_seconds(body))
    return _task_ceiling(_int(re.search(rf"\b(?:Cpu|cpu){_NUM}", body)),
                         _int(re.search(rf"\b{_TASK_MEM_KEY}{_NUM}", body)))


_CDK_CEILING = (
    (True, r"\b\w*lambda\w*\.(?:Cfn)?Function\(|\b(?:Nodejs|Python|Go|DockerImage)Function\("),
    (False, r"\b\w*Fargate\w*(?:Service|TaskDefinition)\(|\becs\.CfnTaskDefinition\("),
)


def _digits(value: object) -> int | None:
    return int(str(value)) if str(value).isdigit() else None


def resource_ceilings(repo_path: Path) -> List[str]:
    """Lambda functions and ECS/Fargate tasks sized at the platform maximum in production
    IaC, as "kind name at value (file:line)"."""
    found: List[str] = []
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        text = _blank_strings(rel, text)
        suffix = "." + rel.rsplit(".", 1)[-1].lower()
        if suffix in _CFN_SUFFIXES:
            for name, body in _cf_resources(rel, text).items():
                kind = str(body.get("Type"))
                props = _props(body)
                if kind in ("AWS::Lambda::Function", "AWS::Serverless::Function"):
                    hit = _lambda_ceiling(_digits(props.get("MemorySize")),
                                          _digits(props.get("Timeout")))
                    label = "Lambda function"
                elif kind == "AWS::ECS::TaskDefinition":
                    hit = _task_ceiling(_digits(props.get("Cpu")), _digits(props.get("Memory")))
                    label = "ECS task definition"
                else:
                    continue
                if hit:
                    found.append(f"{label} {name} at {hit} ({rel}:"
                                 f"{_line_of(text, text.find(name))})")
        elif suffix == ".tf":
            for rtype, name, block, line in _tf_resources(
                text, "aws_lambda_function|aws_ecs_task_definition"
            ):
                lambda_like = rtype == "aws_lambda_function"
                if hit := _ceilings_in_body(block, lambda_like):
                    label = "Lambda function" if lambda_like else "ECS task definition"
                    found.append(f"{label} {name} at {hit} ({rel}:{line})")
        else:
            for lambda_like, pattern in _CDK_CEILING:
                for var, ident, args, line in _cdk_constructs(rel, text, pattern):
                    if hit := _ceilings_in_body(args, lambda_like):
                        label = "Lambda function" if lambda_like else "ECS task definition"
                        found.append(f"{label} {var or ident or '(unnamed)'} at {hit} "
                                     f"({rel}:{line})")
    return found


def profiling_evidence(repo_path: Path) -> str | None:
    """The first profiler, Lambda Insights, Power Tuning or load-test note the repo has."""
    for rel, text in iac_texts(repo_path):
        text = _blank_strings(rel, text)
        for name, pattern in _PROFILER_IN_IAC:
            if _live(pattern, rel, text):
                return f"{name} in {rel}"
    if note := _note_with(repo_path, _LOAD_NAME, _LOAD_HEADING, _NUMBER_UNIT):
        return f"note {note}"
    return None


class HotCodeUnprofiled(_RepoRule):
    id = "REPO-104"
    title = "Compute at its resource ceiling with no profile of the code"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Measure where the time and memory go before sizing to the maximum: enable CodeGuru "
        "Profiler or Lambda Insights, run AWS Lambda Power Tuning, or record a load test or "
        "profile with numbers (latency, memory, requests per second) in a note. Then fix the "
        "hot code path instead of adding more resources."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = resource_ceilings(repo_path)
        if not found or profiling_evidence(repo_path):
            return []
        return [self._finding(
            f"Sized at the platform maximum: {_listed(found, 4)}; searched the IaC for CodeGuru "
            "Profiler, Lambda Insights and AWS Lambda Power Tuning, and notes named or headed "
            "load test, performance profile, profiling, benchmark or capacity test with "
            "figures (ms, seconds, MB, GB, rps, requests); found none",
        )]


_MOBILE_DIR_SUFFIXES = (".xcodeproj", ".xcworkspace")
_MOBILE_FILES = {
    "androidmanifest.xml": "Android app (AndroidManifest.xml)",
    "info.plist": "iOS app (Info.plist)",
}
_MOBILE_CONFIG = re.compile(r"capacitor\.config\.(?:ts|js|json)", re.IGNORECASE)
_MOBILE_PACKAGES = ("react-native", "expo", "@capacitor/core", "cordova")
_DEVICE_IAC = _kinds(
    ("AWS IoT thing", _cf_type(r"IoT::(?:Thing|ProvisioningTemplate)")
     + r"|resource\s+\"aws_iot_(?:thing|provisioning_template)\""
     r"|\biot\.Cfn(?:Thing|ProvisioningTemplate)\("),
    ("Pinpoint app", _cf_type(r"Pinpoint::App") + r"|resource\s+\"aws_pinpoint_app\""
     r"|\bpinpoint\.CfnApp\("),
)
_AMPLIFY_APP = re.compile(
    _cf_type(r"Amplify::App") + r"|resource\s+\"aws_amplify_app\"|\bamplify\.CfnApp\("
)
_MOBILE_WORD = re.compile(r"(?i)\b(?:ios|android|react[- ]native|flutter|mobile)\b")
_DEVICE_TESTING = _kinds(
    ("AWS Device Farm", _cf_type(r"DeviceFarm::(?:Project|DevicePool|InstanceProfile)")
     + r"|resource\s+\"aws_devicefarm_\w+\"|\bdevicefarm\."),
)
_DEVICE_CI = (("AWS Device Farm step", re.compile(r"\baws\s+devicefarm\b")),)
_DEVICE_NAME = re.compile(
    r"(?:^|[-_. ])(?:devices?[-_ ]?(?:support|matrix|matrices|lifecycle)|supported[-_ ]devices"
    r"|minimum[-_ ]os|min[-_ ]os|battery|energy|hardware[-_ ]lifecycle|equipment)(?:$|[-_. ])"
)
_DEVICE_HEADING = re.compile(
    r"(?i).*\b(?:device[- ]support|supported[- ]devices?|device[- ]matri(?:x|ces)"
    r"|minimum[- ]os|battery|energy|hardware[- ]lifecycle|equipment)\b.*"
)


def _json_keys(text: str, *sections: str) -> set[str]:
    try:
        doc = json.loads(text)
    except ValueError:
        return set()
    if not isinstance(doc, dict):
        return set()
    keys: set[str] = set()
    for section in sections:
        value = doc.get(section)
        if isinstance(value, dict):
            keys.update(value)
    return keys


def _amplify_is_mobile(rel: str, text: str) -> bool:
    for match in _AMPLIFY_APP.finditer(text):
        if not _live(re.compile(re.escape(match.group(0))), rel, text):
            continue
        if rel.endswith(_CFN_SUFFIXES):
            for body in _cf_resources(rel, text).values():
                if body.get("Type") == "AWS::Amplify::App" and _MOBILE_WORD.search(
                    json.dumps(_props(body), default=str)
                ):
                    return True
        elif rel.endswith(".tf"):
            if any(_MOBILE_WORD.search(body)
                   for _t, _n, body, _l in _tf_resources(text, "aws_amplify_app")):
                return True
        elif any(_MOBILE_WORD.search(args)
                 for _v, _i, args, _l in _cdk_constructs(rel, text, r"\bamplify\.CfnApp\(")):
            return True
    return False


def device_targets(repo_path: Path) -> dict[str, str]:
    """What the repo builds for end-user devices or a device fleet: kind -> first file."""
    found: dict[str, str] = {}
    for path in walk(repo_path):
        parts = _rel_parts(path, repo_path)
        if _in_test_dir(parts):
            continue
        rel, name = "/".join(parts), path.name.lower()
        if any(p.endswith(_MOBILE_DIR_SUFFIXES) for p in parts[:-1]):
            found.setdefault("iOS project (Xcode)", rel)
        elif name in _MOBILE_FILES:
            found.setdefault(_MOBILE_FILES[name], rel)
        elif _MOBILE_CONFIG.fullmatch(name):
            found.setdefault("Capacitor app", rel)
        elif name == "config.xml" and "<widget" in read_text_safe(path):
            found.setdefault("Cordova app", rel)
        elif name == "pubspec.yaml" and re.search(
            r"(?m)^\s*flutter\s*:|sdk\s*:\s*flutter", read_text_safe(path)
        ):
            found.setdefault("Flutter app", rel)
        elif name in ("package.json", "app.json"):
            text = read_text_safe(path)
            if _saved_report(text):
                continue
            if name == "app.json" and '"expo"' in text:
                found.setdefault("Expo app", rel)
            elif name == "package.json":
                keys = _json_keys(text, "dependencies", "devDependencies")
                if hit := next((k for k in _MOBILE_PACKAGES if k in keys), None):
                    found.setdefault(f"mobile app ({hit})", rel)
    for rel, text in iac_texts(repo_path):
        if not _production(rel):
            continue
        text = _blank_strings(rel, text)
        for kind, pattern in _DEVICE_IAC:
            if _live(pattern, rel, text):
                found.setdefault(kind, rel)
        if _amplify_is_mobile(rel, text):
            found.setdefault("Amplify mobile app", rel)
    return found


def device_testing(repo_path: Path) -> str | None:
    """The first Device Farm setup, CI step or device note the repo has."""
    for rel, text in iac_texts(repo_path):
        text = _blank_strings(rel, text)
        for name, pattern in _DEVICE_TESTING:
            if _live(pattern, rel, text):
                return f"{name} in {rel}"
    _builds, steps = _tools_in_builds(repo_path, _DEVICE_CI)
    for name, where in steps.items():
        return f"{name} in {where}"
    if note := _note_with(repo_path, _DEVICE_NAME, _DEVICE_HEADING, re.compile(r"\S")):
        return f"note {note}"
    return None


class DeviceImpactUnaddressed(_RepoRule):
    id = "REPO-105"
    title = "Impact on end-user devices is not addressed"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Test on the devices your users have and record the decision: add AWS Device Farm to "
        "the pipeline, and write a note on the supported devices and minimum OS, on battery "
        "and energy use, and on how long you keep fleet hardware in service so you do not "
        "force users to replace devices early."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = device_targets(repo_path)
        if not found or device_testing(repo_path):
            return []
        return [self._finding(
            f"Builds for end-user devices: {_named(found)}; searched the IaC for Device Farm, "
            "the build steps for `aws devicefarm`, and notes named or headed device support, "
            "supported devices, device matrix, minimum OS, battery, energy, hardware lifecycle "
            "or equipment; found none",
        )]


class DataAccessPatternMismatch(_RepoRule):
    id = "REPO-106"
    title = "Storage is not matched to the data access pattern"
    category = "Sustainability"
    severity = "Low"
    themes = ("sustainability", "finops")
    recommendation = (
        "Match storage to how the data is read and written, and use managed services that "
        "scale to use instead of idle capacity attached to a host: DynamoDB or Aurora "
        "Serverless for variable key-value or relational access, S3 with lifecycle tiers for "
        "objects, ElastiCache for hot reads, OpenSearch Service for search, and EFS for "
        "shared files."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        found = unmanaged_host_data(repo_path)
        if not found:
            return []
        places = [f"{kind} at {rel}:{line}" for kind, rel, line in found]
        return [self._finding(
            f"Keeps data on host-attached capacity: {_listed(places, 4)}; the volume is "
            "provisioned whether or not it is used and does not follow the access pattern. "
            f"Searched the IaC for a {_MANAGED_SEARCHED} that scales to use; found none",
            file=found[0][1],
            line=found[0][2],
        )]


# Selecting services by cost (COST 5): written cost requirements (REPO-179), the cost of each
# component (REPO-180) and licensing (REPO-181).
_BUDGET_IN_IAC = re.compile(
    _cf_type(r"Budgets::Budget") + r"|resource\s+\"aws_budgets_budget\""
    r"|\bbudgets\.CfnBudget\("
)
_PEAK_WORD = re.compile(r"(?i)\b(?:peak|spikes?|bursts?|seasonal|busiest)\b")
_STEADY_WORD = re.compile(r"(?i)\b(?:steady|baseline|average|normal|typical|off-peak)\b")


class CostRequirementsMissing(_NoteRule):
    id = "REPO-179"
    title = "No budget or cost note states the cost requirements for peak and steady usage"
    category = "Cost"
    themes = ("finops",)
    note_name = _COST_NAME
    note_heading = _COST_HEADING
    recommendation = (
        "Write the cost requirements down: define an AWS Budget for the workload in the IaC, "
        "or keep a cost note that states the monthly limit and what it is at steady usage and "
        "at peak, and review the choice of services against it."
    )
    searched = (
        "the IaC for an AWS Budget, and the notes named or headed for cost, spend or a budget "
        "that mention both peak and steady usage"
    )

    def present(self, repo_path: Path) -> str | None:
        found = _in_iac_text(repo_path, _BUDGET_IN_IAC)
        if found:
            return found
        for rel, text in note_texts(repo_path):
            parts = rel.lower().split("/")
            names = [*parts[:-1], parts[-1].rsplit(".", 1)[0]]
            titled = any(_COST_NAME.search(n) for n in names) or any(
                _COST_HEADING.fullmatch(h.group(2).strip()) for h in _HEADING.finditer(text)
            )
            if titled and _PEAK_WORD.search(text) and _STEADY_WORD.search(text):
                return rel
        return None


class ComponentCostNotAnalysed(CostModelMissing):
    """The same search as REPO-088, answering COST05-BP02 and COST05-BP03 for the question on
    selecting services."""

    id = "REPO-180"
    title = "No cost estimate covers each component the workload declares"
    recommendation = (
        "Cost every component before you pick it: run Infracost in CI (infracost breakdown, "
        "which lists each resource) or write a per-component estimate in the repo with an "
        "amount for each service, and compare the options you did not take."
    )


_MARKETPLACE_IN_IAC = re.compile(r"aws-marketplace|\bmarketplace\b|\bproduct[-_ ]?codes?\b")
_DEDICATED_HOST = re.compile(
    _cf_type(r"EC2::Host") + r"|resource\s+\"aws_ec2_host\"|\bec2\.CfnHost\("
    r"|\btenancy\s*=\s*\"host\"|\bTenancy[\"']?\s*:\s*[\"']?host\b|\bTenancy\.HOST\b"
)
_LICENSE_NAME = re.compile(r"licen[sc]e|licensing|byol|bring[-_ ]?your[-_ ]?own")
_LICENSE_HEADING = re.compile(r"(?i).*\b(?:licen[sc]es?|licensing|byol|bring your own)\b.*")


class LicenseTermsUnrecorded(_RepoRule):
    id = "REPO-181"
    title = "A Marketplace image runs on a dedicated host with no licensing note"
    category = "Cost"
    severity = "Low"
    themes = ("finops",)
    recommendation = (
        "Choose software for its licence cost: write a licensing note that says what the "
        "Marketplace product costs per instance and per host, whether you bring your own "
        "licence and what a licence-included or open source option would cost instead."
    )

    def run(self, repo_path: Path, language: str = "typescript") -> List[Finding]:
        market = _in_iac_text(repo_path, _MARKETPLACE_IN_IAC)
        host = _in_iac_text(repo_path, _DEDICATED_HOST)
        if not market or not host:
            return []
        if _note_having(repo_path, _LICENSE_NAME, _LICENSE_HEADING):
            return []
        return [self._finding(
            f"{market} names a Marketplace image and {host} runs a dedicated host; searched "
            "the notes for a file or heading on licences, licensing or bring your own "
            "licence; found none",
            file=host,
        )]


# Evaluating new services (COST 10): a recurring review of the workload's cost (REPO-182).
_COST_REPORT_IN_IAC = re.compile(
    _cf_type(r"BCMDataExports::Export|CUR::ReportDefinition|CE::AnomalySubscription")
    + r"|resource\s+\"aws_(?:bcmdataexports_export|cur_report_definition"
    r"|ce_anomaly_subscription)\""
)
_COST_REVIEW_NAME = re.compile(
    r"(?:cost|finops|budget|spend)[-_ ]?(?:review|report|checklist|retro(?:spective)?)s?"
    r"|(?:review|checklist)[-_ ]?(?:of[-_ ])?(?:cost|spend)"
)
_COST_REVIEW_HEADING = re.compile(
    r"(?i).*\b(?:cost (?:review|report|checklist)|finops review|budget review|spend review"
    r"|new services review)\b.*"
)


class CostReviewMissing(_NoteRule):
    id = "REPO-182"
    title = "No dated cost review or scheduled cost report is in the repo"
    category = "Cost"
    themes = ("finops",)
    note_name = _COST_REVIEW_NAME
    note_heading = _COST_REVIEW_HEADING
    note_needs = _DATE
    iac = _COST_REPORT_IN_IAC
    recommendation = (
        "Review cost on a schedule and when AWS ships something new: keep a dated cost review "
        "(docs/cost-review-2026-03.md) with a checklist of the services and prices you "
        "re-checked and what you decided, or schedule a cost report (a Data Export or a cost "
        "anomaly subscription) in the IaC."
    )
    searched = (
        "the IaC for a Data Export, a cost and usage report or a cost anomaly subscription, "
        "and the notes for a dated file or heading on a cost review, report or checklist"
    )


REPO_RULES: List[Rule] = [
    RepoTestsMissing(), RepoPipelineMissing(), SingleEnvironment(),
    OrgGuardrailsMissing(), AccountBaselineMissing(), RootUserUnchecked(),
    ForensicCaptureMissing(), ContainmentMissing(),
    DependencyScanMissing(), ArtifactScanMissing(), CentralPackageRepoMissing(),
    QuotaAlarmMissing(), FailoverHeadroomMissing(), VpcCidrOverlap(),
    IdempotencyMissing(), DependencyUrlHardcoded(), SyncCallNoTimeoutOrQueue(),
    EventSeverityMissing(), CustomerCommunicationMissing(), EventStatusDashboardMissing(),
    EventResponseNotAutomated(), VersionControlMissing(), ConfigurationStoreMissing(),
    QualityGateMissing(), SmallReversibleChangesMissing(),
    SecurityTrainingMissing(), PenetrationTestMissing(), CodeReviewNotEnforced(),
    ProgrammaticDeployMissing(), SecurityOwnershipMissing(),
    FailurePlaybookMissing(), PostIncidentAnalysisMissing(), GameDayMissing(),
    KeyContactsMissing(), IncidentPlanMissing(), SecurityPlaybookMissing(),
    ResponseAccessMissing(), SecuritySimulationMissing(),
    IncidentLearningMissing(), PublicEndpointNotHighlyAvailable(), SingleOnPremLink(),
    QuotasNotManaged(), QuotaIncreaseNotAutomated(), FixedQuotaNotDesignedAround(),
    ControlObjectivesMissing(), SecurityScopeNotReduced(), ThreatModelMissing(),
    SecurityServiceReviewMissing(),
    AccessRequirementsMissing(),
    PermissionsNotReduced(),
    LongLivedIdentity(),
    OrgShareOpenToExternal(),
    InteractiveAccessWithKeyPair(),
    ComputeProtectionNotAutomated(),
    ClassifiedDataWithoutLifecycle(),
    MonitoringScopeNotReviewed(),
    LoadTestForDemand(),
    ControlPlaneOnlyRecovery(),
    AcceleratorUtilizationUnchecked(),
    DataClassificationForSustainability(),
    InstanceStoreOnlyData(),
    BlockStorageFixedAndLarge(),
    UnneededDataNotDeleted(),
    CommonDataCopiedPerInstance(),
    RecreatableDataBackedUp(),
    OpsMetricsMissing(),
    OperatorStatusMissing(),
    OpsReviewMissing(),
    OperationsNotAutomated(),
    FaultInjectionMissing(), LoadTestMissing(),
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
    SingleLocationRecoveryMissing(),
    StaticStabilityMissing(), AvailabilityTargetMissing(), AvailabilityNotificationMissing(),
    ComputeMetricsMissing(), StaticComputeFleet(), AcceleratorUtilizationUnwatched(),
    PurposeBuiltDataStoreMissing(),
    EdgeLatencyUnwatched(), NetworkMetricsUnused(), SingleHybridLink(), LoadBalancingMissing(),
    OldNetworkProtocol(),
    CostReportMissing(), CostAttributionTagMissing(), UnitCostMetricMissing(),
    CostNotAllocatedByWorkload(),
    BudgetOwnerMissing(), ReactiveCostMonitoring(), OldGenerationResources(),
    BusinessValueUnquantified(), FinanceTechPartnershipMissing(), CostAwareProcessMissing(),
    CostAwareCultureMissing(),
    CostPolicyMissing(), CostControlMissing(), BudgetTargetMissing(),
    SharedAccountEnvironments(), BillingAccessOnUser(), ProjectLifecycleUntracked(),
    ResourceLifetimeUntracked(), DecommissioningMissing(),
    CostModelMissing(), SharedResourcesUnused(),
    PricingModelUnanalysed(), RegionNotChosenByCost(), ThirdPartyTermsMissing(),
    ManagementPricingMissing(),
    DataTransferUnmodelled(), DataTransferNotOptimised(),
    DemandNotAnalysed(), DemandUnbuffered(),
    SlaIgnoresSustainability(), UnusedAssets(), GeographicPlacementMismatch(),
    TeamResourcesUnsized(), DemandCurveNotFlattened(),
    UnusedComponents(), HotCodeUnprofiled(), DeviceImpactUnaddressed(),
    DataAccessPatternMismatch(),
    CustomerNeedsMissing(), GovernanceControlsMissing(), ThreatLandscapeMissing(), TradeoffsUnrecorded(),
    ProcedureOwnerMissing(), ActivityOwnerMissing(), OwnershipMechanismMissing(), ChangeRequestPathMissing(),
    EscalationMissing(), OperatorChannelMissing(), OperationsCultureMissing(),
    RunbooksMissing(), OperationalPlaybooksMissing(), SupportPlanMissing(), ReadinessReviewMissing(),
    PostIncidentLessonsMissing(), FeedbackLoopMissing(), ImprovementLoopMissing(),
    CostRequirementsMissing(), ComponentCostNotAnalysed(), LicenseTermsUnrecorded(),
    CostReviewMissing(),
    ArchitectureDecisionIncomplete(),
    PerformanceKpiMissing(), PerformanceRemediationMissing(), PerformanceLoadTestMissing(), PerformanceReviewMissing(),
]
