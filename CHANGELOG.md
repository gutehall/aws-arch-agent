# Changelog

New releases go at the top. See [CONTRIBUTING.md](CONTRIBUTING.md#releases) for when to cut one and how the version is bumped.

## v0.2.1 - 2026-11-14

### Changes

- Flag a current x86 EC2 type that has a Graviton class of the same size (`m7i.xlarge` suggests `m7g.xlarge`) on instances, launch templates, launch configurations, and Auto Scaling overrides, with the price difference for a single instance (CF-PERF-005, #101)
- Flag an ECS task definition that runs on `X86_64`, or sets no CPU architecture, and pass Terraform `runtime_platform.cpu_architecture` through to the check (CF-PERF-006, #101)

## v0.2.0 - 2026-11-13

### Features

- Check more in CloudFormation and Terraform templates: network, load balancer, RDS, Lambda, API Gateway, CodeBuild, CodePipeline, KMS, SSM parameters, OpenSearch, MSK, Kinesis, Redshift, DocumentDB, Neptune, Step Functions, EventBridge, SQS, AWS Backup, DynamoDB, ElastiCache, and EFS (#79, #80, #81, #82, #83, #84, #85, #86, #87, #88)
- Report each problem once, and add a coverage table that says which rules have a template check (#79)
- Review findings with a model: a verdict per finding, hypotheses marked unverified, a hard prompt cap, and self-hosted models only (#89, #90)
- Answer every Well-Architected question from the findings, in the Markdown, HTML, and JSON reports (#91, #92)
- Check hardcoded dependency URLs and synchronous calls with no timeout or queue (#93)
- Check the 307 Well-Architected best practices with repo-level rules that read the repo tree: security, reliability, operations, performance, cost, and sustainability (#94, #95, #96)
- Say "off unless rules.org is on" for best practices that only account-level rules answer, and list them under `needs_org` in the JSON answers (#98)

### Chores

- Run the tests in parallel in CI, which cuts the Windows job from about 70 to 25 minutes (#97)
- Test each repo-level rule with a repo that lacks the control and the same repo with it (#98)

## v0.1.1 - 2026-11-07

### Fixes

- Run on Windows and macOS: V2 synth finds `npx.cmd`, ripgrep and synth output is read as UTF-8, and the GitHub Action installs ripgrep on Linux, macOS, and Windows runners (#77)

### Documentation

- Pin the GitHub Action example to a release and explain what each upgrade can change (#75)
- Install a pinned release, with steps for macOS, Linux, and Windows (#76)

### Chores

- Publish a GitHub release when a version tag is pushed (#75)
- Run the tests on Windows, and the GitHub Action on Linux, macOS, and Windows, in CI (#77)

## v0.1.0 - 2026-11-07

First release. Covers everything merged to `main` up to this tag.

### Features

- Detect CDK, CloudFormation, and Terraform repos (#27)
- Scan raw CloudFormation without synth (#28)
- Run CloudFormation checks off a shared resource model (#29)
- Parse root-module Terraform into the resource model (#30)
- Report Terraform findings with the existing controls (#31)
- Write the suggested fix in the source language (#33)
- Resolve Terraform values from plan JSON (#35)
- Render findings as one self-contained HTML page (#37)
- Accept html as a report format (#38)
- Check IAM policies in CloudFormation and Terraform (#41)
- Flag EC2 instances that do not require IMDSv2 (#42)
- Flag EKS clusters with a public endpoint or unencrypted secrets (#43)
- Flag S3 buckets that allow requests without TLS (#44)
- Flag IAM role trust policies that any account can assume (#45)
- Flag full admin access on roles, users and groups (#46)
- Flag resource policies that grant access to any principal (#47)
- Check encryption for SNS, EBS, EFS, Kinesis and ElastiCache (#48)
- Flag deprecated Lambda runtimes (#49)
- Check encryption for OpenSearch, Redshift, DocumentDB, Neptune and MSK (#50)
- Check CloudFront and WAF in templates (#51)
- Flag CloudFront S3 origins without Origin Access Control (#52)
- Flag subnets and instances that assign public IPs (#53)
- Flag CloudFormation parameters that hold secrets (#54)
- Flag stateful resources that are deleted with the stack (#55)
- Check ECR repositories and ECS task definitions in templates (#56)
- Check Secrets Manager rotation and Cognito MFA in templates (#57)
- Flag Terraform variables that hold secrets without sensitive (#58)
- Bundle an offline AWS price snapshot (#59)
- Show an estimated monthly cost on cost findings (#60)
- Check resources against a required tag policy (#61)
- Show an estimated monthly total per stack in the report (#62)
- Open the report with a prioritised summary of top fixes (#63)
- Know which environment a stack is for (#64)
- Flag production-grade spend in non-production stacks (#65)
- Flag previous-generation instance families (#66)
- Tag rules with themes and group the report by theme (#67)
- Port S3 lifecycle, Intelligent-Tiering, DynamoDB autoscaling and launch template gp2 checks (#68)
- Flag S3 and DynamoDB traffic routed through a NAT gateway (#69)
- Link each finding to its control's docs page and drop the HTML summary (#71)
- Price each stack in the region its code deploys to (#72)
- Print the version with `--version` (#73)

### Fixes

- Fail closed when a scan cannot be trusted (#1)
- Key CloudFormation findings and fail a broken scan (#3)
- Accept shifted baseline lines in cf_template (#4)
- Fix IAM wildcard, open port and TLS enum false results (#5)
- Recognize Python keyword argument settings as compliant (#6)
- Make high CDK findings match the code (#7)
- Bound ripgrep and cloud LLM calls (#8)
- Fail the synth job on a non-zero cdk synth (#12)
- Stop GitHub Action input injection (#13)
- Dedupe findings across language passes (#15)
- Detect Python CDK from cdk.json (#16)
- Default org absence rules off (#17)
- Match Python CDK snake_case props (#18)
- Drop static findings CloudFormation already covers (#19)
- Stop flagging default S3 encryption (#20)
- Stop keying baselines on line numbers (#21)
- Limit rule search to max-files (#22)
- Tighten naming, secret, and cache rules (#24)
- Align packaging and SARIF warnings (#26)
- Reject non-CDK --iac in V2 without --templates (#36)

### Performance

- Skip the file walk when ripgrep misses (#14)
- Build RAG once per V2 scan (#23)

### Documentation

- Align RAG, CloudFormation, and rule list docs (#25)
- Document the three IaC sources and the GitHub Action (#34)
- Document the HTML report (#40)
- Fix rule count in the docs and test the untested template checks (#70)
- Document release rules and start this changelog (#73)

### Chores

- Lock ruff to the existing rule set (#2)
- Fail tests when a rule warns (#9)
- Enforce 70% coverage locally (#10)
- Test on Python 3.11 and 3.12 (#11)
- Lock CDK, CloudFormation, and Terraform regression tests (#32)
- Lock HTML report escape and CLI tests (#39)
