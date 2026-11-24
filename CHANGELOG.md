# Changelog

New releases go at the top. See [CONTRIBUTING.md](CONTRIBUTING.md#releases) for when to cut one and how the version is bumped.

## v1.3.1 - 2026-11-24

### Fixes

- Price List bulk API: the offer CSV is served as `application/octet-stream`, so every bulk fetch failed with `can't concat str to bytes` and no price was estimated. It is now read as UTF-8 (#127)
- Ollama: prompts are sized to the model's trained context, read from `/api/show`, instead of `OLLAMA_NUM_CTX` alone. Ollama runs `llama3:8b` at 8192 tokens whatever `num_ctx` asks and cut longer prompts from the middle, so verdict replies were not JSON. Verdicts now go in smaller batches on a short context; hypotheses are skipped with a reason when the rule catalog alone does not fit. Long-context models are unchanged (#127)

## v1.3.0 - 2026-11-23

### Changes

- Stack cost without a usage file: usage-billed resources (Lambda, S3, on-demand DynamoDB, log groups, APIs, queues, topics) are priced at a documented low-traffic profile and shown as an illustration, not a bill. It raises the headline (`headline_monthly_usd`, `illustrated_monthly_usd`) but never `total_monthly_usd`, budgets or `--compare-cost`. A usage file replaces it (#125)
- Flat prices for CloudWatch alarms ($0.10, high resolution $0.30), dashboards after the three free ones ($3) and WAFv2 web ACLs ($5 + $1 per rule). API Gateway authorizers, gateway responses and uncached stages, CloudFront OAC, WAFv2 logging, standard SSM parameters, the first two budgets and Cognito app clients count as free. One line names what has no cost model yet; `prices_unavailable` says when no price could be used instead of showing $0 (#125)
- Ollama: calls take turns, `Reviewing <pillar>` prints when that call starts, `LLM_TIMEOUT_S` (default 300), JSON replies requested. In V2 the pillars that answered keep their verdicts when another fails (`llm.status` `partial`); hypotheses run only when every pillar answered (#125)
- Progress prints one line per phase; rules report `Checking rules (n/total, lang)` (#125)
- The HTML report opens with the summary and shows one card per rule and severity, with locations collapsed (#125)

## v1.2.0 - 2026-11-23

### Changes

- New template checks for CloudFormation and Terraform, all Low: `CF-SUST-004`..`007` (accelerators with no utilization alarm or schedule, instance store with no durable store, EBS volumes with no shared store, backups of cache or temp data), `CF-TAG-002` (created-by and owner tags; CDK app tags and Terraform `default_tags` count), `CF-OBS-001`..`003` (dependency alarms, workload-metric alarms, tracing), `CF-ALARM-004` (an alarm that starts automation), and `CF-DEMAND-001`/`002` (an API or a directly invoked Lambda with no throttle or buffer, reported for cost and for sustainability). `CF-VPC-002`/`003` also answer COST08-BP02 (#123)
- `--live-account` reads, all read-only: RDS Reserved Instances, ElastiCache reserved nodes and Savings Plans (COST-005/009/016) when the scan has that compute; the account-level FSBP controls S3.1, EC2.7 and IAM.7 as new findings `ACCT-001`..`003`; Macie (SEC-065) and Storage Lens (COST-018); and, behind the `rules.org` gate, a Cost and Usage Report or Data Exports export (`ACCT-004`). A denied read is a warning, never a finding (#123)
- The usage file can state usage signals (`read_write_ratio`, `avg_cpu_percent`, `get_parameter_tps`, and a `workload:` block with `traffic_pattern`, `user_regions`, `upload_regions`). REL-011, OPS-023, SUST-002, SUST-003, PERF-011 and PERF-014 now report only when it does; before, they fired on a CDK construct alone. SUST-004 and SUST-005 answer from a repo note that names the batch path or the self-managed components and says why (#123)
- `--live-account` without `rules.org` no longer turns REPO-069 on; `ACCT-004` replaces that read behind the same gate. `CF-APIGW-005` no longer judges `MethodSettings` given as an intrinsic (#123)
- No rule is advice-only any more; `docs/COVERAGE.md` gives the answer for every rule (#123)

## v1.1.0 - 2026-11-22

### Changes

- A scan prints each step as it runs: detecting the source, reading files, every rule (`SEC-001 (12/174, typescript)`), each CloudFormation template, each Terraform module, CDK synth, and any LLM call. A step still running after 15 seconds is printed again, so a long scan does not look stalled. The report file and exit codes are unchanged
- The README is shorter

## v1.0.0 - 2026-11-22

### Breaking

- A plain `aws-arch-agent --repo <path>` now writes an HTML report to `report.html` (was Markdown in `report.md`). Without `--format`, the `--out` suffix (`.md`, `.json`, `.sarif`, `.html`) picks the format, so `--out report.md` still writes Markdown. The GitHub Action passes these flags and is unaffected (#119)
- `--mode` defaults to `auto`: V2 for a CDK app (a `cdk.json` at the repo root) when the `v2` extra and Node.js are installed, or with `--templates`; V1 otherwise, with a console note when a CDK repo stays on V1. `--mode v1` restores the old default (#119)
- The bundled offline price snapshot (`prices.json.gz`) and `scripts/refresh_prices.py` are removed; prices are fetched live (#117)

### Changes

- Live AWS pricing for any region: the Price List Query API when boto3 and credentials are available (`pip install 'aws-arch-agent[aws]'`), else the public bulk API, with a 24-hour SQLite cache and an expired-cache fallback. A scan never fails because pricing failed. New flags `--pricing-source auto|api|bulk|off`, `--price-cache-ttl`, `--refresh-prices`; config `pricing.*` (#117)
- The stack cost covers load balancers, EKS, Fargate services, ElastiCache, OpenSearch, Redshift, interface endpoints, KMS keys, Secrets Manager, Kinesis, RDS storage, EBS IOPS and throughput, and Auto Scaling groups. A Terraform literal `count = N` multiplies a resource's cost; Terraform adapters keep the cost attributes these need (#117)
- Optional usage profile (`.aws-arch-agent-usage.yaml`, `--usage-file`, config `usage_file`) prices usage-billed resources, reported apart from fixed cost and tagged "usage assumed" (#117)
- `--compare-cost` diffs the cost against a baseline `cost_snapshot` (now written by `--update-baseline`) or an earlier JSON report; `--max-monthly-cost` and `--max-cost-increase` (USD or %), or config `budget.*`, exit 1 on a breach. CDK source in V1 gets a hint to use V2 for cost (#117)
- Reports: an HTML cost tab and monthly-cost card; Markdown budget, price source, fixed vs usage and cost-change lines; `context.notes.cost` and `context.notes.prices` gain new fields in the JSON schema (#117)
- After a scan the terminal prints the severity counts, up to five top fixes and the report path; the report file and exit codes are unchanged. The "Wrote report to" line no longer breaks on paths with brackets (#118)
- With no LLM environment variables set, a local Ollama on `localhost:11434` is used when it answers (`llama3:8b` if pulled, else the first chat model); otherwise the LLM is skipped with a note (#119)

## v0.5.0 - 2026-11-22

### Changes

- Walk files in a fixed order (sorted per directory), so the same repo gives the same files on every run and OS. A walk that hits `--max-files` prints a console note, adds a note to the Markdown metadata, and records `files_truncated` and `max_files` in `context.notes`; the exit code does not change (#114)
- CloudFormation findings from YAML and JSON templates carry the 1-based line of the resource's logical ID (#114)
- Suppress a finding inline with `# aws-arch-agent: ignore <RULE_ID>[, ...] [reason="..."] [expires=YYYY-MM-DD]` (or `//`) on its line or the line above, or with `Metadata: {aws-arch-agent: {ignore: [...]}}` on a template resource. Suppressed findings stay in the report, labelled, and do not count for `--fail-on`; an expired one is a warning and counts again. New config key `rules.exclude_paths` skips rule IDs in files matching a path glob (#114)
- SARIF sets `tool.driver.version` and `informationUri`, a `helpUri` per rule, `partialFingerprints` (`awsArchAgent/v1`), and `suppressions`: `inSource` for inline and Metadata suppressions, `external` for baseline-accepted findings (which keep `properties.baselined`) (#114)
- `--tf-plan` fills planned values in local child modules at any depth, each module call with its own values, and ties split S3 and ECR settings resources to `count` and `for_each` instances (#114)
- A CDK source scan without synth turns on the AI lenses when Bedrock, SageMaker, or AgentCore constructs appear in TypeScript or Python source outside tests; `lenses.ai` still overrides (#114)
- New AI lens checks: Bedrock guardrails, keys, aliases, prompt versions and token limits (CF-BEDROCK-005 to CF-BEDROCK-012), AgentCore runtime, gateway and memory (CF-AGENTCORE-001 to CF-AGENTCORE-003), SageMaker notebooks, Studio domains, data capture, endpoint scaling, feature groups and the model registry (CF-SAGE-007 to CF-SAGE-013), and repo checks for Bedrock calls, evaluation steps, model cards, bias evaluation and human escalation (REPO-199 to REPO-204) (#114)
- GitHub Action: new inputs `tf-plan`, `live-account` (also installs the `account` extra), `region`, `theme`, `group-by`, `config`, `templates`, and `job-summary`, which appends the Markdown report to the job summary even when `fail-on` fails the scan (#114)
- Docs and `--help` describe V2 Terraform scans and the CDK, CloudFormation, Terraform, live account and AI lens scope (#114)
- `rules.exclude_paths` rule IDs match without regard to case (#115)
- Line numbers count `\n` only, so a form feed in source or a `\u2028` in a quoted YAML value no longer shifts a finding's line or a suppression (#115)
- A finding in a Terraform child module called more than once names the module calls it came from (#115)
- REPO-199 and REPO-200 follow local imports: a guardrail or token limit in a module the call file imports, or in a file that imports it, counts (#115)
- Replace 10 AWS documentation links whose pages moved, and check every linked page in a new Doc links workflow: on changes to the link map, weekly, and by hand (#114, #115)

## v0.4.0 - 2026-11-21

### Changes

- Read resources for six best practices that only a repo rule answered: user experience telemetry (CF-SYN-001), log analysis (CF-LOGS-001), cost anomaly alerts (CF-CE-001), unattached EBS volumes (CF-EBS-003), RDS storage autoscaling (CF-RDS-015) and noncurrent S3 versions (CF-S3-013). `docs/COVERAGE.md` lists the practices that stay on a repo rule (#112)
- Close the seven partial CDK/template pairs. CF-NACL-001 also reports a VPC with no custom network ACL, CF-RDS-003 an Aurora cluster with one DB instance, and new CF-ECS-013 an ECS service nothing scales. CF-PERF-002 reads ALBs, API caches and DAX. PERF-008 reads RDS only and SUST-001 reads fleets only. All seven are now covered in V2 (#112)
- Check Java Lambda functions for SnapStart (CF-LAM-010) and functions outside a VPC that reach a private RDS or ElastiCache store (CF-LAM-011); they replace PERF-015 and REL-010 in V2 (#112)
- Remove 15 advice rules that read no property: REL-023, REL-025, COST-004, COST-017, OPS-004, OPS-022, PERF-003, PERF-005, PERF-009, PERF-010, PERF-012, PERF-016, PERF-017, PERF-018, PERF-019. Their IDs in `rules.include` or `rules.exclude` are ignored (#112)
- CF-PERF-002 no longer fires on a template with Lambda and no API or load balancer (#112)
- A CDK scan without `cdk synth` output now reports OPS06-BP03 as not checked (#112)
- Install from PyPI (pip or pipx) in the README

## v0.3.1 - 2026-11-18

### Changes

- Mention the AI lenses and their checks in the README
- First release published to PyPI from the release workflow with trusted publishing

## v0.3.0 - 2026-11-18

### Changes

- Answer the four AI Well-Architected lenses (Machine Learning, Generative AI, Responsible AI, Agentic AI) for an AI workload, as a second list beside the 57 core answers: `lens_answers` in JSON (new in `docs/report-schema.json`, each item has `lens`) and a lens section in the Markdown and HTML reports, grouped by lens and pillar or focus area. The 133 questions and 404 best practices are committed in `rules/data/ai_lenses.json`; a scan never fetches the network (#109)
- Run the lens answers and the AI findings only for an AI workload: on when the scan sees a Bedrock, SageMaker, or AgentCore resource, forced on or off with the new `lenses.ai` config key (#109)
- Check Bedrock agents for a guardrail (CF-BEDROCK-001) and an idle session timeout (CF-BEDROCK-003), and model invocation logging as an account check that runs with `rules.org` (CF-BEDROCK-004) (#109)
- Check SageMaker endpoints for a monitoring schedule (CF-SAGE-006) (#109)
- Check AI workloads for a responsible-AI note, an evaluation set, a human-oversight note, an agent role note and a prompt catalog (REPO-194 to REPO-198) (#109)

## v0.2.4 - 2026-11-17

### Changes

- Fix `--format html` on an installed copy: the HTML report template was left out of the wheel, so the command failed with `FileNotFoundError` for `report/templates/report.html`. Releases up to v0.2.3 are affected when installed (running from a source checkout was fine)
- Only run the PyPI upload when the repository variable `PUBLISH_TO_PYPI` is `true`; no version is on PyPI yet (#107)

## v0.2.3 - 2026-11-17

### Changes

- Fix the pinned `pypa/gh-action-pypi-publish` commit in the release workflow, which did not exist. The PyPI upload still needs a trusted publisher registered on PyPI, so no version is on PyPI yet
- Fix a flaky pytest-xdist collection error in the pricing snapshot test (#105)

## v0.2.2 - 2026-11-17

### Changes

- Move the Well-Architected answers in the HTML report into their own tab, one card per question grouped by pillar, with a met / not met filter, so the findings are no longer pushed down the page
- Scan Terraform child modules at any depth, and with `--tf-plan` expand `count` and `for_each` instances and read data source values from the plan (#103)
- Run V2 on Terraform with `--iac terraform`, and accept `--tf-plan` in V2 (#103)
- Check ECS services for a deployment circuit breaker with rollback (CF-ECS-012, #103)
- Add `--live-account`, which reads Security Hub, GuardDuty, CloudTrail, Config, Budgets, a CUR, Access Analyzer and Inspector (read-only) for the account-level rules. Off by default; no AWS call without it. The price snapshot now covers eleven regions (#103)
- Make no LLM call unless a model server is configured (#103)
- Publish each release to PyPI from the release workflow (#103)
- Install `pytest-cov` in the Windows CI job

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
