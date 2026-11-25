# Config file

The IaC source is a CLI flag, not a config key: `--iac auto|cdk|cloudformation|terraform` (see [REFERENCE.md](REFERENCE.md)). V1 scans CDK source, raw CloudFormation templates, and Terraform (root modules and local child modules). V2 synth stays the CDK path; V2 also scans CloudFormation with `--templates` and Terraform with `--iac terraform`.

Optional config file in the repo root. A same-named file in the current directory is not used. A missing `--config` path, or a config file that is not valid JSON or YAML, fails the run.

- `.aws-arch-agent.json` / `aws-arch-agent.json`
- `.aws-arch-agent.yaml` / `aws-arch-agent.yaml`
- `.aws-arch-agent.yml` / `aws-arch-agent.yml`

The first file in that order wins.

Copy [example-config.json](example-config.json) to get started.

Example (JSON):

```json
{
  "format": "markdown",
  "fail_on": "none",
  "no_llm": false,
  "out": "report.md",
  "severity_threshold": "Medium",
  "llm_mode": "full",
  "region": "us-east-1",
  "templates": null,
  "no_synth": false,
  "rules": {
    "include": null,
    "exclude": ["BP-001"],
    "exclude_paths": {"examples/**": ["SEC-005"]},
    "org": false
  },
  "rag": {
    "path": "./docs/waf-snippets.md",
    "use_embeddings": false,
    "embedding_provider": "sentence-transformers",
    "embedding_model": null
  }
}
```

Example (YAML):

```yaml
format: json
fail_on: high
no_llm: true
out: report.json
llm_mode: compact
rules:
  exclude:
    - BP-001
```

- **format**: `html` (default) | `markdown` | `json` | `sarif`. `html` writes one self-contained page to open in a browser. Without **format** (and without `--format`), the suffix of **out** picks it (`.md`, `.json`, `.sarif`, `.html`).
- **fail_on**: `high` | `medium` | `low` | `none` — exit code 1 if any finding at or above this severity
- **no_llm**: make no LLM calls: no verdicts, no hypotheses
- **llm_mode**: V2 only. `full` (one verdict call per pillar with findings) or `compact` (one verdict call). Either way, plus one hypothesis call
- **out**: output file path (default `report.` plus the format's extension: `report.html`, `report.md`, ...)
- **tags**: required tag policy, checked on templates (CloudFormation, `cdk synth` output, Terraform). Off unless `tags.required` lists at least one key:

  ```yaml
  tags:
    required: [CostCenter, Owner, Environment]
    allowed:                       # optional: the values a key may take
      Environment: [prod, staging, dev]
  ```

  CF-TAG-001 (Medium) reports each taggable resource that misses a required tag, or has a value `allowed` does not list, at its file and line. Keys and values are case-sensitive. Tags set for the whole stack count: CDK `Tags.of(app).add(...)` (already on each resource in synth output) and Terraform `provider "aws" { default_tags { ... } }`, including a resource's `provider = aws.<alias>`. Resource types that do not take tags are skipped, and so are tags the scan cannot read, such as `tags = var.tags` or `Fn::If`. Tags passed only at deploy time (`aws cloudformation deploy --tags`) are not in the template, so they do not count. With a policy, the repo-wide guesses BP-001 and COST-015 are dropped wherever templates are checked. A V1 scan of CDK source reads no templates, so it keeps them and says the policy needs `--mode v2`.
- **environments**: which environment each stack is for (a stack is one CloudFormation template, `cdk synth` output included, or one Terraform root module). Keys are matched in order. Each is a glob against the stack's repo-relative path or its name, or `tag:<value>` for an `Environment` tag value. Values are `prod`, `staging` or `dev`:

  ```yaml
  environments:
    "infra/prod/**": prod
    "infra/dev/**": dev
    "*-sandbox*": dev
    "tag:Staging": staging
  ```

  In globs, `*` and `?` stay within one path segment and `**` spans segments. `./` and a leading `/` are dropped, because paths are relative to the repo. A config match decides outright.

  Without a match, the scan looks at every signal and **the most-prod one wins**. The signals are the stack's `Environment` tag values and common words in the path, file or stack name: `prod`/`production`/`prd`/`live`, `staging`/`stage`/`stg`/`uat`/`preprod`, `dev`/`development`/`test`/`testing`/`qa`/`sandbox`/`sbx`. An `Environment` tag the scan cannot read (a `Ref`, `Fn::If`, `var.*` or `tags = var.tags`) counts as prod, and so does a value it does not recognise. So a dev directory holding a prod-tagged resource is prod, and a stray `Environment=dev` in a prod path is prod. A stack with no signal is **unknown, and judged as prod**: a missed prod finding is worse than an extra dev one. Findings from CDK source rules are not tied to a stack, so they are unknown too. Terraform workspaces exist only at run time, so match the directory instead.

  Each template finding records its environment (`environment` in JSON and SARIF, a line in Markdown and HTML). In dev, production durability advice is skipped (CF-RDS-003 Multi-AZ and CF-DEL-001 retain on delete also in staging; CF-RDS-005 deletion protection), and CF-RDS-002 backups, CF-DDB-001 PITR and CF-S3-003 versioning drop to Low. Staging, prod and unknown are judged as prod. The rules are in `aws_arch_agent/rules/environments.py` (`RULE_POLICY`).
- **nonprod.max_instance_size**: the largest EC2 or RDS instance size not flagged in `dev` and `staging` stacks (CF-ENV-003). Default `large`. One of `nano`, `micro`, `small`, `medium`, `large`, `xlarge`, `2xlarge`, `4xlarge`, `8xlarge`, `12xlarge`, `16xlarge`, `24xlarge`, `32xlarge`, `48xlarge`:

  ```yaml
  nonprod:
    max_instance_size: xlarge
  ```
- **dashboards.min_resources**: a stack with more resources than this and no CloudWatch dashboard is reported (CF-DASH-001). Default `20`. A positive integer. Only resources the scan models count, so unmapped types and Terraform `module` calls do not, and neither does wiring that costs nothing, such as a security group rule or a permission:

  ```yaml
  dashboards:
    min_resources: 40
  ```
- **region**: AWS region whose on-demand prices cost estimates use, for every stack (`--region` overrides it). Leave it out to price each stack in its own region: see [Price region](REFERENCE.md#price-region). Any AWS region can be priced; see [Prices](REFERENCE.md#prices)
- **pricing.source**: where prices come from. `auto` (default) uses the AWS Price List Query API when boto3 is installed and AWS credentials resolve, else the public bulk API. `api` and `bulk` use only that source. `off` gives no estimates and makes no network call. Same as `--pricing-source`
- **pricing.cache_ttl_hours**: hours a fetched price is reused from the local price cache. Default `24`. Same as `--price-cache-ttl`:

  ```yaml
  pricing:
    source: auto        # auto | api | bulk | off
    cache_ttl_hours: 24
  ```
- **usage_file**: usage profile that prices usage-based resources (S3, Lambda, on-demand DynamoDB, ...), relative to the repo. Default `.aws-arch-agent-usage.yaml` in the repo, if present. Without a profile those resources stay in "not priced". The same file can state usage signals (read/write ratio, Parameter Store TPS, average CPU, traffic pattern, user and upload Regions) that REL-011, OPS-023, SUST-002, SUST-003, PERF-011 and PERF-014 read; without them those rules stay quiet. Same as `--usage-file`, whose path is relative to the working directory. The keys are in [Usage profile](REFERENCE.md#usage-profile)
- **budget.max_monthly_usd**: exit 1 when the estimated monthly cost (USD) is above this. Same as `--max-monthly-cost`
- **budget.max_monthly_increase_usd**, **budget.max_increase_percent**: exit 1 when the cost rises more than this many USD, or this percent, against `--compare-cost`. Without `--compare-cost` the limit is reported as not checked, not as a failure. `--max-cost-increase 50` or `--max-cost-increase 10%` sets one from the CLI. A breach prints `Budget breached: ...`; exit 1 takes precedence over exit 2 for analysis warnings. See [Cost change and budget](REFERENCE.md#cost-change-and-budget):

  ```yaml
  usage_file: finops/usage.yaml
  budget:
    max_monthly_usd: 500
    max_monthly_increase_usd: 50
    max_increase_percent: 10
  ```
- **severity_threshold**: only report findings at or above this severity
- **templates**: path to CloudFormation templates (dir or file); V2 only. When set, cdk synth is skipped and CF rules run on these templates (JSON or YAML).
- **no_synth**: if `true`, do not run cdk synth (V2 only). Use with **templates** for raw CF, or alone for static analysis only.
- **rules.include**: list of rule IDs to run (e.g. `["SEC-001", "SEC-002"]`); if set, only these run
- **rules.exclude**: list of rule IDs to skip
- **rules.exclude_paths**: mapping of a repo-relative path glob to the rule IDs to skip in files that match it. `*` and `?` stay inside one path segment, `**` spans segments (the same globs as **environments**). A leading `./` is dropped, and rule IDs match without regard to case. An empty or absolute glob, a value that is not a list, or an ID that is not a non-empty string is a config error. V1 and V2 both apply it. The findings are dropped, as with **rules.exclude**, not labelled:

  ```yaml
  rules:
    exclude_paths:
      "examples/**": [SEC-005]
      "infra/sandbox/*.tf": [CF-S3-001, CF-S3-003]
  ```
- **rules.org**: if `true`, also run the account-level rules `SEC-026`, `SEC-027`, `OPS-001`, `OPS-014`, `COST-014`, `REPO-004`, `REPO-007`, `REPO-008`, `REPO-012`, `REPO-032`, `REPO-069`, `REPO-080`, `REPO-133`, `REPO-134`, `REPO-136`, `REPO-137`, `REPO-141`, `REPO-145`, `REPO-162`, `REPO-163`, and the AI template check `CF-BEDROCK-004` (model invocation logging, which has no CloudFormation resource type), and with `--live-account` the cost export read `ACCT-004`. Default is `false` because an app stack does not own those controls. Listing an id in **rules.include** runs that rule even when this is false. **rules.exclude** still skips it.
- **lenses.ai**: the four AI Well-Architected lenses (Machine Learning, Generative AI, Responsible AI, Agentic AI) and the findings written for them. Omitted means auto: they run when the scan sees a Bedrock, SageMaker, or AgentCore resource, and only then. `true` turns them on with no AI resource. `false` turns them off even when one exists. When they are off, `lens_answers` in the JSON report is `[]` and the reports show no lens section. The 57 core questions do not depend on this key. A CDK scan with no synth has no resources to see, so it needs `true`. V1 and V2 both read it:

  ```yaml
  lenses:
    ai: true
  ```
- **themes**: only report rules in these themes. A list of names, or one comma-separated string. Same values as `--theme`: `finops`, `security-baseline`, `identity`, `data-protection`, `network-exposure`, `resilience`, `observability`, `sustainability`. Leave it out to report every theme.
- **group_by**: `severity` (default) or `theme`. Groups Markdown findings. Same as `--group-by`. A finding in two themes is listed under both.
- **rag.path**: path to a markdown doc for RAG context (V2 only). Pillar and merge prompts include retrieved snippets when set.
- **rag.use_embeddings**: if `true`, use embedding-based retrieval (V2 only). Requires **rag.embedding_provider**.
- **rag.embedding_provider**: `"sentence-transformers"` (local; install with `pip install -e ".[rag]"`). It is the only value accepted.
- **rag.embedding_model**: optional model name (e.g. `"all-MiniLM-L6-v2"`). Defaults apply if omitted.

## Baseline / suppressions

For gradual CI adoption, use a baseline file (default: `.aws-arch-agent-baseline.json`):

```bash
# Record current findings as accepted
aws-arch-agent --repo . --no-llm --update-baseline

# Fail only on new findings
aws-arch-agent --repo . --no-llm --fail-on high --enforce-baseline
```

CLI flags override config file values only when that flag is passed. A quoted YAML boolean such as `"false"` is false.

`--update-baseline` also writes a `cost_snapshot` block (the total, each stack, and each priced resource's monthly cost), which `--compare-cost` diffs against. A baseline written before it still loads.

A corrupt baseline with `--enforce-baseline` or `--update-baseline` fails the run and does not change the file. Using both flags still fails on findings that were not accepted before the run. The report lists every finding and marks which ones are accepted.

### Inline suppressions

To accept one finding where it is, write a comment directive on the finding's line or on the line just above it. Comments start with `#` (Python, Terraform, CloudFormation YAML) or `//` (TypeScript, JavaScript, Terraform):

```text
aws-arch-agent: ignore <RULE_ID>[, <RULE_ID>...] [reason="..."] [expires=YYYY-MM-DD]
```

```typescript
// aws-arch-agent: ignore SEC-005 reason="public website bucket" expires=2027-06-30
new s3.Bucket(this, "Site", { publicReadAccess: true });
```

```yaml
Resources:
  # aws-arch-agent: ignore CF-S3-001, CF-S3-005 reason="static site"
  SiteBucket:
    Type: AWS::S3::Bucket
```

A CloudFormation finding is on the line of its resource's logical ID, so the comment goes on or above that line. In any template (JSON included, and `cdk synth` output from CDK `addMetadata`), the resource's `Metadata` can carry the same thing. Each entry is a rule ID or a mapping with `id`, and optional `reason` and `expires`:

```json
"SiteBucket": {
  "Type": "AWS::S3::Bucket",
  "Metadata": {
    "aws-arch-agent": {
      "ignore": ["CF-S3-001", {"id": "CF-S3-005", "reason": "static site", "expires": "2027-06-30"}]
    }
  }
}
```

A suppressed finding stays in the report, labelled suppressed with its reason and expiry (Markdown, HTML, and the `suppression` field of each JSON finding). It does not count for `--fail-on`. With `--enforce-baseline`, the build fails only on findings that are neither suppressed nor in the baseline.

A suppression is active through its `expires` day. After that the finding is reported and counts for `--fail-on` again, and the report warnings say `Suppression of <RULE_ID> at <file>:<line> expired on <date>; the finding is reported again.` A directive or Metadata entry that cannot be read (a bad date, no rule IDs, other text) is a warning and suppresses nothing. Like every report warning, these make the run exit 2 unless `--fail-on` or a budget exits 1. A rule ID that matches no finding is ignored. Rule IDs are matched without regard to case.

CloudFormation findings carry the line of their resource's logical ID, but no line is part of a baseline key. Their baseline key is the rule id, the template path relative to the repo, and `logical_id` (the finding evidence, such as `BucketA (AWS::S3::Bucket)`). Two resources of the same rule in one template stay distinct. A baseline written before `logical_id` was stored does not suppress those findings; regenerate it with `--update-baseline`. An older entry that already has `logical_id` and an absolute path still matches when that path ends with the repo-relative path.

A rule exception, a CloudFormation resource that cannot be checked, a missing or empty template path, or a failed or timed-out `cdk synth` is listed in the report warnings (JSON, SARIF, HTML, and the markdown "Analysis Warnings" section). The process exits 2, unless `--fail-on` or a breached budget exits 1, which takes precedence.
