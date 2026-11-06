# Config file

The IaC source is a CLI flag, not a config key: `--iac auto|cdk|cloudformation|terraform` (see [REFERENCE.md](REFERENCE.md)). V1 scans CDK source, raw CloudFormation templates, and root-module Terraform. V2 synth stays the CDK path.

Optional config file in the repo root. A same-named file in the current directory is not used. A missing `--config` path, or a config file that is not valid JSON or YAML, fails the run.

- `.aws-arch-agent.json` / `aws-arch-agent.json`
- `.aws-arch-agent.yaml` / `aws-arch-agent.yaml` (YAML also supported)

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

- **format**: `markdown` (default) | `json` | `sarif` | `html`. `html` writes one self-contained page to open in a browser; set **out** to a `.html` path (the default is `report.md`).
- **fail_on**: `high` | `medium` | `low` | `none` — exit code 1 if any finding at or above this severity
- **no_llm**: skip LLM polish (V1) or agent reasoning (V2)
- **llm_mode**: `full` (six pillar LLM calls in V2) or `compact` (single merged LLM call)
- **out**: output file path
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

  Each template finding records its environment (`environment` in JSON and SARIF, a line in Markdown and HTML). In dev, production durability advice is skipped (CF-RDS-003 Multi-AZ, CF-RDS-005 deletion protection, CF-DEL-001 retain on delete), and CF-RDS-002 backups, CF-DDB-001 PITR and CF-S3-003 versioning drop to Low. Staging, prod and unknown are judged as prod. The rules are in `aws_arch_agent/rules/environments.py` (`RULE_POLICY`).
- **region**: AWS region whose on-demand prices cost estimates use (default `us-east-1`; `--region` overrides it). Prices come from the snapshot shipped with the package; see [Prices](REFERENCE.md#prices)
- **severity_threshold**: only report findings at or above this severity
- **templates**: path to CloudFormation templates (dir or file); V2 only. When set, cdk synth is skipped and CF rules run on these templates (JSON or YAML).
- **no_synth**: if `true`, do not run cdk synth (V2 only). Use with **templates** for raw CF, or alone for static analysis only.
- **rules.include**: list of rule IDs to run (e.g. `["SEC-001", "SEC-002"]`); if set, only these run
- **rules.exclude**: list of rule IDs to skip
- **rules.org**: if `true`, also run account-level absence rules `SEC-026`, `SEC-027`, `OPS-001`, `OPS-014`, and `COST-014`. Default is `false` because an app stack does not own those controls. Listing an id in **rules.include** runs that rule even when this is false. **rules.exclude** still skips it.
- **rag.path**: path to a markdown doc for RAG context (V2 only). Pillar and merge prompts include retrieved snippets when set.
- **rag.use_embeddings**: if `true`, use embedding-based retrieval (V2 only). Requires **rag.embedding_provider**.
- **rag.embedding_provider**: `"sentence-transformers"` (local; install with `pip install -e ".[rag]"`) or `"openai"` (uses `OPENAI_API_KEY`).
- **rag.embedding_model**: optional model name (e.g. `"all-MiniLM-L6-v2"` for sentence-transformers, `"text-embedding-3-small"` for OpenAI). Defaults apply if omitted.

## Baseline / suppressions

For gradual CI adoption, use a baseline file (default: `.aws-arch-agent-baseline.json`):

```bash
# Record current findings as accepted
aws-arch-agent --repo . --no-llm --update-baseline

# Fail only on new findings
aws-arch-agent --repo . --no-llm --fail-on high --enforce-baseline
```

CLI flags override config file values only when that flag is passed. A quoted YAML boolean such as `"false"` is false.

A corrupt baseline with `--enforce-baseline` or `--update-baseline` fails the run and does not change the file. Using both flags still fails on findings that were not accepted before the run. The report lists every finding and marks which ones are accepted.

CloudFormation findings have no source line. Their baseline key is the rule id, the template path relative to the repo, and `logical_id` (the finding evidence, such as `BucketA (AWS::S3::Bucket)`). Two resources of the same rule in one template stay distinct. A baseline written before `logical_id` was stored does not suppress those findings; regenerate it with `--update-baseline`. An older entry that already has `logical_id` and an absolute path still matches when that path ends with the repo-relative path.

A rule exception, a CloudFormation resource that cannot be checked, a missing or empty template path, or a failed or timed-out `cdk synth` is listed in the report warnings (JSON, SARIF, HTML, and the markdown "Analysis Warnings" section). The process exits 2. That exit is separate from `--fail-on`.
