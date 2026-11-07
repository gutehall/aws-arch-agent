# Reference

The agent covers all six AWS Well-Architected pillars. Static and CloudFormation rules are grouped by pillar; in V2 mode each pillar has a dedicated reviewer node.

## CLI: `aws-arch-agent`

| Option | Default | Description |
|--------|---------|-------------|
| `--repo`, `-r` | — | Path to repo (required unless `--templates` is set; then repo defaults to templates path) |
| `--out`, `-o` | `report.md` | Output report path |
| `--mode` | `v1` | `v1` (rules + LLM) or `v2` (multi-agent + synth) |
| `--iac` | `auto` | IaC source: `auto`, `cdk`, `cloudformation`, or `terraform`. `auto` detects it: CDK wins when `cdk.json` or a CDK package is present; otherwise CloudFormation templates (`AWSTemplateFormatVersion` or an `AWS::` resource) and Terraform (`*.tf`, `*.tf.json`) are detected, and both together are `mixed`. An explicit source with no matching files exits 1 (`cdk` needs `cdk.json`, a CDK package, `bin/*.ts`, or `app.py`). With `--mode v2`, `terraform` exits 1 and `cloudformation` without `--templates` (flag or config `templates`) exits 1 |
| `--tf-plan` | — | `terraform show -json` output (a plan or a state). V1 Terraform scans only. Known planned values replace arguments that depend on `var`, `local`, or another expression, by resource address. Unknown values stay unresolved. Indexed instances (`count`, `for_each`), data sources, and child modules are not read. With one root module, the plan applies to it wherever the plan file is. With several, it applies to the one that holds the plan file. A missing or unreadable plan, or a plan that matches no root module, is a report warning (exit 2) and the scan runs without it. `--mode v2` with `--tf-plan` exits 1 |
| `--max-files` | `400` | Cap on files walked. Rules search only these files |
| `--config` | (auto-detect) | Path to config file |
| `--format`, `-f` | `markdown` | `markdown`, `json`, `sarif`, or `html`. `html` writes one self-contained page (inline CSS and script, no external assets, dark theme) to open in a browser. Each finding links to AWS documentation. With `--enforce-baseline` it labels each finding Accepted or New. `--out` still defaults to `report.md`, so pass a `.html` path. An unknown format fails the run and writes no report |
| `--fail-on` | `none` | Exit 1 if any finding at or above: `high`, `medium`, `low`, `none` |
| `--no-llm` | `false` | Skip LLM polish / agent reasoning |
| `--llm-mode` | `full` | V2 only: `full` (six pillar calls) or `compact` (single LLM call) |
| `--templates` | — | Path to CloudFormation templates (dir or file); V2 only, skips cdk synth |
| `--no-synth` | `false` | Do not run cdk synth; V2 only (static only or with `--templates`) |
| `--rag` | — | Path to RAG doc (V2 only) |
| `--suggestions` | — | Write findings JSON to this path |
| `--baseline` | `.aws-arch-agent-baseline.json` | Path to baseline suppressions file |
| `--enforce-baseline` | `false` | Only fail on findings not in baseline |
| `--update-baseline` | `false` | Add current findings to baseline file |
| `--region` | detected | AWS region whose on-demand prices cost estimates use, for every stack (config `region`). Without it each stack is priced in its own region, then `AWS_REGION`, then `us-east-1`: see [Price region](#price-region). Prices come from a snapshot shipped in the package, so the scan makes no network call. The report states the region and the AWS price list date. A region the snapshot lacks gives no estimates, and the run says so. See [Prices](#prices) |
| `--theme` | — | Only report rules in these themes. Repeatable or comma-separated: `finops`, `security-baseline`, `identity`, `data-protection`, `network-exposure`, `resilience`, `observability`, `sustainability` |
| `--group-by` | `severity` | Group Markdown findings by `severity` or `theme` |
| `--version` | — | Print the version and exit. The version is the release tag the rules come from |

## IaC sources

| `--iac` | What V1 scans |
|---------|---------------|
| `cdk` | CDK TypeScript/Python source with the static rules. Needs `cdk.json`, a CDK package, `bin/*.ts`, or `app.py`. |
| `cloudformation` | Raw templates in the repo (JSON or YAML with `AWSTemplateFormatVersion` or an `AWS::` resource) with the `CF-*` checks. No synth. |
| `terraform` | Root-module `*.tf` / `*.tf.json` with the `CF-*` checks. Findings point at the HCL file and line (approximate for `*.tf.json`). |
| `auto` | CDK when its markers exist; otherwise CloudFormation, Terraform, or both (`mixed`). A repo with none of these falls back to `cdk`. |

**Terraform** is read without `terraform init`, and only root modules are scanned. Local child modules (`source = "./..."`) are skipped and listed under `terraform_child_modules_skipped` in the JSON report's `context.notes`. Remote modules are not fetched. An argument set from `var.*` or `local.*` is unresolved, so no check reports on it. To resolve those values, pass a plan with `--tf-plan`:

```bash
terraform -chdir=infra plan -out=tfplan
terraform -chdir=infra show -json tfplan > infra/plan.json
aws-arch-agent --repo . --iac terraform --tf-plan infra/plan.json --no-llm
```

**V2** synth stays the CDK path. For CloudFormation, use V1, or V2 with `--templates`. For Terraform, use V1. When `--iac auto` detects a non-CDK repo in V2 without `--templates`, the console prints a note. The scan still runs the CDK path, and the exit code does not change.

## Modes

- **V1** (default): static rules over CDK source, or `CF-*` checks over CloudFormation and Terraform. No synth, finishes in seconds.
- **V2**: runs `cdk synth`, then a LangGraph pipeline with six pillar reviewers checks the CloudFormation output. Install with `pip install -e ".[v2]"`. `--llm-mode full` (default) makes six pillar calls plus a merge. `--llm-mode compact` makes one call.

## LLM providers

LLM output is optional. `--no-llm` skips it.

| Variable | Purpose |
|----------|---------|
| `LLM_PROVIDER` | `ollama`, `openai`, or `anthropic` |
| `OLLAMA_HOST`, `OLLAMA_MODEL` | Local Ollama server and model (e.g. `llama3:8b`) |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | OpenAI. Needs `pip install -e ".[cloud]"` |
| `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` | Anthropic. Needs `pip install -e ".[cloud]"` |

## HTML report

`--format html` writes one file to open in a browser. CSS and script are inline and nothing external loads, so it works offline and as a CI artifact. The page has a dark theme, severity counts, All/High/Medium/Low tabs, and each finding's file and line, evidence, recommendation, and suggested code. Each finding links to the AWS docs page for its control (for example S3 default bucket encryption, not the S3 start page) and to the Well-Architected best practice it supports (for example SEC08-BP02 Enforce encryption at rest). The map is `aws_arch_agent/report/doc_topics.py`; `python scripts/check_doc_links.py` checks that every page still exists. A finding with no entry there gets a service start page when its title names a service, and always the pillar overview. The HTML report has no summary section; the summary is in Markdown and JSON. These links are the only external URLs on the page, and they load only when clicked. Evidence and code from the scanned repo are escaped. With `--enforce-baseline`, each finding is labeled Accepted or New.

## Config file (JSON or YAML)

See [CONFIG.md](CONFIG.md) and [example-config.json](example-config.json).

Keys: `format`, `fail_on`, `no_llm`, `llm_mode`, `out`, `severity_threshold`, `templates`, `no_synth`, `rules.include`, `rules.exclude`, `rag.path`.

## GitHub Action

Use the composite action, pinned to a release tag (`@main` changes with every merged check; see the README's CI section). It runs on Linux, macOS, and Windows runners and installs ripgrep if the runner lacks it:

```yaml
- uses: gutehall/aws-arch-agent/.github/actions/aws-arch-agent@v0.1.1
  with:
    repo: .
    fail-on: high
    format: json
    no-llm: "true"
    enforce-baseline: "true"
    baseline: .aws-arch-agent-baseline.json
```

For SARIF upload to GitHub Code Scanning, set `format: sarif` and use `github/codeql-action/upload-sarif`.

## JSON report schema

See [report-schema.json](report-schema.json) for the machine-readable report format.

## Rules

Static and CloudFormation rule IDs, titles, and pillar groups are in [CF_RULES.md](CF_RULES.md). That is the full list. This page does not keep a second copy.

## Prices

Cost estimates read `aws_arch_agent/pricing/prices.json.gz`, an offline snapshot of the AWS Price List bulk API: on-demand USD prices for the resources the cost rules touch (EC2 and RDS instance types, NAT gateway hour and GB, EBS gp2/gp3/io2, public IPv4 addresses including Elastic IPs, Lambda, DynamoDB on-demand and provisioned, S3 storage classes, CloudWatch Logs ingestion and storage). Each price carries its region and the publication date of its AWS offer. A tiered price is the first paid tier. An instance type or region the snapshot lacks gives no estimate, never a guess.

### Price region

Each stack (one template, or one Terraform root module) is priced in one region, the first of:

1. `--region` or config `region`, for every stack.
2. The region the stack's code deploys to: the CDK stack's `env` region (from `cdk.out/manifest.json`; an env-agnostic stack has none), the default `provider "aws"` region in Terraform (a literal, `var.<name>` with a default, or from `--tf-plan`), or else the availability zones written in the template (`eu-north-1a`) when they all name one region.
3. `AWS_REGION`, then `AWS_DEFAULT_REGION`.
4. `us-east-1`.

The report's Prices line names each region and what decided it, for example `eu-north-1 (CDK stack env; AWS price list of 2026-11-05)`. The cost table has a Region column. JSON `context.notes.prices.regions` lists them with their `source`. CDK source scanned without synth has no stacks to read, so it uses steps 1, 3 and 4.

The snapshot covers `us-east-1`, `us-west-2`, `eu-west-1`, `eu-central-1` and `eu-north-1`. A stack in another region gets no estimates, and the run says so. To refresh the snapshot, or to add regions:

```bash
python scripts/refresh_prices.py --regions us-east-1 eu-north-1 --cache-dir /tmp/offers
```

The script streams the offer files (the EC2 one is about 300 MB per region) and writes the same file for the same offers. `--cache-dir` keeps the downloads so a rebuild needs no network. A price two offer rows disagree on stops the build.

## Report summary

Markdown reports open with a **Summary** built from the findings alone, so it is the same with `--no-llm` and the same on every run. It appears in Markdown, and as `summary` in JSON. The HTML report leaves it out:

- **Top fixes**: the five most important fixes. A fix is one rule, covering every resource it reported. They are ranked by severity, then estimated monthly saving, then how many resources the fix covers, then rule id.
- **By pillar**: one line per finding category with its count by severity and possible savings, for example "Cost Optimization: 7 findings (7 Low), about $120.00/month possible savings (estimate)". The lines add up to the findings below, counts and savings alike.
- **Quick wins**: fixes with suggested code and low effort.

Each finding has an `effort` field. `low` means one property, changed in place (versioning, log retention, tracing, gp2 to gp3, NoEcho, a tag). `high` means the fix replaces the resource or changes its design (encrypting an existing database or volume, NAT traffic, a public EKS endpoint). Everything else is `medium`. The map is `aws_arch_agent/rules/effort.py`.

