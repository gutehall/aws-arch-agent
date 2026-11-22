# AWS Arch Agent

Local-first AWS architecture review for infrastructure code. It scans **CDK** (TypeScript and Python), **CloudFormation**, and **Terraform**, and reports security, reliability, operational excellence, performance, cost, and sustainability issues mapped to the AWS Well-Architected Framework. For workloads that use Bedrock, SageMaker, or AgentCore it also answers the four AI Well-Architected lenses (Machine Learning, Generative AI, Responsible AI, Agentic AI).

No AWS credentials needed. The only cloud calls read public AWS prices for cost estimates (`--pricing-source off` turns them off), and the read-only account checks you opt in to with `--live-account`. LLM output is optional and self-hosted only. With `OLLAMA_HOST` or `LLM_BASE_URL` set, it calls that server; with neither set it makes no call. `--no-llm` skips it either way. If the model does not answer, the findings stay as the rules wrote them.

> 368 static rules and 317 template checks are implemented and tested. 141 of the 368 CDK rules (38%) have a template check. Those checks run on CloudFormation, Terraform, and synthesised CDK. [docs/COVERAGE.md](docs/COVERAGE.md) gives the reason for each of the others. Expect some false positives and negatives, and API changes.

## Install

Requires Python 3.11+, git, and [ripgrep](https://github.com/BurntSushi/ripgrep#installation): `brew install ripgrep` (macOS), `sudo apt install ripgrep` (Debian/Ubuntu), or `winget install BurntSushi.ripgrep.MSVC` (Windows).

Install a release (latest: [v0.5.0](https://github.com/gutehall/aws-arch-agent/releases/tag/v0.5.0)). Pin the tag. [CI](#ci) says what a newer tag can change.

macOS and Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install "aws-arch-agent==0.5.0"
aws-arch-agent --version   # 0.5.0
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install "aws-arch-agent==0.5.0"
aws-arch-agent --version   # 0.5.0
```

The package is on [PyPI](https://pypi.org/project/aws-arch-agent/).

To install the command on its own, without managing a virtual environment, use [pipx](https://pipx.pypa.io/):

```bash
pipx install aws-arch-agent
```

To install a tag straight from GitHub instead:

```bash
pip install "git+https://github.com/gutehall/aws-arch-agent@v0.5.0"
```

CI tests on Linux (Python 3.11 and 3.12) and Windows, and runs the GitHub Action on Linux, macOS, and Windows. V2 synth also needs Node.js for `npx cdk synth`.

To work on the scanner, clone `main` and `pip install -e ".[dev]"` (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Usage

```bash
aws-arch-agent --repo ./my-project --no-llm                          # report.md
aws-arch-agent --repo . --no-llm --format html --out report.html     # browser report
aws-arch-agent --repo . --no-llm --format sarif --out results.sarif  # GitHub Code Scanning
aws-arch-agent --repo . --no-llm --fail-on high                      # fail CI on High findings
```

The IaC source is detected automatically. `--iac cdk|cloudformation|terraform` forces one. V1 and V2 both scan Terraform; in V2, CloudFormation needs `--templates`. `--tf-plan plan.json` fills Terraform values from `terraform show -json`, in the root module and in local child modules at any depth.

Each finding has a severity, a pillar, a file and line, evidence, a recommendation, and often suggested code. CloudFormation findings point at the line of the resource's logical ID. The walk reads files in a fixed order and stops at `--max-files` (400); a truncated walk is noted on the console and in the report. The HTML report is one self-contained dark-theme page with severity tabs. Each finding links to the AWS docs for that control and to the Well-Architected best practice it supports.

### Cost

Template scans (CloudFormation, Terraform, `cdk synth` output) get an estimated monthly cost per stack, priced in each stack's region from live AWS on-demand prices. With boto3 installed (`pip install 'aws-arch-agent[aws]'`) and AWS credentials, prices come from the AWS Price List Query API (`pricing:GetProducts`). Without them, from the public AWS Price List bulk API. Prices are cached locally for 24 hours, so the first scan of a region without credentials is the slow one. A scan never fails because pricing failed.

```bash
aws-arch-agent --repo . --no-llm --update-baseline                          # also records the cost
aws-arch-agent --repo . --no-llm --compare-cost .aws-arch-agent-baseline.json --max-cost-increase 10%
aws-arch-agent --repo . --no-llm --max-monthly-cost 500                     # exit 1 above $500/month
```

Usage-based resources (S3, Lambda, on-demand DynamoDB, ...) are priced only from a usage profile, `.aws-arch-agent-usage.yaml`. A breached budget exits 1. See [docs/REFERENCE.md](docs/REFERENCE.md#prices).

## What it checks

| Pillar | Rules | Examples |
|--------|------:|----------|
| **Security** | 115 | Missing encryption, public access, wildcard IAM, hardcoded secrets, no MFA, no threat model |
| **Reliability** | 73 | Missing DLQs, no backups, single-AZ, no health checks, untraced requests, no quota alarms |
| **Operational Excellence** | 73 | No logging, alarms, or tracing; no owner, runbook, test gate, or rollback |
| **Performance Efficiency** | 24 | No caching, no Graviton, oversized tasks, no load balancer, no load test |
| **Cost Optimization** | 51 | No autoscaling, NAT data processing, no lifecycle policy, no budgets or cost owner |
| **Sustainability** | 27 | No Spot, no right-sizing, idle resources, unattached volumes, no data expiry |
| **Best Practices** | 5 | Tags, secrets in environment variables, CDK Aspects |

Repo-level checks (`REPO-*`) read the IaC together with notes in the repo (README, ADRs, runbooks, `docs/`). A missing process is a finding too.

AI-specific checks run only for an AI workload: a Bedrock agent with no guardrail or idle session timeout (`CF-BEDROCK-001`, `CF-BEDROCK-003`), no model invocation logging with `rules.org` (`CF-BEDROCK-004`), a guardrail with no content or sensitive-information filter (`CF-BEDROCK-005`), an agent or prompt with no customer managed key, no alias or no prompt version (`CF-BEDROCK-006` to `CF-BEDROCK-008`), a prompt variant with no maximum tokens (`CF-BEDROCK-009`), a public AgentCore runtime, a gateway with no authorizer and a memory with no customer managed key (`CF-AGENTCORE-001` to `CF-AGENTCORE-003`), a SageMaker endpoint with no monitoring schedule (`CF-SAGE-006`), a SageMaker notebook with no idle-stop lifecycle configuration, a Studio domain open to the internet or with no customer managed key, an endpoint config with no data capture, an endpoint with no automatic scaling, a feature group with no customer managed key and a model not deployed from the model registry (`CF-SAGE-007` to `CF-SAGE-013`), a guardrail with no denied topics, no PII entity filter, or no contextual grounding check for a knowledge base (`CF-BEDROCK-010` to `CF-BEDROCK-012`), AI projects with no responsible-AI, evaluation, human-oversight, agent-role, or prompt-catalog notes (`REPO-194` to `REPO-198`), Bedrock model calls with no guardrail or token bound (`REPO-199`, `REPO-200`), a pipeline with no evaluation step (`REPO-201`), and no model card, no bias evaluation for a SageMaker workload, or no note on escalating to a person who can override the system (`REPO-202` to `REPO-204`). `lenses.ai` forces them on or off; see [docs/CONFIG.md](docs/CONFIG.md).

### Well-Architected answers

The report ends with an answer for each of the 57 Well-Architected questions, **met** or **not met**, computed from the findings alone. Every one of the 307 best practices maps to at least one rule.

A workload that uses Bedrock, SageMaker, or AgentCore also gets a second list, `lens_answers`: an answer for each question of the four AI Well-Architected lenses (Machine Learning, Generative AI, Responsible AI, Agentic AI), computed the same way. It appears only when the scan sees one of those services, or when the config sets `lenses.ai: true`; the 57 core answers do not change. See [docs/REFERENCE.md](docs/REFERENCE.md#ai-lens-answers).

Some practices only make sense at account level (an organization trail, service control policies, a cost and usage report). Those rules are off by default. Set `rules.org: true` to turn them on. Until then a question with those practices reads "N of M best practices off unless rules.org is on", and JSON `answers` carry `needs_org` with the rule ids.

CloudFormation and Terraform run the template checks (`CF-*`). Full list: [docs/CF_RULES.md](docs/CF_RULES.md).

## CI

Record existing findings once, then fail only on new ones. The baseline file defaults to `.aws-arch-agent-baseline.json`.

```bash
aws-arch-agent --repo . --no-llm --update-baseline
aws-arch-agent --repo . --no-llm --fail-on high --enforce-baseline
```

To accept one finding where it is, put `# aws-arch-agent: ignore <RULE_ID> reason="..." expires=YYYY-MM-DD` (or `//`) on its line or the line above, or list the rule under the template resource's `Metadata: {aws-arch-agent: {ignore: [...]}}`. A suppressed finding stays in the report, labelled, and does not count for `--fail-on` until it expires. `rules.exclude_paths` skips rules for path globs. See [docs/CONFIG.md](docs/CONFIG.md#inline-suppressions).

SARIF results carry `partialFingerprints`, a `helpUri` per rule, and `suppressions` for inline (`inSource`) and baseline-accepted (`external`) findings, so Code Scanning tracks them across line moves.

Or use the composite GitHub Action, pinned to a release:

```yaml
- uses: gutehall/aws-arch-agent/.github/actions/aws-arch-agent@v0.5.0
  with:
    repo: .
    fail-on: high
    format: sarif
    no-llm: "true"
    enforce-baseline: "true"
    job-summary: "true"
```

The action also takes `tf-plan`, `live-account`, `region`, `theme`, `group-by`, `config`, and `templates`. `job-summary: "true"` adds the Markdown report to the job summary. See [docs/REFERENCE.md](docs/REFERENCE.md#github-action).

`@main` moves every time a check merges, so a pipeline using `fail-on` or a baseline can start failing with no change on your side. Pin a tag and upgrade on purpose:

- **Patch** (`v0.2.x`): fixes only.
- **Minor** (`v0.x.0`): can add new checks, so new findings may appear.
- **Major** (`vX.0.0`): can change CLI flags or the report schema.

Releases and notes: [GitHub releases](https://github.com/gutehall/aws-arch-agent/releases) and [CHANGELOG.md](CHANGELOG.md).

## Modes

- **V1** (default): static rules. No synth. Finishes in seconds.
- **V2** (`--mode v2`): runs `cdk synth`, then six LangGraph reviewers judge the static findings and the synthesised template. A release install needs the `v2` extra. A checkout installed with `.[dev]` already has it.

```bash
pip install "aws-arch-agent[v2]==0.5.0"
aws-arch-agent --repo . --mode v2 --no-llm --rag ./docs/waf-snippets.md
```

`--rag` is keyword search over a markdown file and needs no extra package. Embedding RAG needs the `rag` extra as well. See [docs/V2_LANGGRAPH.md](docs/V2_LANGGRAPH.md).

## Documentation

- [docs/REFERENCE.md](docs/REFERENCE.md): CLI options, IaC sources, Terraform plans, modes, LLM providers, HTML report, prices and cost
- [docs/CONFIG.md](docs/CONFIG.md): config file (`aws-arch-agent.yaml` or JSON)
- [docs/CF_RULES.md](docs/CF_RULES.md): all rules
- [docs/V2_LANGGRAPH.md](docs/V2_LANGGRAPH.md): V2 pipeline
- [docs/report-schema.json](docs/report-schema.json): JSON report schema
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup and releases
- [CHANGELOG.md](CHANGELOG.md): what each release changed

## License

MIT. See [LICENSE](LICENSE).
