# AWS Arch Agent

Local-first AWS architecture review for **CDK** (TypeScript and Python), **CloudFormation**, and **Terraform**. It reports security, reliability, operational excellence, performance, cost, and sustainability issues mapped to the AWS Well-Architected Framework. A workload that uses Bedrock, SageMaker, or AgentCore also gets the four AI lenses.

A scan needs no AWS credentials. Price lookups are the only network calls, unless you pass `--live-account` or point the optional LLM at a server you run. `--pricing-source off` skips prices. `--no-llm` skips the model. If the model does not answer, the findings stay as the rules wrote them.

368 static rules and 328 template checks are implemented and tested. 141 of the 368 CDK rules (38%) have a template check. Those checks run on CloudFormation, Terraform, and synthesised CDK. Every other rule is answered by a repo rule, a usage signal, or a `--live-account` read; [docs/COVERAGE.md](docs/COVERAGE.md) gives the reason for each.

## Install

Python 3.11+, git, and [ripgrep](https://github.com/BurntSushi/ripgrep#installation) (`brew install ripgrep`, `sudo apt install ripgrep`, or `winget install BurntSushi.ripgrep.MSVC`).

Latest release: [v1.2.0](https://github.com/gutehall/aws-arch-agent/releases/tag/v1.2.0). The package is on [PyPI](https://pypi.org/project/aws-arch-agent/).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install "aws-arch-agent==1.2.0"
aws-arch-agent --version   # 1.2.0
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install "aws-arch-agent==1.2.0"
aws-arch-agent --version   # 1.2.0
```

Without a virtual environment:

```bash
pipx install aws-arch-agent
```

From GitHub:

```bash
pip install "git+https://github.com/gutehall/aws-arch-agent@v1.2.0"
```

| Extra | Adds |
|-------|------|
| `aws` | boto3, for prices from the Price List Query API |
| `account` | `--live-account`: read-only reads of account services (Security Hub, GuardDuty, CloudTrail, Config, Budgets), the account FSBP controls S3.1, EC2.7 and IAM.7, Macie, Storage Lens and a cost export, and of Reserved Instances, reserved nodes and Savings Plans for the compute the scan found |
| `v2` | LangGraph mode and `cdk synth` |
| `rag` | embedding search over `--rag` |

`pip install "aws-arch-agent[v2]==1.2.0"`. V2 synth also needs Node.js (`npx`). To work on the scanner, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Usage

```bash
aws-arch-agent --repo ./my-project                                   # report.html, cost, LLM
aws-arch-agent --repo . --out report.md                              # Markdown, from the suffix
aws-arch-agent --repo . --no-llm --format sarif --out results.sarif  # GitHub Code Scanning
aws-arch-agent --repo . --no-llm --fail-on high                      # fail on High findings
```

A plain `--repo` scan writes `report.html`, prices every stack it can, and uses a local Ollama when one is running. A CDK app uses V2 when the `v2` extra and Node.js are installed, so the synthesised stacks are priced too. Otherwise it says why and scans with V1.

While it runs, the terminal prints each step: detecting the source, reading files, the current rule, synth, templates, and any LLM call. A step that is still going after 15 seconds is printed again. When it finishes, it prints severity counts, up to five top fixes, and the report path. Read the findings in the report. [Terminal summary](docs/REFERENCE.md#terminal-summary).

The source is detected. `--iac cdk|cloudformation|terraform` forces one. `--tf-plan plan.json` fills Terraform values from `terraform show -json`. Every flag is in [docs/REFERENCE.md](docs/REFERENCE.md).

## What it checks

| Pillar | Rules | Examples |
|--------|------:|----------|
| **Security** | 115 | Missing encryption, public access, wildcard IAM, hardcoded secrets, no MFA |
| **Reliability** | 73 | Missing DLQs, no backups, single-AZ, no health checks |
| **Operational Excellence** | 73 | No logging, alarms, or tracing; no owner, runbook, or rollback |
| **Performance Efficiency** | 24 | No caching, no Graviton, oversized tasks, no load test |
| **Cost Optimization** | 51 | No autoscaling, NAT data processing, no lifecycle policy, no budgets |
| **Sustainability** | 27 | No Spot, no right-sizing, idle resources, no data expiry |
| **Best Practices** | 5 | Tags, secrets in environment variables, CDK Aspects |

`REPO-*` checks, SUST-004 and SUST-005 also read notes in the repo (README, ADRs, runbooks, `docs/`). AI checks run only for an AI workload, or when `lenses.ai` is set. Account-level rules stay off until `rules.org: true`.

The report answers each of the 57 Well-Architected questions from the findings. An AI workload also gets the four lens question lists. Full lists: [docs/CF_RULES.md](docs/CF_RULES.md), [Well-Architected answers](docs/REFERENCE.md#well-architected-answers), [AI lens answers](docs/REFERENCE.md#ai-lens-answers).

## Cost

CloudFormation, Terraform, and `cdk synth` output get an estimated monthly cost per stack, from the AWS Price List, cached locally for 24 hours. A missing price skips that estimate. CDK source in V1 is not priced; use `--mode v2`.

```bash
aws-arch-agent --repo . --no-llm --update-baseline
aws-arch-agent --repo . --no-llm --compare-cost .aws-arch-agent-baseline.json --max-cost-increase 10%
aws-arch-agent --repo . --no-llm --max-monthly-cost 500
aws-arch-agent --repo . --no-llm --pricing-source off
```

Usage-based resources (S3, Lambda, NAT data, and similar) are priced only from `.aws-arch-agent-usage.yaml` or `--usage-file`. The same file can state usage signals (read/write ratio, CPU, Parameter Store rate, a daily traffic pattern, user and upload Regions); REL-011, OPS-023, SUST-002, SUST-003, PERF-011 and PERF-014 report only when it does. Prices, budgets, and the usage file: [docs/REFERENCE.md](docs/REFERENCE.md#prices).

## CI

Record current findings once, then fail only on new ones. The baseline file is `.aws-arch-agent-baseline.json`.

```bash
aws-arch-agent --repo . --no-llm --update-baseline
aws-arch-agent --repo . --no-llm --fail-on high --enforce-baseline
```

To accept one finding in source, put `# aws-arch-agent: ignore <RULE_ID> reason="..." expires=YYYY-MM-DD` on its line or the line above. [Inline suppressions](docs/CONFIG.md#inline-suppressions).

```yaml
- uses: gutehall/aws-arch-agent/.github/actions/aws-arch-agent@v1.2.0
  with:
    repo: .
    fail-on: high
    format: sarif
    no-llm: "true"
    enforce-baseline: "true"
    job-summary: "true"
```

Pin a release tag. A minor release can add checks, so new findings may appear. A major release can change CLI flags or the report schema. [GitHub Action](docs/REFERENCE.md#github-action), [releases](https://github.com/gutehall/aws-arch-agent/releases), [CHANGELOG.md](CHANGELOG.md).

## Modes

`--mode auto` (the default) uses V2 for a CDK app when the `v2` extra and Node.js are installed, or when `--templates` is passed. Otherwise it uses V1.

- **V1** (`--mode v1`): static rules. No synth.
- **V2** (`--mode v2`): `cdk synth`, then six reviewers over the findings and the synthesised template. `--rag ./docs/waf-snippets.md` adds keyword search over that file. Embedding search needs the `rag` extra. [V2 pipeline](docs/V2_LANGGRAPH.md).

## Documentation

- [docs/REFERENCE.md](docs/REFERENCE.md): CLI, sources, Terraform plans, LLM, prices, cost
- [docs/CONFIG.md](docs/CONFIG.md): `aws-arch-agent.yaml`
- [docs/CF_RULES.md](docs/CF_RULES.md): every rule
- [docs/V2_LANGGRAPH.md](docs/V2_LANGGRAPH.md): V2 pipeline
- [docs/report-schema.json](docs/report-schema.json): JSON report
- [CONTRIBUTING.md](CONTRIBUTING.md): development and releases
- [CHANGELOG.md](CHANGELOG.md): what each release changed

## License

MIT. See [LICENSE](LICENSE).
