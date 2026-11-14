# AWS Arch Agent

Local-first AWS architecture review for infrastructure code. It scans **CDK** (TypeScript and Python), **CloudFormation**, and **Terraform**, and reports security, reliability, performance, cost, and sustainability issues mapped to the AWS Well-Architected Framework.

No AWS credentials. No cloud calls. LLM output is optional.

> Early-stage: 372 static rules and 285 template checks are implemented and tested. 139 of the 372 CDK rules (37%) have a template check, so they also run for CloudFormation, Terraform and synthesised CDK. [docs/COVERAGE.md](docs/COVERAGE.md) gives the reason for each of the others. Expect some false positives and negatives, and API changes.

## Install

Requires Python 3.11+, git, and [ripgrep](https://github.com/BurntSushi/ripgrep#installation): `brew install ripgrep` (macOS), `sudo apt install ripgrep` (Debian/Ubuntu), or `winget install BurntSushi.ripgrep.MSVC` (Windows).

Install a release (latest: [v0.2.1](https://github.com/gutehall/aws-arch-agent/releases/tag/v0.2.1)).

macOS and Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install "git+https://github.com/gutehall/aws-arch-agent@v0.2.1"
aws-arch-agent --version   # 0.2.1
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install "git+https://github.com/gutehall/aws-arch-agent@v0.2.1"
aws-arch-agent --version   # 0.2.1
```

CI runs the test suite on Linux and Windows, and the GitHub Action on Linux, macOS, and Windows runners. V2 synth also needs Node.js for `npx cdk synth`.

The release tag is the rule set; see [CI](#ci) for what each upgrade can change. To work on the scanner itself, clone `main` and `pip install -e ".[dev]"` (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Usage

```bash
aws-arch-agent --repo ./my-project --no-llm                          # report.md
aws-arch-agent --repo . --no-llm --format html --out report.html     # browser report
aws-arch-agent --repo . --no-llm --format sarif --out results.sarif  # GitHub Code Scanning
aws-arch-agent --repo . --no-llm --fail-on high                      # fail CI on High findings
```

The source is detected automatically. Use `--iac cdk|cloudformation|terraform` to force one.

Each finding has a severity, a pillar, a file and line, evidence, a recommendation, and often suggested code. The HTML report is one self-contained dark-theme page with severity tabs and links to the relevant AWS documentation for each finding.

## What it checks

| Pillar | Rules | Examples |
|--------|------:|----------|
| **Security** | 113 | Missing encryption, public access, hardcoded secrets, no MFA, no threat model, long-lived IAM users, no permission review |
| **Reliability** | 75 | Missing DLQs, no backups, single-AZ, no health checks, untraced requests, fixed-size fleets, no quota alarms, no failover test |
| **Operational Excellence** | 67 | No logging, alarms, tracing, KPI metrics, test gates, or rollback; no named owner, runbook, priorities, post-incident review or evolution notes |
| **Performance Efficiency** | 33 | No caching, oversized instances, no Graviton, no dynamic scaling, no load balancer, single VPN or Direct Connect link, no load test or architecture decision record |
| **Cost Optimization** | 52 | No autoscaling, NAT costs, no lifecycle policies, no cost report, cost tags or budgets, no cost owner, no cost review, fleets with no pricing model, unmodeled data transfer |
| **Sustainability** | 27 | No Spot, no right-sizing, idle or unused resources, unattached volumes, no device testing, no sustainability tradeoff or improvement process |
| **Best Practices** | 5 | Tags, Secrets Manager, CDK Aspects |

Many repo-level checks (`REPO-*`) read the IaC together with notes in the repo (README, ADRs, runbooks, `docs/`), so a missing process is reported as a finding too.

### Well-Architected answers

The report ends with an answer for each of the 57 Well-Architected questions, **met** or **not met**, computed from the findings alone. Every one of the 307 best practices maps to at least one rule. Some practices only make sense at account level (an organization trail, service control policies, a cost and usage report). Those rules are off by default; set `rules.org: true` to turn them on. Until then the question reads "N of M best practices off unless rules.org is on", and JSON `answers` carry `needs_org` with the rule ids.

CloudFormation and Terraform run the template checks (`CF-*`). Full list: [docs/CF_RULES.md](docs/CF_RULES.md).

## CI

Record existing findings once, then fail only on new ones:

```bash
aws-arch-agent --repo . --no-llm --update-baseline
aws-arch-agent --repo . --no-llm --fail-on high --enforce-baseline
```

Or use the composite GitHub Action, pinned to a release:

```yaml
- uses: gutehall/aws-arch-agent/.github/actions/aws-arch-agent@v0.2.1
  with:
    repo: .
    fail-on: high
    format: sarif
    no-llm: "true"
    enforce-baseline: "true"
```

The tag is the rule set. `@main` moves every time a check merges, so a pipeline using `fail-on` or a baseline can start failing without any change on your side. Pin a tag and upgrade on purpose:

- **Patch** (`v0.1.x`): fixes only.
- **Minor** (`v0.x.0`): can add new checks, so new findings may appear.
- **Major** (`vX.0.0`): can change CLI flags or the report schema.

Releases and notes: [GitHub releases](https://github.com/gutehall/aws-arch-agent/releases) and [CHANGELOG.md](CHANGELOG.md).

## Modes

- **V1** (default): static rules. No synth, finishes in seconds.
- **V2** (`--mode v2`): runs `cdk synth`, then six LangGraph pillar reviewers check the CloudFormation output. Install with `pip install -e ".[v2]"`. Optional LLM via Ollama or another self-hosted model, and optional RAG over your own docs:

```bash
aws-arch-agent --repo . --mode v2 --rag ./docs/waf-snippets.md
```

## Documentation

- [docs/REFERENCE.md](docs/REFERENCE.md): CLI options, IaC sources, Terraform plans, modes, LLM providers, HTML report
- [docs/CONFIG.md](docs/CONFIG.md): config file (`aws-arch-agent.yaml` or JSON)
- [docs/CF_RULES.md](docs/CF_RULES.md): all rules
- [docs/V2_LANGGRAPH.md](docs/V2_LANGGRAPH.md): V2 pipeline
- [docs/report-schema.json](docs/report-schema.json): JSON report schema
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup and releases
- [CHANGELOG.md](CHANGELOG.md): what each release changed

## License

MIT. See [LICENSE](LICENSE).
