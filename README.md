# AWS Arch Agent

Local-first AWS architecture review for infrastructure code. It scans **CDK** (TypeScript and Python), **CloudFormation**, and **Terraform**, and reports security, reliability, operational excellence, performance, cost, and sustainability issues mapped to the AWS Well-Architected Framework. For workloads that use Bedrock, SageMaker, or AgentCore it also answers the four AI Well-Architected lenses (Machine Learning, Generative AI, Responsible AI, Agentic AI).

No AWS credentials. No cloud calls, unless you opt in with `--live-account` (read-only account checks). LLM output is optional and self-hosted only. With `OLLAMA_HOST` or `LLM_BASE_URL` set, it calls that server; with neither set it makes no call. `--no-llm` skips it either way. If the model does not answer, the findings stay as the rules wrote them.

> 362 static rules and 299 template checks are implemented and tested. 141 of the 362 CDK rules (39%) have a template check. Those checks run on CloudFormation, Terraform, and synthesised CDK. [docs/COVERAGE.md](docs/COVERAGE.md) gives the reason for each of the others. Expect some false positives and negatives, and API changes.

## Install

Requires Python 3.11+, git, and [ripgrep](https://github.com/BurntSushi/ripgrep#installation): `brew install ripgrep` (macOS), `sudo apt install ripgrep` (Debian/Ubuntu), or `winget install BurntSushi.ripgrep.MSVC` (Windows).

Install a release (latest: [v0.3.1](https://github.com/gutehall/aws-arch-agent/releases/tag/v0.3.1)). Pin the tag. [CI](#ci) says what a newer tag can change.

macOS and Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install "aws-arch-agent==0.3.1"
aws-arch-agent --version   # 0.3.1
```

Windows (PowerShell):

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install "aws-arch-agent==0.3.1"
aws-arch-agent --version   # 0.3.1
```

The package is on [PyPI](https://pypi.org/project/aws-arch-agent/).

To install the command on its own, without managing a virtual environment, use [pipx](https://pipx.pypa.io/):

```bash
pipx install aws-arch-agent
```

To install a tag straight from GitHub instead:

```bash
pip install "git+https://github.com/gutehall/aws-arch-agent@v0.3.1"
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

The IaC source is detected automatically. `--iac cdk|cloudformation|terraform` forces one. In V2, `terraform` exits 1, and CloudFormation needs `--templates`.

Each finding has a severity, a pillar, a file and line, evidence, a recommendation, and often suggested code. The HTML report is one self-contained dark-theme page with severity tabs. Each finding links to the AWS docs for that control and to the Well-Architected best practice it supports.

## What it checks

| Pillar | Rules | Examples |
|--------|------:|----------|
| **Security** | 114 | Missing encryption, public access, wildcard IAM, hardcoded secrets, no MFA, no threat model |
| **Reliability** | 73 | Missing DLQs, no backups, single-AZ, no health checks, untraced requests, no quota alarms |
| **Operational Excellence** | 69 | No logging, alarms, or tracing; no owner, runbook, test gate, or rollback |
| **Performance Efficiency** | 24 | No caching, no Graviton, oversized tasks, no load balancer, no load test |
| **Cost Optimization** | 50 | No autoscaling, NAT data processing, no lifecycle policy, no budgets or cost owner |
| **Sustainability** | 27 | No Spot, no right-sizing, idle resources, unattached volumes, no data expiry |
| **Best Practices** | 5 | Tags, secrets in environment variables, CDK Aspects |

Repo-level checks (`REPO-*`) read the IaC together with notes in the repo (README, ADRs, runbooks, `docs/`). A missing process is a finding too.

AI-specific checks run only for an AI workload: a Bedrock agent with no guardrail or idle session timeout (`CF-BEDROCK-001`, `CF-BEDROCK-003`), no model invocation logging with `rules.org` (`CF-BEDROCK-004`), a SageMaker endpoint with no monitoring schedule (`CF-SAGE-006`), and AI projects with no responsible-AI, evaluation, human-oversight, agent-role, or prompt-catalog notes (`REPO-194` to `REPO-198`). `lenses.ai` forces them on or off; see [docs/CONFIG.md](docs/CONFIG.md).

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

Or use the composite GitHub Action, pinned to a release:

```yaml
- uses: gutehall/aws-arch-agent/.github/actions/aws-arch-agent@v0.3.1
  with:
    repo: .
    fail-on: high
    format: sarif
    no-llm: "true"
    enforce-baseline: "true"
```

`@main` moves every time a check merges, so a pipeline using `fail-on` or a baseline can start failing with no change on your side. Pin a tag and upgrade on purpose:

- **Patch** (`v0.2.x`): fixes only.
- **Minor** (`v0.x.0`): can add new checks, so new findings may appear.
- **Major** (`vX.0.0`): can change CLI flags or the report schema.

Releases and notes: [GitHub releases](https://github.com/gutehall/aws-arch-agent/releases) and [CHANGELOG.md](CHANGELOG.md).

## Modes

- **V1** (default): static rules. No synth. Finishes in seconds.
- **V2** (`--mode v2`): runs `cdk synth`, then six LangGraph reviewers judge the static findings and the synthesised template. A release install needs the `v2` extra. A checkout installed with `.[dev]` already has it.

```bash
pip install "aws-arch-agent[v2]==0.3.1"
aws-arch-agent --repo . --mode v2 --no-llm --rag ./docs/waf-snippets.md
```

`--rag` is keyword search over a markdown file and needs no extra package. Embedding RAG needs the `rag` extra as well. See [docs/V2_LANGGRAPH.md](docs/V2_LANGGRAPH.md).

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
