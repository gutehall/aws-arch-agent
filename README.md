# AWS Arch Agent

Local-first AWS architecture review for infrastructure code. It scans **CDK** (TypeScript and Python), **CloudFormation**, and **Terraform**, and reports security, reliability, performance, cost, and sustainability issues mapped to the AWS Well-Architected Framework.

No AWS credentials. No cloud calls. LLM output is optional.

> Early-stage: 169 static rules are implemented and tested. Expect some false positives and negatives, and API changes.

## Install

Requires Python 3.11+ and [ripgrep](https://github.com/BurntSushi/ripgrep#installation) (`brew install ripgrep`).

```bash
git clone https://github.com/gutehall/aws-arch-agent.git
cd aws-arch-agent
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

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
| **Security** | 65 | Missing encryption, public access, hardcoded secrets, no MFA |
| **Reliability** | 31 | Missing DLQs, no backups, single-AZ, no health checks |
| **Operational Excellence** | 24 | No logging, alarms, or tracing |
| **Performance Efficiency** | 19 | No caching, oversized instances, no Graviton |
| **Cost Optimization** | 18 | No autoscaling, NAT costs, no lifecycle policies |
| **Sustainability** | 7 | No Spot, right-sizing |
| **Best Practices** | 5 | Tags, Secrets Manager, CDK Aspects |

CloudFormation and Terraform run the template checks (`CF-*`). Full list: [docs/CF_RULES.md](docs/CF_RULES.md).

## CI

Record existing findings once, then fail only on new ones:

```bash
aws-arch-agent --repo . --no-llm --update-baseline
aws-arch-agent --repo . --no-llm --fail-on high --enforce-baseline
```

Or use the composite GitHub Action:

```yaml
- uses: gutehall/aws-arch-agent/.github/actions/aws-arch-agent@main
  with:
    repo: .
    fail-on: high
    format: sarif
    no-llm: "true"
    enforce-baseline: "true"
```

## Modes

- **V1** (default): static rules. No synth, finishes in seconds.
- **V2** (`--mode v2`): runs `cdk synth`, then six LangGraph pillar reviewers check the CloudFormation output. Install with `pip install -e ".[v2]"`. Optional LLM via Ollama, OpenAI, or Anthropic, and optional RAG over your own docs:

```bash
aws-arch-agent --repo . --mode v2 --rag ./docs/waf-snippets.md
```

## Documentation

- [docs/REFERENCE.md](docs/REFERENCE.md): CLI options, IaC sources, Terraform plans, modes, LLM providers, HTML report
- [docs/CONFIG.md](docs/CONFIG.md): config file (`aws-arch-agent.yaml` or JSON)
- [docs/CF_RULES.md](docs/CF_RULES.md): all rules
- [docs/V2_LANGGRAPH.md](docs/V2_LANGGRAPH.md): V2 pipeline
- [docs/report-schema.json](docs/report-schema.json): JSON report schema
- [CONTRIBUTING.md](CONTRIBUTING.md): development setup

## License

MIT. See [LICENSE](LICENSE).
