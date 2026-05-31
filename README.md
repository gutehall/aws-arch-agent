# AWS Arch Agent

**Note:** Early-stage project — **170 static rules** are implemented and tested, but expect occasional false positives/negatives and API changes.

> **Automated AWS CDK architecture review tool** that scans your infrastructure code and finds security, reliability, performance, and cost issues.

Runs locally. No AWS credentials needed. Supports TypeScript and Python CDK.



```bash
# Quick start - scan your CDK project
pip install -e .
aws-arch-agent --repo ./my-cdk-project --no-llm
```

## What It Does

AWS Arch Agent reviews your CDK code against **170 rules** across the six AWS Well-Architected Framework pillars, plus CDK best-practice checks:

| Pillar | Rules | Examples |
|--------|-------|----------|
| **Security** | 65 | Encryption missing, public access, hardcoded secrets, MFA not enabled |
| **Reliability** | 31 | Missing DLQs, no backups, single-AZ deployments, no health checks |
| **Operational Excellence** | 25 | No logging, missing alarms, no monitoring, no observability |
| **Performance Efficiency** | 19 | No caching, wrong instance sizes, ARM not used, no CDN |
| **Cost Optimization** | 18 | No autoscaling, oversized resources, NAT costs, no lifecycle policies |
| **Sustainability** | 7 | Spot instances not used, right-sizing opportunities |
| **Best Practices** | 5 | Missing tags, Secrets Manager, CDK Aspects, naming conventions |

**See complete rule list:** [docs/CF_RULES.md](docs/CF_RULES.md)

## Quick Start

### 1. Install

```bash
# Clone or download the repo
cd aws-arch-agent

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install
pip install -U pip
pip install -e .

# Verify installation
aws-arch-agent --help
```

**Requirements:**
- Python 3.11+
- [ripgrep](https://github.com/BurntSushi/ripgrep#installation) (`brew install ripgrep` on Mac)

### 2. Run Your First Scan

```bash
# Scan a CDK project (fast, no AWS access needed)
aws-arch-agent --repo /path/to/your/cdk-project --no-llm

# Or scan the current directory
aws-arch-agent --repo . --no-llm
```

This creates a `report.md` file with all findings.

### 3. Review the Report

Open `report.md` to see:
- **High/Medium/Low priority findings** organized by severity
- **Specific file and line numbers** for each issue
- **Actionable recommendations** with CDK code examples
- **AWS Well-Architected pillar** for each finding

## Usage Guide

### Basic Commands

```bash
# Fast scan with static rules only (recommended for first run)
aws-arch-agent --repo . --no-llm

# Advanced scan with CloudFormation template analysis
aws-arch-agent --repo . --mode v2

# JSON output for CI/CD pipelines
aws-arch-agent --repo . --format json --out report.json

# Fail build if high-severity issues found
aws-arch-agent --repo . --fail-on high
```

### Two Modes

**V1 Mode (Default - Fast):**
- Scans CDK TypeScript/Python code with static rules
- No `cdk synth` required
- Completes in seconds
- Best for: Quick checks, CI/CD, local development

**V2 Mode (Advanced):**
- Runs `cdk synth` and analyzes CloudFormation templates
- Multi-agent LangGraph pipeline with 6 specialized reviewers
- Catches resource-level issues (encryption, settings, etc.)
- Best for: Comprehensive reviews, production deployments

```bash
# V1 - Fast static analysis
aws-arch-agent --repo . --no-llm

# V2 - Comprehensive analysis with CloudFormation
aws-arch-agent --repo . --mode v2
```

### Common Options

| Option | Description | Example |
|--------|-------------|---------|
| `--repo`, `-r` | Path to your CDK project | `--repo ./my-project` |
| `--out`, `-o` | Output file path | `--out review.md` |
| `--mode` | Analysis mode: `v1` or `v2` | `--mode v2` |
| `--format`, `-f` | Output format: `markdown`, `json`, or `sarif` | `--format sarif` |
| `--no-llm` | Skip LLM-based recommendations | `--no-llm` |
| `--fail-on` | Exit with error if findings ≥ severity | `--fail-on high` |
| `--baseline` | Baseline suppressions file (default: `.aws-arch-agent-baseline.json`) | `--baseline baseline.json` |
| `--enforce-baseline` | Only fail on findings not in baseline | `--enforce-baseline` |
| `--update-baseline` | Record current findings into baseline | `--update-baseline` |
| `--config` | JSON or YAML config file | `--config aws-arch-agent.yaml` |

See all options: `aws-arch-agent --help`

## Use Cases

### Local Development
```bash
# Quick check before committing
aws-arch-agent --repo . --no-llm

# Optional: install pre-commit hook (see CONTRIBUTING.md)
pip install pre-commit && pre-commit install
```

### CI/CD Pipeline
```yaml
# GitHub Actions example (gradual adoption with baseline)
- name: CDK Architecture Review
  run: |
    pip install -e .
    aws-arch-agent --repo . \
      --no-llm \
      --format json \
      --out report.json \
      --fail-on high \
      --enforce-baseline \
      --baseline .aws-arch-agent-baseline.json
```

Or use the composite action (see [GitHub Action](#github-action) below).

### CloudFormation-Only Projects
```bash
# If you have raw CloudFormation templates (no CDK)
aws-arch-agent --templates ./cloudformation --no-synth --mode v2
```

### With AI Recommendations
```bash
# Install Ollama first: https://ollama.ai
ollama serve &
export OLLAMA_MODEL=llama3:8b

# Run with AI-powered recommendations
aws-arch-agent --repo . --mode v2
```


## Advanced Features

### CloudFormation Analysis (V2 Mode)

V2 mode runs `cdk synth` and analyzes the generated CloudFormation templates:

```bash
aws-arch-agent --repo . --mode v2
```

This catches issues like:
- RDS encryption disabled
- DynamoDB point-in-time recovery not enabled
- Lambda without VPC configuration
- Security Group rules allowing 0.0.0.0/0

### LLM Integration

Add AI-powered recommendations (optional):

```bash
# Option 1: Ollama (local, free)
ollama serve &
export OLLAMA_MODEL=llama3:8b
export LLM_PROVIDER=ollama

# Option 2: OpenAI
pip install -e ".[cloud]"
export LLM_PROVIDER=openai
export OPENAI_API_KEY=sk-...

# Option 3: Anthropic
pip install -e ".[cloud]"
export LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# Run with LLM
aws-arch-agent --repo . --mode v2
```

### Configuration File

Create `aws-arch-agent.yaml` in your project:

```yaml
format: markdown
fail_on: high
no_llm: true
llm_mode: compact
rules:
  exclude:
    - BP-001  # Skip tagging rule
severity_threshold: medium
```

Use it:
```bash
aws-arch-agent --repo . --config aws-arch-agent.yaml
```

JSON config is also supported (see [docs/example-config.json](docs/example-config.json)).

### Baseline (gradual CI adoption)

Baseline suppressions live in `.aws-arch-agent-baseline.json` by default (override with `--baseline`).

```bash
# Record current findings as accepted (writes .aws-arch-agent-baseline.json)
aws-arch-agent --repo . --no-llm --update-baseline

# Fail only on new high-severity findings
aws-arch-agent --repo . --no-llm --fail-on high --enforce-baseline

# Custom baseline path
aws-arch-agent --repo . --no-llm --fail-on high --enforce-baseline --baseline baseline.json
```

### SARIF output (GitHub Code Scanning)

```bash
aws-arch-agent --repo . --no-llm --format sarif --out results.sarif
```

### V2 LLM modes

- **`--llm-mode full`** (default): six pillar reviewers + merge (best narrative, more API calls)
- **`--llm-mode compact`**: single LLM call for the merged review (faster, lower cost)

### RAG (V2)

Index Well-Architected or team conventions and inject citations into V2 pillar/merge LLM prompts:

```bash
pip install -e ".[rag]"   # optional, for embedding-based retrieval
aws-arch-agent --repo . --mode v2 --rag ./docs/waf-snippets.md
```

Set `rag.use_embeddings: true` in config for semantic retrieval (requires `sentence-transformers` or OpenAI embeddings). See [docs/CONFIG.md](docs/CONFIG.md).

### GitHub Action

```yaml
- uses: ./.github/actions/aws-arch-agent
  with:
    repo: .
    fail-on: high
    format: json
    no-llm: "true"
    enforce-baseline: "true"
    baseline: .aws-arch-agent-baseline.json
```

For SARIF upload to GitHub Code Scanning, set `format: sarif` and use `github/codeql-action/upload-sarif`.

## Documentation

- **[docs/CF_RULES.md](docs/CF_RULES.md)** - Complete list of all static rules + CloudFormation rules
- **[docs/REFERENCE.md](docs/REFERENCE.md)** - Complete CLI reference
- **[docs/CONFIG.md](docs/CONFIG.md)** - Configuration file options
- **[docs/V2_LANGGRAPH.md](docs/V2_LANGGRAPH.md)** - V2 multi-agent pipeline architecture
- **[docs/report-schema.json](docs/report-schema.json)** - JSON report schema
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development setup and contributing guide

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

```bash
# Development setup
pip install -e ".[dev]"
pytest tests/ -v              # Run tests (70% coverage gate)
ruff check src tests          # Lint
mypy src                      # Type check
```

## License

MIT License - see [LICENSE](LICENSE) file for details.




