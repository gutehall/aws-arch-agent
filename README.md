# AWS Arch Agent

**Note:** This solution is still in an early phase. There may be bugs, and not all rules have been added yet. More updates to come.

> **Automated AWS CDK architecture review tool** that scans your infrastructure code and finds security, reliability, performance, and cost issues.

Runs locally. No AWS credentials needed. Supports TypeScript and Python CDK.



```bash
# Quick start - scan your CDK project
pip install -e .
aws-arch-agent --repo ./my-cdk-project --no-llm
```

## What It Does

AWS Arch Agent reviews your CDK code against **170 rules** across all 6 AWS Well-Architected Framework pillars:

| Pillar | Rules | Examples |
|--------|-------|----------|
| **Security** | 65 | Encryption missing, public access, hardcoded secrets, MFA not enabled |
| **Reliability** | 31 | Missing DLQs, no backups, single-AZ deployments, no health checks |
| **Operational Excellence** | 25 | No logging, missing alarms, no monitoring, no observability |
| **Performance** | 19 | No caching, wrong instance sizes, ARM not used, no CDN |
| **Cost Optimization** | 18 | No autoscaling, oversized resources, NAT costs, no lifecycle policies |
| **Sustainability** | 7 | Spot instances not used, right-sizing opportunities |

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
| `--format`, `-f` | Output format: `markdown` or `json` | `--format json` |
| `--no-llm` | Skip LLM-based recommendations | `--no-llm` |
| `--fail-on` | Exit with error if findings ≥ severity | `--fail-on high` |

See all options: `aws-arch-agent --help`

## Use Cases

### Local Development
```bash
# Quick check before committing
aws-arch-agent --repo . --no-llm
```

### CI/CD Pipeline
```yaml
# GitHub Actions example
- name: CDK Architecture Review
  run: |
    pip install -e .
    aws-arch-agent --repo . \
      --format json \
      --fail-on high \
      --out report.json
```

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
rules_exclude:
  - BP-001  # Skip tagging rule
severity_threshold: medium
```

Use it:
```bash
aws-arch-agent --repo . --config aws-arch-agent.yaml
```

## Documentation

- **[docs/CF_RULES.md](docs/CF_RULES.md)** - Complete list of all static rules + CloudFormation rules
- **[docs/REFERENCE.md](docs/REFERENCE.md)** - Complete CLI reference
- **[docs/CONFIG.md](docs/CONFIG.md)** - Configuration file options
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development setup and contributing guide

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

```bash
# Development setup
pip install -e ".[dev]"
pytest          # Run tests
ruff check .    # Lint
mypy .          # Type check
```

## License

MIT License - see [LICENSE](LICENSE) file for details.




