# AWS Arch Agent

An **agentic AWS CDK architecture reviewer** that runs locally and can scale into a multi-agent workflow using LangGraph.

It combines:

- Static CDK code heuristics (ripgrep-based rules)
- CloudFormation template analysis (via `cdk synth`)
- LLM-based reasoning (local Ollama by default)
- Multi-agent orchestration (all 6 AWS Well-Architected pillars: Operational Excellence, Security, Reliability, Performance Efficiency, Cost Optimization, Sustainability)

Supports **TypeScript CDK** and **Python CDK**.

---

# How It Works

## V1 – Rules + LLM Polishing

Flow:

1. Scan repository files (TypeScript / Python / JSON / YAML)
2. Run heuristic rule engine (IAM, S3, RDS, SG, logs, etc.)
3. Generate structured findings
4. Send findings to LLM for improvement / prioritization
5. Output Markdown report

This is fast and works without `cdk synth`.

---

## V2 – LangGraph Multi-Agent + CDK Synth

Flow:

1. Collect repository context
2. Run `cdk synth` (language-aware: TypeScript or Python CDK)
3. Parse generated CloudFormation templates in `cdk.out/`
4. Apply template-based rules (higher signal)
5. Run multi-agent reasoning (6 pillars):
   - Operational Excellence (observability, CloudTrail, Flow Logs)
   - Security
   - Reliability
   - Performance Efficiency
   - Cost Optimization
   - Sustainability
6. Merge into a lead-review section
7. Generate final Markdown report

If `cdk synth` fails, the system gracefully falls back to static-only analysis.

---

# Architecture Overview

Core components:

- `rules/` → Static CDK heuristics
- `rules/cf_template.py` → CloudFormation-level validation
- `tools/` → File system, ripgrep, LLM client, CDK synth
- `agent/v1.py` → Simple pipeline
- `agent/v2_graph.py` → LangGraph multi-agent workflow
- `report/markdown.py` → Report renderer

---

# Requirements

- Python 3.11+
- Node.js
- ripgrep (`brew install ripgrep`)
- CDK project must have dependencies installed (`npm i`, `pnpm i`, or `yarn`)

Optional:

- Ollama (recommended for local inference)
- OpenAI or Anthropic API key (cloud fallback)

---

# Getting Started

## 1. Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

## 2. (Optional) Start Ollama

```bash
ollama serve
export OLLAMA_MODEL=llama3:8b
```

## 3. Analyze a CDK Project

### V1 (fast, static)

```bash
aws-arch-agent analyze /path/to/cdk-project
```

### V2 (multi-agent + synth)

```bash
aws-arch-agent analyze /path/to/cdk-project --mode v2
```

Report is written to `report.md` by default.

### Options

- `--format json` — output structured JSON (context + findings) for CI
- `--fail-on high|medium|low` — exit with code 1 if any finding at or above that severity
- `--no-llm` — skip LLM polish (faster, rules-only)
- `--rag /path/to/doc.md` — add RAG context from a doc (e.g. Well-Architected); V2 only
- `--suggestions path.json` — write findings (including suggested code) to a JSON file
- `--config path` — use a config file (default: `.aws-arch-agent.json` in repo or cwd)

Config file (JSON) can set: `format`, `fail_on`, `no_llm`, `out`, `rules.include`, `rules.exclude`, `severity_threshold`, `rag.path`, and optionally `rag.use_embeddings`, `rag.embedding_provider` (e.g. `sentence-transformers` or `openai`), `rag.embedding_model` for embedding-based RAG (see [docs/CONFIG.md](docs/CONFIG.md)).

---

# LLM Configuration

Default: **Ollama (local)**

Environment variables:

```bash
export LLM_PROVIDER=ollama
export OLLAMA_MODEL=llama3:8b
```

Cloud options:

```bash
export LLM_PROVIDER=openai
export OPENAI_API_KEY=...
```

or

```bash
export LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=...
```

---

# Current Rule Coverage

Static (CDK-level), by pillar:
- **Operational Excellence**: CloudTrail (OPS-001), VPC Flow Logs (OPS-002)
- **Security**: IAM wildcards, open security groups, S3 encryption/public access, KMS key policy (SEC-001–SEC-007)
- **Reliability**: RDS Multi-AZ/backups, Lambda DLQ
- **Performance Efficiency**: Graviton/ARM, caching (PERF-001, PERF-002)
- **Cost Optimization**: Log retention, autoscaling
- **Sustainability**: Spot, right-sizing (SUST-001, SUST-002)
- **Best Practices**: Missing tags (BP-001)

Template-level (CloudFormation): S3, RDS, ALB, CloudTrail, KMS, VPC/FlowLog, Lambda (DLQ, X-Ray), DynamoDB (PITR, SSE), Security Groups, CloudWatch Logs, SQS, API Gateway, EKS. See [docs/CF_RULES.md](docs/CF_RULES.md).

---

# Day-to-day use

- **Quick check**: `aws-arch-agent analyze . --no-llm` (rules only, no LLM)
- **Full review**: `aws-arch-agent analyze . --mode v2`
- **CI**: `aws-arch-agent analyze . --format json --fail-on high --out report.json`
- **With RAG**: `aws-arch-agent analyze . --mode v2 --rag ./docs/waf.md`
- **Export suggestions**: `aws-arch-agent analyze . --suggestions suggestions.json`

# CI

A GitHub Actions workflow is included: [.github/workflows/aws-arch-agent.yml](.github/workflows/aws-arch-agent.yml). It runs tests, ruff, mypy, and the agent (rules-only). The analyze steps use `continue-on-error: true` by default so the build does not fail when findings exist. To **fail the build** when high-severity (or higher) findings are reported, set `continue-on-error: false` on the step that runs `--fail-on high` (the "Run AWS Arch Agent (JSON, fail on high)" step).

# Development

For contributing, see [CONTRIBUTING.md](CONTRIBUTING.md). Quick setup: `pip install -e ".[dev]"`, then `pytest tests/ -v`, `ruff check src tests`, `mypy src`.

# Reference

Full CLI and config reference: [docs/REFERENCE.md](docs/REFERENCE.md). Example config: [docs/example-config.json](docs/example-config.json).

# Rule coverage (6 pillars)

- **Operational Excellence**: CloudTrail (OPS-001), VPC Flow Logs (OPS-002); CF: CloudTrail log validation (CF-CT-001)
- **Security**: IAM, S3, KMS (SEC-001–SEC-007); CF: S3, RDS, KMS (CF-S3-*, CF-RDS-*, CF-KMS-001)
- **Reliability**: RDS Multi-AZ/backup, Lambda DLQ; CF: RDS, S3 versioning
- **Performance Efficiency**: Graviton/ARM (PERF-001), caching hint (PERF-002)
- **Cost Optimization**: Log retention, autoscaling (COST-001, COST-002)
- **Sustainability**: Spot (SUST-001), right-sizing (SUST-002)

---

# Design Philosophy

- Local-first
- High signal findings
- Agentic reasoning layered on deterministic checks
- Production-architect oriented, not toy-AI


