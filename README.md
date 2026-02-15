# AWS Arch Agent

An **agentic AWS CDK architecture reviewer** that runs locally (Apple Silicon friendly) and scales into a multi-agent workflow using LangGraph.

- **Static CDK heuristics** — ripgrep-based rules across six Well-Architected pillars
- **CloudFormation checks** — template-level rules after `cdk synth` (S3, RDS, Lambda, DynamoDB, Security Groups, CloudWatch, SQS, API Gateway, EKS, and more)
- **LLM polish** — local Ollama by default; optional OpenAI or Anthropic
- **V2 multi-agent** — LangGraph pipeline with per-pillar reviewers and optional RAG (keyword or embedding-based)

Supports **TypeScript CDK** and **Python CDK**. MIT licensed.

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

# Architecture

- **rules/** — Static CDK rules (security, reliability, cost, etc.) and [cf_template.py](src/aws_arch_agent/rules/cf_template.py) for CloudFormation checks
- **tools/** — File scan, ripgrep, LLM client, CDK synth
- **agent/v1.py** — V1 pipeline (rules + optional LLM polish)
- **agent/v2_graph.py** — V2 LangGraph pipeline (collect → synth → 6 pillars → merge → report)
- **report/** — Markdown and JSON output
- **rag/** — Keyword and optional embedding RAG for V2 merge

---

# Requirements

- **Python 3.11+**
- **Node.js** (for V2 `cdk synth`)
- **ripgrep** (`brew install ripgrep`)
- CDK project with deps installed (`npm i` / `pnpm i` / `yarn`)

Optional:

- **Ollama** — recommended for local LLM
- **OpenAI / Anthropic** — `pip install -e ".[cloud]"` and set API keys
- **sentence-transformers** — `pip install -e ".[rag]"` for embedding-based RAG

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

## 3. Analyze a CDK project

Use `--repo` / `-r` for the repo path:

### V1 (fast, static only)

```bash
aws-arch-agent --repo /path/to/cdk-project --no-llm
```

### V2 (multi-agent + CDK synth)

```bash
aws-arch-agent --repo /path/to/cdk-project --mode v2
```

Report is written to `report.md` by default.

### Options

| Option | Description |
|--------|-------------|
| `--repo`, `-r` | Path to CDK repository (required) |
| `--out`, `-o` | Output path (default: `report.md`) |
| `--mode` | `v1` or `v2` (default: `v1`) |
| `--format`, `-f` | `markdown` or `json` (for CI) |
| `--fail-on` | Exit 1 if any finding at or above `high`, `medium`, or `low` |
| `--no-llm` | Skip LLM polish / agent reasoning (rules-only) |
| `--rag` | Path to RAG doc (e.g. Well-Architected); V2 only |
| `--suggestions` | Write findings JSON to this path |
| `--config` | Config file path (default: `.aws-arch-agent.json` in repo or cwd) |

Config file can set all of the above plus `rules.include`, `rules.exclude`, `severity_threshold`, and for V2 RAG: `rag.use_embeddings`, `rag.embedding_provider`, `rag.embedding_model`. See [docs/CONFIG.md](docs/CONFIG.md).

---

# RAG (V2)

V2 can inject context from a markdown doc (e.g. Well-Architected snippets) into the merge step.

- **Keyword (default)** — no extra deps; `rag.path` in config or `--rag path/to/doc.md`.
- **Embeddings** — better relevance; set in config: `rag.use_embeddings: true`, `rag.embedding_provider: "sentence-transformers"` or `"openai"`. For local embeddings install with `pip install -e ".[rag]"` (sentence-transformers). For OpenAI, set `OPENAI_API_KEY` and use `embedding_provider: "openai"`.

---

# LLM configuration

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

# Rule coverage

**Static (CDK-level)** — Operational Excellence (OPS-001, OPS-002), Security (SEC-001–SEC-007), Reliability (RDS, Lambda DLQ), Performance (PERF-001, PERF-002), Cost (COST-001, COST-002), Sustainability (SUST-001, SUST-002), Best Practices (BP-001). See [docs/REFERENCE.md](docs/REFERENCE.md).

**Template (CloudFormation, V2)** — S3, RDS, ALB, CloudTrail, KMS, VPC/Flow Logs, Lambda, DynamoDB, Security Groups, CloudWatch Logs, SQS, API Gateway, EKS, and more. Performance Efficiency and Sustainability include template-based rules (CF-PERF-001, CF-SUST-001, CF-SUST-002) when `cdk synth` succeeds. Full list: [docs/CF_RULES.md](docs/CF_RULES.md).

---

# Day-to-day use

- **Quick check** (rules only): `aws-arch-agent --repo . --no-llm`
- **Full review** (V2 + synth): `aws-arch-agent --repo . --mode v2`
- **CI**: `aws-arch-agent --repo . --format json --fail-on high --out report.json`
- **With RAG**: `aws-arch-agent --repo . --mode v2 --rag ./docs/waf.md`
- **Suggestions file**: `aws-arch-agent --repo . --suggestions suggestions.json`

# CI

[.github/workflows/aws-arch-agent.yml](.github/workflows/aws-arch-agent.yml) runs tests, ruff, mypy, and the agent (rules-only). Analyze steps use `continue-on-error: true` by default. To fail the build on high-severity findings, set `continue-on-error: false` on the step that runs `--fail-on high`.

# Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Install: `pip install -e ".[dev]"`. Then: `pytest tests/ -v`, `ruff check src tests`, `mypy src`. Optional: `.[rag]` for embedding RAG, `.[cloud]` for OpenAI/Anthropic.

# Reference

- [docs/REFERENCE.md](docs/REFERENCE.md) — CLI and rule IDs
- [docs/CONFIG.md](docs/CONFIG.md) — config file options
- [docs/example-config.json](docs/example-config.json) — example config

# Design philosophy

- Local-first
- High signal findings
- Agentic reasoning layered on deterministic checks
- Production-architect oriented, not toy-AI


