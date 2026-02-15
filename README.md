# AWS Arch Agent

An **agentic AWS CDK architecture reviewer** that runs locally (Apple Silicon friendly) and scales via LangGraph.

- **Static CDK heuristics** — ripgrep rules across six Well-Architected pillars
- **CloudFormation checks** — template rules after `cdk synth` (S3, RDS, Lambda, DynamoDB, SG, CloudWatch, SQS, API Gateway, EKS, etc.)
- **LLM polish** — Ollama by default; optional OpenAI/Anthropic
- **V2 multi-agent** — LangGraph pipeline with per-pillar reviewers and optional RAG

Supports **TypeScript** and **Python CDK**. MIT licensed.

## How It Works

- **V1** — Scan repo → heuristic rules → LLM polish → Markdown report. Fast, no `cdk synth`.
- **V2** — Repo context → `cdk synth` → parse CloudFormation → template rules → 6-pillar agents (Ops, Security, Reliability, Performance, Cost, Sustainability) → merge → report. Falls back to static-only if synth fails.

## Requirements

- Python 3.11+, Node.js (for V2), **ripgrep** (`brew install ripgrep`), CDK deps installed
- Optional: Ollama (local LLM); `pip install -e ".[cloud]"` for OpenAI/Anthropic; `.[rag]` for embedding RAG

## Getting Started

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -U pip && pip install -e .
# Optional: ollama serve && export OLLAMA_MODEL=llama3:8b
```

**V1 (fast):** `aws-arch-agent --repo /path/to/cdk-project --no-llm`  
**V2 (multi-agent + synth):** `aws-arch-agent --repo /path/to/cdk-project --mode v2`

Report → `report.md` by default.

| Option | Description |
|--------|-------------|
| `--repo`, `-r` | CDK repo path (required) |
| `--out`, `-o` | Output path (default: `report.md`) |
| `--mode` | `v1` or `v2` |
| `--format`, `-f` | `markdown` or `json` |
| `--fail-on` | Exit 1 if finding ≥ `high` / `medium` / `low` |
| `--no-llm` | Rules only |
| `--rag` | RAG doc path (V2) |
| `--config` | Config file (see [docs/CONFIG.md](docs/CONFIG.md)) |

## Quick usage

- Rules only: `aws-arch-agent --repo . --no-llm`
- Full V2: `aws-arch-agent --repo . --mode v2`
- CI: `aws-arch-agent --repo . --format json --fail-on high --out report.json`
- With RAG: `aws-arch-agent --repo . --mode v2 --rag ./docs/waf.md`

## LLM & RAG

**LLM:** Default Ollama. Set `LLM_PROVIDER=ollama` and `OLLAMA_MODEL=llama3:8b`. For cloud: `LLM_PROVIDER=openai` + `OPENAI_API_KEY`, or `anthropic` + `ANTHROPIC_API_KEY`.

**RAG (V2):** Keyword (default) via `--rag path/to/doc.md` or config. Embeddings: config `rag.use_embeddings`, `rag.embedding_provider`; install `pip install -e ".[rag]"` for sentence-transformers.

## Reference

- [docs/REFERENCE.md](docs/REFERENCE.md) — CLI and rule IDs
- [docs/CONFIG.md](docs/CONFIG.md) — config options
- [docs/CF_RULES.md](docs/CF_RULES.md) — CloudFormation rules
- [.github/workflows/aws-arch-agent.yml](.github/workflows/aws-arch-agent.yml) — CI (tests, ruff, mypy, agent). Use `--fail-on high` and `continue-on-error: false` to fail on high findings.
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup: `pip install -e ".[dev]"`, then `pytest`, `ruff`, `mypy`.
