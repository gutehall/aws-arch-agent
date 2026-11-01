# Version 2 – LangGraph / Multi-agent

V2 uses a LangGraph StateGraph:

- **collect**: walks the repo up to `--max-files`, runs the static rules on those files, and loads RAG once when `--rag` or `rag.path` is set.
- **synth**: runs `npx cdk synth` and then the CloudFormation rules on `cdk.out/*.template.json`. `--templates` skips synth and reads the JSON or YAML templates you pass. `--no-synth` stays on the static rules.
- **Six pillar reviewers** in parallel: Operational Excellence (observability), Security, Reliability, Performance Efficiency, Cost Optimization, Sustainability. Each sees the static findings, the synth summary, and up to three RAG chunks for that pillar.
- **merge**: one review across the six pillars. It uses the same RAG instance and a broader query.
- **report**: writes the final report.

## RAG

RAG is optional. With no path, the prompts have no reference block.

Collect builds one instance. Pillars and merge reuse it. They do not reload the file or re-embed the chunks.

The default is keyword overlap. Set `rag.use_embeddings` and `rag.embedding_provider` for vectors:

- `sentence-transformers` (install with `pip install -e ".[rag]"`). Chunk vectors stay on the instance.
- `openai` (`OPENAI_API_KEY`). Chunk vectors are cached the same way. Each retrieve embeds only the query.

A failed load or retrieve is a warning. The scan continues. The config examples point at [waf-snippets.md](waf-snippets.md).

## CloudFormation rules

Template rules run after a successful synth, or on `--templates`. A skipped or failed synth keeps the static findings.

When a template finding covers the same control, the static finding is dropped:

| Template finding | Static finding dropped |
|------------------|------------------------|
| CF-S3-001 | SEC-005 |
| CF-S3-002 | SEC-006 |
| CF-VPC-001 | SEC-022 |
| CF-FL-001 | OPS-002 |

S3 encryption is a finding only when the template sets the algorithm to none, disabled, or unencrypted. Omitting encryption is the SSE-S3 default, not a finding.

Rule IDs are in [CF_RULES.md](CF_RULES.md).

## Prerequisites for synth

- **TypeScript CDK**: Node and CDK dependencies installed (`npm i` / `pnpm i` / `yarn`). The agent runs `npx cdk synth` in the repo.
- **Python CDK**: the same CLI. The app command comes from `cdk.json`, or from `app.py` / `main.py` / `cdk_app.py` as `--app "python app.py"`.
- A timeout or a missing `npx` is a failed synth. Analysis continues with the static findings.
