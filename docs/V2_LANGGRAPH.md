# Version 2 – LangGraph / Multi-agent

V2 uses a LangGraph StateGraph. Synth is the CDK path. Raw CloudFormation and root-module Terraform are scanned by V1 (see `--iac` in [REFERENCE.md](REFERENCE.md)). For raw CloudFormation in V2, pass `--templates`. V2 has no Terraform path. `--iac terraform` exits 1, and `--iac cloudformation` without `--templates` (flag or config) exits 1. When `--iac auto` detects CloudFormation, Terraform, or both and no `--templates` is set, the console prints a note that V2 will not read those files; the scan runs the CDK path and the exit code does not change.

- **collect**: walks the repo up to `--max-files`, resolves `--iac` (from the CLI, an explicit source with no matching files exits 1), runs the CDK static rules on those files, and loads RAG once when `--rag` or `rag.path` is set.
- **synth**: runs `npx cdk synth` and then the CloudFormation rules on `cdk.out/*.template.json`. `--templates` skips synth and reads the JSON or YAML templates you pass. `--no-synth` stays on the static rules.
- **Six pillar reviewers** in parallel: Operational Excellence (observability), Security, Reliability, Performance Efficiency, Cost Optimization, Sustainability. With the LLM on, each judges its pillar's findings, with up to three RAG chunks for that pillar.
- **merge**: joins the six pillars' notes. With the LLM on it makes no call, except that `--llm-mode compact` judges one batch here with a broader RAG query.
- **hypotheses**: with the LLM on, one call that may name catalog rules the scanner missed in files with no finding. It also gets the synth summary.
- **report**: writes the final report.

## Verdicts and hypotheses

A verdict labels a finding and does not change the exit code. A hypothesis cites a catalog rule id and is unverified. It is not a finding, so it never reaches fail-on, the baseline, or SARIF. The rules for both are in [LLM review](REFERENCE.md#llm-review).

Any pillar batch that does not answer means no labels at all. The hypothesis call is apart from that: it runs only when the verdict calls did not fail, and its own failure leaves the labels alone.

## RAG

RAG is optional. With no path, the prompts have no reference block.

Collect builds one instance. Pillars and merge reuse it. They do not reload the file or re-embed the chunks.

The default is keyword overlap. Set `rag.use_embeddings` and `rag.embedding_provider` to `sentence-transformers` for vectors (install with `pip install -e ".[rag]"`). It runs locally. Chunk vectors stay on the instance, and each retrieve embeds only the query.

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
