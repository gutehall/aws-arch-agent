# Config file

Optional config file in the repo root or current directory:

- `.aws-arch-agent.json` / `aws-arch-agent.json`
- `.aws-arch-agent.yaml` / `aws-arch-agent.yaml` (YAML also supported)

Copy [example-config.json](example-config.json) to get started.

Example (JSON):

```json
{
  "format": "markdown",
  "fail_on": "none",
  "no_llm": false,
  "out": "report.md",
  "severity_threshold": "Medium",
  "llm_mode": "full",
  "templates": null,
  "no_synth": false,
  "rules": {
    "include": null,
    "exclude": ["BP-001"]
  },
  "rag": {
    "path": "./docs/waf-snippets.md",
    "use_embeddings": false,
    "embedding_provider": "sentence-transformers",
    "embedding_model": null
  }
}
```

Example (YAML):

```yaml
format: json
fail_on: high
no_llm: true
out: report.json
llm_mode: compact
rules:
  exclude:
    - BP-001
```

- **format**: `markdown` | `json` | `sarif`
- **fail_on**: `high` | `medium` | `low` | `none` — exit code 1 if any finding at or above this severity
- **no_llm**: skip LLM polish (V1) or agent reasoning (V2)
- **llm_mode**: `full` (six pillar LLM calls in V2) or `compact` (single merged LLM call)
- **out**: output file path
- **severity_threshold**: only report findings at or above this severity
- **templates**: path to CloudFormation templates (dir or file); V2 only. When set, cdk synth is skipped and CF rules run on these templates (JSON or YAML).
- **no_synth**: if `true`, do not run cdk synth (V2 only). Use with **templates** for raw CF, or alone for static analysis only.
- **rules.include**: list of rule IDs to run (e.g. `["SEC-001", "SEC-002"]`); if set, only these run
- **rules.exclude**: list of rule IDs to skip
- **rag.path**: path to a markdown doc for RAG context (V2 only). Pillar and merge prompts include retrieved snippets when set.
- **rag.use_embeddings**: if `true`, use embedding-based retrieval (V2 only). Requires **rag.embedding_provider**.
- **rag.embedding_provider**: `"sentence-transformers"` (local; install with `pip install -e ".[rag]"`) or `"openai"` (uses `OPENAI_API_KEY`).
- **rag.embedding_model**: optional model name (e.g. `"all-MiniLM-L6-v2"` for sentence-transformers, `"text-embedding-3-small"` for OpenAI). Defaults apply if omitted.

## Baseline / suppressions

For gradual CI adoption, use a baseline file (default: `.aws-arch-agent-baseline.json`):

```bash
# Record current findings as accepted
aws-arch-agent --repo . --no-llm --update-baseline

# Fail only on new findings
aws-arch-agent --repo . --no-llm --fail-on high --enforce-baseline
```

CLI flags override config file values.
