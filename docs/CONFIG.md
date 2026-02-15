# Config file

Optional config file: `.aws-arch-agent.json` or `aws-arch-agent.json` in the repo root or current directory. Copy [example-config.json](example-config.json) to get started.

Example:

```json
{
  "format": "markdown",
  "fail_on": "none",
  "no_llm": false,
  "out": "report.md",
  "severity_threshold": "Medium",
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

- **format**: `markdown` | `json`
- **fail_on**: `high` | `medium` | `low` | `none` — exit code 1 if any finding at or above this severity
- **no_llm**: skip LLM polish (V1) or agent reasoning (V2)
- **out**: output file path
- **severity_threshold**: only report findings at or above this severity
- **rules.include**: list of rule IDs to run (e.g. `["SEC-001", "SEC-002"]`); if set, only these run
- **rules.exclude**: list of rule IDs to skip
- **rag.path**: path to a markdown doc for RAG context (V2 only)
- **rag.use_embeddings**: if `true`, use embedding-based retrieval (V2 only). Requires **rag.embedding_provider**.
- **rag.embedding_provider**: `"sentence-transformers"` (local; install with `pip install -e ".[rag]"`) or `"openai"` (uses `OPENAI_API_KEY`).
- **rag.embedding_model**: optional model name (e.g. `"all-MiniLM-L6-v2"` for sentence-transformers, `"text-embedding-3-small"` for OpenAI). Defaults apply if omitted.

CLI flags override config file values.
