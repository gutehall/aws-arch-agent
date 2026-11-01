# Reference

The agent covers all six AWS Well-Architected pillars. Static and CloudFormation rules are grouped by pillar; in V2 mode each pillar has a dedicated reviewer node.

## CLI: `aws-arch-agent`

| Option | Default | Description |
|--------|---------|-------------|
| `--repo`, `-r` | — | Path to repo (required unless `--templates` is set; then repo defaults to templates path) |
| `--out`, `-o` | `report.md` | Output report path |
| `--mode` | `v1` | `v1` (rules + LLM) or `v2` (multi-agent + synth) |
| `--max-files` | `400` | Cap on files walked. Rules search only these files |
| `--config` | (auto-detect) | Path to config file |
| `--format`, `-f` | `markdown` | `markdown`, `json`, or `sarif` |
| `--fail-on` | `none` | Exit 1 if any finding at or above: `high`, `medium`, `low`, `none` |
| `--no-llm` | `false` | Skip LLM polish / agent reasoning |
| `--llm-mode` | `full` | V2 only: `full` (six pillar calls) or `compact` (single LLM call) |
| `--templates` | — | Path to CloudFormation templates (dir or file); V2 only, skips cdk synth |
| `--no-synth` | `false` | Do not run cdk synth; V2 only (static only or with `--templates`) |
| `--rag` | — | Path to RAG doc (V2 only) |
| `--suggestions` | — | Write findings JSON to this path |
| `--baseline` | `.aws-arch-agent-baseline.json` | Path to baseline suppressions file |
| `--enforce-baseline` | `false` | Only fail on findings not in baseline |
| `--update-baseline` | `false` | Add current findings to baseline file |

## Config file (JSON or YAML)

See [CONFIG.md](CONFIG.md) and [example-config.json](example-config.json).

Keys: `format`, `fail_on`, `no_llm`, `llm_mode`, `out`, `severity_threshold`, `templates`, `no_synth`, `rules.include`, `rules.exclude`, `rag.path`.

## GitHub Action

Use the composite action from this repository:

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

## JSON report schema

See [report-schema.json](report-schema.json) for the machine-readable report format.

## Rules

Static and CloudFormation rule IDs, titles, and pillar groups are in [CF_RULES.md](CF_RULES.md). That is the full list. This page does not keep a second copy.
