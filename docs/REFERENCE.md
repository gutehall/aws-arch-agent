# Reference

The agent covers all six AWS Well-Architected pillars. Static and CloudFormation rules are grouped by pillar; in V2 mode each pillar has a dedicated reviewer node.

## CLI: `aws-arch-agent`

| Option | Default | Description |
|--------|---------|-------------|
| `--repo`, `-r` | — | Path to repo (required unless `--templates` is set; then repo defaults to templates path) |
| `--out`, `-o` | `report.md` | Output report path |
| `--mode` | `v1` | `v1` (rules + LLM) or `v2` (multi-agent + synth) |
| `--max-files` | `400` | Max files to scan |
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

## Rule IDs (static, 6 pillars)

| ID | Pillar | Title |
|----|--------|--------|
| OPS-001 | Operational Excellence | CloudTrail may be missing |
| OPS-002 | Operational Excellence | VPC Flow Logs may be missing |
| OPS-003 | Operational Excellence | X-Ray / distributed tracing may be missing |
| SEC-001 | Security | IAM wildcard actions |
| SEC-002 | Security | IAM wildcard resources |
| SEC-003 | Security | SSH open to 0.0.0.0/0 |
| SEC-004 | Security | DB ports open to 0.0.0.0/0 |
| SEC-005 | Security | S3 Block Public Access missing |
| SEC-006 | Security | S3 encryption missing |
| SEC-007 | Security | KMS key policy wildcard principal |
| REL-001 | Reliability | RDS Multi-AZ missing |
| REL-002 | Reliability | RDS backup retention missing |
| REL-003 | Reliability | Lambda DLQ missing |
| PERF-001 | Performance Efficiency | Graviton/ARM not used |
| PERF-002 | Performance Efficiency | No caching layer detected |
| COST-001 | Cost Optimization | Log retention infinite |
| COST-002 | Cost Optimization | Autoscaling hint missing |
| SUST-001 | Sustainability | Spot not considered |
| SUST-002 | Sustainability | Right-sizing recommended |
| BP-001 | Best Practices | Standard tags missing |

## CF template rules (V2, when synth succeeds or `--templates` used)

CF-S3-001–004, CF-RDS-001–005, CF-ALB-001, CF-CT-001–003, CF-KMS-001, CF-VPC-001, CF-FL-001, CF-LAM-001–002, CF-PERF-001–004, CF-DDB-001–002, CF-SG-001, CF-CW-001–002, CF-COST-002, CF-SQS-001–002, CF-APIGW-001–002, CF-SUST-001–003, CF-EKS-001 — see [CF_RULES.md](CF_RULES.md).
