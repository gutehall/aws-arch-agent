# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Raw CloudFormation support:** V2 can run without CDK or Node.js by pointing at a directory or file of CloudFormation templates. Use `--templates <path>` with `--mode v2`; template discovery supports `*.template.json`, `*.yaml`, and `*.yml`.
- **YAML templates:** CloudFormation templates in YAML are now supported (via PyYAML). Use `load_template()` and `list_templates_from_path()` for JSON or YAML.
- **`--no-synth`:** V2 can skip `cdk synth` entirely. Use with `--templates` to run CF rules on provided templates, or alone for static (code) analysis only. No Node.js required in either case.
- **`--templates`:** Path to CloudFormation templates (file or directory). When set, V2 skips synth and runs template rules on discovered files. Config key: `templates`.
- **Config:** `templates` and `no_synth` in config file (see CONFIG.md). CLI flags override config.

### Changed

- **CF rules refactor:** `run_cf_rules(cdk_out)` now delegates to `run_cf_rules_from_paths()`. New `run_cf_rules_from_paths(template_paths)` and `_run_cf_rules_on_template(path, doc)` for reuse with arbitrary template paths.
- **V2 node_synth:** If `templates_path` is set, synth is skipped and CF rules run on the given path. If `skip_synth` is set, synth is skipped (static only). Report shows "Templates: provided (no synth)" or "CDK synth: skipped" accordingly.
- **Dependencies:** PyYAML added as a core dependency for YAML CloudFormation template support.

## [0.1.0] - 2025-02-15

### Added

- Initial release: V1 (rules + LLM polish) and V2 (LangGraph multi-agent + CDK synth).
- Static CDK rules across six Well-Architected pillars.
- CloudFormation template rules (S3, RDS, ALB, CloudTrail, KMS).
- Optional RAG (keyword-based) for V2 merge.
- CLI: `aws-arch-agent analyze` with config file and fail-on severity.
- GitHub Actions workflow for tests, ruff, mypy, and analyze.
- LICENSE file (MIT).
- `py.typed` marker for PEP 561 typed package.
- Structured logging in agent (v1, v2), tools (LLM), with DEBUG/INFO/WARNING for rule failures, synth fallback, RAG load, and LLM fallbacks.
- CHANGELOG.md and CONTRIBUTING.md.
- Mypy configuration in pyproject.toml and CI type-check step.
- PyPI classifiers and keywords in pyproject.toml.
- SECURITY.md for vulnerability reporting.
- CODE_OF_CONDUCT.md (Contributor Covenant 2.1).

### Fixed

- V2 observability pillar now receives findings from rules with category "Operational Excellence" (OPS-001, OPS-002) via a pillar-to-category mapping.

### Changed

- Bare `except Exception` replaced with logged exceptions (debug or warning) in rule loops, CDK synth, CF rules, RAG, and LLM client.
