# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- LICENSE file (MIT).
- `py.typed` marker for PEP 561 typed package.
- Structured logging in agent (v1, v2), tools (LLM), with DEBUG/INFO/WARNING for rule failures, synth fallback, RAG load, and LLM fallbacks.
- CHANGELOG.md and CONTRIBUTING.md.
- Mypy configuration in pyproject.toml and CI type-check step.

### Fixed

- V2 observability pillar now receives findings from rules with category "Operational Excellence" (OPS-001, OPS-002) via a pillar-to-category mapping.

### Changed

- Bare `except Exception` replaced with logged exceptions (debug or warning) in rule loops, CDK synth, CF rules, RAG, and LLM client.

## [0.1.0] - 2025-02-15

### Added

- Initial release: V1 (rules + LLM polish) and V2 (LangGraph multi-agent + CDK synth).
- Static CDK rules across six Well-Architected pillars.
- CloudFormation template rules (S3, RDS, ALB, CloudTrail, KMS).
- Optional RAG (keyword-based) for V2 merge.
- CLI: `aws-arch-agent analyze` with config file and fail-on severity.
- GitHub Actions workflow for tests, ruff, mypy, and analyze.
