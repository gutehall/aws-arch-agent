# Contributing to AWS Arch Agent

Thanks for your interest in contributing. This document covers local setup, running tests and linting, and PR expectations.

## Development setup

1. **Clone and create a virtual environment**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # or .venv\Scripts\activate on Windows
   pip install -U pip
   pip install -e ".[dev]"
   ```

2. **Optional: cloud LLM providers**

   ```bash
   pip install -e ".[dev,cloud]"
   ```

   Then set `LLM_PROVIDER`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY` as needed.

3. **External tools**

   - [ripgrep](https://github.com/BurntSushi/ripgrep) (`brew install ripgrep` on macOS).
   - For V2 CDK synth: Node.js and a CDK project with dependencies installed.

## Running tests and linting

- **Tests:** `pytest tests/ -v` (includes coverage gate at 70%)
- **Lint (ruff):** `ruff check src tests`
- **Type check (mypy):** `mypy src`

CI runs all of these on push/PR to `main` or `master`, plus V1/V2 dogfood scans.

### Optional pre-commit hook

A [`.pre-commit-config.yaml`](.pre-commit-config.yaml) is included. Install and enable:

```bash
pip install pre-commit
pre-commit install
```

Or run manually:

```bash
aws-arch-agent --repo . --no-llm --fail-on high --enforce-baseline
```

## Pull requests

- Keep changes focused; prefer smaller PRs.
- Ensure tests pass and `ruff check src tests` and `mypy src` succeed.
- Update docs (README, REFERENCE, CONFIG, or this file) if you change behavior or CLI.
- For new rules or pillars, add tests under `tests/` and consider documenting in `docs/`.

## Code style

- Line length: 100 (ruff).
- Python 3.11+.
- Use the existing patterns: rule classes in `rules/`, tools in `tools/`, agents in `agent/`.

## Questions

Open an issue for bugs, feature ideas, or documentation improvements.
