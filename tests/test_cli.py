"""Tests for CLI entrypoint and analyze command."""
import json
from pathlib import Path

from typer.testing import CliRunner

from aws_arch_agent.cli import app

runner = CliRunner()


def _make_repo(root: Path, stack_content: str = 'new s3.Bucket(this, "B");') -> None:
    (root / "package.json").write_text("{}", encoding="utf-8")
    (root / "lib").mkdir(exist_ok=True)
    (root / "lib" / "stack.ts").write_text(stack_content, encoding="utf-8")


def test_analyze_creates_report(tmp_path: Path) -> None:
    """analyze writes report to default or --out path."""
    _make_repo(tmp_path)
    out_file = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["--repo", str(tmp_path), "--no-llm", "--out", str(out_file)],
    )
    assert result.exit_code == 0, result.output or result.stderr
    assert out_file.exists()
    assert "AWS Architecture Review Report" in out_file.read_text()


def test_analyze_json_format(tmp_path: Path) -> None:
    """analyze --format json produces valid JSON with context and findings."""
    _make_repo(tmp_path, "export class Stack {};")
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["--repo", str(tmp_path), "--no-llm", "--format", "json", "--out", str(out_file)],
    )
    assert result.exit_code == 0, result.output or result.stderr
    data = json.loads(out_file.read_text())
    assert "context" in data
    assert "findings" in data
    assert "repo_path" in data["context"]


def test_analyze_fail_on_high_exit_code(tmp_path: Path) -> None:
    """analyze --fail-on high exits 1 when high-severity finding exists."""
    # Use content that triggers SEC-001 (IAM wildcard action) so we get a High finding
    _make_repo(
        tmp_path,
        'const policy = { Action: "*", Resource: "arn:aws:s3:::foo" };\nnew s3.Bucket(this, "B");',
    )
    out_file = tmp_path / "r.md"
    result = runner.invoke(
        app,
        ["--repo", str(tmp_path), "--no-llm", "--fail-on", "high", "--out", str(out_file)],
    )
    assert result.exit_code == 1, result.output or result.stderr


def test_analyze_nonexistent_repo() -> None:
    """analyze with nonexistent path raises BadParameter."""
    result = runner.invoke(app, ["--repo", "/nonexistent/path/xyz"])
    assert result.exit_code != 0


def test_analyze_requires_repo_or_templates() -> None:
    """analyze without --repo and without --templates fails."""
    result = runner.invoke(app, ["--no-llm"])
    assert result.exit_code != 0
    assert "required" in (result.output or result.stderr).lower()


def test_analyze_templates_only_no_repo(tmp_path: Path) -> None:
    """analyze with --templates and no --repo uses templates path as repo (CF-only)."""
    (tmp_path / "stack.yaml").write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    out_file = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["--templates", str(tmp_path), "--no-synth", "--mode", "v2", "--no-llm", "--out", str(out_file)],
    )
    assert result.exit_code == 0, result.output or result.stderr
    assert out_file.exists()
    assert "CF-S3-001" in out_file.read_text() or "Architecture Review" in out_file.read_text()
