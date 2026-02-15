"""Tests for CLI entrypoint and analyze command."""
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent.cli import app

runner = CliRunner()


def test_analyze_creates_report(tmp_path: Path) -> None:
    """analyze writes report to default or --out path."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    out_file = tmp_path / "report.md"
    result = runner.invoke(app, ["analyze", str(tmp_path), "--no-llm", "-o", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()
    assert "AWS Architecture Review Report" in out_file.read_text()


def test_analyze_json_format(tmp_path: Path) -> None:
    """analyze --format json produces valid JSON with context and findings."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text("export class Stack {};", encoding="utf-8")
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app, ["analyze", str(tmp_path), "--no-llm", "--format", "json", "-o", str(out_file)]
    )
    assert result.exit_code == 0
    import json
    data = json.loads(out_file.read_text())
    assert "context" in data
    assert "findings" in data
    assert "repo_path" in data["context"]


def test_analyze_fail_on_high_exit_code(tmp_path: Path) -> None:
    """analyze --fail-on high exits 1 when high-severity finding exists."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    result = runner.invoke(
        app, ["analyze", str(tmp_path), "--no-llm", "--fail-on", "high", "-o", str(tmp_path / "r.md")]
    )
    assert result.exit_code == 1


def test_analyze_nonexistent_repo() -> None:
    """analyze with nonexistent path raises BadParameter."""
    result = runner.invoke(app, ["analyze", "/nonexistent/path/xyz"])
    assert result.exit_code != 0
