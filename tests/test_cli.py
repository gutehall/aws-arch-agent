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
    assert "CF-S3-001" in out_file.read_text()


def _high_finding_repo(root: Path) -> None:
    _make_repo(
        root,
        'const policy = { Action: "*", Resource: "arn:aws:s3:::foo" };\nnew s3.Bucket(this, "B");',
    )


def test_config_file_wins_when_flags_omitted(tmp_path: Path, monkeypatch) -> None:
    """Repo config fail_on and no_llm apply when those flags are not passed."""
    _high_finding_repo(tmp_path)
    out_file = tmp_path / "from-config.json"
    (tmp_path / ".aws-arch-agent.json").write_text(
        json.dumps(
            {
                "fail_on": "high",
                "no_llm": True,
                "format": "json",
                "out": str(out_file),
            }
        ),
        encoding="utf-8",
    )

    def boom(*_args, **_kwargs):
        raise AssertionError("LLM should stay off when config no_llm is true")

    monkeypatch.setattr("aws_arch_agent.tools.llm.LLMClient.polish", boom)
    result = runner.invoke(app, ["--repo", str(tmp_path)])
    assert result.exit_code == 1, result.output or result.stderr
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "findings" in data


def test_explicit_flag_overrides_config_file(tmp_path: Path) -> None:
    _high_finding_repo(tmp_path)
    out_file = tmp_path / "report.md"
    (tmp_path / ".aws-arch-agent.json").write_text(
        json.dumps({"fail_on": "high", "no_llm": True, "format": "json", "out": str(tmp_path / "ignored.json")}),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "--repo",
            str(tmp_path),
            "--fail-on",
            "none",
            "--format",
            "markdown",
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code == 0, result.output or result.stderr
    text = out_file.read_text(encoding="utf-8")
    assert text.lstrip().startswith("#")
    assert not (tmp_path / "ignored.json").exists()


def test_string_rules_exclude_fails_run(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    out_file = tmp_path / "report.md"
    (tmp_path / ".aws-arch-agent.json").write_text(
        '{"rules": {"exclude": "BP-001"}}',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["--repo", str(tmp_path), "--no-llm", "--out", str(out_file)])
    assert result.exit_code != 0
    assert not out_file.exists()


def test_unknown_mode_format_and_fail_on_write_no_report(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    for args in (
        ["--mode", "v3"],
        ["--format", "html"],
        ["--fail-on", "critical"],
    ):
        out_file = tmp_path / f"report-{args[-1]}.md"
        result = runner.invoke(
            app,
            ["--repo", str(tmp_path), "--no-llm", "--out", str(out_file), *args],
        )
        assert result.exit_code != 0, args
        assert not out_file.exists()


def test_mode_v1_still_runs(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    out_file = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["--repo", str(tmp_path), "--mode", "v1", "--no-llm", "--out", str(out_file)],
    )
    assert result.exit_code == 0, result.output or result.stderr
    assert "AWS Architecture Review Report" in out_file.read_text(encoding="utf-8")


def test_truncated_config_exits_nonzero(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    cfg = tmp_path / "broken.json"
    cfg.write_text('{"fail_on":', encoding="utf-8")
    out_file = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["--repo", str(tmp_path), "--config", str(cfg), "--no-llm", "--out", str(out_file)],
    )
    assert result.exit_code != 0
    assert not out_file.exists()


def test_missing_config_path_exits_nonzero(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    out_file = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "--repo",
            str(tmp_path),
            "--config",
            str(tmp_path / "nope.json"),
            "--no-llm",
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code != 0
    assert not out_file.exists()


def test_corrupt_baseline_enforce_does_not_overwrite(tmp_path: Path) -> None:
    _high_finding_repo(tmp_path)
    baseline = tmp_path / ".aws-arch-agent-baseline.json"
    original = "{not json"
    baseline.write_text(original, encoding="utf-8")
    out_file = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "--repo",
            str(tmp_path),
            "--no-llm",
            "--enforce-baseline",
            "--fail-on",
            "high",
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code != 0
    assert baseline.read_text(encoding="utf-8") == original
    assert not out_file.exists()


def test_update_and_enforce_does_not_suppress_new_findings(tmp_path: Path) -> None:
    _high_finding_repo(tmp_path)
    out_file = tmp_path / "report.json"
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"accepted": []}', encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "--repo",
            str(tmp_path),
            "--no-llm",
            "--format",
            "json",
            "--fail-on",
            "high",
            "--baseline",
            str(baseline),
            "--update-baseline",
            "--enforce-baseline",
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code == 1, result.output or result.stderr
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["findings"]
    assert all(item["baselined"] is False for item in data["findings"])
    saved = json.loads(baseline.read_text(encoding="utf-8"))
    assert saved["accepted"]

    second = tmp_path / "report-2.json"
    again = runner.invoke(
        app,
        [
            "--repo",
            str(tmp_path),
            "--no-llm",
            "--format",
            "json",
            "--fail-on",
            "high",
            "--baseline",
            str(baseline),
            "--enforce-baseline",
            "--out",
            str(second),
        ],
    )
    assert again.exit_code == 0, again.output or again.stderr
    marked = json.loads(second.read_text(encoding="utf-8"))
    assert marked["findings"]
    assert all(item["baselined"] is True for item in marked["findings"])
