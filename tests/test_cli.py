"""Tests for CLI entrypoint and analyze command."""
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

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
    assert "AWS Architecture Review Report" in out_file.read_text(encoding="utf-8")


def test_analyze_json_format(tmp_path: Path) -> None:
    """analyze --format json produces valid JSON with context and findings."""
    _make_repo(tmp_path, "export class Stack {};")
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["--repo", str(tmp_path), "--no-llm", "--format", "json", "--out", str(out_file)],
    )
    assert result.exit_code == 0, result.output or result.stderr
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "context" in data
    assert "findings" in data
    assert "repo_path" in data["context"]


def test_analyze_sarif_format(tmp_path: Path) -> None:
    """--format sarif writes SARIF and registers each result rule on the driver."""
    _high_finding_repo(tmp_path)
    out_file = tmp_path / "report.sarif"
    result = runner.invoke(
        app,
        [
            "--repo",
            str(tmp_path),
            "--no-llm",
            "--format",
            "sarif",
            "--fail-on",
            "none",
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code == 0, result.output or result.stderr
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert any(item["ruleId"] == "SEC-001" for item in run["results"])
    assert any(rule["id"] == "SEC-001" for rule in run["tool"]["driver"]["rules"])


_BLOCK_LANGGRAPH = """
import sys
from importlib.abc import MetaPathFinder

class _Block(MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        root = fullname.split(".", 1)[0]
        if root in {"langgraph", "langchain_core"}:
            raise ImportError(fullname)
        return None

sys.meta_path.insert(0, _Block())
"""


def _run_without_langgraph(tmp_path: Path, mode: str) -> subprocess.CompletedProcess[str]:
    repo = Path(__file__).resolve().parents[1]
    out_file = tmp_path / "report.md"
    script = tmp_path / "run_scan.py"
    script.write_text(
        _BLOCK_LANGGRAPH
        + (
            "sys.argv = ['aws-arch-agent', '--repo', sys.argv[1], '--mode', sys.argv[2], "
            "'--no-llm', '--no-synth', '--fail-on', 'none', '--out', sys.argv[3]]\n"
            "from aws_arch_agent.cli import app\n"
            "app()\n"
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo / "src")
    return subprocess.run(
        [sys.executable, str(script), str(tmp_path), mode, str(out_file)],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_v1_scan_does_not_import_langgraph(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    result = _run_without_langgraph(tmp_path, "v1")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "report.md").is_file()


def test_v2_without_langgraph_names_the_extra(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    result = _run_without_langgraph(tmp_path, "v2")
    assert result.returncode != 0
    assert "aws-arch-agent[v2]" in result.stdout + result.stderr


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
    assert "CF-S3-001" in out_file.read_text(encoding="utf-8")


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
    first, _, rest = text.partition("\n")
    assert first == "LLM: skipped (--no-llm)"  # no_llm still comes from the config file
    assert rest.lstrip().startswith("#")
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
        ["--format", "pdf"],
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


def test_cf_baseline_roundtrip_ignores_cwd(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "stack.yaml").write_text(
        "Resources:\n"
        "  BucketA:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties: {}\n"
        "  BucketB:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties: {}\n",
        encoding="utf-8",
    )
    baseline = tmp_path / "baseline.json"
    out_file = tmp_path / "report.md"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    result = runner.invoke(
        app,
        [
            "--templates",
            str(tmp_path),
            "--no-synth",
            "--mode",
            "v2",
            "--no-llm",
            "--update-baseline",
            "--baseline",
            str(baseline),
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code == 0, result.output or result.stderr
    saved = json.loads(baseline.read_text(encoding="utf-8"))
    buckets = [item for item in saved["accepted"] if item["id"] == "CF-S3-001"]
    assert {item["logical_id"] for item in buckets} == {
        "BucketA (AWS::S3::Bucket)",
        "BucketB (AWS::S3::Bucket)",
    }
    assert all(item["file"] == "stack.yaml" for item in buckets)
    assert str(tmp_path) not in baseline.read_text(encoding="utf-8")

    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)
    enforced = tmp_path / "enforced.md"
    again = runner.invoke(
        app,
        [
            "--templates",
            str(tmp_path),
            "--no-synth",
            "--mode",
            "v2",
            "--no-llm",
            "--fail-on",
            "high",
            "--enforce-baseline",
            "--baseline",
            str(baseline),
            "--out",
            str(enforced),
        ],
    )
    assert again.exit_code == 0, again.output or again.stderr


def test_synth_failure_is_json_warning_and_exit_2(tmp_path: Path, monkeypatch) -> None:
    _make_repo(tmp_path)
    monkeypatch.setattr(
        "aws_arch_agent.agent.v2_graph.run_cdk_synth",
        lambda *args, **kwargs: (1, "", "synth blew up"),
    )
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "--repo",
            str(tmp_path),
            "--mode",
            "v2",
            "--no-llm",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code == 2, result.output or result.stderr
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert any("CDK synth exited 1" in warning for warning in data["warnings"])


def test_missing_templates_directory_exits_2(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    out_file = tmp_path / "report.sarif"
    missing = tmp_path / "no-templates"
    result = runner.invoke(
        app,
        [
            "--repo",
            str(tmp_path),
            "--templates",
            str(missing),
            "--mode",
            "v2",
            "--no-llm",
            "--format",
            "sarif",
            "--fail-on",
            "none",
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code == 2, result.output or result.stderr
    text = out_file.read_text(encoding="utf-8")
    assert "Template path does not exist" in text


def test_raising_rule_keeps_other_findings_and_exits_2(tmp_path: Path, monkeypatch) -> None:
    _high_finding_repo(tmp_path)

    def boom(repo_path: Path, language: str = "typescript") -> list:
        raise RuntimeError("rule exploded")

    monkeypatch.setattr(
        "aws_arch_agent.rules.best_practices.CdkContextMissing.run",
        boom,
    )
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "--repo",
            str(tmp_path),
            "--mode",
            "v1",
            "--no-llm",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--out",
            str(out_file),
        ],
    )
    assert result.exit_code == 2, result.output or result.stderr
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert any(item["id"] == "SEC-001" for item in data["findings"])
    assert any("failed" in warning for warning in data["warnings"])


def _cfn_repo(root: Path) -> None:
    (root / "stack.yaml").write_text(
        'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  B:\n    Type: AWS::S3::Bucket\n',
        encoding="utf-8",
    )


def test_v2_rejects_iac_terraform(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")
    for extra in ([], ["--templates", str(tmp_path)]):
        result = runner.invoke(
            app, ["--repo", str(tmp_path), "--mode", "v2", "--no-llm", "--iac", "terraform", *extra]
        )
        assert result.exit_code == 1, result.output
        assert "V1 only" in result.output


def test_v2_rejects_iac_cloudformation_without_templates(tmp_path: Path) -> None:
    _cfn_repo(tmp_path)
    result = runner.invoke(
        app, ["--repo", str(tmp_path), "--mode", "v2", "--no-llm", "--iac", "cloudformation"]
    )
    assert result.exit_code == 1, result.output
    assert "needs --templates" in result.output


def test_v2_iac_cloudformation_with_templates_runs(tmp_path: Path) -> None:
    _cfn_repo(tmp_path)
    out_file = tmp_path / "report.md"
    result = runner.invoke(app, [
        "--repo", str(tmp_path), "--mode", "v2", "--no-llm", "--iac", "cloudformation",
        "--templates", str(tmp_path), "--out", str(out_file),
    ])
    assert result.exit_code == 0, result.output
    assert "CF-S3-001" in out_file.read_text(encoding="utf-8")


def test_v2_iac_cloudformation_with_config_templates_runs(tmp_path: Path) -> None:
    _cfn_repo(tmp_path)
    (tmp_path / ".aws-arch-agent.json").write_text(
        json.dumps({"templates": str(tmp_path)}), encoding="utf-8"
    )
    out_file = tmp_path / "report.md"
    result = runner.invoke(app, [
        "--repo", str(tmp_path), "--mode", "v2", "--no-llm", "--iac", "cloudformation",
        "--out", str(out_file),
    ])
    assert result.exit_code == 0, result.output


def test_v2_auto_non_cdk_prints_a_note_and_keeps_exit_code(tmp_path: Path) -> None:
    _cfn_repo(tmp_path)
    out_file = tmp_path / "report.md"
    result = runner.invoke(app, [
        "--repo", str(tmp_path), "--mode", "v2", "--no-llm", "--no-synth", "--out", str(out_file),
    ])
    assert result.exit_code == 0, result.output
    assert "V2 scans CDK only" in result.output
    assert out_file.exists()


def test_v2_auto_cdk_has_no_note(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    (tmp_path / "cdk.json").write_text('{"app": "npx ts-node bin/app.ts"}', encoding="utf-8")
    result = runner.invoke(app, [
        "--repo", str(tmp_path), "--mode", "v2", "--no-llm", "--no-synth",
        "--out", str(tmp_path / "r.md"),
    ])
    assert result.exit_code == 0, result.output
    assert "V2 scans CDK only" not in result.output


def test_v2_iac_cloudformation_with_templates_outside_repo(tmp_path: Path) -> None:
    repo, cfn = tmp_path / "repo", tmp_path / "cfn"
    repo.mkdir()
    cfn.mkdir()
    (repo / "package.json").write_text("{}", encoding="utf-8")
    _cfn_repo(cfn)
    out_file = tmp_path / "report.md"
    result = runner.invoke(app, [
        "--repo", str(repo), "--mode", "v2", "--no-llm", "--iac", "cloudformation",
        "--templates", str(cfn), "--out", str(out_file),
    ])
    assert result.exit_code == 0, result.output
    assert "CF-S3-001" in out_file.read_text(encoding="utf-8")


def test_analyze_html_format(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    out_file = tmp_path / "report.html"
    result = runner.invoke(
        app, ["--repo", str(tmp_path), "--no-llm", "--format", "html", "--out", str(out_file)]
    )
    assert result.exit_code == 0, result.output
    page = out_file.read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert "SEC-005" in page
    assert "Baseline:" not in page


def test_config_format_html(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    (tmp_path / ".aws-arch-agent.json").write_text(
        json.dumps({"format": "html", "out": str(tmp_path / "review.html")}), encoding="utf-8"
    )
    result = runner.invoke(app, ["--repo", str(tmp_path), "--no-llm"])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "review.html").read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_config_unknown_format_fails(tmp_path: Path) -> None:
    _make_repo(tmp_path)
    (tmp_path / ".aws-arch-agent.json").write_text(json.dumps({"format": "pdf"}), encoding="utf-8")
    out_file = tmp_path / "report.out"
    result = runner.invoke(app, ["--repo", str(tmp_path), "--no-llm", "--out", str(out_file)])
    assert result.exit_code != 0
    assert "format" in result.output
    assert not out_file.exists()


def test_html_marks_baselined_findings(tmp_path: Path) -> None:
    _high_finding_repo(tmp_path)
    baseline = tmp_path / "baseline.json"
    base_args = ["--repo", str(tmp_path), "--no-llm", "--baseline", str(baseline)]
    first = runner.invoke(app, [*base_args, "--update-baseline", "--out", str(tmp_path / "a.md")])
    assert first.exit_code == 0, first.output
    # A new finding after the baseline was written.
    (tmp_path / "lib" / "extra.ts").write_text('new sqs.Queue(this, "Q");', encoding="utf-8")
    out_file = tmp_path / "report.html"
    result = runner.invoke(app, [
        *base_args, "--format", "html", "--enforce-baseline", "--out", str(out_file),
    ])
    assert result.exit_code == 0, result.output
    page = out_file.read_text(encoding="utf-8")
    assert 'data-baseline="accepted"' in page
    assert 'data-baseline="new"' in page
    assert "Accepted findings stay in the report" in page
    assert "## Baseline" not in page  # the markdown appendix is not glued onto the page


def test_cli_html_escapes_scanned_source(tmp_path: Path) -> None:
    _make_repo(tmp_path, 'new s3.Bucket(this, "B"); // </pre><script>alert(1)</script>')
    out_file = tmp_path / "report.html"
    result = runner.invoke(
        app, ["--repo", str(tmp_path), "--no-llm", "--format", "html", "--out", str(out_file)]
    )
    assert result.exit_code == 0, result.output
    page = out_file.read_text(encoding="utf-8")
    assert "SEC-005" in page
    assert "<script>alert" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert page.count("<script>") == 1


def test_cli_html_with_no_findings_writes_a_page(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('variable "x" {}\n', encoding="utf-8")
    # Tests, a git checkout, a CI workflow that lints, scans dependencies, deploys behind a test,
    # smoke-tests the deploy, runs a load test and a FIS experiment, and two environments: the
    # repo-level rules have nothing to say.
    (tmp_path / ".git").mkdir()
    # Notes for SEC 11: security training, a dated pen test and who owns security.
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "security-training.md").write_text("Yearly course.\n", encoding="utf-8")
    (tmp_path / "docs" / "pentest.md").write_text("Run on 2026-03-14.\n", encoding="utf-8")
    (tmp_path / "SECURITY.md").write_text("Owner: @alice\n", encoding="utf-8")
    # Notes for REL 12: a failure playbook, a post-incident template and a game day plan.
    for note in ("playbook.md", "postmortem-template.md", "game-days.md"):
        (tmp_path / "docs" / note).write_text("Notes.\n", encoding="utf-8")
    # Notes and IaC for SEC 10: contacts, an incident plan, security playbooks, a response
    # role, a simulation and a security post-incident template.
    for note in ("security-contacts.md", "incident-response-plan.md", "security-playbook.md",
                 "security-postmortem-template.md"):
        (tmp_path / "docs" / note).write_text("Notes.\n", encoding="utf-8")
    # Notes and IaC for SEC 1: a threat model, a dated security review, a standards subscription
    # and a delegated administrator.
    (tmp_path / "docs" / "threat-model.md").write_text("Assets.\n", encoding="utf-8")
    (tmp_path / "docs" / "security-review.md").write_text("Reviewed 2026-03-02.\n", encoding="utf-8")
    (tmp_path / "controls.tf").write_text(
        'resource "aws_securityhub_standards_subscription" "s" {\n  standards_arn = "a"\n}\n'
        'resource "aws_organizations_delegated_administrator" "d" {\n  account_id = "1"\n}\n',
        encoding="utf-8",
    )
    (tmp_path / "response.tf").write_text(
        'resource "aws_iam_role" "ir" {\n  name = "IncidentResponder"\n'
        '  permissions_boundary = "arn:aws:iam::123456789012:policy/boundary"\n}\n'
        'resource "aws_fis_experiment_template" "t" {\n  description = "d"\n}\n',
        encoding="utf-8",
    )
    # Notes and IaC for OPS 9: a dated operations review and an error budget.
    (tmp_path / "docs" / "ops-review.md").write_text("Reviewed 2026-03-02.\n", encoding="utf-8")
    (tmp_path / "slo.tf").write_text("locals {\n  error_budget = 0.001\n}\n", encoding="utf-8")
    # Notes for OPS 1: the customers and an architecture decision with its tradeoff.
    (tmp_path / "docs" / "customers.md").write_text("Shops and support.\n", encoding="utf-8")
    (tmp_path / "docs" / "adr").mkdir()
    (tmp_path / "docs" / "adr" / "0001-queue.md").write_text("Tradeoff: cost.\n", encoding="utf-8")
    # Notes and a pull request template for OPS 2: an owned runbook and who is on call.
    (tmp_path / "docs" / "runbooks").mkdir()
    (tmp_path / "docs" / "runbooks" / "restore.md").write_text("Owner: platform\n", encoding="utf-8")
    (tmp_path / "docs" / "on-call.md").write_text("Platform is on call.\n", encoding="utf-8")
    (tmp_path / ".github" / "pull_request_template.md").parent.mkdir(exist_ok=True)
    (tmp_path / ".github" / "pull_request_template.md").write_text("What changed?\n", encoding="utf-8")
    (tmp_path / "CODEOWNERS").write_text("* @org/platform\n", encoding="utf-8")
    for rel in (".github/workflows/ci.yml", "tests/main.tftest.hcl", "dev.tfvars", "prod.tfvars"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("\n", encoding="utf-8")
    (tmp_path / ".github/workflows/ci.yml").write_text(
        "jobs:\n  build:\n    steps:\n      - run: tflint\n      - run: osv-scanner -r .\n"
        "      - run: terraform test\n      - run: terraform apply -auto-approve\n"
        "      - run: curl -fsS https://example.com/health\n"
        "      - run: k6 run load/smoke.js\n"
        "      - run: aws fis start-experiment --experiment-template-id EXT1\n",
        encoding="utf-8",
    )
    out_file = tmp_path / "report.html"
    result = runner.invoke(app, [
        "--repo", str(tmp_path), "--no-llm", "--iac", "terraform", "--format", "html",
        "--out", str(out_file),
    ])
    assert result.exit_code == 0, result.output
    page = out_file.read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert "All (0)" in page
    assert '<p class="empty">No findings.</p>' in page


def _fail_connection(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setattr(
        "aws_arch_agent.tools.llm.requests.post",
        lambda *_a, **_k: (_ for _ in ()).throw(ConnectionError("http://secret:1 refused")),
    )


def _forbid_calls(monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise AssertionError("--no-llm must make no LLM call")

    monkeypatch.setattr("aws_arch_agent.tools.llm.requests.post", boom)
    monkeypatch.setattr("aws_arch_agent.tools.llm.LLMClient.polish", boom)


def test_connection_failure_in_console_and_markdown(tmp_path: Path, monkeypatch) -> None:
    _make_repo(tmp_path)
    _fail_connection(monkeypatch)
    out_file = tmp_path / "report.md"
    result = runner.invoke(app, ["--repo", str(tmp_path), "--out", str(out_file)])
    assert result.exit_code == 0, result.output
    line = "LLM: fallback (Ollama request failed)"
    assert line in result.output.splitlines()
    assert "LLM: on" not in result.output
    assert "responded" not in result.output
    assert "secret" not in result.output
    assert out_file.read_text(encoding="utf-8").splitlines()[0] == line


def test_connection_failure_is_a_top_level_json_object(tmp_path: Path, monkeypatch) -> None:
    _make_repo(tmp_path)
    _fail_connection(monkeypatch)
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app, ["--repo", str(tmp_path), "--format", "json", "--out", str(out_file)]
    )
    assert result.exit_code == 0, result.output
    assert "LLM: fallback (Ollama request failed)" in result.output.splitlines()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["llm"]["status"] == "fallback"
    assert data["llm"]["reason"] == "Ollama request failed"
    assert data["llm"]["provider"] == "ollama"
    assert "text" not in data["llm"]
    assert "llm" not in data["context"]
    assert data["findings"]
    assert all("llm" not in finding for finding in data["findings"])


def test_answering_model_is_reported(tmp_path: Path, monkeypatch) -> None:
    _make_repo(tmp_path)
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_MODEL", "llama3:8b")
    reply = MagicMock()
    reply.json.return_value = {"message": {"content": "[]"}}
    monkeypatch.setattr("aws_arch_agent.tools.llm.requests.post", lambda *_a, **_k: reply)
    out_file = tmp_path / "report.md"
    result = runner.invoke(app, ["--repo", str(tmp_path), "--out", str(out_file)])
    assert result.exit_code == 0, result.output
    line = "LLM: ollama/llama3:8b responded"
    assert line in result.output.splitlines()
    assert out_file.read_text(encoding="utf-8").splitlines()[0] == line


def test_no_llm_is_skipped_with_no_call(tmp_path: Path, monkeypatch) -> None:
    _make_repo(tmp_path)
    _forbid_calls(monkeypatch)
    md_file, json_file = tmp_path / "report.md", tmp_path / "report.json"
    line = "LLM: skipped (--no-llm)"
    result = runner.invoke(app, ["--repo", str(tmp_path), "--no-llm", "--out", str(md_file)])
    assert result.exit_code == 0, result.output
    assert line in result.output.splitlines()
    assert md_file.read_text(encoding="utf-8").splitlines()[0] == line
    result = runner.invoke(
        app, ["--repo", str(tmp_path), "--no-llm", "--format", "json", "--out", str(json_file)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(json_file.read_text(encoding="utf-8"))["llm"] == {
        "status": "skipped", "provider": None, "model": None, "reason": "--no-llm",
    }


def test_v2_connection_failure_reaches_console_and_markdown(tmp_path: Path, monkeypatch) -> None:
    _make_repo(tmp_path)
    _fail_connection(monkeypatch)
    out_file = tmp_path / "report.md"
    result = runner.invoke(
        app, ["--repo", str(tmp_path), "--mode", "v2", "--no-synth", "--out", str(out_file)]
    )
    assert result.exit_code == 0, result.output
    line = "LLM: fallback (Ollama request failed)"
    assert line in result.output.splitlines()
    assert out_file.read_text(encoding="utf-8").splitlines()[0] == line


def test_v2_no_llm_is_skipped_with_no_call(tmp_path: Path, monkeypatch) -> None:
    _make_repo(tmp_path)
    _forbid_calls(monkeypatch)
    out_file = tmp_path / "report.md"
    result = runner.invoke(
        app,
        ["--repo", str(tmp_path), "--mode", "v2", "--no-llm", "--no-synth", "--out", str(out_file)],
    )
    assert result.exit_code == 0, result.output
    line = "LLM: skipped (--no-llm)"
    assert line in result.output.splitlines()
    assert out_file.read_text(encoding="utf-8").splitlines()[0] == line
