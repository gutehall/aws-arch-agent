"""Outputs for any CI: --summary-out (Markdown from the same scan) and --format codequality
(GitLab Code Quality)."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent.cli import app
from aws_arch_agent.config import ConfigError, load_config
from aws_arch_agent.models import Finding
from aws_arch_agent.report.codequality import render_codequality
from aws_arch_agent.report.sarif import fingerprint

runner = CliRunner()

_TEMPLATE = {
    "Resources": {
        "Open": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "GroupDescription": "x", "SecurityGroupIngress": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]}},
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
    }
}


def _repo(root: Path, template: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "stack.template.json").write_text(json.dumps(template or _TEMPLATE), encoding="utf-8")
    return root


def _scan(repo: Path, *args: str):
    return runner.invoke(app, ["--repo", str(repo), "--no-llm", "--pricing-source", "off", *args])


def _without_times(text: str) -> str:
    """The Markdown with the run's timestamps blanked, so two runs compare equal."""
    return re.sub(r"\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?", "<time>", text)


# --- --summary-out ----------------------------------------------------------------------------

@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_summary_out_writes_both_files_and_keeps_the_exit_code(tmp_path: Path, fmt: str) -> None:
    repo = _repo(tmp_path / "repo")
    out, summary = tmp_path / f"report.{fmt}", tmp_path / "summary.md"
    result = _scan(repo, "--format", fmt, "--out", str(out), "--summary-out", str(summary), "--fail-on", "high")
    assert result.exit_code == 1, result.output
    json.loads(out.read_text(encoding="utf-8"))
    assert "AWS Architecture Review Report" in summary.read_text(encoding="utf-8")


def test_summary_matches_a_markdown_run_of_the_same_scan(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    summary, markdown = tmp_path / "summary.md", tmp_path / "report.md"
    assert _scan(repo, "--format", "sarif", "--out", str(tmp_path / "r.sarif"),
                 "--summary-out", str(summary)).exit_code == 0
    assert _scan(repo, "--format", "markdown", "--out", str(markdown)).exit_code == 0
    assert _without_times(summary.read_text(encoding="utf-8")) == _without_times(markdown.read_text(encoding="utf-8"))


def test_summary_out_with_markdown_is_the_same_text(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    out, summary = tmp_path / "report.md", tmp_path / "summary.md"
    assert _scan(repo, "--format", "markdown", "--out", str(out), "--summary-out", str(summary)).exit_code == 0
    assert out.read_text(encoding="utf-8") == summary.read_text(encoding="utf-8")
    # The same path as --out with markdown is allowed: one file, one text.
    assert _scan(repo, "--format", "markdown", "--out", str(out), "--summary-out", str(out)).exit_code == 0


def test_summary_out_with_a_missing_directory_writes_no_report(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    out = tmp_path / "report.json"
    result = _scan(repo, "--format", "json", "--out", str(out), "--summary-out", str(tmp_path / "nope" / "s.md"))
    assert result.exit_code != 0 and "does not exist" in result.output
    assert not out.exists()


def test_summary_out_equal_to_out_for_another_format_writes_no_report(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    out = tmp_path / "report.sarif"
    result = _scan(repo, "--format", "sarif", "--out", str(out), "--summary-out", str(out))
    assert result.exit_code != 0 and "same file" in result.output
    assert not out.exists()


# --- --format codequality ---------------------------------------------------------------------

def test_codequality_entries_have_the_gitlab_fields(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    out = tmp_path / "gl-code-quality-report.json"
    assert _scan(repo, "--format", "codequality", "--out", str(out)).exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, list) and data
    for entry in data:
        assert {"description", "check_name", "fingerprint", "severity", "location"} <= set(entry)
        assert entry["severity"] in {"major", "minor", "info"}
        assert entry["location"]["path"] and entry["location"]["lines"]["begin"] >= 1
    assert any(e["check_name"] == "CF-SG-001" and e["location"]["path"] == "stack.template.json" for e in data)
    assert all(e["location"]["path"] == "." for e in data if e["check_name"].startswith("REPO-"))


def test_codequality_fingerprint_and_severity_follow_sarif() -> None:
    findings = [
        Finding(id="SEC-001", title="IAM", severity="High", recommendation="Fix.", file="lib/a.ts", line=10,
                evidence="x"),
        Finding(id="REL-001", title="AZ", severity="Medium", recommendation="Fix.", file="lib/a.ts"),
        Finding(id="COST-001", title="Logs", severity="Low", recommendation="Fix."),
    ]
    data = json.loads(render_codequality(findings))
    assert [e["fingerprint"] for e in data] == [fingerprint(f) for f in findings]
    assert [e["severity"] for e in data] == ["major", "minor", "info"]
    assert data[0]["location"] == {"path": "lib/a.ts", "lines": {"begin": 10}}
    moved = Finding(id="SEC-001", title="IAM", severity="High", recommendation="Fix.", file="lib/a.ts",
                    line=42, evidence="x")
    assert fingerprint(moved) == data[0]["fingerprint"]


def test_codequality_leaves_out_suppressed_and_baselined_findings(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    out = tmp_path / "cq.json"
    assert _scan(repo, "--update-baseline", "--format", "codequality", "--out", str(out)).exit_code == 0
    assert json.loads(out.read_text(encoding="utf-8"))  # without --enforce-baseline every finding shows
    assert _scan(repo, "--enforce-baseline", "--format", "codequality", "--out", str(out)).exit_code == 0
    assert json.loads(out.read_text(encoding="utf-8")) == []

    suppressed = _repo(tmp_path / "inline", {"Resources": {"Open": {**_TEMPLATE["Resources"]["Open"], "Metadata": {
        "aws-arch-agent": {"ignore": [{"id": "CF-SG-001", "reason": "bastion"}]}}}}})
    assert _scan(suppressed, "--format", "codequality", "--out", str(out)).exit_code == 0
    assert "CF-SG-001" not in {e["check_name"] for e in json.loads(out.read_text(encoding="utf-8"))}


def test_config_accepts_codequality_and_rejects_unknown_formats(tmp_path: Path) -> None:
    (tmp_path / "aws-arch-agent.yaml").write_text("format: codequality\n", encoding="utf-8")
    cfg = load_config(tmp_path, None)
    assert cfg.format == "codequality" and cfg.out == "report.codequality.json"
    (tmp_path / "aws-arch-agent.yaml").write_text("format: junit\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path, None)
    repo = _repo(tmp_path / "repo")
    out = tmp_path / "r.json"
    assert _scan(repo, "--format", "junit", "--out", str(out)).exit_code != 0
    assert not out.exists()


def test_a_codequality_out_suffix_picks_the_format(tmp_path: Path) -> None:
    (tmp_path / "aws-arch-agent.yaml").write_text("out: gl.codequality.json\n", encoding="utf-8")
    assert load_config(tmp_path, None).format == "codequality"
