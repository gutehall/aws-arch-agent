"""Scan progress stays quiet for library callers and speaks when a reporter is set."""
import io
import time
from pathlib import Path

from rich.console import Console

from aws_arch_agent.progress import ScanProgress, report, use_progress
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths
from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.runner import run_all_rules


def test_report_is_quiet_without_a_reporter(capsys) -> None:
    report("Reading files")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_rules_report_each_step(tmp_path: Path) -> None:
    seen: list[str] = []
    rules = ALL_RULES[:2]
    with use_progress(seen.append):
        _findings, warnings = run_all_rules(tmp_path, rules, ["typescript", "python"])
    assert warnings == []
    # The reporter gets every count; ScanProgress decides what to print.
    assert seen == [
        "Checking rules (1/4, typescript)",
        "Checking rules (2/4, typescript)",
        "Checking rules (3/4, python)",
        "Checking rules (4/4, python)",
    ]


def test_template_scan_reports_each_file(tmp_path: Path) -> None:
    (tmp_path / "stack.yaml").write_text(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    seen: list[str] = []
    with use_progress(seen.append):
        run_cf_rules_from_paths([tmp_path / "stack.yaml"], repo_path=tmp_path)
    assert seen == ["Template stack.yaml (1/1)"]


def test_fast_steps_are_printed_once() -> None:
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    with ScanProgress(console, idle_after=5) as progress:
        progress("Reading files")
        for done in range(1, 349):
            progress(f"Checking rules ({done}/348, typescript)")
        progress("Merging review")
    lines = buf.getvalue().splitlines()
    assert lines == ["Reading files", "Checking rules (1/348, typescript)", "Merging review"]


def test_a_quiet_step_repeats_with_its_latest_count() -> None:
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    with ScanProgress(console, idle_after=0.05) as progress:
        progress("Checking rules (1/348, typescript)")
        progress("Checking rules (7/348, typescript)")
        time.sleep(0.35)
    lines = buf.getvalue().splitlines()
    assert lines[0] == "Checking rules (1/348, typescript)"
    assert "Checking rules (7/348, typescript) (still running)" in lines[1:]


def test_a_quiet_step_is_repeated() -> None:
    buf = io.StringIO()
    console = Console(file=buf, highlight=False)
    with ScanProgress(console, idle_after=0.05) as progress:
        progress("Running cdk synth")
        time.sleep(0.35)
    assert "Running cdk synth (still running)" in buf.getvalue()
