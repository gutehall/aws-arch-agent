"""Tests for shared rule runner."""
from pathlib import Path

import pytest

from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.runner import filter_by_severity, run_all_rules
from aws_arch_agent.models import Finding


def test_run_all_rules_on_empty_repo(tmp_path: Path) -> None:
    findings, warnings = run_all_rules(tmp_path, ALL_RULES[:3], ["typescript"])
    assert isinstance(findings, list)
    assert isinstance(warnings, list)


def test_filter_by_severity() -> None:
    findings = [
        Finding(id="A", title="a", severity="Low", recommendation="x"),
        Finding(id="B", title="b", severity="High", recommendation="y"),
    ]
    out = filter_by_severity(findings, "Medium")
    assert len(out) == 1
    assert out[0].id == "B"


@pytest.mark.parametrize("rule_id", [r.id for r in ALL_RULES])
def test_every_rule_runs_without_error(tmp_path: Path, rule_id: str) -> None:
    """Each registered rule executes without raising on an empty repo."""
    rule = next(r for r in ALL_RULES if r.id == rule_id)
    findings, warnings = run_all_rules(tmp_path, [rule], ["typescript", "python"])
    assert isinstance(findings, list)
    assert isinstance(warnings, list)


def test_fallback_search_skips_tests_directory(tmp_path: Path) -> None:
    from aws_arch_agent.rules.base import DEFAULT_EXCLUDE_GLOBS
    from aws_arch_agent.tools.rg import _fallback_search

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "stack.py").write_text('Action: "*"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text('Action: "*"\n', encoding="utf-8")
    hits = _fallback_search(tmp_path, r'Action:\s*"\*"', "**/*.py", 50, DEFAULT_EXCLUDE_GLOBS)
    assert [hit[0] for hit in hits] == ["app.py"]
