"""Tests for shared rule runner."""
import subprocess
from pathlib import Path

import pytest

from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.runner import filter_by_severity, run_all_rules
from aws_arch_agent.models import Finding


def test_run_all_rules_on_empty_repo(tmp_path: Path) -> None:
    findings, warnings = run_all_rules(tmp_path, ALL_RULES[:3], ["typescript"])
    assert isinstance(findings, list)
    assert warnings == []


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
    assert warnings == [], warnings


def test_cloudtrail_missing_once_across_languages(tmp_path: Path) -> None:
    from aws_arch_agent.rules.operational_excellence import CloudTrailMissing

    findings, warnings = run_all_rules(tmp_path, [CloudTrailMissing()], ["typescript", "python"])
    assert warnings == []
    assert [finding.id for finding in findings] == ["OPS-001"]


def test_same_id_different_file_is_kept() -> None:
    from aws_arch_agent.rules.base import Rule

    class Twice(Rule):
        id = "DUP"
        title = "dup"
        category = "test"
        severity = "Low"

        def run(self, repo_path: Path, language: str = "typescript") -> list[Finding]:
            return [
                Finding(
                    id="DUP",
                    title="dup",
                    severity="Low",
                    recommendation="keep",
                    file="a.ts",
                    line=1,
                    evidence="a",
                ),
                Finding(
                    id="DUP",
                    title="dup",
                    severity="Low",
                    recommendation="keep",
                    file="b.ts",
                    line=2,
                    evidence="b",
                ),
                Finding(
                    id="DUP",
                    title="dup",
                    severity="Low",
                    recommendation="keep",
                    file="a.ts",
                    line=1,
                    evidence="a",
                ),
            ]

    findings, _warnings = run_all_rules(Path("."), [Twice()], ["typescript", "python"])
    assert [(finding.file, finding.line) for finding in findings] == [("a.ts", 1), ("b.ts", 2)]


def test_account_finding_emitted_once(tmp_path: Path) -> None:
    from aws_arch_agent.rules.operational_excellence import CloudTrailMissing
    from aws_arch_agent.rules.security_iam import SecurityHubNotEnabled

    findings, _warnings = run_all_rules(
        tmp_path,
        [SecurityHubNotEnabled(), CloudTrailMissing()],
        ["typescript", "python"],
    )
    assert [f.id for f in findings].count("SEC-026") == 1
    assert findings[0].file is None


def test_reserved_concurrency_is_only_rel_027(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("aws_lambda.Function(self, 'Fn')\n", encoding="utf-8")
    findings, _warnings = run_all_rules(tmp_path, ALL_RULES, ["typescript", "python"])
    ids = [f.id for f in findings if f.id in {"REL-027", "OPS-024"}]
    assert ids == ["REL-027"]


def test_raising_rule_warns_and_keeps_other_findings(tmp_path: Path) -> None:
    from aws_arch_agent.rules.base import Rule

    class Boom(Rule):
        id = "BOOM"
        title = "boom"
        category = "test"
        severity = "Low"

        def run(self, repo_path: Path, language: str = "typescript") -> list[Finding]:
            raise RuntimeError("boom")

    class Quiet(Rule):
        id = "QUIET"
        title = "quiet"
        category = "test"
        severity = "Low"

        def run(self, repo_path: Path, language: str = "typescript") -> list[Finding]:
            return [
                Finding(
                    id="QUIET",
                    title="quiet",
                    severity="Low",
                    recommendation="keep",
                    file="app.ts",
                )
            ]

    findings, warnings = run_all_rules(tmp_path, [Boom(), Quiet()], ["typescript"])
    assert [finding.id for finding in findings] == ["QUIET"]
    assert warnings == ["Rule BOOM failed for typescript: boom"]


def test_ripgrep_timeout_is_a_warning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aws_arch_agent.rules.security_iam import IamWildcardAction

    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "stack.ts").write_text('Action: "*"\n', encoding="utf-8")

    def hung(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd=["rg"], timeout=30)

    monkeypatch.setattr(subprocess, "run", hung)
    findings, warnings = run_all_rules(tmp_path, [IamWildcardAction()], ["typescript"])
    assert findings == []
    assert any("timed out after 30s" in warning for warning in warnings)


def test_rg_zero_hits_does_not_walk_the_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aws_arch_agent.tools import rg as rg_mod

    class Result:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: Result())

    def walked(*_args: object, **_kwargs: object) -> list[tuple[str, int, str]]:
        raise AssertionError("fallback walked the tree")

    monkeypatch.setattr(rg_mod, "_fallback_search", walked)
    (tmp_path / "app.ts").write_text("nothing to see\n", encoding="utf-8")
    assert rg_mod.rg(tmp_path, "Action") == []


def test_rg_missing_binary_uses_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aws_arch_agent.tools.rg import rg

    def missing(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError("rg")

    monkeypatch.setattr(subprocess, "run", missing)
    (tmp_path / "app.ts").write_text('Action: "*"\n', encoding="utf-8")
    hits = rg(tmp_path, r'Action:\s*"\*"', glob="**/*.ts")
    assert [hit[0] for hit in hits] == ["app.ts"]


def test_rg_tool_failure_uses_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aws_arch_agent.tools.rg import rg

    class Result:
        returncode = 2
        stdout = ""
        stderr = "regex parse error"

    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: Result())
    (tmp_path / "app.ts").write_text('Action: "*"\n', encoding="utf-8")
    hits = rg(tmp_path, r'Action:\s*"\*"', glob="**/*.ts")
    assert [hit[0] for hit in hits] == ["app.ts"]


def test_rg_hits_are_stable(tmp_path: Path) -> None:
    from aws_arch_agent.tools.rg import rg

    (tmp_path / "b.ts").write_text('Action: "*"\n', encoding="utf-8")
    (tmp_path / "a.ts").write_text('Action: "*"\n', encoding="utf-8")
    first = rg(tmp_path, r'Action:\s*"\*"', glob="**/*.ts")
    second = rg(tmp_path, r'Action:\s*"\*"', glob="**/*.ts")
    assert [hit[0] for hit in first] == ["a.ts", "b.ts"]
    assert first[0] == second[0]


def test_fallback_search_skips_tests_directory(tmp_path: Path) -> None:
    from aws_arch_agent.rules.base import DEFAULT_EXCLUDE_GLOBS
    from aws_arch_agent.tools.rg import _fallback_search

    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "stack.py").write_text('Action: "*"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text('Action: "*"\n', encoding="utf-8")
    hits = _fallback_search(tmp_path, r'Action:\s*"\*"', "**/*.py", 50, DEFAULT_EXCLUDE_GLOBS)
    assert [hit[0] for hit in hits] == ["app.py"]


def test_limit_to_files_skips_the_rest_of_the_tree(tmp_path: Path) -> None:
    from aws_arch_agent.agent.v1 import collect_ctx_findings
    from aws_arch_agent.tools.rg import limit_to_files, rg

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    lib = tmp_path / "lib"
    lib.mkdir()
    clean = lib / "clean.ts"
    bad = lib / "bad.ts"
    clean.write_text("export const x = 1;\n", encoding="utf-8")
    bad.write_text('Action: "*"\n', encoding="utf-8")

    assert rg(tmp_path, r'Action:\s*"\*"', glob="**/*.ts")
    with limit_to_files(tmp_path, [bad]):
        hits = rg(tmp_path, r'Action:\s*"\*"', glob="**/*.ts")
    assert [hit[0] for hit in hits] == ["lib/bad.ts"]
    with limit_to_files(tmp_path, [clean]):
        assert rg(tmp_path, r'Action:\s*"\*"', glob="**/*.ts") == []

    _ctx, findings, warnings = collect_ctx_findings(tmp_path)
    assert any(finding.id == "SEC-001" for finding in findings)
    assert warnings == []


def test_collect_searches_only_sampled_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aws_arch_agent.agent.v1 import collect_ctx_findings
    from aws_arch_agent.agent.v2_graph import analyze_v2

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    lib = tmp_path / "lib"
    lib.mkdir()
    clean = lib / "clean.ts"
    (lib / "bad.ts").write_text('Action: "*"\n', encoding="utf-8")
    clean.write_text("export const x = 1;\n", encoding="utf-8")

    def only_clean(repo: Path, max_files: int = 400) -> list[Path]:
        return [clean]

    monkeypatch.setattr("aws_arch_agent.agent.v1.iter_files", only_clean)
    _ctx, findings, warnings = collect_ctx_findings(tmp_path, max_files=1)
    assert warnings == []
    assert not any(finding.id == "SEC-001" for finding in findings)

    monkeypatch.setattr("aws_arch_agent.agent.v2_graph.iter_files", only_clean)
    _report, _ctx, v2_findings, v2_warnings = analyze_v2(
        tmp_path, max_files=1, use_llm=False, skip_synth=True
    )
    assert v2_warnings == []
    assert not any(finding.id == "SEC-001" for finding in v2_findings)
