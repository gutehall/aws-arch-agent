"""Org-level absence rules stay off unless config or include turns them on."""
from pathlib import Path

from aws_arch_agent.agent.v1 import ORG_RULE_IDS, analyze_v1
from aws_arch_agent.agent.v2_graph import node_collect


def _app(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")


def test_org_rules_off_by_default(tmp_path: Path) -> None:
    _app(tmp_path)
    _report, _ctx, findings, warnings = analyze_v1(tmp_path, use_llm=False)
    assert warnings == []
    assert {finding.id for finding in findings}.isdisjoint(ORG_RULE_IDS)


def test_org_rules_run_when_enabled(tmp_path: Path) -> None:
    _app(tmp_path)
    _report, _ctx, findings, _warnings = analyze_v1(tmp_path, use_llm=False, rules_org=True)
    ids = {finding.id for finding in findings}
    assert ORG_RULE_IDS <= ids


def test_include_runs_one_org_rule(tmp_path: Path) -> None:
    _app(tmp_path)
    _report, _ctx, findings, _warnings = analyze_v1(
        tmp_path, use_llm=False, rules_include=["OPS-001"]
    )
    assert {finding.id for finding in findings} == {"OPS-001"}


def test_exclude_skips_org_rule_when_enabled(tmp_path: Path) -> None:
    _app(tmp_path)
    _report, _ctx, findings, _warnings = analyze_v1(
        tmp_path,
        use_llm=False,
        rules_org=True,
        rules_exclude=["OPS-001"],
    )
    ids = {finding.id for finding in findings}
    assert "OPS-001" not in ids
    assert "SEC-026" in ids


def test_v2_collect_leaves_org_rules_off(tmp_path: Path) -> None:
    _app(tmp_path)
    out = node_collect({"repo_path": str(tmp_path)})
    assert {finding.id for finding in out["raw_findings"]}.isdisjoint(ORG_RULE_IDS)
