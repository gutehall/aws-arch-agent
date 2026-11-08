"""docs/COVERAGE.md stays in sync with ALL_RULES, CF_COVERS_STATIC and the template checks."""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from aws_arch_agent.rules import tag_policy
from aws_arch_agent.rules.cf_template import CF_COVERS_STATIC, CF_PARTLY_COVERS_STATIC, CF_THEMES
from aws_arch_agent.rules.registry import ALL_RULES

ROOT = Path(__file__).parents[1]
DOC = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
RULES_DIR = ROOT / "src" / "aws_arch_agent" / "rules"

STATUSES = ("covered", "partial", "account", "cdk-only", "advice")
_RULE_ROW = re.compile(
    r"^\| ([A-Z]+-\d{3}) \| (.*?) \| (.*?) \| `([a-z0-9-]+)(?:: ([a-z0-9-]+))?` \| (.*?) \|$", re.M
)
_FSBP_ROW = re.compile(r"^\| ([A-Za-z0-9]+\.\d+) \| `(CF-[A-Z0-9-]+)` \| (.+) \|$", re.M)


def _section(title: str) -> str:
    start = DOC.index(f"## {title}\n")
    end = DOC.find("\n## ", start + 1)
    return DOC[start:] if end == -1 else DOC[start:end]


def _rule_rows() -> list[tuple[str, str, list[str], str | None]]:
    """(rule id, status, template checks, planned work) per row of the CDK rules table."""
    return [
        (rule_id, status, re.findall(r"`(CF-[A-Z0-9-]+)`", checks), work or None)
        for rule_id, _title, checks, status, work, _note in _RULE_ROW.findall(_section("CDK rules"))
    ]


def _covers(cf_id: str, rule_id: str) -> bool:
    if rule_id in CF_COVERS_STATIC.get(cf_id, ()):
        return True
    return cf_id == tag_policy.CHECK_ID and rule_id in tag_policy.REPLACED_STATIC_RULES


def _template_check_ids() -> set[str]:
    ids: set[str] = set()
    for path in RULES_DIR.glob("*.py"):
        ids |= set(re.findall(r'"(CF-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{3})"', path.read_text(encoding="utf-8")))
    return ids


def test_every_rule_has_one_row() -> None:
    ids = [row[0] for row in _rule_rows()]
    dupes = sorted(i for i, n in Counter(ids).items() if n > 1)
    assert not dupes, f"rules listed twice: {dupes}"
    missing = sorted({r.id for r in ALL_RULES} - set(ids))
    assert not missing, f"rules with no row in docs/COVERAGE.md: {missing}"
    extra = sorted(set(ids) - {r.id for r in ALL_RULES})
    assert not extra, f"rows for rules not in ALL_RULES: {extra}"


def test_statuses_are_known() -> None:
    bad = [(i, s) for i, s, _c, _w in _rule_rows() if s not in STATUSES]
    assert not bad


def test_covered_rows_match_the_map() -> None:
    covered_in_code = {r for rules in CF_COVERS_STATIC.values() for r in rules}
    covered_in_code |= set(tag_policy.REPLACED_STATIC_RULES)
    for rule_id, status, checks, _w in _rule_rows():
        if status == "covered":
            assert checks, f"{rule_id}: covered with no template check"
            wrong = [c for c in checks if not _covers(c, rule_id)]
            assert not wrong, f"{rule_id}: marked covered by {wrong}, not in CF_COVERS_STATIC"
        else:
            assert rule_id not in covered_in_code, f"{rule_id}: in CF_COVERS_STATIC but marked {status}"


def test_partial_rows_match_the_partial_map() -> None:
    for rule_id, status, checks, _w in _rule_rows():
        if status != "partial":
            continue
        assert checks, f"{rule_id}: partial with no template check"
        for cf_id in checks:
            assert rule_id in CF_PARTLY_COVERS_STATIC.get(cf_id, ((), ""))[0], (
                f"{rule_id}: {cf_id} not in CF_PARTLY_COVERS_STATIC"
            )


def test_no_planned_work_is_left() -> None:
    assert not [row[0] for row in _rule_rows() if row[1] == "planned" or row[3]]
    assert "planned" not in DOC.lower(), "a coverage row or section still mentions planned work"


def test_fsbp_rows_name_a_check() -> None:
    rows = _FSBP_ROW.findall(_section("FSBP controls"))
    assert len(rows) > 50
    controls = [r[0] for r in rows]
    assert len(controls) == len(set(controls)), "FSBP control listed twice"
    checks = _template_check_ids()
    for control, cf_id, resource_type in rows:
        assert cf_id in checks, f"{control}: unknown template check {cf_id}"
        assert "AWS::" in resource_type, f"{control}: no resource type"
    all_rows = re.findall(r"^\| [A-Za-z0-9]+\.\d+ \|", _section("FSBP controls"), re.M)
    assert len(all_rows) == len(rows), "an FSBP row has no template check"


def test_docs_state_the_real_counts() -> None:
    with_check = sum(1 for _i, status, _c, _w in _rule_rows() if status in ("covered", "partial"))
    total = len(ALL_RULES)
    stated = f"{total} CDK rules and {len(CF_THEMES)} template checks"
    share = f"{with_check} of the {total} CDK rules ({round(100 * with_check / total)}%)"
    for path in ("README.md", "docs/CF_RULES.md"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert stated in text, f"{path}: update the counts to: {stated}"
        assert share in text, f"{path}: update the share to: {share}"


def test_rule_count_line_matches_the_rows() -> None:
    counts = Counter(status for _i, status, _c, _w in _rule_rows())
    line = f"{len(ALL_RULES)} rules: " + ", ".join(
        f"{counts[s]} {s}" for s in STATUSES if counts[s]
    ) + "."
    assert line in _section("CDK rules"), f"update the count line to: {line}"
