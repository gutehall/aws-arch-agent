"""Rule cards: every static and template rule has one, and they stay true to the rules."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from aws_arch_agent.models import Finding
from aws_arch_agent.rules import environments
from aws_arch_agent.rules.cards import (
    STATIC_CARDS,
    RuleCard,
    card_for_finding,
    cards_for_findings,
    compact_catalog,
    render_cards,
)
from aws_arch_agent.rules.cf_template import CF_THEMES, CF_TITLES
from aws_arch_agent.rules.registry import ALL_RULES

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "src" / "aws_arch_agent" / "rules"
CASES = json.loads((ROOT / "tests" / "fixtures" / "rule_cases.json").read_text(encoding="utf-8"))

# Rules whose run() writes computed text. The class attribute holds the general guidance.
COMPUTED_RECOMMENDATION = frozenset({"SEC-068"})


def _write_repo(repo: Path, language: str, content: str) -> None:
    repo.mkdir()
    if language == "typescript":
        (repo / "package.json").write_text("{}", encoding="utf-8")
        (repo / "lib").mkdir()
        (repo / "lib" / "stack.ts").write_text(content, encoding="utf-8")
    else:
        (repo / "requirements.txt").write_text("", encoding="utf-8")
        (repo / "app.py").write_text(content, encoding="utf-8")


def _findings_on_positive_cases(rule, tmp_path: Path) -> list[Finding]:
    found: list[Finding] = []
    for suffix, language in (("ts", "typescript"), ("py", "python")):
        content = CASES.get(rule.id, {}).get(f"positive_{suffix}")
        if content:
            repo = tmp_path / suffix
            _write_repo(repo, language, content)
            found += [f for f in rule.run(repo, language) if f.id == rule.id]
    return found


def _template_ids_in_source() -> set[str]:
    found: set[str] = set()
    for module in RULES_DIR.glob("*.py"):
        text = module.read_text(encoding="utf-8")
        found |= set(re.findall(r'"(CF-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{3})"', text))
    return found


def test_every_rule_declares_a_recommendation_on_its_class() -> None:
    for rule in ALL_RULES:
        assert "recommendation" in type(rule).__dict__, rule.id
        assert type(rule).recommendation.strip(), rule.id


def test_every_rule_has_a_card_with_the_class_fields() -> None:
    assert len(STATIC_CARDS) == len(ALL_RULES)
    for rule in ALL_RULES:
        cls = type(rule)
        assert STATIC_CARDS[rule.id] == RuleCard(
            id=cls.id,
            title=cls.title,
            severity=cls.severity,
            category=cls.category,
            recommendation=cls.recommendation,
        )


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_emitted_recommendation_is_the_class_attribute(rule, tmp_path: Path) -> None:
    """This is what stops the attribute drifting from run()."""
    found = _findings_on_positive_cases(rule, tmp_path)
    if not found:
        pytest.skip(f"{rule.id} does not fire on its positive cases")
    emitted = {f.recommendation for f in found}
    if rule.id in COMPUTED_RECOMMENDATION:
        assert type(rule).recommendation not in emitted, f"{rule.id} can leave the allowlist"
    else:
        assert emitted == {type(rule).recommendation}
        cls = type(rule)
        assert {(f.title, f.severity, f.category) for f in found} == {
            (cls.title, cls.severity, cls.category)
        }


def test_every_template_id_the_code_can_emit_has_a_title() -> None:
    emitted = _template_ids_in_source()
    assert len(emitted) >= 272  # the regex still finds the template checks
    assert sorted(emitted - set(CF_TITLES)) == []
    assert all(title.strip() for title in CF_TITLES.values())


def test_titles_and_themes_list_the_same_template_ids() -> None:
    assert sorted(set(CF_TITLES) - set(CF_THEMES)) == []
    assert sorted(set(CF_THEMES) - set(CF_TITLES)) == []


def test_static_and_template_ids_do_not_overlap() -> None:
    assert sorted(set(STATIC_CARDS) & set(CF_TITLES)) == []


def test_catalog_has_one_line_per_rule() -> None:
    lines = compact_catalog().splitlines()
    ids = [line.split(": ", 1)[0] for line in lines]
    assert len(ids) == len(set(ids))
    assert set(ids) == {rule.id for rule in ALL_RULES} | set(CF_TITLES)
    assert ids == sorted(ids)
    titles = dict(line.split(": ", 1) for line in lines)
    assert titles["CF-EC2-001"] == CF_TITLES["CF-EC2-001"]
    assert titles["SEC-068"] == type(next(r for r in ALL_RULES if r.id == "SEC-068")).title


def test_template_card_uses_the_finding_fields() -> None:
    finding = Finding(
        id="CF-RDS-002",
        title="the finding's title",
        severity="High",
        category="Reliability",
        recommendation="the finding's recommendation",
    )
    assert card_for_finding(finding) == RuleCard(
        id="CF-RDS-002",
        title="the finding's title",
        severity="High",
        category="Reliability",
        recommendation="the finding's recommendation",
    )


def test_template_card_uses_an_environment_overridden_severity() -> None:
    finding = Finding(id="CF-RDS-002", title="t", severity="High", recommendation="r")
    kept = environments.apply([finding], Path("dev-stack.json"), [])
    assert kept[0].severity == "Low"
    assert card_for_finding(kept[0]).severity == "Low"


def test_static_finding_gets_its_registry_card() -> None:
    rule = next(r for r in ALL_RULES if r.id == "SEC-068")
    finding = Finding(id="SEC-068", title="computed", severity="Low", recommendation="computed")
    assert card_for_finding(finding) == STATIC_CARDS["SEC-068"]
    assert card_for_finding(finding).recommendation == type(rule).recommendation


def test_cards_for_findings_are_the_batch_ids_deduped_in_first_seen_order() -> None:
    batch = [
        Finding(id="SEC-001", title="t", recommendation="r"),
        Finding(id="CF-S3-001", title="first", recommendation="r"),
        Finding(id="SEC-001", title="t", recommendation="r"),
        Finding(id="CF-S3-001", title="second", recommendation="r"),
        Finding(id="BP-001", title="t", recommendation="r"),
    ]
    cards = cards_for_findings(batch)
    assert [card.id for card in cards] == ["SEC-001", "CF-S3-001", "BP-001"]
    assert cards[1].title == "first"
    assert cards_for_findings([]) == []


def test_render_cards_shows_only_the_cards_given() -> None:
    text = render_cards([STATIC_CARDS["SEC-068"]])
    card = STATIC_CARDS["SEC-068"]
    for field in (card.id, card.title, card.severity, card.category, card.recommendation):
        assert field in text
    assert "SEC-001" not in text
    assert render_cards([]) == ""
