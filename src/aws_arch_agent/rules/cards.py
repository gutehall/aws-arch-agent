"""Rule cards: what a rule means, in a shape a prompt can use.

A card holds a rule's id, title, severity, category and recommendation. Cards come from
the registry, so there is no separate document to keep in sync. tests/test_rule_cards.py
fails when a rule has no card.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.cf_template import CF_TITLES
from aws_arch_agent.rules.registry import ALL_RULES


@dataclass(frozen=True)
class RuleCard:
    """One rule's intent."""

    id: str
    title: str
    severity: str
    category: str
    recommendation: str


STATIC_CARDS: dict[str, RuleCard] = {
    rule.id: RuleCard(
        id=rule.id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        recommendation=rule.recommendation,
    )
    for rule in ALL_RULES
}


def card_for_finding(finding: Finding) -> RuleCard:
    """The registry card of a static rule; other ids get a card from the finding's own fields.

    A template finding's severity can depend on the stack's environment
    (rules/environments.py), so the finding's value is the one that applies.
    """
    card = STATIC_CARDS.get(finding.id)
    if card is not None:
        return card
    return RuleCard(
        id=finding.id,
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        recommendation=finding.recommendation,
    )


def cards_for_findings(findings: Iterable[Finding]) -> list[RuleCard]:
    """One card per distinct id in first-seen order, built from the first finding of that id."""
    cards: dict[str, RuleCard] = {}
    for finding in findings:
        if finding.id not in cards:
            cards[finding.id] = card_for_finding(finding)
    return list(cards.values())


def render_cards(cards: Iterable[RuleCard]) -> str:
    """The cards as text, one block per card, for a verdict prompt."""
    return "\n\n".join(
        f"{card.id}: {card.title}\n"
        f"Severity: {card.severity}\n"
        f"Category: {card.category}\n"
        f"Recommendation: {card.recommendation}"
        for card in cards
    )


def compact_catalog() -> str:
    """Every static and template rule, one `<id>: <title>` line each, sorted by id."""
    titles = {card.id: card.title for card in STATIC_CARDS.values()} | CF_TITLES
    return "\n".join(f"{rule_id}: {titles[rule_id]}" for rule_id in sorted(titles))
