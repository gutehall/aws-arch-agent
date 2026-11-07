"""Rule themes: concerns that cut across pillars.

A FinOps lead or a security reviewer reads one theme instead of the whole report. Each
rule has one or more themes. CDK source rules declare them in their class (`themes = ...`);
template checks declare them in CF_THEMES in rules/cf_template.py, next to the other
per-check definitions. tests/test_themes.py fails when a rule has none.
"""
from __future__ import annotations

from typing import Iterable, List

from aws_arch_agent.models import Finding

THEMES: tuple[str, ...] = (
    "finops", "security-baseline", "identity", "data-protection",
    "network-exposure", "resilience", "observability", "sustainability",
)


def themes_of(rule_id: str) -> tuple[str, ...]:
    """The themes a rule declares; () for an id no rule defines."""
    from aws_arch_agent.rules.cf_template import CF_THEMES  # deferred: cf_template is large
    from aws_arch_agent.rules.registry import ALL_RULES

    if rule_id in CF_THEMES:
        return CF_THEMES[rule_id]
    for rule in ALL_RULES:
        if rule.id == rule_id:
            return rule.themes
    return ()


def annotate(findings: Iterable[Finding]) -> None:
    """Set each finding's themes from its rule. Mutates the findings."""
    cache: dict[str, tuple[str, ...]] = {}
    for f in findings:
        if f.id not in cache:
            cache[f.id] = themes_of(f.id)
        f.themes = list(cache[f.id])


def select(findings: List[Finding], wanted: Iterable[str] | None) -> List[Finding]:
    """The findings in any of the wanted themes; all of them when none are wanted."""
    chosen = set(wanted or ())
    if not chosen:
        return findings
    return [f for f in findings if chosen & set(f.themes)]


def parse(values: Iterable[str]) -> list[str]:
    """Theme names from --theme (repeatable, comma-separated). Raises ValueError on unknown."""
    out: list[str] = []
    for value in values:
        for name in value.split(","):
            name = name.strip().lower()
            if not name:
                continue
            if name not in THEMES:
                raise ValueError(f"unknown theme {name!r}; use one of {', '.join(THEMES)}")
            if name not in out:
                out.append(name)
    return out


DOC_START, DOC_END = "<!-- themes:start -->", "<!-- themes:end -->"


def docs_table() -> str:
    """The themes-per-rule table in docs/CF_RULES.md (tests/test_themes.py keeps it current)."""
    from aws_arch_agent.rules.cf_template import CF_THEMES
    from aws_arch_agent.rules.registry import ALL_RULES

    rows = [(rid, CF_THEMES[rid]) for rid in sorted(CF_THEMES)]
    rows += [(rule.id, rule.themes) for rule in sorted(ALL_RULES, key=lambda r: r.id)]
    lines = ["| Rule | Themes |", "|------|--------|"]
    lines += [f"| {rid} | {', '.join(t)} |" for rid, t in rows]
    return "\n".join(lines)
