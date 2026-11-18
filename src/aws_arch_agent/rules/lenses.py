"""The AI Well-Architected lenses and the answer the scan computes for each lens question.

data/ai_lenses.json lists every question and best practice of the Machine Learning, Generative
AI, Responsible AI, and Agentic AI lenses. rules/lens_map.py says which best practices each
lens rule checks. The answers are computed the way the core ones are (rules/well_architected.py)
but kept in a second list: the 57 core questions, their report block, and RULE_BEST_PRACTICES
do not change.

Nothing here fetches the network. The catalog is a committed file.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.lens_map import LENS_RULE_BEST_PRACTICES
from aws_arch_agent.rules.well_architected import (
    Answer,
    BestPractice,
    Question,
    question_id_of_practice,
)

DATA_PATH = Path(__file__).with_name("data") / "ai_lenses.json"

# The lens ids, in the order the catalog lists them.
LENSES = ("machine-learning", "generative-ai", "responsible-ai", "agentic-ai")


@dataclass(frozen=True)
class LensQuestion(Question):
    lens: str = ""


@dataclass(frozen=True)
class LensAnswer(Answer):
    """A lens question's answer. The lens is on the answer so reports can group by it."""

    @property
    def lens(self) -> str:
        q = self.question
        return q.lens if isinstance(q, LensQuestion) else ""

    def to_dict(self) -> dict:
        out = super().to_dict()
        out["lens"] = self.lens
        return out


@lru_cache(maxsize=1)
def questions() -> tuple[LensQuestion, ...]:
    """Every question of the four lenses, lens by lens, in lens order."""
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    return tuple(
        LensQuestion(
            id=q["id"],
            pillar=q["pillar"],
            title=q["title"],
            url=q["url"],
            best_practices=tuple(BestPractice(b["id"], b["title"]) for b in q["best_practices"]),
            lens=q["lens"],
        )
        for q in data["questions"]
    )


def lens_best_practices_of(rule_id: str) -> tuple[str, ...]:
    """The lens best-practice ids a rule checks; () for a rule not in the lens map."""
    return LENS_RULE_BEST_PRACTICES.get(rule_id, ())


def lens_question_of(rule_id: str) -> str | None:
    """The lens question id a rule answers; None for a rule not in the lens map."""
    bps = lens_best_practices_of(rule_id)
    return question_id_of_practice(bps[0]) if bps else None


@lru_cache(maxsize=1)
def _rules_by_practice() -> dict[str, frozenset[str]]:
    by_bp: dict[str, set[str]] = {}
    for rid, bps in LENS_RULE_BEST_PRACTICES.items():
        for bp in bps:
            by_bp.setdefault(bp, set()).add(rid)
    return {bp: frozenset(rules) for bp, rules in by_bp.items()}


def lens_answers(
    findings: Iterable[Finding], ran: Iterable[str] | None = None
) -> List[LensAnswer]:
    """One answer per lens question, computed from the findings the same way as answers().

    ran is the rule ids that could report (RepoContext.rules_run); None means every lens rule.
    The caller decides whether the lenses apply (the AI gate); this computes them.
    """
    from aws_arch_agent.agent.v1 import ORG_RULE_IDS

    ids = LENS_RULE_BEST_PRACTICES if ran is None else set(ran)
    org_only = {
        bp for bp, rules in _rules_by_practice().items() if rules and rules <= ORG_RULE_IDS
    }
    checked = {bp for rid in ids for bp in LENS_RULE_BEST_PRACTICES.get(rid, ())}
    under: dict[str, List[Finding]] = {}
    for f in findings:
        qid = lens_question_of(f.id)
        if qid:
            under.setdefault(qid, []).append(f)
    out: List[LensAnswer] = []
    for q in questions():
        found = tuple(under.get(q.id, ()))
        missing = tuple(bp.id for bp in q.best_practices if bp.id not in checked)
        org = tuple(bp for bp in missing if bp in org_only)
        out.append(
            LensAnswer(q, met=not found and not missing, findings=found,
                       not_checked=missing, needs_org=org)
        )
    return out


def answers_for(ctx, findings: Iterable[Finding]) -> List[LensAnswer]:
    """The lens answers a report shows: all of them for an AI workload, else none."""
    if not getattr(ctx, "ai_lenses", False):
        return []
    return lens_answers(findings, ctx.rules_run)


LENS_TITLES = {
    "machine-learning": "Machine Learning Lens",
    "generative-ai": "Generative AI Lens",
    "responsible-ai": "Responsible AI Lens",
    "agentic-ai": "Agentic AI Lens",
}


def html_groups(items: List[LensAnswer]) -> List[dict]:
    """The lens answers grouped by lens, then pillar or focus area, as the HTML template reads them."""
    from aws_arch_agent.rules.well_architected import html_rows

    out: List[dict] = []
    for lens in LENSES:
        mine = [a for a in items if a.lens == lens]
        if not mine:
            continue
        rows = html_rows(mine)
        pillars: dict[str, list] = {}
        for a, row in zip(mine, rows):
            pillars.setdefault(a.question.pillar, []).append(row)
        out.append({
            "lens": lens,
            "title": LENS_TITLES[lens],
            "met": sum(1 for a in mine if a.met),
            "total": len(mine),
            "pillars": [
                {"name": name, "rows": rows_, "met": sum(1 for r in rows_ if r["met"])}
                for name, rows_ in pillars.items()
            ],
        })
    return out


def markdown_lines(items: List[LensAnswer]) -> List[str]:
    """The lens answers section: by lens, then pillar or focus area. Nothing for an empty list."""
    from aws_arch_agent.rules.well_architected import finding_rows

    if not items:
        return []
    lines = [
        "## AI Well-Architected lens answers",
        "",
        "The workload uses an AI service, so the four AI lenses are answered as well. Each answer "
        "is computed from the findings, as for the core questions above.",
        "",
    ]
    for lens in LENSES:
        mine = [a for a in items if a.lens == lens]
        if not mine:
            continue
        met = sum(1 for a in mine if a.met)
        lines.extend([f"### {LENS_TITLES[lens]}", "", f"{met} of {len(mine)} questions met.", ""])
        pillar = None
        for a in mine:
            if a.question.pillar != pillar:
                pillar = a.question.pillar
                lines.extend([f"#### {pillar}", ""])
            line = f"- **{a.question.id}** {a.question.title} — **{a.status}**"
            if not a.met:
                line += f" ({a.reason()})"
            lines.append(line)
            for rid, title, n in finding_rows(a):
                more = f" ×{n}" if n > 1 else ""
                lines.append(f"  - [{rid}] {title}{more}")
        lines.append("")
    return lines
