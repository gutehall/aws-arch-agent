"""The Well-Architected catalog and the answer the scan computes for each question.

data/well_architected.json lists every question and best practice of the current
framework. rules/wa_map.py says which best practices each rule checks. CDK, CloudFormation,
and Terraform scans read the same two tables.

A question is met when every one of its best practices is checked by a rule that ran in this
scan, and no finding falls under it. Otherwise it is not met: a best practice that no rule
checks yet, or whose rules did not run (another IaC source, --rules, --theme, or a severity
threshold), is not checked. The answer is computed from the findings alone: the
operator is not asked anything, and the LLM does not change it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List

from aws_arch_agent.models import Finding
from aws_arch_agent.rules.wa_map import RULE_BEST_PRACTICES

DATA_PATH = Path(__file__).with_name("data") / "well_architected.json"


@dataclass(frozen=True)
class BestPractice:
    id: str
    title: str


@dataclass(frozen=True)
class Question:
    id: str
    pillar: str
    title: str
    url: str
    best_practices: tuple[BestPractice, ...]


@dataclass(frozen=True)
class Answer:
    """One question's answer. findings are the ones under the question, in report order."""

    question: Question
    met: bool
    findings: tuple[Finding, ...]
    not_checked: tuple[str, ...]

    @property
    def status(self) -> str:
        return "met" if self.met else "not met"

    def reason(self) -> str:
        """Why it is not met, in a few words; empty when met."""
        parts: List[str] = []
        if self.findings:
            n = len(self.findings)
            parts.append(f"{n} finding{'s' if n != 1 else ''}")
        if self.not_checked:
            total = len(self.question.best_practices)
            parts.append(f"{len(self.not_checked)} of {total} best practices not checked")
        return "; ".join(parts)

    def to_dict(self) -> dict:
        return {
            "question": self.question.id,
            "pillar": self.question.pillar,
            "title": self.question.title,
            "status": self.status,
            "findings": [f.id for f in self.findings],
            "not_checked": list(self.not_checked),
        }


@lru_cache(maxsize=1)
def questions() -> tuple[Question, ...]:
    """Every question of the framework, in framework order."""
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    return tuple(
        Question(
            id=q["id"],
            pillar=q["pillar"],
            title=q["title"],
            url=q["url"],
            best_practices=tuple(BestPractice(b["id"], b["title"]) for b in q["best_practices"]),
        )
        for q in data["questions"]
    )


def question_id_of_practice(bp_id: str) -> str:
    """The question a best practice belongs to: SEC08-BP02 -> SEC 8."""
    head = bp_id.split("-", 1)[0]
    letters = head.rstrip("0123456789")
    return f"{letters} {int(head[len(letters):])}"


def best_practices_of(rule_id: str) -> tuple[str, ...]:
    """The best-practice ids a rule checks; () for an id no rule defines."""
    return RULE_BEST_PRACTICES.get(rule_id, ())


def question_of(rule_id: str) -> str | None:
    """The question id a rule answers; None for an id no rule defines."""
    bps = best_practices_of(rule_id)
    return question_id_of_practice(bps[0]) if bps else None


def annotate(findings: Iterable[Finding]) -> None:
    """Set each finding's question and best practices from its rule. Mutates the findings."""
    for f in findings:
        f.question = question_of(f.id)
        f.best_practices = list(best_practices_of(f.id))


def rules_run(
    active: Iterable[str],
    *,
    cdk: bool,
    templates: bool,
    theme_filter: Iterable[str] | None = None,
    severity_threshold: str | None = None,
) -> List[str]:
    """The rule ids a report can show findings for.

    active is the catalog less what the config turned off. cdk keeps the CDK source rules,
    templates the CF-* checks (CloudFormation, Terraform, or synth output). The repo-level
    REPO-* checks read the tree, so they run for either source. A theme filter
    keeps the rules in those themes. A severity threshold above Low hides findings of any
    rule, so then no rule counts.
    """
    from aws_arch_agent.rules.themes import themes_of

    if severity_threshold and severity_threshold.capitalize() != "Low":
        return []
    wanted = set(theme_filter or ())
    out = []
    for rid in active:
        if rid.startswith("REPO-"):
            if not (cdk or templates):
                continue
        elif not (templates if rid.startswith("CF-") else cdk):
            continue
        if wanted and not wanted & set(themes_of(rid)):
            continue
        out.append(rid)
    return out


def answers(findings: Iterable[Finding], ran: Iterable[str] | None = None) -> List[Answer]:
    """One answer per question, in framework order, computed from the findings.

    ran is the rule ids that could report (RepoContext.rules_run); None means every rule.
    """
    ids = RULE_BEST_PRACTICES if ran is None else set(ran)
    checked = {bp for rid in ids for bp in RULE_BEST_PRACTICES.get(rid, ())}
    under: dict[str, List[Finding]] = {}
    for f in findings:
        qid = question_of(f.id)
        if qid:
            under.setdefault(qid, []).append(f)
    out: List[Answer] = []
    for q in questions():
        found = tuple(under.get(q.id, ()))
        missing = tuple(bp.id for bp in q.best_practices if bp.id not in checked)
        out.append(Answer(q, met=not found and not missing, findings=found, not_checked=missing))
    return out


def finding_rows(answer: Answer) -> List[tuple[str, str, int]]:
    """(rule id, title, how many) for the findings under an answer, one row per rule."""
    rows: dict[str, tuple[str, int]] = {}
    for f in answer.findings:
        title, n = rows.get(f.id, (f.title, 0))
        rows[f.id] = (title, n + 1)
    return [(rid, title, n) for rid, (title, n) in rows.items()]


def html_rows(items: List[Answer]) -> List[dict]:
    """The answers as the HTML template reads them."""
    return [
        {
            "id": a.question.id,
            "title": a.question.title,
            "status": a.status,
            "met": a.met,
            "reason": a.reason(),
            "findings": finding_rows(a),
        }
        for a in items
    ]


def markdown_lines(items: List[Answer]) -> List[str]:
    """The answers section: one line per question, its findings under it."""
    met = sum(1 for a in items if a.met)
    lines = [
        "## Well-Architected answers",
        "",
        f"{met} of {len(items)} questions met. Each answer is computed from the findings; "
        "a question with a best practice this scan did not check is not met.",
        "",
    ]
    for a in items:
        line = f"- **{a.question.id}** {a.question.title} — **{a.status}**"
        if not a.met:
            line += f" ({a.reason()})"
        lines.append(line)
        for rid, title, n in finding_rows(a):
            more = f" ×{n}" if n > 1 else ""
            lines.append(f"  - [{rid}] {title}{more}")
    lines.append("")
    return lines
