"""Pydantic models for repo context and findings."""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Literal, List, Dict, Any

from aws_arch_agent.tools.llm import NO_CALL, LLMResult


Severity = Literal["High", "Medium", "Low"]
Effort = Literal["low", "medium", "high"]
IacSource = Literal["cdk", "cloudformation", "terraform", "mixed"]
VerdictValue = Literal["confirm", "false_positive", "unsure"]

_VERDICT_LABELS: Dict[str, str] = {
    "confirm": "confirmed",
    "false_positive": "likely false positive",
    "unsure": "unsure",
}


class Verdict(BaseModel):
    """What the model said about one finding. It labels the finding and changes nothing else."""

    verdict: VerdictValue
    why: str

    @property
    def label(self) -> str:
        """The words the Markdown and HTML reports show."""
        return _VERDICT_LABELS[self.verdict]


class Finding(BaseModel):
    """A single architecture finding (rule result) with id, severity, and recommendation."""

    id: str
    title: str
    severity: Severity = "Medium"
    category: str = "Best Practices"
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    recommendation: str
    suggested_code: str | None = None
    # Estimates, from the offline price snapshot. Savings are their own number,
    # never subtracted from the cost. None means the finding has too little to price.
    monthly_cost_usd: float | None = None
    monthly_savings_usd: float | None = None
    estimate_basis: str | None = None
    # How much work the fix is: low = one property, applied in place; high = the
    # resource is replaced or redesigned. Set from rules/effort.py.
    effort: Effort = "medium"
    # The environment of the stack the finding came from; unknown is judged as
    # prod. None for findings not tied to a template (CDK source rules).
    environment: Literal["prod", "staging", "dev", "unknown"] | None = None
    # The rule's themes: finops, security-baseline, identity, data-protection,
    # network-exposure, resilience, observability, sustainability.
    themes: List[str] = Field(default_factory=list)
    # The model's opinion. Excluded so JSON findings, SARIF, the baseline and fail-on cannot
    # depend on it; the renderers that show it read it explicitly.
    verdict: Verdict | None = Field(default=None, exclude=True)


class Hypothesis(BaseModel):
    """A catalog rule the model thinks the scanner missed. No check confirmed it; never a Finding."""

    rule_id: str
    title: str
    file: str
    line: int
    why: str
    unverified: Literal[True] = True


class RepoContext(BaseModel):
    """Context about the scanned repo (path, language, file count, optional notes)."""

    repo_path: str
    language: Literal["typescript", "python", "unknown"] = "unknown"
    source: IacSource = "cdk"
    files_scanned: int = 0
    key_files: List[str] = Field(default_factory=list)
    notes: Dict[str, Any] = Field(default_factory=dict)
    # Run-level LLM outcome. Excluded from `context`: the JSON report has its own `llm`.
    llm: LLMResult = Field(default=NO_CALL, exclude=True)
    # Excluded from `context` too: the JSON report has its own `hypotheses`.
    hypotheses: List[Hypothesis] = Field(default_factory=list, exclude=True)
    # Apart from `llm`, which is the verdict calls: a label shows only when `llm` is ok, and
    # the larger hypothesis prompt failing must not take good verdicts with it.
    hypothesis_llm: LLMResult = Field(default=NO_CALL, exclude=True)
