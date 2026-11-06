"""Pydantic models for repo context and findings."""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Literal, List, Dict, Any


Severity = Literal["High", "Medium", "Low"]
IacSource = Literal["cdk", "cloudformation", "terraform", "mixed"]


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
    # Estimates (DM3-541), from the offline price snapshot. Savings are their own number,
    # never subtracted from the cost. None means the finding has too little to price.
    monthly_cost_usd: float | None = None
    monthly_savings_usd: float | None = None
    estimate_basis: str | None = None


class RepoContext(BaseModel):
    """Context about the scanned repo (path, language, file count, optional notes)."""

    repo_path: str
    language: Literal["typescript", "python", "unknown"] = "unknown"
    source: IacSource = "cdk"
    files_scanned: int = 0
    key_files: List[str] = Field(default_factory=list)
    notes: Dict[str, Any] = Field(default_factory=dict)
