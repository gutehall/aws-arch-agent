"""Pydantic models for repo context and findings."""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Literal, Optional, List, Dict, Any


Severity = Literal["High", "Medium", "Low"]


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


class RepoContext(BaseModel):
    """Context about the scanned repo (path, language, file count, optional notes)."""

    repo_path: str
    language: Literal["typescript", "python", "unknown"] = "unknown"
    files_scanned: int = 0
    key_files: List[str] = Field(default_factory=list)
    notes: Dict[str, Any] = Field(default_factory=dict)
