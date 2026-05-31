"""V1 pipeline: collect files, run rules, optional LLM polish, return report."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from aws_arch_agent.models import RepoContext, Finding
from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.runner import filter_by_severity, run_all_rules
from aws_arch_agent.report.markdown import render_markdown
from aws_arch_agent.tools.llm import LLMClient
from aws_arch_agent.tools.files import iter_files

logger = logging.getLogger(__name__)


RepoLanguage = Literal["typescript", "python", "unknown"]


def detect_language(repo_path: Path) -> RepoLanguage:
    """Return 'typescript', 'python', or 'unknown' from repo contents."""
    # Check for marker files first (fast path)
    if (repo_path / "package.json").exists() or (repo_path / "cdk.json").exists():
        return "typescript"
    if (repo_path / "requirements.txt").exists() or (repo_path / "setup.py").exists():
        return "python"
    
    # Quick check for files without walking entire tree (limit search)
    # Only check top-level and common CDK directories
    check_dirs = [repo_path, repo_path / "lib", repo_path / "bin", repo_path / "src"]
    for check_dir in check_dirs:
        if not check_dir.exists():
            continue
        try:
            # Check just immediate children, not recursive
            if any(check_dir.glob("*.ts")):
                return "typescript"
            if any(check_dir.glob("*.py")):
                return "python"
        except (PermissionError, OSError):
            continue
    
    return "unknown"


def _languages_to_scan(language: str) -> list[str]:
    """Return list of languages to run rules for (both TS and PY when unknown)."""
    if language == "unknown":
        return ["typescript", "python"]
    return [language]


def _filter_rules(
    rules: list,
    include_ids: list[str] | None = None,
    exclude_ids: list[str] | None = None,
) -> list:
    out = list(rules)
    if include_ids is not None:
        out = [r for r in out if r.id in include_ids]
    if exclude_ids is not None:
        out = [r for r in out if r.id not in exclude_ids]
    return out


def _collect_findings(
    repo_path: Path,
    max_files: int,
    rules_include: list[str] | None,
    rules_exclude: list[str] | None,
    severity_threshold: str | None,
) -> tuple[RepoContext, list[Finding], list[str]]:
    files = iter_files(repo_path, max_files=max_files)
    language = detect_language(repo_path)
    ctx = RepoContext(
        repo_path=str(repo_path),
        language=language,
        files_scanned=len(files),
        key_files=[p.name for p in files if p.name in {"cdk.json", "package.json", "requirements.txt"}],
    )
    rules = _filter_rules(ALL_RULES, rules_include, rules_exclude)
    findings, warnings = run_all_rules(repo_path, rules, _languages_to_scan(language))
    findings = filter_by_severity(findings, severity_threshold)
    return ctx, findings, warnings


def analyze_v1(
    repo_path: Path,
    max_files: int = 400,
    use_llm: bool = True,
    rules_include: list[str] | None = None,
    rules_exclude: list[str] | None = None,
    severity_threshold: str | None = None,
) -> tuple[str, RepoContext, list[Finding], list[str]]:
    """Run V1 pipeline: scan repo, run rules, optionally polish with LLM; return (report_md, ctx, findings, warnings)."""
    ctx, findings, warnings = _collect_findings(
        repo_path, max_files, rules_include, rules_exclude, severity_threshold
    )

    draft = render_markdown(ctx, findings, warnings=warnings)
    if not use_llm:
        return draft, ctx, findings, warnings
    llm = LLMClient()
    polished = llm.polish(draft)
    return polished, ctx, findings, warnings


def collect_ctx_findings(
    repo_path: Path,
    max_files: int = 400,
    rules_include: list[str] | None = None,
    rules_exclude: list[str] | None = None,
    severity_threshold: str | None = None,
) -> tuple[RepoContext, list[Finding], list[str]]:
    """Run rules only and return context, findings, and warnings."""
    return _collect_findings(
        repo_path, max_files, rules_include, rules_exclude, severity_threshold
    )
