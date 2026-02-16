"""V1 pipeline: collect files, run rules, optional LLM polish, return report."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from aws_arch_agent.models import RepoContext, Finding
from aws_arch_agent.rules.registry import ALL_RULES
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


def analyze_v1(
    repo_path: Path,
    max_files: int = 400,
    use_llm: bool = True,
    rules_include: list[str] | None = None,
    rules_exclude: list[str] | None = None,
    severity_threshold: str | None = None,
) -> tuple[str, RepoContext, list[Finding]]:
    """Run V1 pipeline: scan repo, run rules, optionally polish with LLM; return (report_md, ctx, findings)."""
    files = iter_files(repo_path, max_files=max_files)
    language = detect_language(repo_path)
    ctx = RepoContext(
        repo_path=str(repo_path),
        language=language,
        files_scanned=len(files),
        key_files=[p.name for p in files if p.name in {"cdk.json", "package.json", "requirements.txt"}],
    )

    rules = _filter_rules(ALL_RULES, rules_include, rules_exclude)
    findings: list[Finding] = []
    for lang in _languages_to_scan(language):
        for rule in rules:
            try:
                findings.extend(rule.run(repo_path, lang))
            except Exception as e:
                logger.debug("Rule %s failed for %s: %s", rule.id, lang, e)
                continue

    if severity_threshold:
        sev_order = ("Low", "Medium", "High")
        try:
            idx = sev_order.index(severity_threshold.capitalize())
            allowed = set(sev_order[idx:])
            findings = [f for f in findings if f.severity in allowed]
        except ValueError:
            pass

    draft = render_markdown(ctx, findings)
    if not use_llm:
        return draft, ctx, findings
    llm = LLMClient()
    polished = llm.polish(draft)
    return polished, ctx, findings


def collect_ctx_findings(
    repo_path: Path,
    max_files: int = 400,
    rules_include: list[str] | None = None,
    rules_exclude: list[str] | None = None,
    severity_threshold: str | None = None,
) -> tuple[RepoContext, list[Finding]]:
    """Run rules only and return context and findings (for JSON export or custom rendering)."""
    files = iter_files(repo_path, max_files=max_files)
    language = detect_language(repo_path)
    ctx = RepoContext(
        repo_path=str(repo_path),
        language=language,
        files_scanned=len(files),
        key_files=[p.name for p in files if p.name in {"cdk.json", "package.json", "requirements.txt"}],
    )
    rules = _filter_rules(ALL_RULES, rules_include, rules_exclude)
    findings: list[Finding] = []
    for lang in _languages_to_scan(language):
        for rule in rules:
            try:
                findings.extend(rule.run(repo_path, lang))
            except Exception as e:
                logger.debug("Rule %s failed for %s: %s", rule.id, lang, e)
                continue
    if severity_threshold:
        sev_order = ("Low", "Medium", "High")
        try:
            idx = sev_order.index(severity_threshold.capitalize())
            findings = [f for f in findings if f.severity in set(sev_order[idx:])]
        except ValueError:
            pass
    return ctx, findings
