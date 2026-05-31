"""CLI entrypoint for aws-arch-agent (Typer app and analyze command)."""
from __future__ import annotations

from pathlib import Path
from typing import cast

import typer
from rich.console import Console
from rich.panel import Panel

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.agent.v2_graph import analyze_v2
from aws_arch_agent.baseline import (
    DEFAULT_BASELINE_NAME,
    filter_new_findings,
    load_baseline,
    merge_into_baseline,
    save_baseline,
)
from aws_arch_agent.config import LLMMode, OutputFormat, SeverityThreshold, load_config
from aws_arch_agent.report.json_report import render_json
from aws_arch_agent.report.sarif import render_sarif

app = typer.Typer(add_completion=False, help="AWS CDK architecture reviewer (agentic).")
console = Console()

SEVERITY_ORDER = ("Low", "Medium", "High")


def _should_fail(fail_on: str, findings: list) -> bool:
    """Return True if any finding has severity at or above fail_on threshold."""
    if fail_on == "none":
        return False
    try:
        idx = SEVERITY_ORDER.index(fail_on.capitalize())
        threshold = set(SEVERITY_ORDER[idx:])
        return any(f.severity in threshold for f in findings)
    except ValueError:
        return False


def _resolve_baseline_path(repo_path: Path, baseline: str | None) -> Path:
    if baseline:
        return Path(baseline).expanduser().resolve()
    return repo_path / DEFAULT_BASELINE_NAME


@app.command()
def analyze(
    repo: str | None = typer.Option(None, "--repo", "-r", help="Path to repo (required unless --templates is set; then defaults to templates path)"),
    out: str = typer.Option("report.md", "--out", "-o", help="Output report path"),
    mode: str = typer.Option("v1", "--mode", help="v1 (rules) or v2 (LangGraph multi-agent)"),
    max_files: int = typer.Option(400, "--max-files", help="Max files to scan"),
    config: str | None = typer.Option(None, "--config", help="Path to config file (JSON or YAML)"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown | json | sarif"),
    fail_on: str = typer.Option(
        "none", "--fail-on", help="Exit non-zero if any finding has this severity or higher (high|medium|low|none)"
    ),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM polish / agent reasoning"),
    llm_mode: str = typer.Option("full", "--llm-mode", help="V2 LLM strategy: full (6 pillar calls) or compact (single call)"),
    templates: str | None = typer.Option(None, "--templates", help="Path to CloudFormation templates (dir or file); V2 only, skips cdk synth"),
    no_synth: bool = typer.Option(False, "--no-synth", help="Do not run cdk synth; V2 only (static analysis or use with --templates)"),
    rag: str | None = typer.Option(None, "--rag", help="Path to RAG doc (e.g. Well-Architected markdown); V2 only"),
    suggestions: str | None = typer.Option(None, "--suggestions", help="Write findings with suggested code to this JSON file"),
    baseline: str | None = typer.Option(None, "--baseline", help="Path to baseline file for suppressions"),
    enforce_baseline: bool = typer.Option(False, "--enforce-baseline", help="Only fail on findings not in baseline"),
    update_baseline: bool = typer.Option(False, "--update-baseline", help="Add current findings to baseline file"),
):
    """Run architecture review on a CDK repo (V1 or V2 mode) and write report."""
    resolved_repo = repo if repo is not None else templates
    if resolved_repo is None:
        raise typer.BadParameter("Either --repo or --templates is required.")
    repo_path = Path(resolved_repo).expanduser().resolve()
    if not repo_path.exists():
        raise typer.BadParameter(f"Repo path does not exist: {repo_path}")
    if repo_path.is_file():
        repo_path = repo_path.parent

    fmt = format if format in ("markdown", "json", "sarif") else "markdown"
    resolved_llm_mode = llm_mode if llm_mode in ("full", "compact") else "full"

    cfg = load_config(
        repo_path,
        Path(config) if config else None,
        format=cast(OutputFormat, fmt),
        fail_on=cast(SeverityThreshold, fail_on.lower() if fail_on.lower() in ("high", "medium", "low", "none") else "none"),
        no_llm=no_llm,
        out=out,
        templates=templates,
        no_synth=no_synth,
        rag_path=rag,
        llm_mode=cast(LLMMode, resolved_llm_mode),
    )

    out_path = Path(cfg.out).expanduser().resolve()
    console.print(Panel.fit(
        f"[bold]Analyzing[/bold] {repo_path}\nMode: {mode} | Format: {cfg.format} | LLM: {'off' if cfg.no_llm else 'on'}",
        title="aws-arch-agent",
    ))

    use_llm = not cfg.no_llm
    rules_include = cfg.rules_include
    rules_exclude = cfg.rules_exclude
    severity_threshold = cfg.severity_threshold

    if mode.lower() == "v2":
        report_md, ctx, findings, warnings = analyze_v2(
            repo_path,
            max_files=max_files,
            use_llm=use_llm,
            rules_include=rules_include,
            rules_exclude=rules_exclude,
            severity_threshold=severity_threshold,
            templates_path=cfg.templates,
            skip_synth=cfg.no_synth,
            rag_path=cfg.rag_path,
            rag_use_embeddings=cfg.rag_use_embeddings,
            rag_embedding_provider=cfg.rag_embedding_provider,
            rag_embedding_model=cfg.rag_embedding_model,
            llm_mode=cast(LLMMode, cfg.llm_mode),
        )
    else:
        report_md, ctx, findings, warnings = analyze_v1(
            repo_path,
            max_files=max_files,
            use_llm=use_llm,
            rules_include=rules_include,
            rules_exclude=rules_exclude,
            severity_threshold=severity_threshold,
        )

    baseline_path = _resolve_baseline_path(repo_path, baseline)
    if update_baseline:
        existing = load_baseline(baseline_path)
        merged = merge_into_baseline(existing, findings)
        save_baseline(baseline_path, merged)
        console.print(f"Updated baseline: [bold]{baseline_path}[/bold] ({len(merged)} entries)")

    findings_for_fail = findings
    if enforce_baseline:
        accepted = load_baseline(baseline_path)
        if accepted:
            findings_for_fail = filter_new_findings(findings, accepted)

    if cfg.format == "json":
        content = render_json(ctx, findings, warnings=warnings)
    elif cfg.format == "sarif":
        content = render_sarif(ctx, findings, warnings=warnings)
    else:
        content = report_md

    out_path.write_text(content, encoding="utf-8")
    console.print(f"Wrote report to: [bold]{out_path}[/bold]")

    if suggestions:
        suggestions_path = Path(suggestions).expanduser().resolve()
        suggestions_path.write_text(render_json(ctx, findings, warnings=warnings), encoding="utf-8")
        console.print(f"Wrote suggestions to: [bold]{suggestions_path}[/bold]")

    if warnings:
        console.print(f"[yellow]{len(warnings)} rule(s) failed during analysis (see report warnings)[/yellow]")

    if _should_fail(cfg.fail_on, findings_for_fail):
        console.print(f"[red]fail-on={cfg.fail_on}: findings at or above threshold[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
