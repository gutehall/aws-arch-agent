"""CLI entrypoint for aws-arch-agent (Typer app and analyze command)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import NoReturn, cast

import typer
from rich.console import Console
from rich.panel import Panel

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.agent.v2_graph import analyze_v2
from aws_arch_agent.baseline import (
    DEFAULT_BASELINE_NAME,
    BaselineError,
    Fingerprint,
    filter_new_findings,
    is_baselined,
    load_baseline,
    merge_into_baseline,
    save_baseline,
)
from aws_arch_agent.config import (
    ConfigError,
    LLMMode,
    OutputFormat,
    SeverityThreshold,
    load_config,
)
from aws_arch_agent.models import Finding
from aws_arch_agent.report.json_report import render_json
from aws_arch_agent.report.sarif import render_sarif

app = typer.Typer(add_completion=False, help="AWS CDK architecture reviewer (agentic).")
console = Console()

SEVERITY_ORDER = ("Low", "Medium", "High")
_MODES = ("v1", "v2")
_FORMATS = ("markdown", "json", "sarif")
_FAIL_ON = ("high", "medium", "low", "none")
_LLM_MODES = ("full", "compact")


def _passed(ctx: typer.Context, name: str) -> bool:
    """True when the user passed this flag on the command line."""
    source = ctx.get_parameter_source(name)
    return getattr(source, "name", None) == "COMMANDLINE"


def _require_choice(value: str, allowed: tuple[str, ...], label: str) -> str:
    token = value.strip().lower()
    if token not in allowed:
        raise typer.BadParameter(f"{label} must be one of {', '.join(allowed)} (got {value!r})")
    return token


def _should_fail(fail_on: str, findings: list) -> bool:
    """Return True if any finding has severity at or above fail_on threshold."""
    if fail_on == "none":
        return False
    try:
        idx = SEVERITY_ORDER.index(fail_on.capitalize())
    except ValueError as exc:
        raise typer.BadParameter(
            f"--fail-on must be one of {', '.join(_FAIL_ON)} (got {fail_on!r})"
        ) from exc
    threshold = set(SEVERITY_ORDER[idx:])
    return any(f.severity in threshold for f in findings)


def _resolve_baseline_path(repo_path: Path, baseline: str | None) -> Path:
    if baseline:
        return Path(baseline).expanduser().resolve()
    return repo_path / DEFAULT_BASELINE_NAME


def _finding_location(finding: Finding) -> str:
    if not finding.file:
        return ""
    if finding.line is None:
        return f" `{finding.file}`"
    return f" `{finding.file}` line {finding.line}"


def _mark_baselined(
    content: str,
    fmt: str,
    findings: list[Finding],
    accepted: set[Fingerprint],
) -> str:
    """Keep every finding and label which ones were already accepted."""
    if fmt == "json":
        data = json.loads(content)
        for item, finding in zip(data.get("findings", []), findings):
            item["baselined"] = is_baselined(finding, accepted)
        return json.dumps(data, indent=2)
    if fmt == "sarif":
        data = json.loads(content)
        results = data["runs"][0]["results"]
        for result, finding in zip(results, findings):
            props = result.setdefault("properties", {})
            props["baselined"] = is_baselined(finding, accepted)
        return json.dumps(data, indent=2)

    lines = [
        "",
        "## Baseline",
        "",
        "Accepted findings stay in the report and do not fail the build.",
        "",
    ]
    if not findings:
        lines.append("- No findings.")
    for finding in findings:
        state = "accepted" if is_baselined(finding, accepted) else "new"
        lines.append(f"- [{finding.id}]{_finding_location(finding)} — {state}")
    return content.rstrip() + "\n" + "\n".join(lines) + "\n"


def _fail(message: str) -> NoReturn:
    console.print(f"[red]{message}[/red]")
    raise typer.Exit(code=1)


@app.command()
def analyze(
    ctx: typer.Context,
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

    mode_value = _require_choice(mode, _MODES, "--mode")
    if _passed(ctx, "format"):
        _require_choice(format, _FORMATS, "--format")
    if _passed(ctx, "fail_on"):
        _require_choice(fail_on, _FAIL_ON, "--fail-on")
    if _passed(ctx, "llm_mode"):
        _require_choice(llm_mode, _LLM_MODES, "--llm-mode")

    try:
        cfg = load_config(
            repo_path,
            Path(config) if config is not None and _passed(ctx, "config") else None,
            format=cast(OutputFormat, format) if _passed(ctx, "format") else None,
            fail_on=cast(SeverityThreshold, fail_on.lower()) if _passed(ctx, "fail_on") else None,
            no_llm=no_llm if _passed(ctx, "no_llm") else None,
            out=out if _passed(ctx, "out") else None,
            templates=templates if _passed(ctx, "templates") else None,
            no_synth=no_synth if _passed(ctx, "no_synth") else None,
            rag_path=rag if _passed(ctx, "rag") else None,
            llm_mode=cast(LLMMode, llm_mode.lower()) if _passed(ctx, "llm_mode") else None,
        )
    except ConfigError as exc:
        _fail(str(exc))

    out_path = Path(cfg.out).expanduser().resolve()
    baseline_path = _resolve_baseline_path(repo_path, baseline)
    accepted_before: set[Fingerprint] | None = None
    if enforce_baseline or update_baseline:
        try:
            accepted_before = load_baseline(baseline_path)
        except BaselineError as exc:
            _fail(str(exc))

    console.print(Panel.fit(
        f"[bold]Analyzing[/bold] {repo_path}\nMode: {mode_value} | Format: {cfg.format} | LLM: {'off' if cfg.no_llm else 'on'}",
        title="aws-arch-agent",
    ))

    use_llm = not cfg.no_llm
    rules_include = cfg.rules_include
    rules_exclude = cfg.rules_exclude
    severity_threshold = cfg.severity_threshold

    if mode_value == "v2":
        report_md, ctx_report, findings, warnings = analyze_v2(
            repo_path,
            max_files=max_files,
            use_llm=use_llm,
            rules_include=rules_include,
            rules_exclude=rules_exclude,
            rules_org=cfg.rules_org,
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
        report_md, ctx_report, findings, warnings = analyze_v1(
            repo_path,
            max_files=max_files,
            use_llm=use_llm,
            rules_include=rules_include,
            rules_exclude=rules_exclude,
            rules_org=cfg.rules_org,
            severity_threshold=severity_threshold,
        )

    if update_baseline:
        merged = merge_into_baseline(accepted_before or set(), findings)
        try:
            save_baseline(baseline_path, merged)
        except OSError as exc:
            _fail(f"Failed to write baseline {baseline_path}: {exc}")
        console.print(f"Updated baseline: [bold]{baseline_path}[/bold] ({len(merged)} entries)")

    findings_for_fail = findings
    if enforce_baseline:
        findings_for_fail = filter_new_findings(findings, accepted_before or set())

    if cfg.format == "json":
        content = render_json(ctx_report, findings, warnings=warnings)
    elif cfg.format == "sarif":
        content = render_sarif(ctx_report, findings, warnings=warnings)
    else:
        content = report_md

    if enforce_baseline:
        content = _mark_baselined(content, cfg.format, findings, accepted_before or set())

    out_path.write_text(content, encoding="utf-8")
    console.print(f"Wrote report to: [bold]{out_path}[/bold]")

    if suggestions:
        suggestions_path = Path(suggestions).expanduser().resolve()
        suggestions_path.write_text(render_json(ctx_report, findings, warnings=warnings), encoding="utf-8")
        console.print(f"Wrote suggestions to: [bold]{suggestions_path}[/bold]")

    if warnings:
        console.print(f"[yellow]{len(warnings)} check(s) failed during analysis (see report warnings)[/yellow]")

    severity_hit = _should_fail(cfg.fail_on, findings_for_fail)
    if severity_hit:
        console.print(f"[red]fail-on={cfg.fail_on}: findings at or above threshold[/red]")
    if warnings:
        raise typer.Exit(code=2)
    if severity_hit:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
