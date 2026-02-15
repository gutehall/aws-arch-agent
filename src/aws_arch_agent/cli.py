"""CLI entrypoint for aws-arch-agent (Typer app and analyze command)."""
from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from pathlib import Path

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.agent.v2_graph import analyze_v2
from aws_arch_agent.config import load_config
from aws_arch_agent.report.json_report import render_json

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


@app.command()
def analyze(
    repo: str = typer.Option(..., "--repo", "-r", help="Path to CDK repository"),
    out: str = typer.Option("report.md", "--out", "-o", help="Output report path"),
    mode: str = typer.Option("v1", "--mode", help="v1 (rules) or v2 (LangGraph multi-agent)"),
    max_files: int = typer.Option(400, "--max-files", help="Max files to scan"),
    config: str | None = typer.Option(None, "--config", help="Path to config file"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown | json"),
    fail_on: str = typer.Option(
        "none", "--fail-on", help="Exit non-zero if any finding has this severity or higher (high|medium|low|none)"
    ),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM polish / agent reasoning"),
    rag: str | None = typer.Option(None, "--rag", help="Path to RAG doc (e.g. Well-Architected markdown); V2 only"),
    suggestions: str | None = typer.Option(None, "--suggestions", help="Write findings with suggested code to this JSON file"),
):
    """Run architecture review on a CDK repo (V1 or V2 mode) and write report."""
    repo_path = Path(repo).expanduser().resolve()
    if not repo_path.exists():
        raise typer.BadParameter(f"Repo path does not exist: {repo_path}")

    cfg = load_config(
        repo_path,
        Path(config) if config else None,
        format=format if format in ("markdown", "json") else "markdown",
        fail_on=fail_on.lower() if fail_on.lower() in ("high", "medium", "low", "none") else "none",
        no_llm=no_llm,
        out=out,
        rag_path=rag,
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
        report_md, ctx, findings = analyze_v2(
            repo_path,
            max_files=max_files,
            use_llm=use_llm,
            rules_include=rules_include,
            rules_exclude=rules_exclude,
            severity_threshold=severity_threshold,
            rag_path=cfg.rag_path,
            rag_use_embeddings=cfg.rag_use_embeddings,
            rag_embedding_provider=cfg.rag_embedding_provider,
            rag_embedding_model=cfg.rag_embedding_model,
        )
    else:
        report_md, ctx, findings = analyze_v1(
            repo_path,
            max_files=max_files,
            use_llm=use_llm,
            rules_include=rules_include,
            rules_exclude=rules_exclude,
            severity_threshold=severity_threshold,
        )

    if cfg.format == "json":
        content = render_json(ctx, findings)
    else:
        content = report_md

    out_path.write_text(content, encoding="utf-8")
    console.print(f"Wrote report to: [bold]{out_path}[/bold]")

    if suggestions:
        suggestions_path = Path(suggestions).expanduser().resolve()
        suggestions_path.write_text(render_json(ctx, findings), encoding="utf-8")
        console.print(f"Wrote suggestions to: [bold]{suggestions_path}[/bold]")

    if _should_fail(cfg.fail_on, findings):
        console.print(f"[red]fail-on={cfg.fail_on}: findings at or above threshold[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
