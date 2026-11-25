"""CLI entrypoint for aws-arch-agent (Typer app and analyze command)."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import NoReturn, cast

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from aws_arch_agent import __version__, pricing, suppressions
from aws_arch_agent.agent.v1 import IAC_CHOICES, IacError, analyze_v1, resolve_source
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
    RunConfig,
    SeverityThreshold,
    load_config,
)
from aws_arch_agent.models import Finding, IacSource, RepoContext
from aws_arch_agent.progress import ScanProgress, use_progress
from aws_arch_agent.pricing import usage as usage_profile
from aws_arch_agent.rules import account, cost_diff, stack_cost
from aws_arch_agent.rules.themes import THEMES
from aws_arch_agent.report.json_report import render_json
from aws_arch_agent.report.html import render_html
from aws_arch_agent.report.summary import _span_text, build_summary, terminal_lines
from aws_arch_agent.report.sarif import BASELINE_SUPPRESSION, render_sarif
from aws_arch_agent.tools.files import iter_files, truncation_message

app = typer.Typer(
    add_completion=False,
    help="AWS Well-Architected reviewer for CDK, CloudFormation, and Terraform repos, "
    "with optional read-only live account checks and AI lens answers for Bedrock, "
    "SageMaker, and AgentCore workloads.",
)
console = Console()

SEVERITY_ORDER = ("Low", "Medium", "High")
_MODES = ("auto", "v1", "v2")
_FORMATS = ("markdown", "json", "sarif", "html")
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


def _verdict_line(findings: list[Finding]) -> str | None:
    """How many findings the model judged, so a capped or partial run says so. None if none."""
    judged = sum(1 for f in findings if f.verdict is not None)
    return f"Verdicts: {judged} of {len(findings)} findings judged" if judged else None


def _hypothesis_line(ctx: RepoContext) -> str | None:
    """What the hypothesis call did. None when no call was made."""
    result = ctx.hypothesis_llm
    if result.status == "skipped":
        return None
    if result.status == "ok":
        return f"Hypotheses: {len(ctx.hypotheses)} unverified"
    return f"Hypotheses: {result.status} ({result.reason})"


def _resolve_baseline_path(repo_path: Path, baseline: str | None) -> Path:
    if baseline:
        return Path(baseline).expanduser().resolve()
    return repo_path / DEFAULT_BASELINE_NAME


def _finding_location(finding: Finding) -> str:
    if not finding.file:
        return ""
    if finding.line is None:
        return f" `{_span_text(finding.file)}`"
    return f" `{_span_text(finding.file)}` line {finding.line}"


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
            if props["baselined"]:
                result.setdefault("suppressions", []).append(dict(BASELINE_SUPPRESSION))
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
    console.print(message, style="red", markup=False)
    raise typer.Exit(code=1)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


def _v2_installed() -> bool:
    """Whether the v2 extra (LangGraph) can be imported."""
    try:
        import aws_arch_agent.agent.v2_graph  # noqa: F401
    except ImportError:
        return False
    return True


def _synth_available() -> bool:
    """Whether `npx cdk synth` can run (Node.js on PATH)."""
    return shutil.which("npx") is not None


def _auto_mode(
    source: str | None, templates: bool, no_synth: bool = False, cdk_app: bool = True,
) -> tuple[str, str | None]:
    """--mode auto: V2 where it adds something (CDK synth and its cost, --templates), else V1.

    Returns (mode, note): the note says why a CDK repo stayed on V1."""
    if templates:
        if _v2_installed():
            return "v2", None
        return "v1", ("--templates needs V2, and the v2 extra is not installed "
                      "(pip install 'aws-arch-agent[v2]'): scanning with V1, which ignores --templates.")
    if source != "cdk":
        return "v1", None
    if no_synth:
        return "v1", "CDK detected, but --no-synth is set: scanning with V1, which does not synthesise or price the stacks."
    if not cdk_app:
        return "v1", ("CDK detected, but there is no cdk.json at the repo root to synth: scanning with V1, "
                      "which does not synthesise or price the stacks. Pass --mode v2 with --templates cdk.out "
                      "to price synthesised stacks.")
    missing = [what for ok, what in ((_v2_installed(), "the v2 extra (pip install 'aws-arch-agent[v2]')"),
                                     (_synth_available(), "Node.js (npx)")) if not ok]
    if not missing:
        return "v2", None
    return "v1", (f"CDK detected, but synth needs {' and '.join(missing)}: scanning with V1, "
                  "which does not synthesise or price the stacks.")


def _run(
    mode_value: str, repo_path: Path, max_files: int, use_llm: bool, cfg: RunConfig, iac_value: str,
    tf_plan_path: Path | None, account_facts: account.AccountFacts | None, finops: stack_cost.FinOps,
) -> tuple[str, RepoContext, list[Finding], list[str]]:
    """Run the V1 or V2 pipeline with the resolved options."""
    if mode_value == "v2":
        from aws_arch_agent.agent.v2_graph import analyze_v2

        return analyze_v2(
            repo_path,
            max_files=max_files,
            use_llm=use_llm,
            rules_include=cfg.rules_include,
            rules_exclude=cfg.rules_exclude,
            rules_org=cfg.rules_org,
            severity_threshold=cfg.severity_threshold,
            templates_path=cfg.templates,
            skip_synth=cfg.no_synth,
            rag_path=cfg.rag_path,
            rag_use_embeddings=cfg.rag_use_embeddings,
            rag_embedding_provider=cfg.rag_embedding_provider,
            rag_embedding_model=cfg.rag_embedding_model,
            llm_mode=cast(LLMMode, cfg.llm_mode),
            iac=iac_value,
            tf_plan=tf_plan_path,
            price_region=cfg.region,
            tag_policy=cfg.tag_policy,
            environment_map=cfg.environments,
            nonprod_max_size=cfg.nonprod_max_size,
            dashboards_min_resources=cfg.dashboards_min_resources,
            theme_filter=cfg.themes,
            group_by=cfg.group_by,
            account_facts=account_facts,
            lenses_ai=cfg.lenses_ai,
            rules_exclude_paths=cfg.rules_exclude_paths,
            finops=finops,
        )
    return analyze_v1(
        repo_path,
        max_files=max_files,
        use_llm=use_llm,
        rules_include=cfg.rules_include,
        rules_exclude=cfg.rules_exclude,
        rules_org=cfg.rules_org,
        severity_threshold=cfg.severity_threshold,
        iac=iac_value,
        tf_plan=tf_plan_path,
        price_region=cfg.region,
        tag_policy=cfg.tag_policy,
        environment_map=cfg.environments,
        nonprod_max_size=cfg.nonprod_max_size,
        dashboards_min_resources=cfg.dashboards_min_resources,
        theme_filter=cfg.themes,
        group_by=cfg.group_by,
        account_facts=account_facts,
        lenses_ai=cfg.lenses_ai,
        rules_exclude_paths=cfg.rules_exclude_paths,
        finops=finops,
    )


@app.command()
def analyze(
    ctx: typer.Context,
    repo: str | None = typer.Option(None, "--repo", "-r", help="Path to repo (required unless --templates is set; then defaults to templates path)"),
    out: str = typer.Option(
        "report.html", "--out", "-o",
        help="Output report path (default report.<format extension>). Without --format, its suffix "
             "(.md, .json, .sarif, .html) picks the format",
    ),
    mode: str = typer.Option(
        "auto", "--mode",
        help="auto (default: v2 for CDK when the v2 extra and npx are installed, so CDK stacks are "
             "synthesised and priced; v1 otherwise), v1 (rules), or v2 (LangGraph multi-agent)",
    ),
    iac: str = typer.Option(
        "auto", "--iac", help="IaC source: auto | cdk | cloudformation | terraform"
    ),
    tf_plan: str | None = typer.Option(
        None,
        "--tf-plan",
        help="`terraform show -json` output; fills var/local values, count and for_each instances in Terraform scans",
    ),
    live_account: bool = typer.Option(
        False,
        "--live-account",
        help="Read the AWS account (read-only describe/list calls) for Security Hub, GuardDuty, "
        "Config, CloudTrail, Budgets, a cost and usage report, Access Analyzer and Inspector. "
        "Off by default: a scan makes no AWS call. Needs boto3 and credentials",
    ),
    max_files: int = typer.Option(
        400, "--max-files", help="Max files to scan. Rules search only these files."
    ),
    config: str | None = typer.Option(None, "--config", help="Path to config file (JSON or YAML)"),
    format: str = typer.Option(
        "html", "--format", "-f",
        help="Output format: html (default) | markdown | json | sarif. Default: from --out's suffix, else html",
    ),
    fail_on: str = typer.Option(
        "none", "--fail-on", help="Exit non-zero if any finding has this severity or higher (high|medium|low|none)"
    ),
    no_llm: bool = typer.Option(False, "--no-llm", help="Make no LLM calls: no verdicts, no hypotheses"),
    llm_mode: str = typer.Option("full", "--llm-mode", help="V2 LLM strategy: full (6 pillar calls) or compact (single call)"),
    templates: str | None = typer.Option(None, "--templates", help="Path to CloudFormation templates (dir or file); V2 only, skips cdk synth"),
    no_synth: bool = typer.Option(False, "--no-synth", help="Do not run cdk synth; V2 only (static analysis or use with --templates)"),
    rag: str | None = typer.Option(None, "--rag", help="Path to RAG doc (e.g. Well-Architected markdown); V2 only"),
    suggestions: str | None = typer.Option(None, "--suggestions", help="Write findings with suggested code to this JSON file"),
    baseline: str | None = typer.Option(None, "--baseline", help="Path to baseline file for suppressions"),
    enforce_baseline: bool = typer.Option(False, "--enforce-baseline", help="Only fail on findings not in baseline"),
    update_baseline: bool = typer.Option(False, "--update-baseline", help="Add current findings to baseline file"),
    region: str | None = typer.Option(
        None, "--region",
        help="AWS region whose prices cost estimates use. Default: each "
             "stack's own region (CDK env, Terraform provider), then AWS_REGION, then us-east-1",
    ),
    pricing_source: str | None = typer.Option(
        None, "--pricing-source",
        help="Where prices come from: auto (Price List Query API with AWS credentials, else the "
             "public bulk API), api, bulk, or off (no estimates, no network). Config pricing.source",
    ),
    price_cache_ttl: float | None = typer.Option(
        None, "--price-cache-ttl",
        help="Hours a fetched price is reused from the local cache (default 24). Config pricing.cache_ttl_hours",
    ),
    refresh_prices: bool = typer.Option(False, "--refresh-prices", help="Empty the price cache and fetch again"),
    usage_file: str | None = typer.Option(
        None, "--usage-file",
        help="Usage profile YAML that prices usage-based resources (default .aws-arch-agent-usage.yaml "
             "in the repo, if present). Config usage_file",
    ),
    compare_cost: str | None = typer.Option(
        None, "--compare-cost",
        help="Baseline file or earlier JSON report to diff the estimated monthly cost against",
    ),
    max_monthly_cost: float | None = typer.Option(
        None, "--max-monthly-cost",
        help="Exit 1 when the estimated monthly cost (USD) is above this. Config budget.max_monthly_usd",
    ),
    max_cost_increase: str | None = typer.Option(
        None, "--max-cost-increase",
        help="Exit 1 when the cost rises more than this against --compare-cost: USD (50) or percent (10%). "
             "Config budget.max_monthly_increase_usd / max_increase_percent",
    ),
    theme: list[str] = typer.Option(
        [], "--theme",
        help="Only report rules in these themes (repeatable or comma-separated): " + ", ".join(THEMES),
    ),
    group_by: str = typer.Option(
        "severity", "--group-by", help="Group Markdown findings by severity (default) or theme"
    ),
    version: bool = typer.Option(
        False, "--version", callback=_print_version, is_eager=True,
        help="Print the version and exit",
    ),
):
    """Review a CDK, CloudFormation, or Terraform repo against AWS Well-Architected and write a report.

    V1 runs the static rules. V2 adds cdk synth (or reads --templates or Terraform) and LangGraph pillar reviewers. --live-account reads the AWS account (read-only) for org-level controls. A Bedrock, SageMaker, or AgentCore workload also gets the AI lens rules and answers.
    """
    resolved_repo = repo if repo is not None else templates
    if resolved_repo is None:
        raise typer.BadParameter("Either --repo or --templates is required.")
    repo_path = Path(resolved_repo).expanduser().resolve()
    if not repo_path.exists():
        raise typer.BadParameter(f"Repo path does not exist: {repo_path}")
    if repo_path.is_file():
        repo_path = repo_path.parent

    mode_value = _require_choice(mode, _MODES, "--mode")
    tf_plan_path = Path(tf_plan).expanduser().resolve() if tf_plan is not None else None
    iac_value = _require_choice(iac, IAC_CHOICES, "--iac")
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
            region=region if _passed(ctx, "region") else None,
            themes=list(theme) if theme else None,
            group_by=group_by.lower() if _passed(ctx, "group_by") else None,
            pricing_source=pricing_source.lower() if pricing_source is not None else None,
            price_cache_ttl_hours=price_cache_ttl,
            usage_file=usage_file,
            max_monthly_cost=max_monthly_cost,
            max_cost_increase=max_cost_increase,
        )
        found_usage = usage_profile.find(repo_path, Path(cfg.usage_file) if cfg.usage_file else None)
        profile = usage_profile.load(found_usage) if found_usage is not None else None
        previous = cost_diff.load_previous(Path(compare_cost).expanduser().resolve()) if compare_cost else None
    except ConfigError as exc:
        _fail(str(exc))
    budget = cost_diff.Budget(cfg.budget_max_monthly_usd, cfg.budget_max_increase_usd, cfg.budget_max_increase_percent)
    finops = stack_cost.FinOps(
        usage=profile, previous=previous, previous_source=compare_cost or "",
        budget=budget if budget.is_set() else None,
    )
    price_provider = pricing.configure(cfg.pricing_source, cfg.price_cache_ttl_hours, refresh=refresh_prices)

    out_path = Path(cfg.out).expanduser().resolve()
    baseline_path = _resolve_baseline_path(repo_path, baseline)
    accepted_before: set[Fingerprint] | None = None
    if enforce_baseline or update_baseline:
        try:
            accepted_before = load_baseline(baseline_path)
        except BaselineError as exc:
            _fail(str(exc))

    progress = ScanProgress(console)
    with progress, use_progress(progress):
        source: IacSource | None = None
        if mode_value == "auto":
            if not cfg.templates:
                try:
                    progress("Detecting source")
                    source = resolve_source(repo_path, iac_value, iter_files(repo_path, max_files=max_files))
                except IacError as exc:
                    _fail(str(exc))
            mode_value, note = _auto_mode(source, bool(cfg.templates), cfg.no_synth, (repo_path / "cdk.json").is_file())
            if note:
                console.print(note, style="yellow", markup=False, soft_wrap=True)

        if mode_value == "v2":
            try:
                from aws_arch_agent.agent.v2_graph import analyze_v2  # noqa: F401 - fail early without the v2 extra
            except ImportError as exc:
                _fail(
                    "V2 mode requires the v2 extra: pip install 'aws-arch-agent[v2]'. "
                    f"({exc})"
                )

        if mode_value == "v2":
            # V2 synth is the CDK path. Raw CloudFormation passed with --templates and Terraform
            # (--iac terraform) are the other two.
            if iac_value == "cloudformation" and not cfg.templates:
                _fail(
                    "--iac cloudformation in V2 needs --templates: V2 synth is the CDK path. "
                    "Use --mode v1, or pass --templates."
                )

        try:
            if mode_value == "v2" and iac_value == "cloudformation" and cfg.templates:
                # The templates path may sit outside --repo; synth warns when it is missing or empty.
                source = "cloudformation"
            elif source is None:
                progress("Detecting source")
                source = resolve_source(
                    repo_path, iac_value, iter_files(repo_path, max_files=max_files)
                )
        except IacError as exc:
            _fail(str(exc))

        progress(f"Source: {source}")
        
        if mode_value == "v2" and iac_value == "auto" and source != "cdk" and not cfg.templates:
            console.print(
                f"Detected {source}, but V2 scans CDK only and will not read these files. "
                "Use --mode v1 to scan them, --templates for CloudFormation, or --iac terraform.",
                style="yellow",
                markup=False,
            )

        console.print(Panel.fit(
            f"[bold]Analyzing[/bold] {repo_path}\nMode: {mode_value} | Source: {source} | Format: {cfg.format}",
            title="aws-arch-agent",
        ))

        use_llm = not cfg.no_llm
        account_facts = account.read_live(cfg.region) if live_account else None
        with pricing.use_provider(price_provider):
            report_md, ctx_report, findings, warnings = _run(
                mode_value, repo_path, max_files, use_llm, cfg, iac_value, tf_plan_path, account_facts, finops,
            )

        # What happened, not what was configured. soft_wrap keeps the line whole for anyone grepping it.
        console.print(
            ctx_report.llm.line,
            style=None if ctx_report.llm.status in ("ok", "skipped") else "yellow",
            markup=False,
            soft_wrap=True,
        )
        llm_lines = [ctx_report.llm.line]
        verdict_line = _verdict_line(findings)
        if verdict_line:
            llm_lines.append(verdict_line)
            console.print(verdict_line, markup=False, soft_wrap=True)
        hypothesis_line = _hypothesis_line(ctx_report)
        if hypothesis_line:
            llm_lines.append(hypothesis_line)
            console.print(
                hypothesis_line,
                style=None if ctx_report.hypothesis_llm.status == "ok" else "yellow",
                markup=False,
                soft_wrap=True,
            )

        truncated = truncation_message(ctx_report.notes)
        if truncated:
            console.print(truncated, style="yellow", markup=False, soft_wrap=True)
        if ctx_report.notes.get("tag_policy") == "not checked":
            console.print(
                "tags.required is checked on templates, and this scan read none "
                "(CDK source is not a template: run --mode v2 to synth it).",
                style="yellow",
                markup=False,
            )
        for warning in ctx_report.notes.get("prices", {}).get("warnings", []):
            console.print(warning, style="yellow", markup=False, soft_wrap=True)
        cost_note = ctx_report.notes.get("cost") if isinstance(ctx_report.notes.get("cost"), dict) else None
        if ctx_report.notes.get("cost_hint"):
            console.print(ctx_report.notes["cost_hint"], style="yellow", markup=False, soft_wrap=True)
        if cost_note is None and (finops.budget is not None or finops.previous is not None):
            console.print(
                "No stack was priced, so the cost comparison and budget were not checked.",
                style="yellow", markup=False, soft_wrap=True,
            )
        change = (cost_note or {}).get("diff")
        if change:
            pct = f", {change['delta_percent']:+g}%" if change.get("delta_percent") is not None else ""
            console.print(
                f"Cost vs {change['source']}: ${change['previous_monthly_usd']:,.2f} -> "
                f"${change['current_monthly_usd']:,.2f}/month ({change['delta_monthly_usd']:+,.2f}{pct}); "
                f"{len(change['added'])} added, {len(change['removed'])} removed, {len(change['changed'])} changed",
                markup=False, soft_wrap=True,
            )
        budget_note = (cost_note or {}).get("budget")
        budget_breached = isinstance(budget_note, dict) and not budget_note["passed"]
        if isinstance(budget_note, dict):
            for line in budget_note["breaches"]:
                console.print(f"Budget breached: {line}", style="red", markup=False, soft_wrap=True)
            for line in budget_note["not_checked"]:
                console.print(f"Budget not checked: {line}", style="yellow", markup=False, soft_wrap=True)
            if budget_note["passed"]:
                console.print("Budget: within limits", markup=False)

        if update_baseline:
            merged = merge_into_baseline(accepted_before or set(), findings)
            try:
                save_baseline(baseline_path, merged, cost_diff.snapshot(cost_note) if cost_note else None)
            except OSError as exc:
                _fail(f"Failed to write baseline {baseline_path}: {exc}")
            console.print(f"Updated baseline: [bold]{baseline_path}[/bold] ({len(merged)} entries)")

        # An active inline or Metadata suppression keeps the finding out of --fail-on; an expired
        # one does not.
        findings_for_fail = suppressions.active(findings)
        if enforce_baseline:
            findings_for_fail = filter_new_findings(findings_for_fail, accepted_before or set())

        progress("Writing report")
        if cfg.format == "json":
            content = render_json(ctx_report, findings, warnings=warnings)
        elif cfg.format == "sarif":
            content = render_sarif(ctx_report, findings, warnings=warnings)
        elif cfg.format == "html":
            # The page labels accepted findings itself, so it skips _mark_baselined.
            baselined = (
                [is_baselined(f, accepted_before or set()) for f in findings]
                if enforce_baseline else None
            )
            content = render_html(ctx_report, findings, warnings=warnings, baselined=baselined)
        else:
            content = "\n".join(llm_lines) + f"\n\n{report_md}"

        if enforce_baseline and cfg.format != "html":
            content = _mark_baselined(content, cfg.format, findings, accepted_before or set())

        out_path.write_text(content, encoding="utf-8")
        console.print(f"Wrote report to: [bold]{escape(str(out_path))}[/bold]")
        # Before any exit, so a failing run still shows what it found.
        for line in terminal_lines(build_summary(findings), str(out_path)):
            console.print(line, markup=False, highlight=False, emoji=False, soft_wrap=True)

        if suggestions:
            suggestions_path = Path(suggestions).expanduser().resolve()
            suggestions_path.write_text(render_json(ctx_report, findings, warnings=warnings), encoding="utf-8")
            console.print(f"Wrote suggestions to: [bold]{suggestions_path}[/bold]")

        if warnings:
            console.print(f"[yellow]{len(warnings)} check(s) failed during analysis (see report warnings)[/yellow]")

        severity_hit = _should_fail(cfg.fail_on, findings_for_fail)
        if severity_hit:
            console.print(f"[red]fail-on={cfg.fail_on}: findings at or above threshold[/red]")
        # A gate the user set (--fail-on, a budget) wins over analysis warnings.
        if severity_hit or budget_breached:
            raise typer.Exit(code=1)
        if warnings:
            raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
