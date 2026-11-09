"""V2 LangGraph multi-agent pipeline: collect, synth, six pillars, merge, report."""
from __future__ import annotations

import logging
import operator
import subprocess
from pathlib import Path
from typing import Annotated, Literal, TypedDict, List

from aws_arch_agent.models import Finding, Hypothesis, IacSource, RepoContext, Verdict
from aws_arch_agent.agent.hypotheses import find_hypotheses
from aws_arch_agent.agent.verdicts import VerdictCache, apply_verdicts, judge_batch, make_batches
from aws_arch_agent.agent.v1 import (
    _filter_rules,
    _languages_to_scan,
    detect_language,
    iac_files,
    resolve_source,
)
from aws_arch_agent.tools.files import iter_files
from aws_arch_agent.tools.llm import NO_LLM, LLMClient, LLMResult, aggregate_results
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.runner import filter_by_severity, run_all_rules
from aws_arch_agent.rules import cf_template, effort, environments, nonprod, regions, stack_cost, themes
from aws_arch_agent.rules.tag_policy import TagPolicy, use_tag_policy
from aws_arch_agent.report.markdown import render_markdown
from aws_arch_agent.tools.cdk_synth import (
    list_cf_templates,
    list_templates_from_path,
    run_cdk_synth,
    summarize_templates,
    summarize_templates_from_paths,
)
from aws_arch_agent.tools.rg import limit_to_files
from aws_arch_agent.rules.cf_template import (
    drop_static_covered_by_cf,
    run_cf_rules,
    run_cf_rules_from_paths,
)

from langgraph.graph import StateGraph, END

logger = logging.getLogger(__name__)

LLMMode = Literal["full", "compact"]
# Keyed on the verdict prompt. Holds only ok outcomes, so a failure is asked again next run.
_pillar_cache: VerdictCache = {}


def _first_verdict_wins(
    left: dict[str, Verdict], right: dict[str, Verdict]
) -> dict[str, Verdict]:
    """Merge the pillars' verdicts; a finding judged twice keeps its first verdict."""
    return {**right, **left}


class State(TypedDict, total=False):
    repo_path: str
    max_files: int
    ctx: RepoContext
    raw_findings: List[Finding]
    rule_warnings: List[str]
    use_llm: bool
    llm_mode: str
    rules_include: List[str] | None
    rules_exclude: List[str] | None
    rules_org: bool
    severity_threshold: str
    templates_path: str
    skip_synth: bool
    rag_path: str
    rag_use_embeddings: bool
    rag_embedding_provider: str
    rag_embedding_model: str
    iac: str
    price_region: str | None
    theme_filter: List[str] | None
    group_by: str
    rag: object
    synth_ok: bool
    synth_stdout: str
    synth_stderr: str
    synth_summary: str
    security_notes: str
    cost_notes: str
    reliability_notes: str
    observability_notes: str
    performance_efficiency_notes: str
    sustainability_notes: str
    merged_notes: str
    final_report: str
    # Pillars run in parallel, so every call's result is appended rather than overwritten.
    llm_results: Annotated[List[LLMResult], operator.add]
    verdicts: Annotated[dict[str, Verdict], _first_verdict_wins]
    # Findings before the theme filter, which must not make a file with findings look quiet.
    unfiltered_findings: Annotated[List[Finding], operator.add]
    hypotheses: List[Hypothesis]
    # Apart from llm_results: a label needs every verdict batch ok, and this call is not one.
    hypothesis_result: LLMResult


# Map pillar node names to finding categories (static rules use "Operational Excellence", not "Observability")
PILLAR_CATEGORIES: dict[str, list[str]] = {
    "Observability": ["Observability", "Operational Excellence"],
    "Cost": ["Cost", "Cost Optimization"],
}


def _build_rag(state: State) -> object | None:
    """Load the RAG doc once. Pillars and merge reuse this instance."""
    rag_path = state.get("rag_path")
    if not rag_path:
        return None
    try:
        from aws_arch_agent.rag import get_rag

        use_emb = state.get("rag_use_embeddings", False)
        provider = state.get("rag_embedding_provider") or None
        model = state.get("rag_embedding_model") or None
        rag = get_rag(
            Path(rag_path),
            use_embeddings=use_emb,
            embedding_provider=provider,
            embedding_model=model,
        )
        warm = getattr(rag, "ensure_chunk_embeddings", None)
        if warm is not None:
            warm()
        return rag
    except Exception as e:
        logger.warning("RAG load failed for %s: %s", rag_path, e)
        return None


def _rag_block(state: State, query: str | None = None) -> str:
    rag = state.get("rag")
    retrieve = getattr(rag, "retrieve", None)
    if retrieve is None:
        return ""
    try:
        q = query or "operational excellence security reliability performance cost sustainability"
        text = str(retrieve(q, k=3))
        return "\n\n## Reference (RAG)\n" + text
    except Exception as e:
        logger.warning("RAG retrieve failed: %s", e)
        return ""


def _summarize_role(
    role: str,
    findings: List[Finding],
    synth_summary: str,
    llm: LLMClient,
    repo_path: Path,
    use_llm: bool = True,
    rag_block: str = "",
) -> tuple[str, LLMResult | None, dict[str, Verdict]]:
    """Return the pillar notes, the LLM result (None when none was asked) and its verdicts."""
    categories = PILLAR_CATEGORIES.get(role, [role])
    rel = [f for f in findings if f.category.lower() in [c.lower() for c in categories]]
    if not rel:
        return f"## {role}\n\nNo findings in this pillar.\n", None, {}
    snippet = "\n".join([f"- [{x.id}] {x.title}: {x.recommendation}" for x in rel[:12]])
    if not use_llm:
        notes = f"## {role}\n(skipped LLM)\n\n{snippet}\n\nSynth summary: {synth_summary[:500]}"
        return notes, None, {}
    verdicts, result = judge_batch(
        llm, make_batches(rel)[0], repo_path, reference=rag_block, cache=_pillar_cache
    )
    return f"## {role}\n\n{snippet}\n", result, verdicts


def _parts_under(path: Path, root: Path) -> tuple[str, ...]:
    """Path parts below root (all parts when path is outside it)."""
    try:
        return path.resolve().relative_to(root.resolve()).parts
    except ValueError:
        return path.parts


def _in_themes(findings: List[Finding], state: State) -> List[Finding]:
    """Keep only findings in the --theme themes, before the pillar notes and the LLM see
    them, so a finops scan reports and reasons about finops findings alone."""
    wanted = state.get("theme_filter")
    if not wanted:
        return findings
    themes.annotate(findings)
    return themes.select(findings, wanted)


def node_collect(state: State) -> State:
    repo_path = Path(state["repo_path"])
    max_files = state.get("max_files") or 400
    files = iter_files(repo_path, max_files=max_files)
    iac = state.get("iac") or "auto"
    if iac == "cloudformation" and state.get("templates_path"):
        source: IacSource = "cloudformation"  # templates may sit outside the repo
    else:
        source = resolve_source(repo_path, iac, files)
    ctx = RepoContext(
        repo_path=str(repo_path),
        language=detect_language(repo_path),
        source=source,
        files_scanned=len(files),
        key_files=[p.name for p in files if p.name in {"cdk.json", "package.json", "requirements.txt"}],
        notes={
            "top_level": [p.name for p in repo_path.iterdir() if p.is_dir()],
            "prices": regions.note(),  # replaced in node_report once stacks are priced
        },
    )

    rules = _filter_rules(
        ALL_RULES,
        state.get("rules_include"),
        state.get("rules_exclude"),
        org=bool(state.get("rules_org")),
    )
    language = ctx.language
    with limit_to_files(repo_path, files):
        findings, warnings = run_all_rules(repo_path, rules, _languages_to_scan(language))
    unfiltered = filter_by_severity(findings, state.get("severity_threshold"))
    findings = _in_themes(unfiltered, state)

    return {
        "ctx": ctx,
        "raw_findings": findings,
        "unfiltered_findings": unfiltered,
        "rule_warnings": warnings,
        "rag": _build_rag(state),
    }


def _note(warnings: list[str], message: str) -> None:
    warnings.append(message)
    logger.warning(message)


def node_synth(state: State) -> State:
    repo_path = Path(state["repo_path"])
    ctx = state.get("ctx")
    templates_path = state.get("templates_path") or ""
    skip_synth = state.get("skip_synth") or False
    warnings = list(state.get("rule_warnings") or [])

    if templates_path:
        tpath = Path(templates_path).expanduser().resolve()
        out_findings = list(state.get("raw_findings", []))
        if not tpath.exists():
            message = f"Template path does not exist: {tpath}"
            _note(warnings, message)
            return {
                "synth_ok": False,
                "synth_stdout": "",
                "synth_stderr": message,
                "synth_summary": message,
                "raw_findings": out_findings,
                "rule_warnings": warnings,
            }
        template_paths = list_templates_from_path(tpath)
        if not template_paths:
            message = f"No template files found at {tpath}."
            _note(warnings, message)
            return {
                "synth_ok": False,
                "synth_stdout": "",
                "synth_stderr": message,
                "synth_summary": message,
                "raw_findings": out_findings,
                "rule_warnings": warnings,
            }
        synth_summary = summarize_templates_from_paths(template_paths)
        cf_warnings: list[str] = []
        cf_failed = False
        try:
            cf_findings = run_cf_rules_from_paths(
                template_paths, repo_path=repo_path, warnings=cf_warnings
            )
            # --templates points at templates the user edits; synth output (cdk.out) keeps CDK hints.
            if not any("cdk.out" in _parts_under(p, repo_path) for p in template_paths):
                attach_fixes(cf_findings, "cloudformation")
            out_findings.extend(cf_findings)
            unfiltered = drop_static_covered_by_cf(out_findings)
            out_findings = _in_themes(unfiltered, state)
        except Exception as exc:
            cf_failed = True
            unfiltered = []
            _note(warnings, f"CF template rules failed: {exc}")
        warnings.extend(cf_warnings)
        return {
            "synth_ok": not cf_failed,
            "synth_stdout": "",
            "synth_stderr": "",
            "synth_summary": synth_summary,
            "raw_findings": out_findings,
            "unfiltered_findings": unfiltered,
            "rule_warnings": warnings,
        }

    if skip_synth:
        synth_summary = "Synth skipped (--no-synth). Static analysis only."
        logger.info("Synth skipped; continuing with static analysis only")
        return {
            "synth_ok": False,
            "synth_stdout": "",
            "synth_stderr": "",
            "synth_summary": synth_summary,
        }

    language = ctx.language if ctx else "typescript"
    try:
        rc, out, err = run_cdk_synth(repo_path, language=language)
    except subprocess.TimeoutExpired as exc:
        message = f"CDK synth timed out after {exc.timeout}s"
        _note(warnings, message)
        return {
            "synth_ok": False,
            "synth_stdout": "",
            "synth_stderr": message,
            "synth_summary": message,
            "rule_warnings": warnings,
        }
    except Exception as exc:
        message = f"CDK synth failed: {exc}"
        _note(warnings, message)
        return {
            "synth_ok": False,
            "synth_stdout": "",
            "synth_stderr": message,
            "synth_summary": message,
            "rule_warnings": warnings,
        }

    if rc != 0:
        detail = (err or out or "").strip()
        message = f"CDK synth exited {rc}"
        if detail:
            message = f"{message}: {detail[-500:]}"
        _note(warnings, message)
        return {
            "synth_ok": False,
            "synth_stdout": (out or "")[-4000:],
            "synth_stderr": (err or "")[-4000:],
            "synth_summary": message,
            "rule_warnings": warnings,
        }

    cdk_out = repo_path / "cdk.out"
    out_findings = list(state.get("raw_findings", []))
    if not list_cf_templates(cdk_out):
        message = "CDK synth produced no template files."
        _note(warnings, message)
        return {
            "synth_ok": False,
            "synth_stdout": out[-4000:],
            "synth_stderr": err[-4000:],
            "synth_summary": message,
            "raw_findings": out_findings,
            "rule_warnings": warnings,
        }

    synth_summary = summarize_templates(cdk_out)
    cf_warnings = []
    cf_failed = False
    try:
        cf_findings = run_cf_rules(cdk_out, repo_path=repo_path, warnings=cf_warnings)
        out_findings.extend(cf_findings)
        unfiltered = drop_static_covered_by_cf(out_findings)
        out_findings = _in_themes(unfiltered, state)
    except Exception as exc:
        cf_failed = True
        unfiltered = []
        _note(warnings, f"CF template rules failed: {exc}")
    warnings.extend(cf_warnings)
    return {
        "synth_ok": not cf_failed,
        "synth_stdout": out[-4000:],
        "synth_stderr": err[-4000:],
        "synth_summary": synth_summary,
        "raw_findings": out_findings,
        "unfiltered_findings": unfiltered,
        "rule_warnings": warnings,
    }


def _pillar_node(role: str, state_key: str):
    def _node(state: State) -> State:
        use_llm = state.get("use_llm", True)
        llm_mode = state.get("llm_mode", "full")
        findings = state.get("raw_findings", [])
        synth_summary = state.get("synth_summary", "")
        rag_block = _rag_block(state, query=f"{role} AWS Well-Architected best practices")
        result: LLMResult | None = None
        verdicts: dict[str, Verdict] = {}
        if llm_mode == "compact":
            categories = PILLAR_CATEGORIES.get(role, [role])
            rel = [f for f in findings if f.category.lower() in [c.lower() for c in categories]]
            snippet = "\n".join([f"- [{x.id}] {x.title}" for x in rel[:8]]) or "No findings."
            # With an LLM the block goes in the verdict prompt, and these notes reach the report.
            notes = f"## {role}\n\n{snippet}\n{'' if use_llm else rag_block}\n"
        else:
            llm = LLMClient()
            notes, result, verdicts = _summarize_role(
                role,
                findings,
                synth_summary,
                llm,
                Path(state["repo_path"]),
                use_llm=use_llm,
                rag_block=rag_block,
            )
        out: State = {}
        out[state_key] = notes  # type: ignore[literal-required]
        if result is not None:
            out["llm_results"] = [result]
        if verdicts:
            out["verdicts"] = verdicts
        return out

    return _node


node_security = _pillar_node("Security", "security_notes")
node_cost = _pillar_node("Cost", "cost_notes")
node_reliability = _pillar_node("Reliability", "reliability_notes")
node_observability = _pillar_node("Observability", "observability_notes")
node_performance_efficiency = _pillar_node("Performance Efficiency", "performance_efficiency_notes")
node_sustainability = _pillar_node("Sustainability", "sustainability_notes")


def _joined_notes(state: State) -> str:
    return "\n".join(
        [
            state.get("observability_notes", ""),
            state.get("security_notes", ""),
            state.get("reliability_notes", ""),
            state.get("performance_efficiency_notes", ""),
            state.get("cost_notes", ""),
            state.get("sustainability_notes", ""),
        ]
    )


def node_merge(state: State) -> State:
    use_llm = state.get("use_llm", True)
    llm_mode = state.get("llm_mode", "full")
    findings = state.get("raw_findings", [])
    synth_summary = state.get("synth_summary", "")

    if use_llm:
        out: State = {"merged_notes": _joined_notes(state)}
        if llm_mode == "compact" and findings:
            verdicts, result = judge_batch(
                LLMClient(),
                make_batches(findings)[0],
                Path(state["repo_path"]),
                reference=_rag_block(state),
            )
            out["llm_results"] = [result]
            out["verdicts"] = verdicts
        return out

    rag_block = _rag_block(state)
    prompt = f"""Merge these into a single coherent review section with headings (AWS Well-Architected 6 pillars).
Be specific, avoid repetition, and keep it to ~350-550 words.

## CloudFormation synthesis
{synth_summary}

## 1. Operational Excellence (Observability)
{state.get("observability_notes","")}

## 2. Security
{state.get("security_notes","")}

## 3. Reliability
{state.get("reliability_notes","")}

## 4. Performance Efficiency
{state.get("performance_efficiency_notes","")}

## 5. Cost Optimization
{state.get("cost_notes","")}

## 6. Sustainability
{state.get("sustainability_notes","")}
{rag_block}
"""
    return {"merged_notes": prompt}


def node_hypotheses(state: State) -> State:
    """Ask about the files with no finding, counting the findings a theme filter removed."""
    if not state.get("use_llm", True):
        return {}
    # A model that did not answer gets no second wait.
    if aggregate_results(state.get("llm_results") or []).status not in ("ok", "skipped"):
        return {}
    repo_path = Path(state["repo_path"])
    hypotheses, result = find_hypotheses(
        LLMClient(),
        [*state.get("raw_findings", []), *(state.get("unfiltered_findings") or [])],
        repo_path,
        iac_files(repo_path, state["ctx"].source, state.get("max_files", 400)),
        synth_summary=state.get("synth_summary", ""),
    )
    out: State = {"hypotheses": hypotheses}
    if result is not None:
        out["hypothesis_result"] = result
    return out


def node_report(state: State) -> State:
    ctx = state["ctx"]
    ctx.hypotheses = state.get("hypotheses") or []
    findings = state.get("raw_findings", [])
    warnings = state.get("rule_warnings") or []
    effort.annotate(findings)  # the summary's quick wins need it
    themes.annotate(findings)
    wanted = state.get("theme_filter")
    if wanted:
        findings = themes.select(findings, wanted)
        ctx.notes["themes"] = list(wanted)
    cost = stack_cost.summary(findings, Path(state["repo_path"]))
    if cost is not None:
        ctx.notes["cost"] = cost
    ctx.notes["prices"] = regions.note()
    # Any batch that did not answer means no labels at all, as in V1.
    if aggregate_results(state.get("llm_results") or []).status == "ok":
        apply_verdicts(findings, state.get("verdicts") or {})
    base_report = render_markdown(ctx, findings, warnings=warnings, group_by=state.get("group_by") or "severity")
    synth_block = state.get("synth_summary", "")
    if state.get("templates_path"):
        synth_status = "Templates: provided (no synth)"
    elif state.get("skip_synth"):
        synth_status = "CDK synth: skipped"
    else:
        synth_status = "success" if state.get("synth_ok") else "failed/skip"
        synth_status = f"CDK synth: {synth_status}"
    final = f"""# AWS Architecture Review Report (V2 Multi-Agent)

**{synth_status}**

{state.get("merged_notes","")}

---

{synth_block}

---

{base_report}
"""
    return {"final_report": final, "ctx": ctx, "raw_findings": findings}  # ctx carries the cost section


def build_graph():
    """Build and compile the LangGraph StateGraph (collect -> synth -> 6 pillars -> merge -> hypotheses -> report)."""
    g = StateGraph(State)
    g.add_node("collect", node_collect)
    g.add_node("synth", node_synth)
    g.add_node("security", node_security)
    g.add_node("cost", node_cost)
    g.add_node("reliability", node_reliability)
    g.add_node("observability", node_observability)
    g.add_node("performance_efficiency", node_performance_efficiency)
    g.add_node("sustainability", node_sustainability)
    g.add_node("merge", node_merge)
    g.add_node("hypotheses", node_hypotheses)
    g.add_node("report", node_report)

    g.set_entry_point("collect")
    g.add_edge("collect", "synth")

    g.add_edge("synth", "security")
    g.add_edge("synth", "cost")
    g.add_edge("synth", "reliability")
    g.add_edge("synth", "observability")
    g.add_edge("synth", "performance_efficiency")
    g.add_edge("synth", "sustainability")

    g.add_edge("security", "merge")
    g.add_edge("cost", "merge")
    g.add_edge("reliability", "merge")
    g.add_edge("observability", "merge")
    g.add_edge("performance_efficiency", "merge")
    g.add_edge("sustainability", "merge")

    g.add_edge("merge", "hypotheses")
    g.add_edge("hypotheses", "report")
    g.add_edge("report", END)
    return g.compile()


def analyze_v2(
    repo_path: Path,
    max_files: int = 400,
    use_llm: bool = True,
    rules_include: List[str] | None = None,
    rules_exclude: List[str] | None = None,
    severity_threshold: str | None = None,
    templates_path: str | None = None,
    skip_synth: bool = False,
    rag_path: str | None = None,
    rag_use_embeddings: bool = False,
    rag_embedding_provider: str | None = None,
    rag_embedding_model: str | None = None,
    llm_mode: LLMMode = "full",
    rules_org: bool = False,
    iac: str = "auto",
    price_region: str | None = None,
    tag_policy: TagPolicy | None = None,
    environment_map: dict[str, str] | None = None,
    nonprod_max_size: str | None = None,
    dashboards_min_resources: int | None = None,
    theme_filter: List[str] | None = None,
    group_by: str = "severity",
) -> tuple[str, RepoContext, List[Finding], List[str]]:
    """Run V2 graph; return (final_report_md, ctx, findings, warnings)."""
    graph = build_graph()
    initial: State = {
        "repo_path": str(repo_path),
        "max_files": max_files,
        "use_llm": use_llm,
        "llm_mode": llm_mode,
        "rules_include": rules_include if rules_include else None,
        "rules_exclude": rules_exclude if rules_exclude else None,
        "rules_org": rules_org,
        "severity_threshold": severity_threshold or "",
        "templates_path": templates_path or "",
        "skip_synth": skip_synth,
        "rag_path": rag_path or "",
        "rag_use_embeddings": rag_use_embeddings,
        "rag_embedding_provider": rag_embedding_provider or "",
        "rag_embedding_model": rag_embedding_model or "",
        "iac": iac,
        "price_region": price_region,
        "theme_filter": theme_filter,
        "group_by": group_by,
    }
    with (
        regions.use_regions(price_region),
        use_tag_policy(tag_policy),
        stack_cost.collect(),
        environments.use_environments(environment_map, repo_path),
        nonprod.use_max_size(nonprod_max_size),
        cf_template.use_dashboard_min_resources(dashboards_min_resources),
    ):
        out = graph.invoke(initial)
    report = out.get("final_report") or "No report produced."
    ctx = out.get("ctx")
    findings = out.get("raw_findings") or []
    warnings = out.get("rule_warnings") or []
    if ctx is None:
        ctx = RepoContext(repo_path=str(repo_path), language="unknown")
    ctx.llm = aggregate_results(out.get("llm_results") or []) if use_llm else NO_LLM
    ctx.hypothesis_llm = aggregate_results([out["hypothesis_result"]] if "hypothesis_result" in out else [])
    return report, ctx, findings, warnings
