"""V1 pipeline: collect files, run rules, optional LLM polish, return report."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Literal

from aws_arch_agent.models import IacSource, RepoContext, Finding
from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.cf_template import (
    run_cf_rules_from_paths,
    run_resource_checks,
    terraform_variable_findings,
)
from aws_arch_agent.rules.fix_snippets import attach_fixes
from aws_arch_agent.rules.terraform_model import (
    TerraformError,
    find_modules,
    load_plan_values,
    resources_from_terraform,
    variables_from_terraform,
)
from aws_arch_agent.rules.runner import filter_by_severity, run_all_rules
from aws_arch_agent.rules import cf_template, effort, environments, nonprod, regions, stack_cost, themes
from aws_arch_agent.rules.tag_policy import TagPolicy, policy_checked, use_tag_policy
from aws_arch_agent.report.markdown import insert_summary, render_markdown
from aws_arch_agent.tools.llm import LLMClient
from aws_arch_agent.tools.files import iter_files, read_text_safe
from aws_arch_agent.tools.cdk_synth import list_templates_from_path
from aws_arch_agent.tools.cfn_yaml import is_cf_template
from aws_arch_agent.tools.paths import to_repo_relative
from aws_arch_agent.tools.rg import limit_to_files

logger = logging.getLogger(__name__)


RepoLanguage = Literal["typescript", "python", "unknown"]
IAC_CHOICES: tuple[str, ...] = ("auto", "cdk", "cloudformation", "terraform")


class IacError(ValueError):
    """An explicit --iac source has no matching files in the repo."""


_PYTHON_CMD = re.compile(
    r"(?:^|[\s\"'/])python(?:\d+(?:\.\d+)*)?(?=$|[\s\"'])",
    re.IGNORECASE,
)


def _cdk_app_command(repo_path: Path) -> str | None:
    """Return the cdk.json app command, or None when it is missing or unreadable."""
    cdk_json = repo_path / "cdk.json"
    if not cdk_json.is_file():
        return None
    try:
        data = json.loads(cdk_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(data, dict):
        return None
    app = data.get("app")
    if isinstance(app, str) and app.strip():
        return app.strip()
    return None


def _command_languages(app: str) -> set[str]:
    langs: set[str] = set()
    if _PYTHON_CMD.search(app) or re.search(r"\.py\b", app, re.IGNORECASE):
        langs.add("python")
    lowered = app.lower()
    if "npx" in lowered or "ts-node" in lowered or re.search(r"\.ts\b", app, re.IGNORECASE):
        langs.add("typescript")
    return langs


def _package_has_cdk(repo_path: Path) -> bool:
    package_json = repo_path / "package.json"
    if not package_json.is_file():
        return False
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return False
    if not isinstance(data, dict):
        return False
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name in deps:
            if name == "aws-cdk-lib" or name.startswith("@aws-cdk/"):
                return True
    return False


def _has_bin_ts(repo_path: Path) -> bool:
    bin_dir = repo_path / "bin"
    if not bin_dir.is_dir():
        return False
    try:
        return any(bin_dir.glob("*.ts"))
    except (PermissionError, OSError):
        return False


def detect_language(repo_path: Path) -> RepoLanguage:
    """Return 'typescript', 'python', or 'unknown' from repo contents.

    unknown means both languages are scanned. A Python CDK app is not treated
    as TypeScript just because cdk.json exists.
    """
    app = _cdk_app_command(repo_path)
    from_command = _command_languages(app) if app else set()
    typescript = "typescript" in from_command or _has_bin_ts(repo_path) or _package_has_cdk(repo_path)
    python = "python" in from_command or (repo_path / "app.py").is_file()
    py_project = (repo_path / "requirements.txt").is_file() or (repo_path / "pyproject.toml").is_file()
    if py_project and not typescript:
        python = True
    # package.json alone is a TypeScript CDK app. It does not override a Python app.
    if (repo_path / "package.json").is_file() and not python:
        typescript = True

    if python and typescript:
        return "unknown"
    if python:
        return "python"
    if typescript:
        return "typescript"

    saw_ts = False
    saw_py = False
    for check_dir in (repo_path, repo_path / "lib", repo_path / "bin", repo_path / "src"):
        if not check_dir.is_dir():
            continue
        try:
            saw_ts = saw_ts or any(check_dir.glob("*.ts"))
            saw_py = saw_py or any(check_dir.glob("*.py"))
        except (PermissionError, OSError):
            continue
    if saw_ts and saw_py:
        return "unknown"
    if saw_ts:
        return "typescript"
    if saw_py:
        return "python"
    return "unknown"


_PY_CDK_PACKAGE = re.compile(r"\baws[-_]cdk(?:[-_.]lib|\.)", re.IGNORECASE)


def _python_has_cdk(repo_path: Path) -> bool:
    for name in ("requirements.txt", "pyproject.toml", "setup.py"):
        path = repo_path / name
        if path.is_file() and _PY_CDK_PACKAGE.search(read_text_safe(path)):
            return True
    return False


def has_cdk_markers(repo_path: Path) -> bool:
    """True when cdk.json, a CDK app command, or a CDK package is present."""
    if (repo_path / "cdk.json").is_file() or _cdk_app_command(repo_path):
        return True
    return _package_has_cdk(repo_path) or _python_has_cdk(repo_path)


def is_terraform_file(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".tf") or name.endswith(".tf.json")


def _has_cdk_entrypoint(repo_path: Path) -> bool:
    return _has_bin_ts(repo_path) or (repo_path / "app.py").is_file()


def detect_source(repo_path: Path, files: list[Path] | None = None) -> IacSource:
    """Return 'cdk', 'cloudformation', 'terraform', or 'mixed' from repo contents.

    CDK wins when its markers exist, so cdk.out templates and workflow YAML keep a CDK
    repo a CDK repo. 'mixed' is CloudFormation and Terraform without CDK. A repo with
    none of these falls back to 'cdk' (the source-code scan).
    """
    if has_cdk_markers(repo_path):
        return "cdk"
    if files is None:
        files = iter_files(repo_path, max_files=400)
    cloudformation = any(is_cf_template(p) for p in files)
    terraform = any(is_terraform_file(p) for p in files)
    if cloudformation and terraform:
        return "mixed"
    if cloudformation:
        return "cloudformation"
    if terraform:
        return "terraform"
    return "cdk"


def resolve_source(repo_path: Path, iac: str, files: list[Path] | None = None) -> IacSource:
    """Resolve --iac. auto detects; an explicit source with no matching files raises IacError."""
    choice = iac.strip().lower()
    if choice not in IAC_CHOICES:
        raise IacError(f"--iac must be one of {', '.join(IAC_CHOICES)} (got {iac!r})")
    if files is None:
        files = iter_files(repo_path, max_files=400)
    if choice == "auto":
        return detect_source(repo_path, files)
    if choice == "cdk":
        found = has_cdk_markers(repo_path) or _has_cdk_entrypoint(repo_path)
        label = "CDK app (cdk.json, CDK package, bin/*.ts, or app.py)"
    elif choice == "cloudformation":
        found = any(is_cf_template(p) for p in files)
        label = "CloudFormation template"
    else:
        found = any(is_terraform_file(p) for p in files)
        label = "Terraform (*.tf, *.tf.json)"
    if not found:
        raise IacError(f"--iac {choice}: no {label} files found in {repo_path}")
    return choice  # type: ignore[return-value]


def _languages_to_scan(language: str) -> list[str]:
    """Return list of languages to run rules for (both TS and PY when unknown)."""
    if language == "unknown":
        return ["typescript", "python"]
    return [language]


# Account controls an app stack does not own. Off unless rules.org or rules.include.
ORG_RULE_IDS = frozenset({"SEC-026", "SEC-027", "OPS-001", "OPS-014", "COST-014"})


def _filter_rules(
    rules: list,
    include_ids: list[str] | None = None,
    exclude_ids: list[str] | None = None,
    *,
    org: bool = False,
) -> list:
    out = list(rules)
    if include_ids is not None:
        allowed = set(include_ids)
        out = [r for r in out if r.id in allowed]
    elif not org:
        out = [r for r in out if r.id not in ORG_RULE_IDS]
    if exclude_ids is not None:
        blocked = set(exclude_ids)
        out = [r for r in out if r.id not in blocked]
    return out


# Sources scanned with the CF-* checks instead of the CDK regex pass.
TEMPLATE_SOURCES = frozenset({"cloudformation", "mixed"})
TERRAFORM_SOURCES = frozenset({"terraform", "mixed"})


def discover_templates(repo_path: Path, files: list[Path]) -> list[Path]:
    """Real CloudFormation templates in the repo, limited to the files walked (--max-files)."""
    found: list[Path] = []
    for path in files:
        found.extend(list_templates_from_path(path, real_only=True))
    return sorted(found)


def _scan_templates(
    repo_path: Path,
    templates: list[Path],
    rules_include: list[str] | None,
    rules_exclude: list[str] | None,
) -> tuple[list[Finding], list[str]]:
    """Run the shared template checks on raw CloudFormation. No synth, no CDK regex pass."""
    warnings: list[str] = []
    findings = run_cf_rules_from_paths(templates, repo_path=repo_path, warnings=warnings)
    attach_fixes(findings, "cloudformation")
    return _filter_ids(findings, rules_include, rules_exclude), warnings


def _filter_ids(
    findings: list[Finding], rules_include: list[str] | None, rules_exclude: list[str] | None
) -> list[Finding]:
    if rules_include is not None:
        allowed = set(rules_include)
        findings = [f for f in findings if f.id in allowed]
    if rules_exclude is not None:
        blocked = set(rules_exclude)
        findings = [f for f in findings if f.id not in blocked]
    return findings


def _plan_module(
    repo_path: Path, modules: list[Path], tf_plan: Path, warnings: list[str]
) -> tuple[Path | None, dict[str, dict]]:
    """Load --tf-plan and pick the root module it belongs to. Problems are warnings."""
    try:
        values = load_plan_values(tf_plan)
    except TerraformError as exc:
        warnings.append(str(exc))
        return None, {}
    if len(modules) == 1:
        return modules[0], values
    plan_dir = tf_plan.resolve().parent
    if plan_dir in modules:
        return plan_dir, values
    warnings.append(
        f"--tf-plan {to_repo_relative(str(tf_plan), repo_path)}: {len(modules)} root modules "
        "and the plan file is in none of them; plan not applied"
    )
    return None, {}


def _scan_terraform(
    repo_path: Path,
    modules: list[Path],
    rules_include: list[str] | None,
    rules_exclude: list[str] | None,
    tf_plan: Path | None = None,
    notes: dict | None = None,
) -> tuple[list[Finding], list[str]]:
    """Run the CF-* checks on each Terraform root module. Findings point at the HCL file and line.

    tf_plan (`terraform show -json` output) fills unresolved values in its root module.
    """
    warnings: list[str] = []
    findings: list[Finding] = []
    plan_target: Path | None = None
    plan_values: dict[str, dict] = {}
    if tf_plan is not None:
        plan_target, plan_values = _plan_module(repo_path, modules, tf_plan, warnings)
        if plan_target is not None and notes is not None:
            notes["terraform_plan_module"] = to_repo_relative(str(plan_target), repo_path)
        plan_region = regions.terraform_plan_region(tf_plan) if plan_target is not None else None
        if plan_target is not None and plan_region:
            regions.remember(plan_target, plan_region, "Terraform plan")
    for module in modules:
        resources = resources_from_terraform(
            module, warnings, plan_values if module == plan_target else None
        )
        module_findings = run_resource_checks(resources, module, warnings)
        module_findings += environments.apply(
            terraform_variable_findings(variables_from_terraform(module)), module, resources)
        for finding in module_findings:
            if finding.file:
                finding.file = to_repo_relative(finding.file, repo_path)
        findings.extend(module_findings)
    attach_fixes(findings, "terraform")
    return _filter_ids(findings, rules_include, rules_exclude), warnings


def _collect_findings(
    repo_path: Path,
    max_files: int,
    rules_include: list[str] | None,
    rules_exclude: list[str] | None,
    severity_threshold: str | None,
    rules_org: bool = False,
    iac: str = "auto",
    tf_plan: Path | None = None,
) -> tuple[RepoContext, list[Finding], list[str]]:
    files = iter_files(repo_path, max_files=max_files)
    source = resolve_source(repo_path, iac, files)
    language = detect_language(repo_path)
    ctx = RepoContext(
        repo_path=str(repo_path),
        language=language,
        source=source,
        files_scanned=len(files),
        key_files=[p.name for p in files if p.name in {"cdk.json", "package.json", "requirements.txt"}],
    )
    if source in TEMPLATE_SOURCES or source in TERRAFORM_SOURCES:
        findings, warnings = [], []
        if source in TEMPLATE_SOURCES:
            templates = discover_templates(repo_path, files)
            ctx.notes["templates_scanned"] = len(templates)
            found, warned = _scan_templates(repo_path, templates, rules_include, rules_exclude)
            findings.extend(found)
            warnings.extend(warned)
        if source in TERRAFORM_SOURCES:
            modules, children = find_modules(files)
            ctx.notes["terraform_modules"] = [to_repo_relative(str(m), repo_path) for m in modules]
            if children:
                # Child modules are not read (no terraform init); say which were left out.
                ctx.notes["terraform_child_modules_skipped"] = [
                    to_repo_relative(str(m), repo_path) for m in children
                ]
            found, warned = _scan_terraform(
                repo_path, modules, rules_include, rules_exclude, tf_plan, ctx.notes
            )
            findings.extend(found)
            warnings.extend(warned)
    else:
        rules = _filter_rules(ALL_RULES, rules_include, rules_exclude, org=rules_org)
        with limit_to_files(repo_path, files):
            findings, warnings = run_all_rules(repo_path, rules, _languages_to_scan(language))
    if tf_plan is not None and source not in TERRAFORM_SOURCES:
        warnings.append(f"--tf-plan applies only to a Terraform scan (source is {source}); ignored")
    findings = filter_by_severity(findings, severity_threshold)
    effort.annotate(findings)
    themes.annotate(findings)
    return ctx, findings, warnings


def analyze_v1(
    repo_path: Path,
    max_files: int = 400,
    use_llm: bool = True,
    rules_include: list[str] | None = None,
    rules_exclude: list[str] | None = None,
    severity_threshold: str | None = None,
    rules_org: bool = False,
    iac: str = "auto",
    tf_plan: Path | None = None,
    price_region: str | None = None,
    tag_policy: TagPolicy | None = None,
    environment_map: dict[str, str] | None = None,
    nonprod_max_size: str | None = None,
    dashboards_min_resources: int | None = None,
    theme_filter: list[str] | None = None,
    group_by: str = "severity",
) -> tuple[str, RepoContext, list[Finding], list[str]]:
    """Run V1 pipeline: scan repo, run rules, optionally polish with LLM; return (report_md, ctx, findings, warnings)."""
    with (
        regions.use_regions(price_region),
        use_tag_policy(tag_policy),
        stack_cost.collect(),
        environments.use_environments(environment_map, repo_path),
        nonprod.use_max_size(nonprod_max_size),
        cf_template.use_dashboard_min_resources(dashboards_min_resources),
    ):
        ctx, findings, warnings = _collect_findings(
            repo_path, max_files, rules_include, rules_exclude, severity_threshold, rules_org, iac,
            tf_plan,
        )
        if tag_policy is not None:
            ctx.notes["tag_policy"] = "checked" if policy_checked() else "not checked"
        if theme_filter:
            findings = themes.select(findings, theme_filter)
            ctx.notes["themes"] = list(theme_filter)
        cost = stack_cost.summary(findings, repo_path)
        if cost is not None:
            ctx.notes["cost"] = cost
        ctx.notes["prices"] = regions.note()

    if not use_llm:
        return render_markdown(ctx, findings, warnings=warnings, group_by=group_by), ctx, findings, warnings
    # The summary is built from rule output: the LLM polishes the rest, never its numbers.
    llm = LLMClient()
    polished = llm.polish(render_markdown(ctx, findings, warnings=warnings, include_summary=False,
                                          group_by=group_by))
    return insert_summary(polished, findings), ctx, findings, warnings


def collect_ctx_findings(
    repo_path: Path,
    max_files: int = 400,
    rules_include: list[str] | None = None,
    rules_exclude: list[str] | None = None,
    severity_threshold: str | None = None,
    rules_org: bool = False,
    iac: str = "auto",
    tf_plan: Path | None = None,
) -> tuple[RepoContext, list[Finding], list[str]]:
    """Run rules only and return context, findings, and warnings."""
    return _collect_findings(
        repo_path, max_files, rules_include, rules_exclude, severity_threshold, rules_org, iac,
        tf_plan,
    )
