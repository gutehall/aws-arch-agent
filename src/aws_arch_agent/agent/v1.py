"""V1 pipeline: collect files, run rules, optional LLM polish, return report."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Literal

import yaml

from aws_arch_agent.models import IacSource, RepoContext, Finding
from aws_arch_agent.rules.registry import ALL_RULES
from aws_arch_agent.rules.runner import filter_by_severity, run_all_rules
from aws_arch_agent.report.markdown import render_markdown
from aws_arch_agent.tools.llm import LLMClient
from aws_arch_agent.tools.files import iter_files, read_text_safe
from aws_arch_agent.tools.rg import limit_to_files

logger = logging.getLogger(__name__)


RepoLanguage = Literal["typescript", "python", "unknown"]
IacChoice = Literal["auto", "cdk", "cloudformation", "terraform"]
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


_CF_VERSION_KEY = re.compile(r"""^\s*["']?AWSTemplateFormatVersion["']?\s*:""", re.MULTILINE)
_TEMPLATE_SUFFIXES = {".json", ".yaml", ".yml", ".template"}
_PY_CDK_PACKAGE = re.compile(r"\baws[-_]cdk(?:[-_.]lib|\.)", re.IGNORECASE)


class _TagTolerantLoader(yaml.SafeLoader):
    """SafeLoader that reads CloudFormation short tags (!Ref, !Sub) as plain values."""


def _construct_tag(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)  # type: ignore[arg-type]


_TagTolerantLoader.add_multi_constructor("!", _construct_tag)


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


def is_cf_template(path: Path) -> bool:
    """True for a CloudFormation template.

    Needs AWSTemplateFormatVersion, or a Resources entry whose Type starts with AWS::.
    Other YAML and JSON (GitHub Actions, package.json) is not a template.
    """
    if path.suffix.lower() not in _TEMPLATE_SUFFIXES:
        return False
    text = read_text_safe(path)
    if "AWSTemplateFormatVersion" not in text and "AWS::" not in text:
        return False
    if _CF_VERSION_KEY.search(text):
        return True
    try:
        if path.suffix.lower() == ".json":
            doc = json.loads(text)
        else:
            doc = yaml.load(text, Loader=_TagTolerantLoader)  # noqa: S506 - SafeLoader subclass
    except (ValueError, yaml.YAMLError):
        return False
    if not isinstance(doc, dict):
        return False
    resources = doc.get("Resources")
    if not isinstance(resources, dict):
        return False
    return any(
        isinstance(res, dict) and isinstance(res.get("Type"), str) and res["Type"].startswith("AWS::")
        for res in resources.values()
    )


def is_terraform_file(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".tf") or name.endswith(".tf.json")


def _has_cdk_sources(files: list[Path]) -> bool:
    return any(p.suffix.lower() in {".ts", ".py"} for p in files)


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
        found = has_cdk_markers(repo_path) or _has_cdk_sources(files)
        label = "CDK app (cdk.json, CDK package, .ts or .py)"
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


def _collect_findings(
    repo_path: Path,
    max_files: int,
    rules_include: list[str] | None,
    rules_exclude: list[str] | None,
    severity_threshold: str | None,
    rules_org: bool = False,
    iac: str = "auto",
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
    rules = _filter_rules(ALL_RULES, rules_include, rules_exclude, org=rules_org)
    with limit_to_files(repo_path, files):
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
    rules_org: bool = False,
    iac: str = "auto",
) -> tuple[str, RepoContext, list[Finding], list[str]]:
    """Run V1 pipeline: scan repo, run rules, optionally polish with LLM; return (report_md, ctx, findings, warnings)."""
    ctx, findings, warnings = _collect_findings(
        repo_path, max_files, rules_include, rules_exclude, severity_threshold, rules_org, iac
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
    rules_org: bool = False,
    iac: str = "auto",
) -> tuple[RepoContext, list[Finding], list[str]]:
    """Run rules only and return context, findings, and warnings."""
    return _collect_findings(
        repo_path, max_files, rules_include, rules_exclude, severity_threshold, rules_org, iac
    )
