"""Whether a scan is of an AI workload. The AI lens answers and the AI findings run only then.

Auto: the normalized resources of the scan include a Bedrock, SageMaker, or AgentCore type
(rules/resource_model.py and rules/terraform_model.py map the CloudFormation and Terraform
types onto the canonical ones below). Config `lenses.ai` overrides it: true turns the lenses
on with no AI resource, false turns them off even when one exists.

The setting and the resources seen live in context variables, set by `use()` around a scan,
the way the tag policy and the price region are. Outside `use()` nothing is seen, so only
`lenses.ai: true` turns the gate on. A CDK source scan has no normalized resources, so
observe_cdk_source() reads the TypeScript and Python source instead: a Bedrock, SageMaker,
or AgentCore import or construct outside test files turns the gate on.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Iterable, Iterator, Set

from aws_arch_agent.tools.files import read_text_safe

# Canonical types of the AI services.
BEDROCK_AGENT_TYPES = frozenset({"bedrock_agent", "bedrockagentcore_agent_runtime"})
AI_TYPES = frozenset({
    "bedrock_agent", "bedrock_agent_alias", "bedrock_guardrail", "bedrock_knowledge_base",
    "bedrock_prompt", "bedrock_prompt_version", "bedrock_model_invocation_logging",
    "bedrockagentcore_agent_runtime", "bedrockagentcore_gateway", "bedrockagentcore_memory",
    "sagemaker_notebook_instance", "sagemaker_endpoint_config", "sagemaker_endpoint",
    "sagemaker_monitoring_schedule", "sagemaker_domain", "sagemaker_feature_group",
    "sagemaker_model", "sagemaker_model_package_group", "sagemaker_model_card",
})

# The types added for the AI gate. The core dashboard check (CF-DASH-001) does not count them,
# so a Bedrock or AgentCore resource does not move a core answer.
UNCOUNTED_TYPES = AI_TYPES - {"sagemaker_notebook_instance", "sagemaker_endpoint_config"}

_setting: ContextVar[bool | None] = ContextVar("ai_lenses_setting", default=None)
# CF-BEDROCK-004 is an account control (model invocation logging has no CloudFormation type),
# so it is off unless rules.org is on or rules.include names it.
_account_checks: ContextVar[bool] = ContextVar("ai_lenses_account_checks", default=False)
# One mutable set per scan, so a graph node that runs in a copied context still reports to it.
_seen: ContextVar[Set[str] | None] = ContextVar("ai_lenses_seen", default=None)


@contextmanager
def use(setting: bool | None, *, account_checks: bool = False) -> Iterator[None]:
    """Scope a scan: setting is the config `lenses.ai` (None when omitted); account_checks is
    true when rules.org is on or rules.include names the account-level AI check."""
    t_setting = _setting.set(setting)
    t_acct = _account_checks.set(account_checks)
    t_seen = _seen.set(set())
    try:
        yield
    finally:
        _setting.reset(t_setting)
        _account_checks.reset(t_acct)
        _seen.reset(t_seen)


def observe(resources: Iterable) -> None:
    """Record the AI types among a file's normalized resources."""
    seen = _seen.get()
    if seen is not None:
        seen.update(r.type for r in resources if r.type in AI_TYPES)


# CDK modules and L1 constructs of the AI services, as imported or instantiated in source:
# aws_cdk.aws_bedrock / aws-cdk-lib/aws-bedrock, aws_sagemaker, aws_bedrockagentcore, and the
# Cfn* classes. Only code lines count, so a mention in a comment or a README does not.
_CDK_AI = re.compile(
    r"aws[_-]bedrock(?:agentcore)?\b|\bbedrockagentcore\b|aws[_-]sagemaker\b"
    r"|\bCfn(?:Agent|Guardrail|KnowledgeBase|Prompt|Endpoint|NotebookInstance|Domain)\s*\("
)
_COMMENT = re.compile(r"^\s*(?:#|//|/?\*)")
_SOURCE_SUFFIXES = frozenset({".ts", ".py"})
_TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec"})
_TEST_NAME = re.compile(r"\.(?:test|spec)\.ts$|^test_.*\.py$|_test\.py$|^conftest\.py$")
# What a CDK source match records: not a canonical type, so no type-gated check runs on it.
CDK_SOURCE = "cdk_source"


def _is_source(path: Path, root: Path | None) -> bool:
    name = path.name.lower()
    if path.suffix.lower() not in _SOURCE_SUFFIXES or name.endswith(".d.ts") or _TEST_NAME.search(name):
        return False
    # Only directories inside the repo count: a checkout under ~/tests is not test code.
    try:
        parts = path.relative_to(root).parts if root is not None else path.parts
    except ValueError:
        parts = path.parts
    return not any(part.lower() in _TEST_DIRS for part in parts[:-1])


def cdk_source_is_ai(files: Iterable[Path], root: Path | None = None) -> bool:
    """Whether CDK TypeScript or Python source outside tests imports or creates an AI construct.
    root is the repo the files are under; test directories are judged relative to it."""
    for path in files:
        if not _is_source(path, root):
            continue
        for line in read_text_safe(path).splitlines():
            if _CDK_AI.search(line) and not _COMMENT.match(line):
                return True
    return False


def observe_cdk_source(files: Iterable[Path], root: Path | None = None) -> None:
    """Record an AI workload found in CDK source, for a scan with no normalized resources."""
    seen = _seen.get()
    if seen is not None and cdk_source_is_ai(files, root):
        seen.add(CDK_SOURCE)


def seen_types() -> frozenset[str]:
    seen = _seen.get()
    return frozenset(seen) if seen else frozenset()


def active() -> bool:
    """Whether the scan is of an AI workload: the config wins, else an AI resource was seen."""
    setting = _setting.get()
    if setting is not None:
        return setting
    return bool(seen_types())


def checks_on(resources: Iterable) -> bool:
    """Whether the AI template checks run on one file's resources."""
    setting = _setting.get()
    if setting is not None:
        return setting
    return any(r.type in AI_TYPES for r in resources)


def account_checks_on() -> bool:
    return _account_checks.get()


def account_checks_flag(rules_org: bool, rules_include: list[str] | None) -> bool:
    """The `account_checks` argument of use() for a run's rules.org and rules.include."""
    return bool(rules_org or (rules_include and "CF-BEDROCK-004" in rules_include))
