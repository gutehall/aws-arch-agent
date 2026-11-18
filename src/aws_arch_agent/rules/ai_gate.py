"""Whether a scan is of an AI workload. The AI lens answers and the AI findings run only then.

Auto: the normalized resources of the scan include a Bedrock, SageMaker, or AgentCore type
(rules/resource_model.py and rules/terraform_model.py map the CloudFormation and Terraform
types onto the canonical ones below). Config `lenses.ai` overrides it: true turns the lenses
on with no AI resource, false turns them off even when one exists.

The setting and the resources seen live in context variables, set by `use()` around a scan,
the way the tag policy and the price region are. Outside `use()` nothing is seen, so only
`lenses.ai: true` turns the gate on. A CDK source scan has no normalized resources, so it
is on only when forced.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterable, Iterator, Set

# Canonical types of the AI services.
BEDROCK_AGENT_TYPES = frozenset({"bedrock_agent", "bedrockagentcore_agent_runtime"})
AI_TYPES = frozenset({
    "bedrock_agent", "bedrock_guardrail", "bedrock_knowledge_base", "bedrock_prompt",
    "bedrock_model_invocation_logging",
    "bedrockagentcore_agent_runtime", "bedrockagentcore_gateway", "bedrockagentcore_memory",
    "sagemaker_notebook_instance", "sagemaker_endpoint_config", "sagemaker_endpoint",
    "sagemaker_monitoring_schedule",
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
