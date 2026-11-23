"""Estimated monthly cost per template or Terraform root module.

Every resource live pricing covers is priced, not only those with findings. This is
an approximation in the style of Infracost: on-demand prices only, 730 hours a month.
Usage-based charges (data, requests, storage) are priced only where a usage profile
(pricing.usage) states the usage; they are kept apart from the fixed cost and flagged
usage_assumed. Without a usage file the low-traffic usage.ILLUSTRATION is priced instead
and kept apart again: it moves the headline, never total_monthly_usd, so budgets and
--compare-cost read only what the IaC and a usage file state. Resource types that cost
money but cannot be priced are counted in not_priced.
"""
from __future__ import annotations

import re
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, List

from aws_arch_agent.models import Finding
from aws_arch_agent import pricing
from aws_arch_agent.pricing import current_region, snapshot_date
from aws_arch_agent.pricing.usage import ILLUSTRATION, UsageProfile
from aws_arch_agent.rules import cost_diff, estimates
from aws_arch_agent.rules.resource_model import TF_MODULE_CALL, Resource
from aws_arch_agent.tools.paths import to_repo_relative

TOP_N = 5
FREE_BUDGETS = 2  # AWS Budgets: the first two in an account are free
# What still has no cost model, named once in the report instead of a type-by-type list.
NOT_MODELLED = "CloudFront traffic, Cognito monthly active users, CloudTrail data events"

# Types that are free in themselves (configuration, permissions, wiring). They are not
# listed as "not priced". Anything else that cannot be priced is listed.
_FREE_CF = re.compile(
    r"^(?:AWS::IAM::|AWS::CloudFormation::|AWS::CDK::|AWS::ApplicationAutoScaling::|Custom::)"
    r"|^AWS::EC2::(?:SecurityGroup\w*|VPC|Subnet\w*|RouteTable|Route|InternetGateway|"
    r"VPCGatewayAttachment|NetworkAcl\w*|LaunchTemplate|EIPAssociation|VPCEndpointService\w*|"
    r"DHCPOptions|VPCDHCPOptionsAssociation|EgressOnlyInternetGateway|PrefixList)$"
    r"|^AWS::(?:S3::BucketPolicy|SQS::QueuePolicy|SNS::TopicPolicy|SNS::Subscription|KMS::Alias|"
    r"Lambda::Permission|Lambda::EventSourceMapping|Lambda::Version|Lambda::Alias|Events::Rule|"
    r"Logs::SubscriptionFilter|Logs::MetricFilter|Logs::QueryDefinition|ECR::RegistryPolicy|"
    r"CE::AnomalyMonitor|CE::AnomalySubscription|EC2::VolumeAttachment|"
    r"ECS::(?:Cluster|TaskDefinition)|AutoScaling::(?:LaunchConfiguration|ScalingPolicy|ScheduledAction)|"
    r"SecretsManager::RotationSchedule|SecretsManager::ResourcePolicy|"
    r"ElasticLoadBalancingV2::(?:Listener|ListenerRule|TargetGroup)|"
    r"ApiGateway::(?:Resource|Method|Deployment|Account|Authorizer|GatewayResponse)|"
    r"ApiGatewayV2::(?:Authorizer|Stage)|WAFv2::(?:WebACLAssociation|LoggingConfiguration)|"
    r"CloudFront::OriginAccessControl|Cognito::UserPoolClient|"
    r"Backup::(?:BackupPlan|BackupSelection))$"
)
_FREE_TF = re.compile(
    r"^aws_(?:iam_\w+|security_group\w*|vpc_security_group_\w+|vpc|subnet|"
    r"route|route_table|route_table_association|main_route_table_association|"
    r"internet_gateway\w*|network_acl\w*|launch_template|default_\w+|kms_alias|"
    r"lambda_permission|lambda_event_source_mapping|lambda_alias|appautoscaling_\w+|"
    r"cloudwatch_event_\w+|s3_bucket_(?!object)\w+|sqs_queue_policy|sns_topic_\w+|"
    r"ecr_lifecycle_policy|ecr_repository_policy|secretsmanager_secret_\w+|"
    r"eip_association|lb_listener\w*|lb_target_group\w*|wafv2_web_acl_association|"
    r"api_gateway_(?:resource|method|integration|deployment|authorizer|gateway_response)\w*|"
    r"apigatewayv2_(?:authorizer|stage)|wafv2_web_acl_logging_configuration|"
    r"cloudfront_origin_access_control|cognito_user_pool_client|cloudwatch_log_subscription_filter|"
    r"cloudwatch_log_metric_filter|cloudwatch_query_definition|ce_anomaly_\w+|volume_attachment|"
    r"backup_plan|backup_selection|backup_vault_lock_configuration|ecs_cluster|ecs_task_definition|"
    r"launch_configuration|autoscaling_policy|autoscaling_schedule)$"
)


@dataclass
class _Stack:
    path: str
    region: str = ""
    priced: list[tuple[Resource, estimates.Estimate]] = field(default_factory=list)
    usage: list[tuple[Resource, estimates.Estimate]] = field(default_factory=list)
    # Usage from usage.ILLUSTRATION (no usage file): shown, never budgeted or diffed.
    illustrated: list[tuple[Resource, estimates.Estimate]] = field(default_factory=list)
    # Priced (or counted) per account in summary(): the first few of each are free.
    dashboards: list[Resource] = field(default_factory=list)
    budgets: list[Resource] = field(default_factory=list)
    not_priced: Counter = field(default_factory=Counter)


@dataclass(frozen=True)
class FinOps:
    """A scan's cost options: usage profile, earlier cost to diff against, budget."""

    usage: UsageProfile | None = None
    previous: dict[str, Any] | None = None  # a cost_diff.snapshot
    previous_source: str = ""
    budget: cost_diff.Budget | None = None


_stacks: dict[str, _Stack] | None = None
_options = FinOps()
_profile: UsageProfile | None = None


@contextmanager
def collect(options: FinOps | None = None) -> Iterator[None]:
    """Collect per-stack costs for the duration of a scan."""
    global _stacks, _options, _profile
    saved = _stacks, _options, _profile
    _stacks, _options = {}, options or FinOps()
    _profile = _options.usage
    try:
        yield
    finally:
        _stacks, _options, _profile = saved


def usage_profile() -> UsageProfile | None:
    """The usage profile of the scan in progress (collect()), or None."""
    return _profile


def is_free(source_type: str) -> bool:
    return bool(source_type == TF_MODULE_CALL or _FREE_CF.match(source_type) or _FREE_TF.match(source_type))


def _free_by_properties(res: Resource) -> bool:
    """A standard-tier SSM parameter is free; an advanced one is not. A REST API stage is
    free unless it runs a cache cluster (billed hourly, not priced here)."""
    if res.type == "ssm_parameter":
        return res.properties.get("Tier", "Standard") in ("Standard", "standard")
    if res.type == "api_gateway_stage":
        cache = res.properties.get("CacheClusterEnabled")
        return "CacheClusterEnabled" not in res.unresolved and cache not in (True, "true", "True")
    return False


def record(template_path: Path, resources: List[Resource]) -> None:
    """Price one template's (or root module's) resources. A no-op outside collect()."""
    if _stacks is None:
        return
    # One entry per file however the scan reached it (relative, absolute, listed twice).
    stack = _Stack(path=str(Path(template_path).resolve()), region=current_region())
    index = {res.name: res for res in resources}
    for res in resources:
        if res.malformed:
            stack.not_priced[res.source_type] += 1
            continue
        if res.type == "cloudwatch_dashboard":
            stack.dashboards.append(res)
            continue
        if res.type == "budgets_budget":
            stack.budgets.append(res)
            continue
        cost = estimates.resource_cost(res, index)
        profile = _profile or ILLUSTRATION
        stated = profile.for_resource(res.type, res.name)
        used = estimates.usage_cost(
            res, stated, "Illustration" if profile.illustration else "Usage assumed") if stated else None
        if cost is not None:
            stack.priced.append((res, cost))
        if used is not None:
            (stack.illustrated if profile.illustration else stack.usage).append((res, used))
        if cost is None and used is None and not is_free(res.source_type) and not _free_by_properties(res):
            stack.not_priced[res.source_type] += 1
    _stacks[stack.path] = stack


def _prices_unavailable(regions: list[str], not_priced: Counter) -> str | None:
    """Why no AWS price was used, when resources went unpriced for want of one; else None.

    A stack that needed prices and got none must not read as a free stack."""
    if not not_priced or any(snapshot_date(r) for r in regions):
        return None
    if isinstance(pricing.provider(), pricing.OffPriceProvider):
        return "Pricing is off (--pricing-source off), so usage-billed and sized resources are not priced."
    reasons = pricing.warnings()
    if not reasons:
        return None  # nothing failed: no lookup was needed (flat prices, unmodelled types)
    return ("The AWS price list could not be reached, so usage-billed and sized resources are not priced. "
            + " ".join(reasons))


def summary(findings: List[Finding], repo_path: Path | None = None) -> dict[str, Any] | None:
    """The report's cost section, or None when no template was priced in this scan.

    Possible savings are the sum of the findings' monthly_savings_usd: a separate figure,
    never subtracted from the total.
    """
    if not _stacks:
        return None
    def where(path: str) -> str:
        return to_repo_relative(path, repo_path) if repo_path else path

    # Account-wide free allowances, in a fixed order: dashboards after the first three are
    # priced, budgets after the first two are counted as not priced.
    extra: dict[str, list[tuple[Resource, estimates.Estimate]]] = {path: [] for path in _stacks}
    extra_not_priced: Counter = Counter()
    dashboards = [(path, res) for path, st in sorted(_stacks.items()) for res in st.dashboards]
    for path, res in dashboards[estimates.FREE_DASHBOARDS:]:
        extra[path].append((res, estimates.dashboard()))
    budgets = [(path, res) for path, st in sorted(_stacks.items()) for res in st.budgets]
    for _, res in budgets[FREE_BUDGETS:]:
        extra_not_priced[res.source_type] += 1

    stacks: list[dict[str, Any]] = []
    # (stack, resource, estimate, kind): kind is "", "usage" (usage file) or "illustrated".
    everything: list[tuple[str, Resource, estimates.Estimate, str]] = []
    not_priced: Counter = Counter(extra_not_priced)
    for path, stack in sorted(_stacks.items()):
        priced = stack.priced + extra[path]
        fixed = round(sum(c.monthly_cost_usd or 0.0 for _, c in priced), 2)
        used = round(sum(c.monthly_cost_usd or 0.0 for _, c in stack.usage), 2)
        illustrated = round(sum(c.monthly_cost_usd or 0.0 for _, c in stack.illustrated), 2)
        entry: dict[str, Any] = {
            "name": where(path), "region": stack.region, "snapshot_date": snapshot_date(stack.region),
            "resources_priced": len({id(r) for r, _ in priced + stack.usage}),
            "monthly_usd": round(fixed + used, 2),
        }
        if stack.usage:
            entry.update(fixed_monthly_usd=fixed, usage_monthly_usd=used)
        if stack.illustrated:
            entry["illustrated_monthly_usd"] = illustrated
        stacks.append(entry)
        everything.extend((where(path), res, cost, "") for res, cost in priced)
        everything.extend((where(path), res, cost, "usage") for res, cost in stack.usage)
        everything.extend((where(path), res, cost, "illustrated") for res, cost in stack.illustrated)
        not_priced.update(stack.not_priced)
    top = sorted(everything, key=lambda item: (-(item[2].monthly_cost_usd or 0.0), item[0], item[1].name, item[3]))
    budgeted = [item for item in everything if item[3] != "illustrated"]
    savings = [f.monthly_savings_usd for f in findings if f.monthly_savings_usd]
    used_regions = sorted({s.region for s in _stacks.values()})
    dates = [snapshot_date(r) for r in used_regions]
    fixed_total = round(sum(s.get("fixed_monthly_usd", s["monthly_usd"]) for s in stacks), 2)
    usage_total = round(sum(s.get("usage_monthly_usd", 0.0) for s in stacks), 2)
    illustrated_total = round(sum(s.get("illustrated_monthly_usd", 0.0) for s in stacks), 2)
    total = round(fixed_total + usage_total, 2)
    basis = ("On-demand prices, 730 hours a month. Usage-based charges (data processed and "
             "transferred, requests, storage growth) are not included.")
    if _profile is not None:
        basis = ("On-demand prices, 730 hours a month. Usage-based charges are included only where "
                 f"the usage profile ({_profile.path or 'usage file'}) states the usage, and are "
                 "shown apart as usage-assumed cost.")
    elif illustrated_total:
        basis = ("On-demand prices, 730 hours a month. Usage-billed resources are priced at an assumed "
                 "low-traffic usage: an illustration, not a bill and not a budget. A "
                 ".aws-arch-agent-usage.yaml replaces it.")
    def kind_tag(kind: str) -> dict[str, bool]:
        return {"usage_assumed": True, **({"illustrated": True} if kind == "illustrated" else {})} if kind else {}
    out: dict[str, Any] = {
        "region": ", ".join(used_regions),  # one region, or every region the stacks use
        # One region: its price list date. Several: each stack carries its own.
        "snapshot_date": dates[0] if len(used_regions) == 1 else None,
        "basis": basis,
        "stacks": stacks,
        "total_monthly_usd": total,
        "fixed_monthly_usd": fixed_total,
        "usage_monthly_usd": usage_total,
        # What the report leads with: the total plus any illustration.
        "headline_monthly_usd": round(total + illustrated_total, 2),
        "top_resources": [
            {
                "name": res.name, "type": res.source_type, "stack": stack,
                "file": where(res.file) if res.file else stack, "line": res.line,
                "monthly_usd": cost.monthly_cost_usd, "basis": cost.basis, **kind_tag(kind),
            }
            for stack, res, cost, kind in top[:TOP_N] if (cost.monthly_cost_usd or 0) > 0
        ],
        "savings_monthly_usd": round(sum(savings), 2),
        "savings_findings": len(savings),
        "not_priced": dict(sorted(not_priced.items())),
        "not_modelled": NOT_MODELLED,
        # Every priced resource, for --compare-cost against this report and baseline snapshots.
        # The illustration is left out: it is not anyone's stated usage.
        "resources": [
            {"stack": stack, "name": res.name, "type": res.source_type, "monthly_usd": cost.monthly_cost_usd,
             **({"usage_assumed": True} if kind else {})}
            for stack, res, cost, kind in sorted(budgeted, key=lambda i: (i[0], i[1].name, i[3]))
        ],
    }
    if illustrated_total:
        out["illustrated_monthly_usd"] = illustrated_total
    unavailable = _prices_unavailable(used_regions, not_priced)
    if unavailable:
        out["prices_unavailable"] = unavailable
    if _profile is not None:
        out["usage_file"] = _profile.path
    if _options.previous is not None:
        out["diff"] = cost_diff.diff(_options.previous, out, _options.previous_source)
    if _options.budget is not None and _options.budget.is_set():
        out["budget"] = cost_diff.evaluate(_options.budget, out)
    return out
