"""Estimated monthly cost per template or Terraform root module.

Every resource live pricing covers is priced, not only those with findings. This is
an approximation in the style of Infracost: on-demand prices only, 730 hours a month.
Usage-based charges (data, requests, storage) are priced only where a usage profile
(pricing.usage) states the usage; they are kept apart from the fixed cost and flagged
usage_assumed. Resource types that cost money but cannot be priced are listed so the
reader knows what the total leaves out.
"""
from __future__ import annotations

import re
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, List

from aws_arch_agent.models import Finding
from aws_arch_agent.pricing import current_region, snapshot_date
from aws_arch_agent.pricing.usage import UsageProfile
from aws_arch_agent.rules import cost_diff, estimates
from aws_arch_agent.rules.resource_model import TF_MODULE_CALL, Resource
from aws_arch_agent.tools.paths import to_repo_relative

TOP_N = 5

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
    r"ApiGateway::(?:Resource|Method|Deployment|Account)|WAFv2::WebACLAssociation|"
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
    r"api_gateway_(?:resource|method|integration|deployment)\w*|cloudwatch_log_subscription_filter|"
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
        cost = estimates.resource_cost(res, index)
        stated = _profile.for_resource(res.type, res.name) if _profile else None
        used = estimates.usage_cost(res, stated) if stated else None
        if cost is not None:
            stack.priced.append((res, cost))
        if used is not None:
            stack.usage.append((res, used))
        if cost is None and used is None and not is_free(res.source_type):
            stack.not_priced[res.source_type] += 1
    _stacks[stack.path] = stack


def summary(findings: List[Finding], repo_path: Path | None = None) -> dict[str, Any] | None:
    """The report's cost section, or None when no template was priced in this scan.

    Possible savings are the sum of the findings' monthly_savings_usd: a separate figure,
    never subtracted from the total.
    """
    if not _stacks:
        return None
    def where(path: str) -> str:
        return to_repo_relative(path, repo_path) if repo_path else path

    stacks: list[dict[str, Any]] = []
    everything: list[tuple[str, Resource, estimates.Estimate, bool]] = []
    not_priced: Counter = Counter()
    for path, stack in sorted(_stacks.items()):
        fixed = round(sum(c.monthly_cost_usd or 0.0 for _, c in stack.priced), 2)
        used = round(sum(c.monthly_cost_usd or 0.0 for _, c in stack.usage), 2)
        entry: dict[str, Any] = {
            "name": where(path), "region": stack.region, "snapshot_date": snapshot_date(stack.region),
            "resources_priced": len({id(r) for r, _ in stack.priced + stack.usage}),
            "monthly_usd": round(fixed + used, 2),
        }
        if stack.usage:
            entry.update(fixed_monthly_usd=fixed, usage_monthly_usd=used)
        stacks.append(entry)
        everything.extend((where(path), res, cost, False) for res, cost in stack.priced)
        everything.extend((where(path), res, cost, True) for res, cost in stack.usage)
        not_priced.update(stack.not_priced)
    top = sorted(everything, key=lambda item: (-(item[2].monthly_cost_usd or 0.0), item[0], item[1].name, item[3]))
    savings = [f.monthly_savings_usd for f in findings if f.monthly_savings_usd]
    used_regions = sorted({s.region for s in _stacks.values()})
    dates = [snapshot_date(r) for r in used_regions]
    fixed_total = round(sum(s.get("fixed_monthly_usd", s["monthly_usd"]) for s in stacks), 2)
    usage_total = round(sum(s.get("usage_monthly_usd", 0.0) for s in stacks), 2)
    basis = ("On-demand prices, 730 hours a month. Usage-based charges (data processed and "
             "transferred, requests, storage growth) are not included.")
    if _profile is not None:
        basis = ("On-demand prices, 730 hours a month. Usage-based charges are included only where "
                 f"the usage profile ({_profile.path or 'usage file'}) states the usage, and are "
                 "shown apart as usage-assumed cost.")
    out: dict[str, Any] = {
        "region": ", ".join(used_regions),  # one region, or every region the stacks use
        # One region: its price list date. Several: each stack carries its own.
        "snapshot_date": dates[0] if len(used_regions) == 1 else None,
        "basis": basis,
        "stacks": stacks,
        "total_monthly_usd": round(fixed_total + usage_total, 2),
        "fixed_monthly_usd": fixed_total,
        "usage_monthly_usd": usage_total,
        "top_resources": [
            {
                "name": res.name, "type": res.source_type, "stack": stack,
                "file": where(res.file) if res.file else stack, "line": res.line,
                "monthly_usd": cost.monthly_cost_usd, "basis": cost.basis,
                **({"usage_assumed": True} if usage else {}),
            }
            for stack, res, cost, usage in top[:TOP_N] if (cost.monthly_cost_usd or 0) > 0
        ],
        "savings_monthly_usd": round(sum(savings), 2),
        "savings_findings": len(savings),
        "not_priced": dict(sorted(not_priced.items())),
        # Every priced resource, for --compare-cost against this report and baseline snapshots.
        "resources": [
            {"stack": stack, "name": res.name, "type": res.source_type, "monthly_usd": cost.monthly_cost_usd,
             **({"usage_assumed": True} if usage else {})}
            for stack, res, cost, usage in sorted(everything, key=lambda i: (i[0], i[1].name, i[3]))
        ],
    }
    if _profile is not None:
        out["usage_file"] = _profile.path
    if _options.previous is not None:
        out["diff"] = cost_diff.diff(_options.previous, out, _options.previous_source)
    if _options.budget is not None and _options.budget.is_set():
        out["budget"] = cost_diff.evaluate(_options.budget, out)
    return out
