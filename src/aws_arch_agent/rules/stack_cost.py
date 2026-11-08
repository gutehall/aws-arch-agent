"""Estimated monthly cost per template or Terraform root module.

Every resource the price snapshot covers is priced, not only those with findings. This is
an approximation in the style of Infracost: on-demand prices only, 730 hours a month, and
no usage-based charges (data, requests, storage growth). Resource types that cost money
but cannot be priced are listed so the reader knows what the total leaves out.
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
from aws_arch_agent.rules import estimates
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
    r"Logs::SubscriptionFilter|Logs::MetricFilter|ECR::RegistryPolicy|"
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
    r"backup_plan|backup_selection|backup_vault_lock_configuration)$"
)


@dataclass
class _Stack:
    path: str
    region: str = ""
    priced: list[tuple[Resource, estimates.Estimate]] = field(default_factory=list)
    not_priced: Counter = field(default_factory=Counter)


_stacks: dict[str, _Stack] | None = None


@contextmanager
def collect() -> Iterator[None]:
    """Collect per-stack costs for the duration of a scan."""
    global _stacks
    previous, _stacks = _stacks, {}
    try:
        yield
    finally:
        _stacks = previous


def is_free(source_type: str) -> bool:
    return bool(source_type == TF_MODULE_CALL or _FREE_CF.match(source_type) or _FREE_TF.match(source_type))


def record(template_path: Path, resources: List[Resource]) -> None:
    """Price one template's (or root module's) resources. A no-op outside collect()."""
    if _stacks is None:
        return
    # One entry per file however the scan reached it (relative, absolute, listed twice).
    stack = _Stack(path=str(Path(template_path).resolve()), region=current_region())
    for res in resources:
        if res.malformed:
            stack.not_priced[res.source_type] += 1
            continue
        cost = estimates.resource_cost(res)
        if cost is not None:
            stack.priced.append((res, cost))
        elif not is_free(res.source_type):
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
    everything: list[tuple[str, Resource, estimates.Estimate]] = []
    not_priced: Counter = Counter()
    for path, stack in sorted(_stacks.items()):
        total = round(sum(c.monthly_cost_usd or 0.0 for _, c in stack.priced), 2)
        stacks.append({
            "name": where(path), "region": stack.region, "snapshot_date": snapshot_date(stack.region),
            "resources_priced": len(stack.priced), "monthly_usd": total,
        })
        everything.extend((where(path), res, cost) for res, cost in stack.priced)
        not_priced.update(stack.not_priced)
    top = sorted(everything, key=lambda item: (-(item[2].monthly_cost_usd or 0.0), item[0], item[1].name))
    savings = [f.monthly_savings_usd for f in findings if f.monthly_savings_usd]
    used = sorted({s.region for s in _stacks.values()})
    dates = [snapshot_date(r) for r in used]
    return {
        "region": ", ".join(used),  # one region, or every region the stacks use
        # One region: its price list date. Several: each stack carries its own.
        "snapshot_date": dates[0] if len(used) == 1 else None,
        "basis": "On-demand prices, 730 hours a month. Usage-based charges (data processed and "
                 "transferred, requests, storage growth) are not included.",
        "stacks": stacks,
        "total_monthly_usd": round(sum(s["monthly_usd"] for s in stacks), 2),
        "top_resources": [
            {
                "name": res.name, "type": res.source_type, "stack": stack,
                "file": where(res.file) if res.file else stack, "line": res.line,
                "monthly_usd": cost.monthly_cost_usd, "basis": cost.basis,
            }
            for stack, res, cost in top[:TOP_N] if (cost.monthly_cost_usd or 0) > 0
        ],
        "savings_monthly_usd": round(sum(savings), 2),
        "savings_findings": len(savings),
        "not_priced": dict(sorted(not_priced.items())),
    }
