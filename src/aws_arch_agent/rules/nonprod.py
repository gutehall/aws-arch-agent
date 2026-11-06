"""Production-grade spend in non-production stacks (DM3-545).

These checks run only when a stack resolves to dev or staging (rules/environments.py).
They flag settings copied from production that a dev or staging stack pays for without
needing: Multi-AZ, provisioned concurrency, large instances, a NAT gateway per AZ, long
log retention, provisioned DynamoDB capacity. Each carries an estimated saving when the
price snapshot covers it. The reliability rules that recommend the opposite (CF-RDS-003,
CF-DEL-001; REL-001 and REL-016 in CDK source) are prod-only, so no stack gets both.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, List

from aws_arch_agent.models import Finding
from aws_arch_agent.rules import estimates
from aws_arch_agent.rules.resource_model import Resource

# Instance sizes above this are flagged in dev and staging (config nonprod.max_instance_size).
DEFAULT_MAX_SIZE = "large"
MAX_LOG_RETENTION_DAYS = 30

_max_size = DEFAULT_MAX_SIZE


@contextmanager
def use_max_size(size: str | None) -> Iterator[None]:
    """The largest instance size not flagged in dev and staging, for a scan."""
    global _max_size
    previous, _max_size = _max_size, size or DEFAULT_MAX_SIZE
    try:
        yield
    finally:
        _max_size = previous


def _flag(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


def _size_of(instance_type: Any) -> str | None:
    if not isinstance(instance_type, str) or "." not in instance_type:
        return None
    return instance_type.rpartition(".")[2]


def _bigger(size: str, limit: str) -> bool:
    sizes = estimates._SIZES
    return size in sizes and limit in sizes and sizes.index(size) > sizes.index(limit)


def findings(resources: List[Resource], template_path: Path, env: str) -> List[Finding]:
    out: List[Finding] = []

    def add(fid: str, res: Resource | None, title: str, rec: str, est: estimates.Estimate | None = None,
            evidence: str | None = None) -> None:
        f = Finding(
            id=fid, title=title, severity="Low", category="Cost Optimization",
            file=(res.file if res and res.file else str(template_path)),
            line=res.line if res else None,
            evidence=evidence or (f"{res.name} ({res.source_type})" if res else None),
            recommendation=f"This is a {env} stack. {rec}",
        )
        out.append(estimates.apply(f, est))

    nats = [r for r in resources if r.type == "nat_gateway" and not r.malformed]
    if len(nats) > 1:
        add("CF-ENV-004", nats[0], f"{env.capitalize()} stack runs {len(nats)} NAT gateways",
            "One NAT gateway per Availability Zone buys resilience a non-production stack rarely "
            "needs. Share one NAT gateway, or use VPC endpoints. In CDK: natGateways: 1.",
            estimates.extra_nat_gateways(len(nats)),
            evidence=f"{len(nats)} NAT gateways: " + ", ".join(r.name for r in nats[:5]))

    for res in resources:
        if res.malformed:
            continue
        props = res.properties
        if res.type == "db_instance" and _flag(props.get("MultiAZ")) and not props.get("DBClusterIdentifier"):
            add("CF-ENV-001", res, "Multi-AZ database in a non-production stack",
                "MultiAZ doubles the instance cost for a standby a non-production database rarely "
                "needs. Set MultiAZ to false. In CDK: multiAz: false.",
                estimates.rds_multi_az_premium({**props, "MultiAZ": True}))
        elif res.type == "elasticache_replication_group" and _flag(props.get("MultiAZEnabled")):
            add("CF-ENV-001", res, "Multi-AZ cache in a non-production stack",
                "MultiAZEnabled keeps replicas in other Availability Zones. A non-production cache "
                "rarely needs them: set MultiAZEnabled to false and use fewer replicas.")
        if res.type in ("lambda_alias", "lambda_version"):
            config = props.get("ProvisionedConcurrencyConfig")
            count = config.get("ProvisionedConcurrentExecutions") if isinstance(config, dict) else None
            if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                add("CF-ENV-002", res, "Provisioned concurrency in a non-production stack",
                    f"{count} provisioned concurrent executions are billed every hour, used or not. "
                    "Remove ProvisionedConcurrencyConfig outside production.")
        if res.type in ("instance", "db_instance"):
            key = "InstanceType" if res.type == "instance" else "DBInstanceClass"
            kind = props.get(key)
            size = _size_of(kind)
            if size and _bigger(size, _max_size):
                assert isinstance(kind, str)
                est = estimates.downsize("ec2" if res.type == "instance" else "rds", kind, _max_size, props)
                add("CF-ENV-003", res, "Large instance in a non-production stack",
                    f"{key} {kind} is above {_max_size}, the size set for dev and staging "
                    "(config nonprod.max_instance_size). Use a smaller size of the same family.", est)
        if res.type == "cloudwatch_log_group":
            days = props.get("RetentionInDays")
            if isinstance(days, int) and not isinstance(days, bool) and days > MAX_LOG_RETENTION_DAYS:
                add("CF-ENV-005", res, "Long log retention in a non-production stack",
                    f"RetentionInDays is {days}. Logs from a non-production stack rarely need more "
                    f"than {MAX_LOG_RETENTION_DAYS} days, and storage is billed per GB-month. "
                    "In CDK: retention: logs.RetentionDays.ONE_MONTH.")
        if res.type == "dynamodb_table" and "BillingMode" not in res.unresolved:
            if props.get("BillingMode", "PROVISIONED") == "PROVISIONED":
                add("CF-ENV-006", res, "Provisioned DynamoDB capacity in a non-production stack",
                    "Provisioned capacity is billed every hour, used or not. A non-production table "
                    "with idle periods costs less on demand: set BillingMode to PAY_PER_REQUEST. "
                    "In CDK: billingMode: dynamodb.BillingMode.PAY_PER_REQUEST.",
                    estimates.dynamodb_provisioned(props))
    return out
