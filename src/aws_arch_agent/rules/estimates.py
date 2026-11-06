"""Monthly cost estimates for template findings (DM3-541).

Prices come from the offline snapshot (aws_arch_agent.pricing) for the scan's region.
Only what the template states is priced: instance types, volume sizes and types, counts.
Usage (data processed, requests, transfer) is never guessed; the basis lists it as
excluded. A saving is its own number and is never subtracted from the cost.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from aws_arch_agent.models import Finding
from aws_arch_agent.pricing import Price, current_region, price

HOURS_PER_MONTH = 730
# gp3 includes 3,000 IOPS; a gp2 volume has 3 IOPS per GiB, so above 1,000 GiB gp2 has more
# baseline IOPS than gp3 and matching it on gp3 costs extra.
GP3_BASELINE_GIB = 1000

# Instance sizes from small to large, for "one size smaller".
_SIZES = (
    "nano", "micro", "small", "medium", "large", "xlarge", "2xlarge", "3xlarge", "4xlarge",
    "6xlarge", "8xlarge", "9xlarge", "10xlarge", "12xlarge", "16xlarge", "18xlarge",
    "24xlarge", "32xlarge", "48xlarge",
)
# CloudFormation / Terraform engine names -> snapshot engine names.
_RDS_ENGINES = {
    "mysql": "mysql", "postgres": "postgres", "mariadb": "mariadb",
    "aurora": "aurora-mysql", "aurora-mysql": "aurora-mysql", "aurora-postgresql": "aurora-postgresql",
}
_ENGINE_LABELS = {
    "mysql": "MySQL", "postgres": "PostgreSQL", "mariadb": "MariaDB",
    "aurora-mysql": "Aurora MySQL", "aurora-postgresql": "Aurora PostgreSQL",
}


@dataclass(frozen=True)
class Estimate:
    monthly_cost_usd: float | None
    monthly_savings_usd: float | None
    basis: str


def apply(finding: Finding, estimate: Estimate | None) -> Finding:
    """Set the estimate fields on a finding. None leaves them empty. Returns the finding."""
    if estimate is not None:
        finding.monthly_cost_usd = estimate.monthly_cost_usd
        finding.monthly_savings_usd = estimate.monthly_savings_usd
        finding.estimate_basis = estimate.basis
    return finding


def money(usd: float) -> str:
    return f"${usd:,.2f}"


def _unit_price(p: Price) -> str:
    return f"${p.usd:.6g}"


def _where(p: Price) -> str:
    return f"{p.region}, AWS prices of {p.snapshot_date}" if p.snapshot_date else p.region


def _round(usd: float) -> float:
    return round(usd, 2)


def _literal_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _smaller(instance_type: str, prefix: str, key_for: Any) -> tuple[str, Price] | None:
    """The next smaller size of the same family that the snapshot prices."""
    match = re.fullmatch(rf"({re.escape(prefix)}[a-z0-9-]+)\.([a-z0-9]+)", instance_type)
    if not match or match.group(2) not in _SIZES:
        return None
    family, size = match.groups()
    for smaller in reversed(_SIZES[: _SIZES.index(size)]):
        candidate = f"{family}.{smaller}"
        found = price(key_for(candidate), current_region())
        if found is not None:
            return candidate, found
    return None


def nat_gateways(count: int) -> Estimate | None:
    hour = price("nat:hour", current_region())
    if hour is None or count < 1:
        return None
    gb = price("nat:gb", current_region())
    processing = f" ({_unit_price(gb)}/GB)" if gb else ""
    noun = "NAT gateway" if count == 1 else "NAT gateways"
    return Estimate(
        monthly_cost_usd=_round(count * HOURS_PER_MONTH * hour.usd),
        monthly_savings_usd=None,
        basis=(
            f"{count} {noun} × {HOURS_PER_MONTH} h × {_unit_price(hour)}/h, {_where(hour)}. "
            f"Excludes data processing{processing} and data transfer, which depend on traffic."
        ),
    )


def ec2_instance(instance_type: Any) -> Estimate | None:
    """On-demand Linux cost, and the saving one size smaller."""
    if not isinstance(instance_type, str):
        return None
    now = price(f"ec2:{instance_type}", current_region())
    if now is None:
        return None
    cost = HOURS_PER_MONTH * now.usd
    smaller = _smaller(instance_type, "", lambda t: f"ec2:{t}")
    saving = None
    note = ""
    if smaller is not None:
        saving = _round(cost - HOURS_PER_MONTH * smaller[1].usd)
        note = f" Saving if one size smaller ({smaller[0]}, {_unit_price(smaller[1])}/h)."
    return Estimate(
        monthly_cost_usd=_round(cost),
        monthly_savings_usd=saving,
        basis=(
            f"1 {instance_type} (Linux, on-demand) × {HOURS_PER_MONTH} h × {_unit_price(now)}/h, "
            f"{_where(now)}.{note} Excludes EBS, data transfer, licences and Savings Plans."
        ),
    )


def rds_instance(props: dict) -> Estimate | None:
    """On-demand instance cost from DBInstanceClass, Engine and MultiAZ; saving one size smaller."""
    instance_class, engine_raw = props.get("DBInstanceClass"), props.get("Engine")
    multi_az = props.get("MultiAZ", False)
    if not isinstance(instance_class, str) or not isinstance(engine_raw, str):
        return None
    if isinstance(multi_az, str) and multi_az.lower() in ("true", "false"):
        multi_az = multi_az.lower() == "true"
    if not isinstance(multi_az, bool):
        return None
    engine = _RDS_ENGINES.get(engine_raw.strip().lower())
    if engine is None:
        return None
    # Aurora is priced per instance; Multi-AZ there means more instances, each priced alone.
    deployment = "multi-az" if multi_az and not engine.startswith("aurora") else "single-az"

    def key_for(cls: str) -> str:
        return f"rds:{engine}:{deployment}:{cls}"

    now = price(key_for(instance_class), current_region())
    if now is None:
        return None
    cost = HOURS_PER_MONTH * now.usd
    smaller = _smaller(instance_class, "db.", key_for)
    saving = None
    note = ""
    if smaller is not None:
        saving = _round(cost - HOURS_PER_MONTH * smaller[1].usd)
        note = f" Saving if one size smaller ({smaller[0]}, {_unit_price(smaller[1])}/h)."
    label = _ENGINE_LABELS[engine] + (" Multi-AZ" if deployment == "multi-az" else "")
    return Estimate(
        monthly_cost_usd=_round(cost),
        monthly_savings_usd=saving,
        basis=(
            f"1 {instance_class} {label} × {HOURS_PER_MONTH} h × {_unit_price(now)}/h, {_where(now)}."
            f"{note} Excludes storage, I/O, backups and data transfer."
        ),
    )


def gp2_volume(size: Any) -> Estimate | None:
    """gp2 storage cost, and the saving on gp3 at its baseline performance."""
    gib = _literal_int(size)
    gp2 = price("ebs:gp2", current_region())
    if gib is None or gib < 1 or gp2 is None:
        return None
    gp3 = price("ebs:gp3", current_region())
    cost = gib * gp2.usd
    saving = None
    if gp3 is not None and gib <= GP3_BASELINE_GIB:
        saving = _round(cost - gib * gp3.usd)
        note = (
            f" Saving on gp3 at {_unit_price(gp3)}/GB-month, whose included 3,000 IOPS and "
            "125 MB/s match or exceed this volume's gp2 baseline."
        )
    elif gp3 is not None:
        note = (
            f" No saving is estimated: above {GP3_BASELINE_GIB:,} GiB gp2 has more baseline IOPS "
            "than gp3 includes, and matching them on gp3 costs extra."
        )
    else:
        note = ""
    return Estimate(
        monthly_cost_usd=_round(cost),
        monthly_savings_usd=saving,
        basis=f"{gib:,} GiB gp2 × {_unit_price(gp2)}/GB-month, {_where(gp2)}.{note} Excludes snapshots.",
    )


def idle_public_ipv4() -> Estimate | None:
    """An Elastic IP nothing uses: its cost is also the saving from releasing it."""
    idle = price("eip:idle-hour", current_region())
    if idle is None:
        return None
    cost = _round(HOURS_PER_MONTH * idle.usd)
    return Estimate(
        monthly_cost_usd=cost,
        monthly_savings_usd=cost,
        basis=(
            f"1 public IPv4 address × {HOURS_PER_MONTH} h × {_unit_price(idle)}/h, {_where(idle)}. "
            "The saving is the cost: released, it is not billed."
        ),
    )
