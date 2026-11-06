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
from aws_arch_agent.pricing import Price, current_region, price, regions

HOURS_PER_MONTH = 730
# gp3 includes 3,000 IOPS; a gp2 volume has 3 IOPS per GiB, so above 1,000 GiB gp2 has more
# baseline IOPS than gp3 and matching it on gp3 costs extra.
GP3_BASELINE_GIB = 1000
# Up to 170 GiB gp2 gives 128 MiB/s, about gp3's included 125 MB/s; above it gp2 gives more.
GP2_SMALL_THROUGHPUT_GIB = 170

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
    """The size directly below in the same family (m5.4xlarge -> m5.2xlarge), priced here.

    Families skip sizes (m5 has no 3xlarge), so "directly below" is the next size the
    snapshot lists for the family in any region. If this region does not price that size,
    there is no saving rather than one from a smaller size further down.
    """
    match = re.fullmatch(rf"({re.escape(prefix)}[a-z0-9-]+)\.([a-z0-9]+)", instance_type)
    if not match or match.group(2) not in _SIZES:
        return None
    family, size = match.groups()
    for smaller in reversed(_SIZES[: _SIZES.index(size)]):
        candidate = f"{family}.{smaller}"
        if any(price(key_for(candidate), region) is not None for region in regions()):
            found = price(key_for(candidate), current_region())
            return (candidate, found) if found is not None else None
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
            f" Saving on gp3 at {_unit_price(gp3)}/GB-month, whose included 3,000 IOPS match or "
            "exceed this volume's gp2 baseline."
            + (
                " gp3 includes 125 MB/s; gp2 can reach 250 MB/s above 170 GiB, so a volume that "
                "needs that throughput pays for it on gp3 (not included in the saving)."
                if gib > GP2_SMALL_THROUGHPUT_GIB else ""
            )
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


# --- Whole-resource costs for the stack total (DM3-542) ---------------------------------


def volume(volume_type: Any, size: Any) -> Estimate | None:
    """Storage cost of an EBS volume by type and size (gp2 by default). io2 and gp3 extras
    (provisioned IOPS, throughput) are excluded."""
    kind = "gp2" if volume_type is None else volume_type
    gib = _literal_int(size)
    if not isinstance(kind, str) or gib is None or gib < 1:
        return None
    per_gb = price(f"ebs:{kind}", current_region())
    if per_gb is None:
        return None
    extras = " Excludes provisioned IOPS and throughput." if kind in ("gp3", "io2") else ""
    return Estimate(
        monthly_cost_usd=_round(gib * per_gb.usd),
        monthly_savings_usd=None,
        basis=f"{gib:,} GiB {kind} × {_unit_price(per_gb)}/GB-month, {_where(per_gb)}.{extras} Excludes snapshots.",
    )


def public_ipv4(pool: Any = None) -> Estimate | None:
    if pool is not None and pool != "amazon":
        return Estimate(0.0, None, "Public IPv4 from your own BYOIP pool: not billed by the hour.")
    hour = price("eip:in-use-hour", current_region())
    if hour is None:
        return None
    return Estimate(
        monthly_cost_usd=_round(HOURS_PER_MONTH * hour.usd),
        monthly_savings_usd=None,
        basis=f"1 public IPv4 address × {HOURS_PER_MONTH} h × {_unit_price(hour)}/h, {_where(hour)}.",
    )


def dynamodb_provisioned(props: dict) -> Estimate | None:
    """Provisioned read and write capacity. On-demand tables are usage-based: no estimate."""
    mode = props.get("BillingMode", "PROVISIONED")
    if mode != "PROVISIONED":
        return None
    throughput = props.get("ProvisionedThroughput")
    if not isinstance(throughput, dict):
        return None
    rcu, wcu = _literal_int(throughput.get("ReadCapacityUnits")), _literal_int(throughput.get("WriteCapacityUnits"))
    read, write = price("dynamodb:rcu-hour", current_region()), price("dynamodb:wcu-hour", current_region())
    if rcu is None or wcu is None or read is None or write is None:
        return None
    return Estimate(
        monthly_cost_usd=_round(HOURS_PER_MONTH * (rcu * read.usd + wcu * write.usd)),
        monthly_savings_usd=None,
        basis=(
            f"{rcu:,} RCU × {_unit_price(read)}/h + {wcu:,} WCU × {_unit_price(write)}/h, "
            f"× {HOURS_PER_MONTH} h, {_where(read)}. Excludes storage, index capacity, "
            "free tier and autoscaling."
        ),
    )


def resource_cost(res: Any) -> Estimate | None:
    """The monthly on-demand cost of one resource, or None when the snapshot cannot price it.
    Only the resource's own cost: savings are a finding's business, so they are dropped."""
    props = res.properties
    est: Estimate | None
    if res.type == "instance":
        est = ec2_instance(props.get("InstanceType"))
    elif res.type == "db_instance":
        est = rds_instance(props)
    elif res.type == "nat_gateway":
        est = nat_gateways(1)
    elif res.type == "ebs_volume":
        est = volume(props.get("VolumeType"), props.get("Size"))
    elif res.type == "eip":
        est = public_ipv4(props.get("PublicIpv4Pool"))
    elif res.type == "dynamodb_table":
        est = dynamodb_provisioned(props)
    else:
        return None
    if est is None or est.monthly_cost_usd is None:
        return None
    return Estimate(est.monthly_cost_usd, None, _without_saving(est.basis))


def _without_saving(basis: str) -> str:
    """The basis with its 'Saving if ...' sentence removed (a stack total has no saving)."""
    return re.sub(r" Saving if one size smaller \([^)]*\)\.", "", basis)

