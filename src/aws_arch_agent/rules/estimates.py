"""Monthly cost estimates for template findings.

Prices come from live AWS pricing (aws_arch_agent.pricing) for the scan's region.
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
# Up to 170 GiB gp2 gives 128 MiB/s, about gp3's included 125 MB/s; above it gp2 gives more.
GP2_SMALL_THROUGHPUT_GIB = 170

# Flat monthly list prices the Price List does not carry as a plain per-unit row. The same
# in the Regions this tool prices; requests and metric math are not included.
ALARM_STANDARD_USD = 0.10       # standard-resolution metric alarm
ALARM_HIGH_RES_USD = 0.30       # period under 60 seconds
DASHBOARD_USD = 3.00            # each dashboard after the first three in an account
FREE_DASHBOARDS = 3
WEB_ACL_USD = 5.00              # WAFv2 web ACL
WEB_ACL_RULE_USD = 1.00         # each rule in it

# Instance sizes from small to large, for "one size smaller" and nonprod.max_instance_size.
SIZES = _SIZES = (
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
    where = f"{p.region}, AWS prices of {p.snapshot_date}" if p.snapshot_date else p.region
    return where + " (expired cache)" if p.stale else where


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

    Families skip sizes (m5 has no 3xlarge), so "directly below" is the next smaller size
    the scan's region prices for the family. Only that region is asked.
    """
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


# --- Whole-resource costs for the stack total ---------------------------------


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
    if pool is not None and not isinstance(pool, str):
        return None  # from a parameter: not guessed
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


def _hourly(key: str, count: int, what: str, excludes: str) -> Estimate | None:
    """count × 730 h × the key's hourly price."""
    hour = price(key, current_region())
    if hour is None or count < 1:
        return None
    return Estimate(
        monthly_cost_usd=_round(count * HOURS_PER_MONTH * hour.usd),
        monthly_savings_usd=None,
        basis=f"{count} {what} × {HOURS_PER_MONTH} h × {_unit_price(hour)}/h, {_where(hour)}. {excludes}".rstrip(),
    )


def _monthly(key: str, what: str, excludes: str) -> Estimate | None:
    """One unit at the key's monthly price (KMS key, secret)."""
    month = price(key, current_region())
    if month is None:
        return None
    return Estimate(_round(month.usd), None, f"1 {what} × {_unit_price(month)}/month, {_where(month)}. {excludes}".rstrip())


def _sum(parts: list[Estimate]) -> Estimate:
    return Estimate(
        _round(sum(p.monthly_cost_usd or 0.0 for p in parts)), None, " + ".join(p.basis for p in parts),
    )


_LB_KINDS = {"application": "alb", "network": "nlb", "gateway": "gwlb"}
_LB_NAMES = {"alb": "Application Load Balancer", "nlb": "Network Load Balancer", "gwlb": "Gateway Load Balancer"}


def load_balancer(props: dict) -> Estimate | None:
    """An ALB, NLB or GWLB's hours (Type defaults to application). LCUs are usage-based."""
    kind = _LB_KINDS.get(props.get("Type", "application")) if isinstance(props.get("Type", "application"), str) else None
    if kind is None:
        return None
    return _hourly(f"elb:{kind}-hour", 1, _LB_NAMES[kind], "Excludes capacity units (LCUs), which depend on traffic.")


def classic_load_balancer() -> Estimate | None:
    return _hourly("elb:clb-hour", 1, "Classic Load Balancer", "Excludes data processed.")


def eks_cluster() -> Estimate | None:
    return _hourly("eks:cluster-hour", 1, "EKS cluster control plane", "Excludes nodes, Fargate pods and extended support.")


def _fargate_size(value: Any, unit: str) -> float | None:
    """Task CPU in vCPU ("256" units, "0.25 vCPU", "1 vCPU") or memory in GB ("512" MiB, "1 GB")."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) / 1024
    if not isinstance(value, str):
        return None
    match = re.fullmatch(rf"\s*(\d+(?:\.\d+)?)\s*({unit})?\s*", value, re.IGNORECASE)
    if not match:
        return None
    number = float(match.group(1))
    return number if match.group(2) else number / 1024


def _linked(res: Any, prop: str, index: dict[str, Any] | None, tf_prefixes: tuple[str, ...]) -> Any:
    """The resource a property points at in the same stack: a CloudFormation Ref or a
    Terraform reference, else None."""
    if not index:
        return None
    value = res.properties.get(prop)
    if isinstance(value, str) and value in index:
        return index[value]
    if isinstance(value, dict):
        get_att = value.get("Fn::GetAtt")
        if isinstance(get_att, str):
            get_att = get_att.split(".", 1)
        target = value.get("Ref") or (get_att[0] if isinstance(get_att, list) and get_att else None)
        if isinstance(target, str) and target in index:
            return index[target]
    refs = sorted(a for a in getattr(res, "references", ()) if a.startswith(tf_prefixes))
    return index.get(refs[0]) if len(refs) == 1 else None


def fargate_service(res: Any, index: dict[str, Any] | None) -> Estimate | None:
    """A Fargate ECS service: DesiredCount tasks × the task definition's vCPU and memory hours."""
    props = res.properties
    launch = props.get("LaunchType")
    strategy = props.get("CapacityProviderStrategy") or []
    if not isinstance(strategy, list):
        return None
    providers = [s.get("CapacityProvider") for s in strategy if isinstance(s, dict)]
    if not all(isinstance(p, str) for p in providers) or not (launch is None or isinstance(launch, str)):
        return None  # a provider or launch type from a parameter: not guessed
    task = _linked(res, "TaskDefinition", index, ("aws_ecs_task_definition.",))
    if task is None:
        return None
    tprops = task.properties
    compat = tprops.get("RequiresCompatibilities")
    fargate = launch == "FARGATE" or (launch is None and providers and set(providers) <= {"FARGATE"}) or (
        launch is None and not providers and isinstance(compat, list) and compat == ["FARGATE"]
    )
    if not fargate:
        return None
    if "FARGATE_SPOT" in providers:
        return None
    count = _literal_int(props.get("DesiredCount"))
    vcpu, gb = _fargate_size(tprops.get("Cpu"), "vcpu"), _fargate_size(tprops.get("Memory"), "gb")
    if count is None or vcpu is None or gb is None:
        return None
    platform = tprops.get("RuntimePlatform") or {}
    if not isinstance(platform, dict):
        return None
    arch = platform.get("CpuArchitecture", "X86_64")
    if platform.get("OperatingSystemFamily", "LINUX") != "LINUX" or arch not in ("X86_64", "ARM64"):
        return None
    suffix = "-arm" if arch == "ARM64" else ""
    per_cpu, per_gb = price(f"fargate:vcpu-hour{suffix}", current_region()), price(f"fargate:gb-hour{suffix}", current_region())
    if per_cpu is None or per_gb is None:
        return None
    hourly = vcpu * per_cpu.usd + gb * per_gb.usd
    label = "ARM64" if arch == "ARM64" else "x86"
    return Estimate(
        monthly_cost_usd=_round(count * HOURS_PER_MONTH * hourly),
        monthly_savings_usd=None,
        basis=(
            f"{count} Fargate task(s) ({label}, {vcpu:g} vCPU × {_unit_price(per_cpu)}/h + {gb:g} GB × "
            f"{_unit_price(per_gb)}/h) × {HOURS_PER_MONTH} h, {_where(per_cpu)}. Excludes ephemeral storage "
            "above 20 GB, data transfer and autoscaling."
        ),
    )


def _engine(value: Any, default: str) -> str | None:
    engine = (value if isinstance(value, str) else default if value is None else "").strip().lower()
    return engine if engine in ("redis", "memcached", "valkey") else None


def elasticache(res: Any) -> Estimate | None:
    """Cache nodes × node hours. A replication group has node groups × (replicas + 1) nodes."""
    props = res.properties
    node = props.get("CacheNodeType")
    engine = _engine(props.get("Engine"), "redis")
    if not isinstance(node, str) or engine is None:
        return None
    if res.type == "elasticache_cluster":
        nodes = _literal_int(props.get("NumCacheNodes", 1))
    elif "NumNodeGroups" in props or "ReplicasPerNodeGroup" in props:
        groups, replicas = _literal_int(props.get("NumNodeGroups", 1)), _literal_int(props.get("ReplicasPerNodeGroup", 0))
        nodes = groups * (replicas + 1) if groups is not None and replicas is not None else None
    else:
        nodes = _literal_int(props.get("NumCacheClusters"))
    if nodes is None:
        return None
    return _hourly(f"elasticache:{engine}:{node}", nodes, f"{node} {engine} node(s)", "Excludes backups and data transfer.")


def opensearch_domain(props: dict) -> Estimate | None:
    """Data nodes, dedicated masters and EBS storage per data node."""
    config = props.get("ClusterConfig") or props.get("ElasticsearchClusterConfig") or {}
    if not isinstance(config, dict):
        return None
    node, count = config.get("InstanceType"), _literal_int(config.get("InstanceCount", 1))
    if not isinstance(node, str) or count is None:
        return None
    data = _hourly(f"opensearch:{node}", count, f"{node} data node(s)", "")
    if data is None:
        return None
    parts = [data]
    masters_on = config.get("DedicatedMasterEnabled")
    if masters_on is True or (isinstance(masters_on, str) and masters_on.lower() == "true"):
        master, masters = config.get("DedicatedMasterType"), _literal_int(config.get("DedicatedMasterCount", 3))
        est = _hourly(f"opensearch:{master}", masters, f"{master} dedicated master(s)", "") if (
            isinstance(master, str) and masters is not None) else None
        if est is None:
            return None
        parts.append(est)
    ebs = props.get("EBSOptions") or {}
    if isinstance(ebs, dict) and ebs.get("EBSEnabled") in (True, "true", "True"):
        size, kind = _literal_int(ebs.get("VolumeSize")), ebs.get("VolumeType", "gp2")
        per_gb = price(f"opensearch:storage:{kind}", current_region()) if isinstance(kind, str) else None
        if size is None or per_gb is None:
            return None
        parts.append(Estimate(
            _round(count * size * per_gb.usd), None,
            f"{count} × {size:,} GiB {kind} storage × {_unit_price(per_gb)}/GB-month",
        ))
    total = _sum(parts)
    return Estimate(total.monthly_cost_usd, None, total.basis + ". Excludes UltraWarm, snapshots and data transfer.")


def redshift_cluster(props: dict) -> Estimate | None:
    node = props.get("NodeType")
    single = props.get("ClusterType") == "single-node"
    nodes = 1 if single and "NumberOfNodes" not in props else _literal_int(props.get("NumberOfNodes", 1))
    if not isinstance(node, str) or nodes is None:
        return None
    return _hourly(f"redshift:{node}", nodes, f"{node} node(s)", "Excludes managed storage (RA3), backups and Spectrum.")


def vpc_endpoint(props: dict) -> Estimate | None:
    """An interface endpoint is billed per AZ (one per subnet); a gateway endpoint is free."""
    kind = props.get("VpcEndpointType", "Gateway")
    if kind == "Gateway":
        return Estimate(0.0, None, "Gateway endpoint: no hourly charge.")
    if kind not in ("Interface", "GatewayLoadBalancer"):
        return None
    subnets = props.get("SubnetIds")
    if not isinstance(subnets, list) or not subnets:
        return None
    return _hourly("vpce:hour", len(subnets), "interface endpoint AZ(s)", "Excludes data processed, which depends on traffic.")


def kinesis_stream(props: dict) -> Estimate | None:
    mode = (props.get("StreamModeDetails") or {}).get("StreamMode", "PROVISIONED") if isinstance(
        props.get("StreamModeDetails") or {}, dict) else None
    if mode == "ON_DEMAND":
        return _hourly("kinesis:on-demand-stream-hour", 1, "on-demand stream", "Excludes data in and out, which depend on traffic.")
    if mode != "PROVISIONED":
        return None
    shards = _literal_int(props.get("ShardCount"))
    if shards is None:
        return None
    return _hourly("kinesis:shard-hour", shards, "shard(s)", "Excludes PUT payload units and extended retention.")


def autoscaling_group(res: Any, index: dict[str, Any] | None) -> Estimate | None:
    """DesiredCapacity (else MinSize) instances of the launch template's or configuration's type."""
    props = res.properties
    if props.get("MixedInstancesPolicy"):
        return None
    count = _literal_int(props.get("DesiredCapacity", props.get("MinSize")))
    source = (
        _linked(res, "LaunchConfigurationName", index, ("aws_launch_configuration.",))
        if props.get("LaunchConfigurationName") is not None
        else _linked_template(res, index)
    )
    if count is None or source is None:
        return None
    sprops = source.properties
    data = sprops.get("LaunchTemplateData")
    instance_type = sprops.get("InstanceType") or (data.get("InstanceType") if isinstance(data, dict) else None)
    one = ec2_instance(instance_type)
    if one is None or one.monthly_cost_usd is None:
        return None
    return Estimate(
        _round(count * one.monthly_cost_usd), None,
        f"{count} × ({_without_saving(one.basis)}) Excludes scaling above the desired capacity.",
    )


def _linked_template(res: Any, index: dict[str, Any] | None) -> Any:
    spec = res.properties.get("LaunchTemplate")
    if not isinstance(spec, dict) or not index:
        return None
    for prop in ("LaunchTemplateId", "LaunchTemplateName"):
        value = spec.get(prop)
        target = value.get("Ref") if isinstance(value, dict) else value
        if isinstance(target, str) and target in index:
            return index[target]
    refs = sorted(a for a in getattr(res, "references", ()) if a.startswith("aws_launch_template."))
    return index.get(refs[0]) if len(refs) == 1 else None


def rds_storage(props: dict) -> Estimate | None:
    """AllocatedStorage GB of the storage type (twice for Multi-AZ, which keeps a standby copy)."""
    gib = _literal_int(props.get("AllocatedStorage"))
    kind = props.get("StorageType") or ("io1" if props.get("Iops") is not None else "gp2")
    engine = props.get("Engine")
    if gib is None or gib < 1 or not isinstance(kind, str) or (isinstance(engine, str) and engine.startswith("aurora")):
        return None
    per_gb = price(f"rds:storage:{kind.lower()}", current_region())
    multi = props.get("MultiAZ") in (True, "true", "True")
    if per_gb is None:
        return None
    copies = 2 if multi else 1
    note = " × 2 (Multi-AZ standby)" if multi else ""
    return Estimate(
        _round(copies * gib * per_gb.usd), None,
        f"{gib:,} GiB {kind} storage × {_unit_price(per_gb)}/GB-month{note}",
    )


def volume_extras(props: dict) -> Estimate | None:
    """Provisioned IOPS and throughput: gp3 above its free 3,000 IOPS and 125 MiB/s, io1/io2 all."""
    kind = props.get("VolumeType")
    iops, throughput = _literal_int(props.get("Iops")), _literal_int(props.get("Throughput"))
    parts = []
    if kind == "gp3":
        if iops is not None and iops > 3000 and (p := price("ebs:gp3-iops", current_region())):
            parts.append(Estimate(_round((iops - 3000) * p.usd), None,
                                  f"{iops - 3000:,} IOPS above 3,000 × {_unit_price(p)}/IOPS-month"))
        if throughput is not None and throughput > 125 and (p := price("ebs:gp3-throughput", current_region())):
            parts.append(Estimate(_round((throughput - 125) * p.usd), None,
                                  f"{throughput - 125:,} MiB/s above 125 × {_unit_price(p)}/MiBps-month"))
    elif kind in ("io1", "io2") and iops is not None and (p := price(f"ebs:{kind}-iops", current_region())):
        tier = " (first-tier price; io2 IOPS above 32,000 cost less)" if kind == "io2" and iops > 32000 else ""
        parts.append(Estimate(_round(iops * p.usd), None,
                              f"{iops:,} provisioned IOPS × {_unit_price(p)}/IOPS-month{tier}"))
    return _sum(parts) if parts else None


def cloudwatch_alarm(props: dict) -> Estimate:
    period = _literal_int(props.get("Period"))
    high = period is not None and period < 60
    usd = ALARM_HIGH_RES_USD if high else ALARM_STANDARD_USD
    return Estimate(usd, None, f"1 {'high-resolution' if high else 'standard'} alarm × ${usd:.2f}/month, "
                    "AWS list price. Metric math alarms bill per metric.")


def dashboard() -> Estimate:
    return Estimate(DASHBOARD_USD, None, f"1 dashboard × ${DASHBOARD_USD:.2f}/month, AWS list price "
                    f"(the first {FREE_DASHBOARDS} in an account are free).")


def web_acl(props: dict) -> Estimate | None:
    rules = props.get("Rules", [])
    if not isinstance(rules, list):
        return None  # rules from a variable or a dynamic block: count unknown
    n = len(rules)
    return Estimate(_round(WEB_ACL_USD + n * WEB_ACL_RULE_USD), None,
                    f"1 web ACL × ${WEB_ACL_USD:.2f} + {n} rule(s) × ${WEB_ACL_RULE_USD:.2f}/month, "
                    "AWS list price. Excludes requests.")


def resource_cost(res: Any, index: dict[str, Any] | None = None) -> Estimate | None:
    """The monthly on-demand cost of one resource, or None when it cannot be priced.

    Only the resource's own cost: savings are a finding's business, so they are dropped.
    `index` (name -> resource in the same stack) resolves an ECS service's task definition
    and an Auto Scaling group's launch template. A Terraform `count = N` multiplies the cost.
    """
    props = res.properties
    est: Estimate | None
    if res.type == "instance":
        est = ec2_instance(props.get("InstanceType"))
    elif res.type == "db_instance":
        compute = rds_instance(props)
        storage = rds_storage(props) if compute is not None else None
        est = compute if storage is None or compute is None else Estimate(
            _round((compute.monthly_cost_usd or 0) + (storage.monthly_cost_usd or 0)), None,
            _without_saving(compute.basis).replace(" Excludes storage, I/O", f" Plus {storage.basis}. Excludes I/O"),
        )
    elif res.type == "nat_gateway":
        est = nat_gateways(1)
    elif res.type == "ebs_volume":
        est = volume(props.get("VolumeType"), props.get("Size"))
        extras = volume_extras(props) if est is not None else None
        if est is not None and extras is not None:
            est = Estimate(_round((est.monthly_cost_usd or 0) + (extras.monthly_cost_usd or 0)), None,
                           est.basis.replace(" Excludes provisioned IOPS and throughput.", "") + f" Plus {extras.basis}.")
    elif res.type == "eip":
        est = public_ipv4(props.get("PublicIpv4Pool"))
    elif res.type == "dynamodb_table":
        est = dynamodb_provisioned(props)
    elif res.type == "lb":
        est = load_balancer(props)
    elif res.type == "elb":
        est = classic_load_balancer()
    elif res.type == "eks_cluster":
        est = eks_cluster()
    elif res.type == "ecs_service":
        est = fargate_service(res, index)
    elif res.type in ("elasticache_cluster", "elasticache_replication_group"):
        est = elasticache(res)
    elif res.type == "opensearch_domain":
        est = opensearch_domain(props)
    elif res.type == "redshift_cluster":
        est = redshift_cluster(props)
    elif res.type == "vpc_endpoint":
        est = vpc_endpoint(props)
    elif res.type == "kms_key":
        est = _monthly("kms:key-month", "customer managed KMS key", "Excludes requests.")
    elif res.type == "secretsmanager_secret":
        est = _monthly("secrets:secret-month", "secret", "Excludes API calls.")
    elif res.type == "kinesis_stream":
        est = kinesis_stream(props)
    elif res.type == "autoscaling_group":
        est = autoscaling_group(res, index)
    elif res.type == "cloudwatch_alarm":
        est = cloudwatch_alarm(props)
    elif res.source_type in ("AWS::WAFv2::WebACL", "aws_wafv2_web_acl"):
        est = web_acl(props)
    else:
        return None
    if est is None or est.monthly_cost_usd is None:
        return None
    count = getattr(res, "count", 1)
    basis = _without_saving(est.basis)
    if count != 1:
        return Estimate(_round(count * est.monthly_cost_usd), None, f"count = {count} × ({basis})")
    return Estimate(est.monthly_cost_usd, None, basis)


def _without_saving(basis: str) -> str:
    """The basis with its 'Saving if ...' sentence removed (a stack total has no saving)."""
    return re.sub(r" Saving if one size smaller \([^)]*\)\.", "", basis)


# --- Non-production savings ---------------------------------------------------


def rds_multi_az_premium(props: dict) -> Estimate | None:
    """A Multi-AZ RDS instance's cost, and the saving as a single-AZ instance."""
    if not props.get("MultiAZ"):
        return None
    multi = rds_instance(props)
    single = rds_instance({**props, "MultiAZ": False})
    if multi is None or single is None or multi.monthly_cost_usd is None or single.monthly_cost_usd is None:
        return None
    return Estimate(
        monthly_cost_usd=multi.monthly_cost_usd,
        monthly_savings_usd=_round(multi.monthly_cost_usd - single.monthly_cost_usd),
        basis=_without_saving(multi.basis) + f" Saving as a single-AZ instance ({money(single.monthly_cost_usd)}/month).",
    )


def downsize(kind: str, instance_type: str, size: str, props: dict | None = None) -> Estimate | None:
    """Cost of an EC2 or RDS instance, and the saving at a smaller size of the same family."""
    family, _, current = instance_type.rpartition(".")
    if current not in _SIZES or size not in _SIZES or _SIZES.index(size) >= _SIZES.index(current):
        return None
    target = f"{family}.{size}"
    if kind == "ec2":
        now, smaller = ec2_instance(instance_type), ec2_instance(target)
    else:
        now = rds_instance({**(props or {}), "DBInstanceClass": instance_type})
        smaller = rds_instance({**(props or {}), "DBInstanceClass": target})
    if now is None or smaller is None or now.monthly_cost_usd is None or smaller.monthly_cost_usd is None:
        return None
    return Estimate(
        monthly_cost_usd=now.monthly_cost_usd,
        monthly_savings_usd=_round(now.monthly_cost_usd - smaller.monthly_cost_usd),
        basis=_without_saving(now.basis) + f" Saving at {target} ({money(smaller.monthly_cost_usd)}/month).",
    )


def nat_processing_price() -> str | None:
    """The NAT gateway per-GB data processing price, with its source; None when there is no price."""
    gb = price("nat:gb", current_region())
    return f"{_unit_price(gb)}/GB ({_where(gb)})" if gb else None


def extra_nat_gateways(count: int) -> Estimate | None:
    """All NAT gateways' hours, and the saving with one shared NAT gateway."""
    total, one = nat_gateways(count), nat_gateways(1)
    if count < 2 or total is None or one is None or total.monthly_cost_usd is None or one.monthly_cost_usd is None:
        return None
    return Estimate(
        monthly_cost_usd=total.monthly_cost_usd,
        monthly_savings_usd=_round(total.monthly_cost_usd - one.monthly_cost_usd),
        basis=total.basis + f" Saving with one NAT gateway ({money(one.monthly_cost_usd)}/month).",
    )



# --- Usage-based costs from a usage profile -----------------------------------


def _per(key: str, amount: float, what: str) -> tuple[Estimate, Price] | None:
    """amount × the key's unit price, with the price; None without a price."""
    unit = price(key, current_region())
    if unit is None:
        return None
    # Not rounded: the parts are summed first, then rounded once.
    return Estimate(amount * unit.usd, None, f"{amount:,.6g} {what} × {_unit_price(unit)}"), unit


def _usage_sum(parts: list[tuple[Estimate, Price] | None], stated: str, label: str) -> Estimate | None:
    """The parts' total with the assumptions stated, or None when any part has no price."""
    if not parts or any(p is None for p in parts):
        return None
    found = [p for p in parts if p is not None]
    total = _sum([est for est, _ in found])
    return Estimate(
        total.monthly_cost_usd, None,
        f"{label} ({stated}): {total.basis}, {_where(found[0][1])}. "
        "First paid tier; free tier not deducted.",
    )


def usage_cost(res: Any, usage: dict[str, Any], label: str = "Usage assumed") -> Estimate | None:
    """The monthly cost of the usage a profile states for one resource, or None.

    label opens the basis: "Usage assumed" for a usage file, "Illustration" otherwise."""
    props = res.properties
    def get(key: str) -> Any:
        return usage.get(key)

    stated = ", ".join(f"{k} {v}" for k, v in sorted(usage.items()))
    parts: list[tuple[Estimate, Price] | None] = []
    if res.type == "s3_bucket" and get("storage_gb") is not None:
        storage_class = usage.get("storage_class", "standard")
        parts.append(_per(f"s3:{storage_class}", get("storage_gb"), f"GB-month {storage_class}"))
    elif res.type == "lambda_function":
        requests, duration = get("monthly_requests"), get("avg_duration_ms")
        memory = _literal_int(props.get("MemorySize", 128))
        archs = props.get("Architectures") or ["x86_64"]
        if requests is None or memory is None or not isinstance(archs, list):
            return None
        parts.append(_per("lambda:request", requests, "requests"))
        if duration is not None:
            arm = archs == ["arm64"]
            gb_seconds = requests * duration / 1000 * memory / 1024
            parts.append(_per("lambda:gb-second-arm" if arm else "lambda:gb-second", gb_seconds,
                              f"GB-seconds ({memory} MB{', arm64' if arm else ''})"))
    elif res.type == "nat_gateway" and get("monthly_data_processed_gb") is not None:
        parts.append(_per("nat:gb", get("monthly_data_processed_gb"), "GB processed"))
    elif res.type == "dynamodb_table":
        on_demand = props.get("BillingMode") == "PAY_PER_REQUEST"
        if on_demand and get("monthly_read_request_units") is not None:
            parts.append(_per("dynamodb:read-request", get("monthly_read_request_units"), "read request units"))
        if on_demand and get("monthly_write_request_units") is not None:
            parts.append(_per("dynamodb:write-request", get("monthly_write_request_units"), "write request units"))
        if get("storage_gb") is not None:
            parts.append(_per("dynamodb:storage-gb", get("storage_gb"), "GB-month storage"))
    elif res.type == "cloudwatch_log_group":
        if get("monthly_ingest_gb") is not None:
            parts.append(_per("logs:ingest-gb", get("monthly_ingest_gb"), "GB ingested"))
        if get("storage_gb") is not None:
            parts.append(_per("logs:storage-gb", get("storage_gb"), "GB-month stored"))
    elif res.type in ("api_gateway_rest_api", "apigatewayv2_api") and get("monthly_requests") is not None:
        if res.type == "apigatewayv2_api" and props.get("ProtocolType", "HTTP") != "HTTP":
            return None  # WebSocket APIs bill messages and connection minutes
        key = "apigw:rest-request" if res.type == "api_gateway_rest_api" else "apigw:http-request"
        parts.append(_per(key, get("monthly_requests"), "requests"))
    elif res.type == "lb" and get("monthly_lcu_hours") is not None:
        kind = _LB_KINDS.get(props.get("Type", "application")) if isinstance(props.get("Type", "application"), str) else None
        if kind not in ("alb", "nlb"):
            return None
        parts.append(_per(f"elb:{kind}-lcu", get("monthly_lcu_hours"), "LCU-hours"))
    elif res.type == "vpc_endpoint" and get("monthly_data_processed_gb") is not None:
        if props.get("VpcEndpointType", "Gateway") != "Interface":
            return None
        parts.append(_per("vpce:gb", get("monthly_data_processed_gb"), "GB processed"))
    elif res.type == "sqs_queue" and get("monthly_requests") is not None:
        fifo = props.get("FifoQueue") in (True, "true", "True")
        parts.append(_per("sqs:fifo-request" if fifo else "sqs:standard-request", get("monthly_requests"),
                          "FIFO requests" if fifo else "requests"))
    elif res.type == "sns_topic" and get("monthly_requests") is not None:
        parts.append(_per("sns:request", get("monthly_requests"), "publish requests"))
    est = _usage_sum(parts, stated, label)
    count = getattr(res, "count", 1)
    if est is None or est.monthly_cost_usd is None or count == 1:
        return est
    return Estimate(_round(count * est.monthly_cost_usd), None, f"count = {count} × ({est.basis})")
