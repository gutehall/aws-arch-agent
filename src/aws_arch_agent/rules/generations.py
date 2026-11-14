"""Previous-generation instance families.

CF-GEN-001 flags a previous-generation type on an EC2 instance, launch template, launch
configuration, Auto Scaling group override, RDS instance, ElastiCache cluster or
replication group, or OpenSearch domain. It suggests the current x86 family and the
Graviton family from data/instance_generations.json, and prices the move when the
snapshot covers both types (EC2 and RDS). Graviton needs an arm64 build of the workload.

CF-PERF-005 flags a current x86 EC2 type that has a Graviton family of the same size,
from data/graviton_families.json. It stays silent where CF-GEN-001 already speaks.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, List

from aws_arch_agent.models import Finding
from aws_arch_agent.rules import estimates
from aws_arch_agent.rules.resource_model import Resource

DATA_PATH = Path(__file__).with_name("data") / "instance_generations.json"
CHECK_ID = "CF-GEN-001"
GRAVITON_CHECK_ID = "CF-PERF-005"
GRAVITON_PATH = Path(__file__).with_name("data") / "graviton_families.json"
# RDS engines with no Graviton instance classes: only the x86 successor is suggested.
_NO_GRAVITON_ENGINES = ("oracle", "sqlserver", "db2", "custom-")


@lru_cache(maxsize=1)
def _mapping() -> dict[str, dict[str, list[str | None]]]:
    data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


@lru_cache(maxsize=1)
def _graviton() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(GRAVITON_PATH.read_text(encoding="utf-8"))
    return data


def graviton_alternative(instance_type: str) -> str | None:
    """The Graviton type of the same size for a current x86 EC2 type, or None.

    m7i.xlarge -> m7g.xlarge. None when the type is already Graviton, has no Graviton
    family (Mac, GPU, Inferentia, Trainium, bare metal), the family has no such size, or
    CF-GEN-001 already reports it as a previous generation.
    """
    if not isinstance(instance_type, str) or successors("ec2", instance_type) is not None:
        return None
    family, _, size = instance_type.partition(".")
    data = _graviton()
    target = data["families"].get(family)
    if target is None or size not in data["sizes"].get(target, ()):
        return None
    return f"{target}.{size}"


def successors(kind: str, instance_type: str) -> tuple[str | None, str | None] | None:
    """(x86, Graviton) successors of a previous-generation type, or None if it is current.

    kind is ec2, rds, elasticache or opensearch. Types keep their size and suffix:
    m4.large -> m7i.large, db.m4.large -> db.m6i.large, m4.large.search -> m5.large.search.
    """
    if not isinstance(instance_type, str) or "." not in instance_type:
        return None
    if kind in ("rds", "elasticache"):
        prefix, _, rest = instance_type.partition(".")
        family_name, _, tail = rest.partition(".")
        family = f"{prefix}.{family_name}"
    else:
        family, _, tail = instance_type.partition(".")
    pair = _mapping().get(kind, {}).get(family)
    if pair is None:
        return None
    x86, graviton = pair

    def swap(target: str | None) -> str | None:
        return f"{target}.{tail}" if target else None

    return swap(x86), swap(graviton)


def _types(res: Resource) -> list[tuple[str, str]]:
    """(kind, type) pairs a resource runs, where literal."""
    props = res.properties
    out: list[tuple[str, Any]] = []
    if res.type in ("instance", "launch_configuration"):
        out.append(("ec2", props.get("InstanceType")))
    elif res.type == "launch_template":
        data = props.get("LaunchTemplateData")
        out.append(("ec2", data.get("InstanceType") if isinstance(data, dict) else None))
        out.append(("ec2", props.get("InstanceType")))  # Terraform keeps it apart
    elif res.type == "autoscaling_group":
        mixed = props.get("MixedInstancesPolicy")
        template = mixed.get("LaunchTemplate") if isinstance(mixed, dict) else None
        overrides = template.get("Overrides") if isinstance(template, dict) else None
        for item in overrides if isinstance(overrides, list) else []:
            if isinstance(item, dict):
                out.append(("ec2", item.get("InstanceType")))
        terraform = props.get("OverrideInstanceTypes")  # Terraform override blocks
        for value in terraform if isinstance(terraform, list) else []:
            out.append(("ec2", value))
    elif res.type == "db_instance":
        out.append(("rds", props.get("DBInstanceClass")))
    elif res.type in ("elasticache_cluster", "elasticache_replication_group"):
        out.append(("elasticache", props.get("CacheNodeType")))
    elif res.type == "opensearch_domain":
        config = props.get("ClusterConfig")
        if isinstance(config, dict):
            out.append(("opensearch", config.get("InstanceType")))
            out.append(("opensearch", config.get("DedicatedMasterType")))
    seen: list[tuple[str, str]] = []
    for kind, value in out:
        if type(value) is str and (kind, value) not in seen:
            seen.append((kind, value))
    return seen


def _estimate(res: Resource, kind: str, current: str, x86: str | None, graviton: str | None) -> estimates.Estimate | None:
    """The current cost, and the saving on the x86 successor (Graviton's price in the basis).

    Only a single EC2 or RDS instance is priced: an Auto Scaling group runs some number of
    instances and a launch template or configuration may run none.
    """
    if x86 is None or res.type not in ("instance", "db_instance"):
        return None
    if kind == "ec2":
        now, new, arm = (estimates.ec2_instance(t) if t else None for t in (current, x86, graviton))
    elif kind == "rds":
        props = res.properties
        now, new, arm = (
            estimates.rds_instance({**props, "DBInstanceClass": t}) if t else None for t in (current, x86, graviton))
    else:
        return None  # ElastiCache and OpenSearch are not in the price snapshot
    if now is None or new is None or now.monthly_cost_usd is None or new.monthly_cost_usd is None:
        return None
    basis = estimates._without_saving(now.basis) + f" {x86}: {estimates.money(new.monthly_cost_usd)}/month."
    if arm is not None and arm.monthly_cost_usd is not None:
        basis += f" {graviton}: {estimates.money(arm.monthly_cost_usd)}/month."
    saving = round(now.monthly_cost_usd - new.monthly_cost_usd, 2)
    return estimates.Estimate(now.monthly_cost_usd, saving if saving > 0 else None, basis)


def findings(res: Resource, template_path: Path) -> List[Finding]:
    """One CF-GEN-001 finding per resource that runs a previous-generation type."""
    old = [(kind, t, successors(kind, t)) for kind, t in _types(res)]
    old = [(kind, t, s) for kind, t, s in old if s is not None]
    if res.type == "db_instance":
        engine = res.properties.get("Engine")
        if isinstance(engine, str) and engine.lower().startswith(_NO_GRAVITON_ENGINES):
            old = [(kind, t, (pair[0], None) if pair else pair) for kind, t, pair in old]
    if not old:
        return []
    parts = []
    for _kind, current, pair in old:
        assert pair is not None
        x86, graviton = pair
        options = " or ".join(p for p in (
            f"{x86} (x86)" if x86 else None,
            f"{graviton} (Graviton)" if graviton else None,
        ) if p)
        parts.append(f"{current} is a previous-generation type: move to {options}.")
    graviton_note = (
        " Graviton costs less again, but needs an arm64 build of the workload (container "
        "images, native dependencies, agents); check that before switching."
        if any(pair and pair[1] for _, _, pair in old) else ""
    )
    finding = Finding(
        id=CHECK_ID,
        title="Previous-generation instance type",
        severity="Low",
        category="Cost Optimization",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            " ".join(parts) + " Current families cost less per unit of performance." + graviton_note
            + " If the size does not exist in the new family, pick the closest one."
        ),
    )
    if len(old) == 1:
        kind, current, pair = old[0]
        assert pair is not None
        estimates.apply(finding, _estimate(res, kind, current, *pair))
    return [finding]


def graviton_findings(res: Resource, template_path: Path) -> List[Finding]:
    """One CF-PERF-005 finding per resource that runs a current x86 type with a Graviton twin."""
    moves = [(t, alt) for kind, t in _types(res) if kind == "ec2" and (alt := graviton_alternative(t))]
    if not moves:
        return []
    finding = Finding(
        id=GRAVITON_CHECK_ID,
        title="EC2 instance type has a Graviton equivalent",
        severity="Low",
        category="Performance Efficiency",
        file=res.file or str(template_path),
        line=res.line,
        evidence=f"{res.name} ({res.source_type})",
        recommendation=(
            " ".join(f"{current} runs on x86: {alt} is the same size on Graviton." for current, alt in moves)
            + " Graviton costs less per unit of performance, but needs an arm64 build of the workload "
            "(AMI, container images, native dependencies, agents); check that before switching. "
            "Windows has no Graviton option, and the AMI decides the operating system."
        ),
    )
    if len(moves) == 1:
        current, alt = moves[0]
        estimates.apply(finding, _estimate(res, "ec2", current, alt, None))
    return [finding]
