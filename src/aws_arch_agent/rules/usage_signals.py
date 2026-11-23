"""Usage signals: what six former advice rules read from the usage file instead of a property.

A template says how a resource is built, not how it is used, so REL-011, OPS-023, SUST-002,
SUST-003, PERF-011 and PERF-014 had nothing to read. The usage profile
(pricing/usage.py, `.aws-arch-agent-usage.yaml` or --usage-file) can state the missing fact.
When it does, the rule reports from it and the IaC; when it does not, the rule stays quiet
and does not count as run, so its best practice reads not checked instead of met.

The rules read the IaC text of the repo (CloudFormation, Terraform, CDK), the way the
REPO-* rules do, so they run for every source. The profile is the scan's (the one the CLI
loaded, --usage-file included); a rule run outside a scan reads the repo's default file.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, List, cast

from aws_arch_agent.models import Finding, Severity
from aws_arch_agent.pricing import usage

# Thresholds. Fixed: the usage schema states facts, not limits.
READ_HEAVY_RATIO = 4  # REL-011: reads per write at or above which replicas pay off
SSM_STANDARD_TPS = 40  # OPS-023: default GetParameter(s) throughput per account and Region
LOW_CPU_PERCENT = 20  # SUST-002: average CPU under this is over-provisioned
DAILY_PATTERNS = ("daily", "business-hours")  # SUST-003

USAGE_RULE_IDS = frozenset({"REL-011", "OPS-023", "SUST-002", "SUST-003", "PERF-011", "PERF-014"})

_DB = re.compile(
    r"AWS::RDS::DB(?:Instance|Cluster)\b|resource\s+\"aws_(?:db_instance|rds_cluster)\""
    r"|rds\.(?:DatabaseInstance|DatabaseCluster|CfnDBInstance|CfnDBCluster)\b"
)
_REPLICA = re.compile(
    r"SourceDBInstanceIdentifier|replicate_source_db|DatabaseInstanceReadReplica|addReadReplica"
    r"|\breaders\s*[:=]|source_db_instance_identifier"
)
_TF_AURORA_INSTANCE = re.compile(r"resource\s+\"aws_rds_cluster_instance\"")
_TF_COUNT = re.compile(r"\bcount\s*=\s*(\d+)")
_CF_DB_INSTANCE = re.compile(r"AWS::RDS::DBInstance\b")
_CF_DB_CLUSTER = re.compile(r"AWS::RDS::DBCluster\b")
_HIGH_THROUGHPUT = re.compile(r"high-throughput-enabled")
_EC2 = re.compile(r"AWS::EC2::Instance\b|resource\s+\"aws_instance\"|ec2\.(?:Instance|CfnInstance)\b")
_SCALABLE = re.compile(
    r"AWS::AutoScaling::AutoScalingGroup|AWS::ECS::Service|AWS::ApplicationAutoScaling::ScalableTarget"
    r"|resource\s+\"aws_(?:autoscaling_group|ecs_service|appautoscaling_target)\""
    r"|\bAutoScalingGroup\b|\b(?:Fargate|Ec2)Service\b|autoScaleTaskCount|LoadBalancedFargateService"
)
_SCHEDULED = re.compile(
    r"AWS::AutoScaling::ScheduledAction|ScheduledActions|resource\s+\"aws_(?:autoscaling_schedule"
    r"|appautoscaling_scheduled_action)\"|scaleOnSchedule|ScheduledAction|scalingSchedule|ScalingSchedule"
)
_LB = re.compile(
    r"AWS::ElasticLoadBalancingV2::LoadBalancer|resource\s+\"aws_(?:lb|alb)\""
    r"|(?:Application|Network)LoadBalancer\b|LoadBalanced\w*Service"
)
_ACCELERATOR = re.compile(r"AWS::GlobalAccelerator::|resource\s+\"aws_globalaccelerator_|globalaccelerator\.")
_BUCKET = re.compile(r"AWS::S3::Bucket\b|resource\s+\"aws_s3_bucket\"|s3\.(?:Bucket|CfnBucket)\b")
_TRANSFER_ACCELERATION = re.compile(
    r"AccelerateConfiguration|aws_s3_bucket_accelerate_configuration|acceleration_status"
    r"|transferAcceleration\s*:\s*true|transfer_acceleration\s*=\s*True"
)


def profile(repo_path: Path) -> usage.UsageProfile | None:
    """The scan's usage profile, else the repo's default usage file, else None."""
    from aws_arch_agent.rules import stack_cost

    current = stack_cost.usage_profile()
    if current is not None:
        return current
    found = usage.find(Path(repo_path))
    return usage.load(found) if found is not None else None


def _texts(repo_path: Path) -> list[tuple[str, str]]:
    from aws_arch_agent.rules.repo_practices import iac_texts

    return list(iac_texts(Path(repo_path)))


def _first(texts: Iterable[tuple[str, str]], pattern: re.Pattern[str]) -> str | None:
    return next((rel for rel, text in texts if pattern.search(text)), None)


def _has_replica(texts: list[tuple[str, str]]) -> bool:
    if any(_REPLICA.search(text) for _rel, text in texts):
        return True
    # An Aurora cluster with two or more instances has a reader.
    tf_instances = sum(len(_TF_AURORA_INSTANCE.findall(text)) for _rel, text in texts)
    tf_counted = any(
        _TF_AURORA_INSTANCE.search(text) and any(int(n) >= 2 for n in _TF_COUNT.findall(text))
        for _rel, text in texts
    )
    cf_readers = any(
        _CF_DB_CLUSTER.search(text) and len(_CF_DB_INSTANCE.findall(text)) >= 2 for _rel, text in texts
    )
    return tf_instances >= 2 or tf_counted or cf_readers


def stated(repo_path: Path) -> frozenset[str]:
    """The usage rules whose signal the profile states: only they count as run."""
    try:
        p = profile(repo_path)
    except usage.UsageError:
        return frozenset()
    if p is None:
        return frozenset()
    out = set()
    if p.signal("read_write_ratio", ("db_instance", "rds_cluster")):
        out.add("REL-011")
    if p.signal("get_parameter_tps", ("ssm_parameter",)):
        out.add("OPS-023")
    if p.signal("avg_cpu_percent", ("instance", "db_instance")):
        out.add("SUST-002")
    for key, rid in (("traffic_pattern", "SUST-003"), ("user_regions", "PERF-011"),
                     ("upload_regions", "PERF-014")):
        if key in p.workload:
            out.add(rid)
    return frozenset(out)


def _finding(rule: Any, evidence: str, file: str | None = None) -> Finding:
    return Finding(
        id=rule.id, title=rule.title, severity=cast(Severity, rule.severity), category=rule.category,
        file=file, line=None, evidence=evidence, recommendation=rule.recommendation,
    )


def read_replicas(rule: Any, repo_path: Path) -> List[Finding]:
    """REL-011: a read/write ratio of READ_HEAVY_RATIO or more, and no read replica."""
    p = profile(repo_path)
    heavy = [(where, v) for where, v in (p.signal("read_write_ratio", ("db_instance", "rds_cluster")) if p else [])
             if v >= READ_HEAVY_RATIO]
    if not heavy:
        return []
    texts = _texts(repo_path)
    db = _first(texts, _DB)
    if db is None or _has_replica(texts):
        return []
    stated_at = ", ".join(f"{where} read_write_ratio {v}" for where, v in heavy)
    return [_finding(rule, f"Usage file: {stated_at} (read-heavy at {READ_HEAVY_RATIO}:1 or more); "
                           "the IaC declares a database and no read replica or Aurora reader", db)]


def ssm_throughput(rule: Any, repo_path: Path) -> List[Finding]:
    """OPS-023: Parameter Store reads above the default throughput, with no higher setting."""
    p = profile(repo_path)
    over = [(where, v) for where, v in (p.signal("get_parameter_tps", ("ssm_parameter",)) if p else [])
            if v > SSM_STANDARD_TPS]
    if not over:
        return []
    texts = _texts(repo_path)
    if _first(texts, _HIGH_THROUGHPUT) is not None:
        return []
    stated_at = ", ".join(f"{where} get_parameter_tps {v}" for where, v in over)
    return [_finding(rule, f"Usage file: {stated_at}, above the default {SSM_STANDARD_TPS} TPS; the IaC "
                           "does not turn on the higher throughput setting (/ssm/parameter-store/"
                           "high-throughput-enabled)")]


def low_utilization(rule: Any, repo_path: Path) -> List[Finding]:
    """SUST-002: average CPU under LOW_CPU_PERCENT. One finding per place the usage file says it.

    A type default needs that type in the IaC. drop_sized() removes a finding that
    CF-PERF-003 or CF-PERF-004 already reports for the same resource."""
    p = profile(repo_path)
    low = [(where, v) for where, v in (p.signal("avg_cpu_percent", ("instance", "db_instance")) if p else [])
           if v < LOW_CPU_PERCENT]
    if not low:
        return []
    texts = _texts(repo_path)
    out = []
    for where, value in low:
        if where == "defaults.instance" and _first(texts, _EC2) is None:
            continue
        if where == "defaults.db_instance" and _first(texts, _DB) is None:
            continue
        out.append(_finding(rule, f"{where}: average CPU {value}% (usage file), under {LOW_CPU_PERCENT}%"))
    return out


def scheduled_scaling(rule: Any, repo_path: Path) -> List[Finding]:
    """SUST-003: a daily traffic pattern, scalable compute, and no scheduled scaling action."""
    p = profile(repo_path)
    pattern = p.workload.get("traffic_pattern") if p else None
    if pattern not in DAILY_PATTERNS:
        return []
    texts = _texts(repo_path)
    compute = _first(texts, _SCALABLE)
    if compute is None or _first(texts, _SCHEDULED) is not None:
        return []
    return [_finding(rule, f"Usage file: workload.traffic_pattern {pattern}; the IaC scales compute "
                           "and declares no scheduled scaling action", compute)]


def global_accelerator(rule: Any, repo_path: Path) -> List[Finding]:
    """PERF-011: users in more than one Region, a load balancer, and no Global Accelerator."""
    p = profile(repo_path)
    regions = p.workload.get("user_regions") if p else None
    if not regions or regions < 2:
        return []
    texts = _texts(repo_path)
    lb = _first(texts, _LB)
    if lb is None or _first(texts, _ACCELERATOR) is not None:
        return []
    return [_finding(rule, f"Usage file: workload.user_regions {regions}; the IaC declares a load "
                           "balancer and no Global Accelerator", lb)]


def transfer_acceleration(rule: Any, repo_path: Path) -> List[Finding]:
    """PERF-014: uploads from more than one Region, a bucket, and Transfer Acceleration off."""
    p = profile(repo_path)
    regions = p.workload.get("upload_regions") if p else None
    if not regions or regions < 2:
        return []
    texts = _texts(repo_path)
    bucket = _first(texts, _BUCKET)
    if bucket is None or _first(texts, _TRANSFER_ACCELERATION) is not None:
        return []
    return [_finding(rule, f"Usage file: workload.upload_regions {regions}; the IaC declares an S3 "
                           "bucket and no Transfer Acceleration", bucket)]


_SIZED_BY = {"instance": "CF-PERF-004", "db_instance": "CF-PERF-003"}


def drop_sized(findings: List[Finding]) -> List[Finding]:
    """Drop a SUST-002 finding for a resource CF-PERF-003 or CF-PERF-004 already flags as large.

    Those checks name the resource first in their evidence ("Web (AWS::EC2::Instance)"). A
    type default is dropped when any resource of that type is flagged."""
    flagged: dict[str, set[str]] = {}
    for f in findings:
        if f.id in _SIZED_BY.values():
            flagged.setdefault(f.id, set()).add((f.evidence or "").split(" (")[0])
    if not flagged:
        return findings

    def sized(f: Finding) -> bool:
        where = (f.evidence or "").split(":")[0]
        if where.startswith("defaults."):
            return _SIZED_BY.get(where[len("defaults."):], "") in flagged
        name = where[len("resources."):]
        return any(name in names for names in flagged.values())

    return [f for f in findings if not (f.id == "SUST-002" and sized(f))]
