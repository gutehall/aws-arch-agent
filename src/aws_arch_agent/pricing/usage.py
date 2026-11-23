"""An optional usage profile: expected monthly usage for usage-billed resources.

Infrastructure as code says how big a resource is, not how much it is used, so S3,
Lambda, NAT data processing, on-demand DynamoDB, CloudWatch Logs, API Gateway, load
balancer capacity units, interface endpoint data, SQS and SNS are not priced from IaC
alone. A usage profile states the usage, and only what it states is priced:

    # .aws-arch-agent-usage.yaml (or --usage-file / config usage_file)
    defaults:                       # every resource of a type
      lambda_function:
        monthly_requests: 2000000
        avg_duration_ms: 120
      s3_bucket:
        storage_gb: 50
    resources:                      # one resource, by logical ID or Terraform address
      aws_s3_bucket.uploads:
        storage_gb: 2000
        storage_class: standard-ia

A resource's own entry wins over its type's defaults, key by key. Without a profile
nothing usage-based is priced.

The same file carries the usage signals a few rules read instead of a resource property
(rules/usage_signals.py): per type or resource (SIGNAL_FIELDS) and for the whole workload:

    defaults:
      db_instance:
        read_write_ratio: 6         # REL-011
    workload:
      traffic_pattern: business-hours   # SUST-003
      user_regions: 3                   # PERF-011
      upload_regions: 2                 # PERF-014
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from aws_arch_agent.config import ConfigError

DEFAULT_FILE = ".aws-arch-agent-usage.yaml"

S3_CLASSES = ("standard", "intelligent-tiering", "standard-ia", "onezone-ia", "glacier-ir", "glacier", "deep-archive")

# Resource type -> the usage keys it reads.
FIELDS: dict[str, tuple[str, ...]] = {
    "s3_bucket": ("storage_gb", "storage_class"),
    "lambda_function": ("monthly_requests", "avg_duration_ms"),
    "nat_gateway": ("monthly_data_processed_gb",),
    "dynamodb_table": ("monthly_read_request_units", "monthly_write_request_units", "storage_gb"),
    "cloudwatch_log_group": ("monthly_ingest_gb", "storage_gb"),
    "api_gateway_rest_api": ("monthly_requests",),
    "apigatewayv2_api": ("monthly_requests",),
    "lb": ("monthly_lcu_hours",),
    "vpc_endpoint": ("monthly_data_processed_gb",),
    "sqs_queue": ("monthly_requests",),
    "sns_topic": ("monthly_requests",),
}
# Resource type -> the usage signals it carries. Rules read them; nothing is priced from them.
SIGNAL_FIELDS: dict[str, tuple[str, ...]] = {
    "db_instance": ("read_write_ratio", "avg_cpu_percent"),
    "rds_cluster": ("read_write_ratio",),
    "instance": ("avg_cpu_percent",),
    "ssm_parameter": ("get_parameter_tps",),
}
TRAFFIC_PATTERNS = ("steady", "daily", "business-hours", "spiky")
WORKLOAD_FIELDS = ("traffic_pattern", "user_regions", "upload_regions")
_TYPES = {t: FIELDS.get(t, ()) + SIGNAL_FIELDS.get(t, ()) for t in {**FIELDS, **SIGNAL_FIELDS}}
_ALL_FIELDS = sorted({key for keys in _TYPES.values() for key in keys})


class UsageError(ConfigError):
    """The usage profile is not valid."""


@dataclass(frozen=True)
class UsageProfile:
    defaults: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    resources: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    path: str = ""
    workload: Mapping[str, Any] = field(default_factory=dict)

    def for_resource(self, rtype: str | None, name: str) -> dict[str, Any] | None:
        """The usage stated for one resource (its type's defaults, then its own entry), or None."""
        if rtype not in FIELDS:
            return None
        merged = {**self.defaults.get(rtype, {}), **self.resources.get(name, {})}
        merged = {k: v for k, v in merged.items() if k in FIELDS[rtype]}
        return merged or None

    def signal(self, key: str, types: tuple[str, ...]) -> list[tuple[str, Any]]:
        """Where a usage signal is stated: ("defaults.<type>", value) per type default, and
        ("resources.<name>", value) per resource entry that sets it."""
        out = [(f"defaults.{t}", self.defaults[t][key]) for t in types if key in self.defaults.get(t, {})]
        out += [(f"resources.{name}", entry[key]) for name, entry in self.resources.items() if key in entry]
        return out


def _value(key: str, value: Any, where: str) -> Any:
    if key == "storage_class":
        if value not in S3_CLASSES:
            raise UsageError(f"{where}.storage_class must be one of {', '.join(S3_CLASSES)}")
        return value
    if key == "traffic_pattern":
        if value not in TRAFFIC_PATTERNS:
            raise UsageError(f"{where}.traffic_pattern must be one of {', '.join(TRAFFIC_PATTERNS)}")
        return value
    if key in ("user_regions", "upload_regions"):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise UsageError(f"{where}.{key} must be a whole number of Regions, 1 or more")
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise UsageError(f"{where}.{key} must be a number")
    if value < 0:
        raise UsageError(f"{where}.{key} must not be negative")
    if key == "avg_cpu_percent" and value > 100:
        raise UsageError(f"{where}.avg_cpu_percent must be 100 or less")
    return value


def _entry(value: Any, allowed: tuple[str, ...] | list[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UsageError(f"{where} must be a mapping")
    unknown = sorted(set(map(str, value)) - set(allowed))
    if unknown:
        raise UsageError(f"{where}: unknown key(s) {', '.join(unknown)}; allowed: {', '.join(allowed)}")
    return {str(k): _value(str(k), v, where) for k, v in value.items()}


def parse(data: Any, path: str = "") -> UsageProfile:
    """Validate a loaded usage profile. Raises UsageError."""
    if data is None:
        return UsageProfile(path=path)
    if not isinstance(data, dict):
        raise UsageError("the usage profile must be a mapping with defaults, resources and/or workload")
    unknown = sorted(set(map(str, data)) - {"defaults", "resources", "workload"})
    if unknown:
        raise UsageError(f"unknown top-level key(s) {', '.join(unknown)}; allowed: defaults, resources, workload")
    defaults_raw = {} if data.get("defaults") is None else data["defaults"]
    resources_raw = {} if data.get("resources") is None else data["resources"]
    if not isinstance(defaults_raw, dict) or not isinstance(resources_raw, dict):
        raise UsageError("defaults and resources must be mappings")
    defaults = {}
    for rtype, entry in defaults_raw.items():
        if rtype not in _TYPES:
            raise UsageError(f"defaults: unknown resource type {rtype!r}; allowed: {', '.join(sorted(_TYPES))}")
        defaults[str(rtype)] = _entry(entry, _TYPES[str(rtype)], f"defaults.{rtype}")
    resources = {str(name): _entry(entry, _ALL_FIELDS, f"resources.{name}") for name, entry in resources_raw.items()}
    workload_raw = {} if data.get("workload") is None else data["workload"]
    workload = _entry(workload_raw, WORKLOAD_FIELDS, "workload")
    return UsageProfile(defaults, resources, path, workload)


def load(path: Path) -> UsageProfile:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise UsageError(f"cannot read usage file {path}: {exc.strerror or exc}") from exc
    except yaml.YAMLError as exc:
        raise UsageError(f"usage file {path} is not valid YAML: {exc}") from exc
    return parse(data, str(path))


def find(repo_path: Path, explicit: Path | None = None) -> Path | None:
    """The usage file to read: the one named, else .aws-arch-agent-usage.yaml in the repo."""
    if explicit is not None:
        return Path(explicit)
    candidate = Path(repo_path) / DEFAULT_FILE
    return candidate if candidate.is_file() else None
