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
_ALL_FIELDS = sorted({key for keys in FIELDS.values() for key in keys})


class UsageError(ConfigError):
    """The usage profile is not valid."""


@dataclass(frozen=True)
class UsageProfile:
    defaults: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    resources: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    path: str = ""

    def for_resource(self, rtype: str | None, name: str) -> dict[str, Any] | None:
        """The usage stated for one resource (its type's defaults, then its own entry), or None."""
        if rtype not in FIELDS:
            return None
        merged = {**self.defaults.get(rtype, {}), **self.resources.get(name, {})}
        merged = {k: v for k, v in merged.items() if k in FIELDS[rtype]}
        return merged or None


def _value(key: str, value: Any, where: str) -> Any:
    if key == "storage_class":
        if value not in S3_CLASSES:
            raise UsageError(f"{where}.storage_class must be one of {', '.join(S3_CLASSES)}")
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise UsageError(f"{where}.{key} must be a number")
    if value < 0:
        raise UsageError(f"{where}.{key} must not be negative")
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
        raise UsageError("the usage profile must be a mapping with defaults and/or resources")
    unknown = sorted(set(map(str, data)) - {"defaults", "resources"})
    if unknown:
        raise UsageError(f"unknown top-level key(s) {', '.join(unknown)}; allowed: defaults, resources")
    defaults_raw = {} if data.get("defaults") is None else data["defaults"]
    resources_raw = {} if data.get("resources") is None else data["resources"]
    if not isinstance(defaults_raw, dict) or not isinstance(resources_raw, dict):
        raise UsageError("defaults and resources must be mappings")
    defaults = {}
    for rtype, entry in defaults_raw.items():
        if rtype not in FIELDS:
            raise UsageError(f"defaults: unknown resource type {rtype!r}; allowed: {', '.join(FIELDS)}")
        defaults[str(rtype)] = _entry(entry, FIELDS[str(rtype)], f"defaults.{rtype}")
    resources = {str(name): _entry(entry, _ALL_FIELDS, f"resources.{name}") for name, entry in resources_raw.items()}
    return UsageProfile(defaults, resources, path)


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
