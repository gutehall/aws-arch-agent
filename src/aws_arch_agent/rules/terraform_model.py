"""Parse root-module Terraform (*.tf, *.tf.json) into Resource records.

No `terraform init`, no registry or child modules: only the files in a root
module directory. aws_* types map onto the canonical types the CF-* checks use,
and their arguments are translated into the CloudFormation-shaped properties
those checks read. A value that depends on `var.*` or `local.*` is unresolved:
the property is left out and recorded in Resource.unresolved, so no check
reports on it.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from aws_arch_agent.rules.resource_model import Resource

TF_TYPE_TO_CANONICAL: dict[str, str] = {
    "aws_s3_bucket": "s3_bucket",
    "aws_db_instance": "db_instance",
    "aws_rds_cluster": "rds_cluster",
    "aws_instance": "instance",
    "aws_launch_template": "launch_template",
    "aws_security_group": "security_group",
    "aws_vpc_security_group_ingress_rule": "security_group_ingress_rule",
    "aws_security_group_rule": "security_group_ingress_rule",  # type = "ingress" only
    "aws_vpc": "vpc",
    "aws_vpc_endpoint": "vpc_endpoint",
    "aws_flow_log": "flow_log",
    "aws_nat_gateway": "nat_gateway",
    "aws_lb": "lb",
    "aws_alb": "lb",
    "aws_cloudtrail": "cloudtrail",
    "aws_kms_key": "kms_key",
    "aws_lambda_function": "lambda_function",
    "aws_dynamodb_table": "dynamodb_table",
    "aws_cloudwatch_log_group": "cloudwatch_log_group",
    "aws_sqs_queue": "sqs_queue",
    "aws_api_gateway_rest_api": "api_gateway_rest_api",
    "aws_api_gateway_stage": "api_gateway_stage",
    "aws_apigatewayv2_api": "apigatewayv2_api",
    "aws_apigatewayv2_stage": "apigatewayv2_stage",
    "aws_autoscaling_group": "autoscaling_group",
    "aws_ecs_service": "ecs_service",
    "aws_eks_cluster": "eks_cluster",
    "aws_cloudfront_distribution": "cloudfront_distribution",
    "aws_elasticache_cluster": "elasticache_cluster",
    "aws_elasticache_replication_group": "elasticache_replication_group",
}

# S3 settings split into their own resources (AWS provider v4+) -> bucket property.
_S3_PARTS: dict[str, str] = {
    "aws_s3_bucket_public_access_block": "PublicAccessBlockConfiguration",
    "aws_s3_bucket_versioning": "VersioningConfiguration",
    "aws_s3_bucket_server_side_encryption_configuration": "BucketEncryption",
    "aws_s3_bucket_logging": "LoggingConfiguration",
}

_UNRESOLVED_REF = re.compile(r"\b(?:var|local)\.[A-Za-z_]")
_BUCKET_REF = re.compile(r"\baws_s3_bucket\.([A-Za-z0-9_-]+)\.")
_META_KEYS = {"__is_block__", "__start_line__", "__end_line__"}


class _Unresolved:
    """A value that depends on var.* or local.*."""

    def __repr__(self) -> str:
        return "<unresolved>"


UNRESOLVED = _Unresolved()


class TerraformError(ValueError):
    """A Terraform file could not be read."""


# --- value normalization -------------------------------------------------


def _unquote_key(key: str) -> str:
    if len(key) >= 2 and key[0] == key[-1] == '"':
        return key[1:-1]
    return key


def _hcl_value(value: Any) -> Any:
    """python-hcl2 value -> literal, expression string, or UNRESOLVED."""
    if isinstance(value, str):
        if len(value) >= 2 and value[0] == value[-1] == '"':
            text = value[1:-1].replace('\\"', '"')
            return UNRESOLVED if "${" in text and _UNRESOLVED_REF.search(text) else text
        expr = value[2:-1] if value.startswith("${") and value.endswith("}") else value
        if expr in ("true", "false"):
            return expr == "true"
        return UNRESOLVED if _UNRESOLVED_REF.search(expr) else expr
    if isinstance(value, list):
        return [_hcl_value(v) for v in value]
    if isinstance(value, dict):
        return {_unquote_key(k): _hcl_value(v) for k, v in value.items() if k not in _META_KEYS}
    return value


def _json_value(value: Any) -> Any:
    """*.tf.json value: "${...}" strings are expressions."""
    if isinstance(value, str):
        if "${" in value and _UNRESOLVED_REF.search(value):
            return UNRESOLVED
        if value.startswith("${") and value.endswith("}") and value.count("${") == 1:
            return value[2:-1]
        return value
    if isinstance(value, list):
        return [_json_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _json_value(v) for k, v in value.items()}
    return value


def _contains_unresolved(value: Any) -> bool:
    if value is UNRESOLVED:
        return True
    if isinstance(value, list):
        return any(_contains_unresolved(v) for v in value)
    if isinstance(value, dict):
        return any(_contains_unresolved(v) for v in value.values())
    return False


# --- file parsing --------------------------------------------------------


class _Block:
    """One `resource "type" "name"` block after normalization."""

    def __init__(self, rtype: str, name: str, body: dict, file: Path, line: int | None):
        self.type = rtype
        self.name = name
        self.body = body
        self.file = file
        self.line = line

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"


def _find_line(text: str, rtype: str, name: str, is_json: bool) -> int | None:
    if is_json:
        type_at = text.find(f'"{rtype}"')
        if type_at < 0:
            return None
        name_at = text.find(f'"{name}"', type_at)
        at = name_at if name_at >= 0 else type_at
    else:
        match = re.search(
            rf'^\s*resource\s+"{re.escape(rtype)}"\s+"{re.escape(name)}"', text, re.MULTILINE
        )
        if not match:
            return None
        at = match.start() + len(match.group(0)) - len(match.group(0).lstrip())
    return text.count("\n", 0, at) + 1


def _iter_type_maps(section: Any) -> list[dict]:
    """Both syntaxes allow a block section as one map or a list of maps."""
    if isinstance(section, dict):
        return [section]
    if isinstance(section, list):
        return [item for item in section if isinstance(item, dict)]
    return []


def parse_tf_file(path: Path) -> tuple[list[_Block], list[str]]:
    """Return the resource blocks and local module sources declared in one file."""
    text = path.read_text(encoding="utf-8")
    is_json = path.name.endswith(".tf.json")
    try:
        if is_json:
            doc = json.loads(text)
            normalize: Callable[[Any], Any] = _json_value
        else:
            import hcl2  # deferred: only Terraform scans need the parser

            doc = hcl2.loads(text)
            normalize = _hcl_value
    except Exception as exc:  # noqa: BLE001 - any parser error is a bad file
        raise TerraformError(f"Failed to parse Terraform {path.name}: {exc}") from exc
    if not isinstance(doc, dict):
        raise TerraformError(f"Terraform {path.name} is not an object")

    blocks: list[_Block] = []
    for type_map in _iter_type_maps(doc.get("resource")):
        for raw_type, by_name in type_map.items():
            rtype = _unquote_key(raw_type)
            for name_map in _iter_type_maps(by_name):
                for raw_name, body in name_map.items():
                    name = _unquote_key(raw_name)
                    if isinstance(body, list):  # *.tf.json allows a list of bodies
                        body = body[0] if body and isinstance(body[0], dict) else {}
                    if not isinstance(body, dict):
                        continue
                    norm = normalize(body)
                    blocks.append(
                        _Block(rtype, name, norm, path, _find_line(text, rtype, name, is_json))
                    )

    sources: list[str] = []
    for module_map in _iter_type_maps(doc.get("module")):
        for body in module_map.values():
            for item in _iter_type_maps(body):
                source = normalize(item).get("source")
                if isinstance(source, str) and source.startswith(("./", "../")):
                    sources.append(source)
    return blocks, sources


def _module_files(module_dir: Path) -> list[Path]:
    files = [
        p for p in sorted(module_dir.iterdir())
        if p.is_file() and (p.name.endswith(".tf") or p.name.endswith(".tf.json"))
    ]
    # Override files merge into other blocks; reading them as plain resources would double count.
    return [p for p in files if not re.search(r"(?:^|_)override\.tf(?:\.json)?$", p.name)]


# --- argument -> CloudFormation property adapters ----------------------------


def _first_block(body: dict, key: str) -> dict:
    value = body.get(key)
    if isinstance(value, list):
        value = value[0] if value else None
    return value if isinstance(value, dict) else {}


def _blocks(body: dict, key: str) -> list[dict]:
    value = body.get(key)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _dynamic_names(body: dict) -> set[str]:
    names: set[str] = set()
    for item in _blocks(body, "dynamic"):
        names.update(item.keys())
    return names


def _set(props: dict, key: str, value: Any) -> None:
    if value is not None:
        props[key] = value


def _s3_bucket(body: dict) -> dict:
    """Legacy inline arguments (provider < v4). Split resources are merged later."""
    props: dict = {}
    versioning = _first_block(body, "versioning")
    if versioning:
        enabled = versioning.get("enabled")
        props["VersioningConfiguration"] = (
            UNRESOLVED if enabled is UNRESOLVED else {"Status": "Enabled" if enabled is True else "Suspended"}
        )
    sse = _first_block(body, "server_side_encryption_configuration")
    if sse:
        props["BucketEncryption"] = _s3_encryption(sse)
    logging = _first_block(body, "logging")
    if logging:
        props["LoggingConfiguration"] = {"DestinationBucketName": logging.get("target_bucket")}
    return props


def _s3_encryption(body: dict) -> Any:
    configs = []
    for rule in _blocks(body, "rule"):
        default = _first_block(rule, "apply_server_side_encryption_by_default")
        configs.append({"ServerSideEncryptionByDefault": {"SSEAlgorithm": default.get("sse_algorithm")}})
    return {"ServerSideEncryptionConfiguration": configs}


def _s3_part(part_type: str, body: dict) -> Any:
    if part_type == "aws_s3_bucket_public_access_block":
        return {
            "BlockPublicAcls": body.get("block_public_acls"),
            "IgnorePublicAcls": body.get("ignore_public_acls"),
            "BlockPublicPolicy": body.get("block_public_policy"),
            "RestrictPublicBuckets": body.get("restrict_public_buckets"),
        }
    if part_type == "aws_s3_bucket_versioning":
        status = _first_block(body, "versioning_configuration").get("status")
        return {"Status": status}
    if part_type == "aws_s3_bucket_server_side_encryption_configuration":
        return _s3_encryption(body)
    return {"DestinationBucketName": body.get("target_bucket")}


def _db(body: dict) -> dict:
    props: dict = {}
    for tf_key, cf_key in (
        ("storage_encrypted", "StorageEncrypted"),
        ("backup_retention_period", "BackupRetentionPeriod"),
        ("multi_az", "MultiAZ"),
        ("deletion_protection", "DeletionProtection"),
        ("publicly_accessible", "PubliclyAccessible"),
        ("instance_class", "DBInstanceClass"),
        ("cluster_identifier", "DBClusterIdentifier"),
    ):
        _set(props, cf_key, body.get(tf_key))
    return props


def _instance(body: dict) -> dict:
    props: dict = {}
    _set(props, "InstanceType", body.get("instance_type"))
    return props


def _launch_template(body: dict) -> dict:
    market = _first_block(body, "instance_market_options")
    data: dict = {}
    if market:
        data["InstanceMarketOptions"] = {"MarketType": market.get("market_type")}
    return {"LaunchTemplateData": data}


def _ingress_entries(rule: dict) -> Any:
    entries: list[dict] = []
    ports = {"FromPort": rule.get("from_port"), "ToPort": rule.get("to_port")}
    if rule.get("protocol") in ("-1", -1, "all"):
        ports = {"FromPort": None, "ToPort": None}
    for key, cf_key in (("cidr_blocks", "CidrIp"), ("ipv6_cidr_blocks", "CidrIpv6")):
        cidrs = rule.get(key)
        if cidrs is UNRESOLVED:
            return UNRESOLVED
        for cidr in cidrs if isinstance(cidrs, list) else []:
            entries.append({cf_key: cidr, **ports})
    return entries


def _security_group(body: dict) -> dict:
    if "ingress" in _dynamic_names(body):
        return {"SecurityGroupIngress": UNRESOLVED}
    ingress: list = []
    for rule in _blocks(body, "ingress"):
        entries = _ingress_entries(rule)
        if entries is UNRESOLVED:
            return {"SecurityGroupIngress": UNRESOLVED}
        ingress.extend(entries)
    return {"SecurityGroupIngress": ingress}


def _ingress_rule(rtype: str, body: dict) -> dict | None:
    """aws_vpc_security_group_ingress_rule, or aws_security_group_rule with type ingress."""
    if rtype == "aws_security_group_rule":
        kind = body.get("type")
        if kind is UNRESOLVED:
            return {"CidrIp": UNRESOLVED}
        if kind != "ingress":
            return None
        entries = _ingress_entries(body)
        if entries is UNRESOLVED:
            return {"CidrIp": UNRESOLVED}
        open_entry = next(
            (e for e in entries if e.get("CidrIp") == "0.0.0.0/0" or e.get("CidrIpv6") == "::/0"),
            entries[0] if entries else {},
        )
        return dict(open_entry)
    props: dict = {}
    _set(props, "CidrIp", body.get("cidr_ipv4"))
    _set(props, "CidrIpv6", body.get("cidr_ipv6"))
    if body.get("ip_protocol") in ("-1", -1):
        props["FromPort"] = props["ToPort"] = None
    else:
        props["FromPort"] = body.get("from_port")
        props["ToPort"] = body.get("to_port")
    return props


def _lb(body: dict) -> dict:
    logs = _first_block(body, "access_logs")
    enabled = logs.get("enabled", False)  # provider default: false, even with a bucket
    if enabled is UNRESOLVED:
        return {"LoadBalancerAttributes": UNRESOLVED}
    value = "true" if enabled is True else "false"
    return {"LoadBalancerAttributes": [{"Key": "access_logs.s3.enabled", "Value": value}]}


def _cloudtrail(body: dict) -> dict:
    props: dict = {}
    _set(props, "EnableLogFileValidation", body.get("enable_log_file_validation"))
    _set(props, "IsMultiRegionTrail", body.get("is_multi_region_trail"))
    _set(props, "KmsKeyId", body.get("kms_key_id"))
    return props


def _kms_key(body: dict) -> dict:
    props: dict = {}
    _set(props, "KeyPolicy", body.get("policy"))
    return props


def _lambda(body: dict) -> dict:
    props: dict = {}
    dlq = _first_block(body, "dead_letter_config")
    if dlq:
        props["DeadLetterConfig"] = {"TargetArn": dlq.get("target_arn")}
    tracing = _first_block(body, "tracing_config")
    if tracing:
        props["TracingConfig"] = {"Mode": tracing.get("mode")}
    _set(props, "Architectures", body.get("architectures"))
    return props


def _dynamodb(body: dict) -> dict:
    props: dict = {}
    pitr = _first_block(body, "point_in_time_recovery")
    if pitr:
        props["PointInTimeRecoverySpecification"] = {"PointInTimeRecoveryEnabled": pitr.get("enabled")}
    sse = _first_block(body, "server_side_encryption")
    if sse:
        props["SSESpecification"] = {"SSEEnabled": sse.get("enabled")}
    return props


def _log_group(body: dict) -> dict:
    props: dict = {}
    retention = body.get("retention_in_days")
    if retention != 0:  # 0 means "never expire" in Terraform
        _set(props, "RetentionInDays", retention)
    _set(props, "KmsKeyId", body.get("kms_key_id"))
    return props


def _sqs(body: dict) -> dict:
    props: dict = {}
    _set(props, "SqsManagedSseEnabled", body.get("sqs_managed_sse_enabled"))
    _set(props, "KmsMasterKeyId", body.get("kms_master_key_id"))
    redrive = body.get("redrive_policy")
    if isinstance(redrive, str) and "deadLetterTargetArn" in redrive:
        redrive = {"deadLetterTargetArn": redrive}
    _set(props, "RedrivePolicy", redrive)
    return props


def _api_stage(body: dict) -> dict:
    props: dict = {}
    logs = _first_block(body, "access_log_settings")
    if logs:
        props["AccessLogSetting"] = {"DestinationArn": logs.get("destination_arn")}
    _set(props, "TracingEnabled", body.get("xray_tracing_enabled"))
    return props


def _apiv2_stage(body: dict) -> dict:
    props: dict = {}
    logs = _first_block(body, "access_log_settings")
    if logs:
        props["AccessLogSettings"] = {"DestinationArn": logs.get("destination_arn")}
    return props


def _asg(body: dict) -> dict:
    mixed = _first_block(body, "mixed_instances_policy")
    if not mixed:
        return {}
    dist = _first_block(mixed, "instances_distribution")
    return {
        "MixedInstancesPolicy": {
            "InstancesDistribution": {
                "SpotMaxPrice": dist.get("spot_max_price"),
                "SpotAllocationStrategy": dist.get("spot_allocation_strategy"),
            }
        }
    }


def _ecs_service(body: dict) -> dict:
    props: dict = {}
    _set(props, "LaunchType", body.get("launch_type"))
    strategy = [
        {"CapacityProvider": item.get("capacity_provider")}
        for item in _blocks(body, "capacity_provider_strategy")
    ]
    if strategy:
        props["CapacityProviderStrategy"] = strategy
    return props


def _eks(body: dict) -> dict:
    types = body.get("enabled_cluster_log_types")
    if types is UNRESOLVED:
        return {"Logging": UNRESOLVED}
    logs = [{"Type": t, "Enabled": True} for t in types] if isinstance(types, list) else []
    return {"Logging": {"ClusterLogging": logs}}


_ADAPTERS: dict[str, Callable[[dict], dict]] = {
    "aws_s3_bucket": _s3_bucket,
    "aws_db_instance": _db,
    "aws_rds_cluster": _db,
    "aws_instance": _instance,
    "aws_launch_template": _launch_template,
    "aws_security_group": _security_group,
    "aws_lb": _lb,
    "aws_alb": _lb,
    "aws_cloudtrail": _cloudtrail,
    "aws_kms_key": _kms_key,
    "aws_lambda_function": _lambda,
    "aws_dynamodb_table": _dynamodb,
    "aws_cloudwatch_log_group": _log_group,
    "aws_sqs_queue": _sqs,
    "aws_api_gateway_stage": _api_stage,
    "aws_apigatewayv2_stage": _apiv2_stage,
    "aws_autoscaling_group": _asg,
    "aws_ecs_service": _ecs_service,
    "aws_eks_cluster": _eks,
}


def _split_unresolved(props: dict) -> tuple[dict, frozenset[str]]:
    """Drop properties that depend on var/local and name them."""
    unresolved = frozenset(k for k, v in props.items() if _contains_unresolved(v))
    return {k: v for k, v in props.items() if k not in unresolved}, unresolved


def _to_resource(block: _Block) -> Resource | None:
    canonical = TF_TYPE_TO_CANONICAL.get(block.type)
    if block.type == "aws_security_group_rule":
        props = _ingress_rule(block.type, block.body)
        if props is None:  # egress rule: no check covers it
            canonical, props = None, {}
    elif block.type == "aws_vpc_security_group_ingress_rule":
        props = _ingress_rule(block.type, block.body) or {}
    else:
        adapter = _ADAPTERS.get(block.type)
        props = adapter(block.body) if adapter else {}
    clean, unresolved = _split_unresolved(props)
    return Resource(
        type=canonical,
        name=block.address,
        properties=clean,
        file=str(block.file),
        line=block.line,
        source_type=block.type,
        unresolved=unresolved,
    )


def _merge_s3_parts(blocks: list[_Block], resources: dict[str, Resource]) -> None:
    """Attach split S3 settings resources to their aws_s3_bucket."""
    buckets = {r.name.split(".", 1)[1]: r for r in resources.values() if r.source_type == "aws_s3_bucket"}
    by_literal = {
        b.body.get("bucket"): buckets[b.name]
        for b in blocks
        if b.type == "aws_s3_bucket" and isinstance(b.body.get("bucket"), str) and b.name in buckets
    }
    unlinked: set[str] = set()
    for block in blocks:
        cf_key = _S3_PARTS.get(block.type)
        if cf_key is None:
            continue
        ref = block.body.get("bucket")
        target = None
        if isinstance(ref, str):
            match = _BUCKET_REF.search(ref)
            target = buckets.get(match.group(1)) if match else by_literal.get(ref)
        if target is None:
            unlinked.add(cf_key)
            continue
        value = _s3_part(block.type, block.body)
        if _contains_unresolved(value):
            target.properties.pop(cf_key, None)
            target.unresolved = target.unresolved | {cf_key}
        else:
            target.properties[cf_key] = value
            target.unresolved = target.unresolved - {cf_key}
    # A part we could not tie to a bucket may belong to any of them: do not report that control.
    for bucket in buckets.values():
        missing = {k for k in unlinked if k not in bucket.properties}
        if missing:
            bucket.unresolved = bucket.unresolved | missing


def resources_from_terraform(module_dir: Path, warnings: list[str] | None = None) -> list[Resource]:
    """Parse one root module directory (non-recursive) into Resource records."""
    if warnings is None:
        warnings = []
    blocks: list[_Block] = []
    for path in _module_files(module_dir):
        try:
            file_blocks, _sources = parse_tf_file(path)
        except (TerraformError, OSError, UnicodeError) as exc:
            warnings.append(str(exc))
            continue
        blocks.extend(file_blocks)
    resources: dict[str, Resource] = {}
    for block in blocks:
        resource = _to_resource(block)
        if resource is not None:
            resources[resource.name] = resource
    _merge_s3_parts(blocks, resources)
    return list(resources.values())


def find_root_modules(files: list[Path]) -> list[Path]:
    """Directories holding *.tf / *.tf.json, minus those used as local child modules."""
    dirs = sorted({
        p.parent.resolve() for p in files
        if p.name.endswith(".tf") or p.name.endswith(".tf.json")
    })
    children: set[Path] = set()
    for module_dir in dirs:
        for path in _module_files(module_dir):
            try:
                _blocks_unused, sources = parse_tf_file(path)
            except (TerraformError, OSError, UnicodeError):
                continue
            children.update((module_dir / source).resolve() for source in sources)
    return [d for d in dirs if d not in children]
