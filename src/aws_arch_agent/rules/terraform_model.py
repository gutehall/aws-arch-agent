"""Parse root-module Terraform (*.tf, *.tf.json) into Resource records.

No `terraform init`, no registry or child modules: only the files in a root
module directory. aws_* types map onto the canonical types the CF-* checks use,
and their arguments are translated into the CloudFormation-shaped properties
those checks read. A value that depends on `var.*` or `local.*` is unresolved:
the property is left out and recorded in Resource.unresolved, so no check
reports on it. Per-instance values (each.*, count.*, self.*) are treated the same.

With a `terraform show -json` document (see load_plan_values), known planned values
replace those unresolved arguments before the checks run.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
import re
from pathlib import Path
from typing import Any, Callable

from aws_arch_agent.rules.resource_model import Resource
from aws_arch_agent.rules.tag_policy import TF_TAGGABLE
from aws_arch_agent.rules.tag_policy import UNKNOWN as UNKNOWN_TAG

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
    "aws_subnet": "subnet",
    "aws_vpc_endpoint": "vpc_endpoint",
    "aws_flow_log": "flow_log",
    "aws_nat_gateway": "nat_gateway",
    "aws_eip": "eip",
    "aws_lb": "lb",
    "aws_alb": "lb",
    "aws_cloudtrail": "cloudtrail",
    "aws_kms_key": "kms_key",
    "aws_lambda_function": "lambda_function",
    "aws_dynamodb_table": "dynamodb_table",
    "aws_cloudwatch_log_group": "cloudwatch_log_group",
    "aws_sqs_queue": "sqs_queue",
    "aws_sns_topic": "sns_topic",
    "aws_ebs_volume": "ebs_volume",
    "aws_efs_file_system": "efs_file_system",
    "aws_kinesis_stream": "kinesis_stream",
    "aws_opensearch_domain": "opensearch_domain",
    "aws_redshift_cluster": "redshift_cluster",
    "aws_docdb_cluster": "docdb_cluster",
    "aws_neptune_cluster": "neptune_cluster",
    "aws_msk_cluster": "msk_cluster",
    "aws_wafv2_web_acl_association": "waf_association",
    "aws_wafregional_web_acl_association": "waf_association",
    "aws_cloudfront_origin_access_control": "cloudfront_origin_access_control",
    "aws_api_gateway_rest_api": "api_gateway_rest_api",
    "aws_api_gateway_stage": "api_gateway_stage",
    "aws_apigatewayv2_api": "apigatewayv2_api",
    "aws_apigatewayv2_stage": "apigatewayv2_stage",
    "aws_autoscaling_group": "autoscaling_group",
    "aws_launch_configuration": "launch_configuration",
    "aws_appautoscaling_target": "scalable_target",
    "aws_ecs_service": "ecs_service",
    "aws_eks_cluster": "eks_cluster",
    "aws_cloudfront_distribution": "cloudfront_distribution",
    "aws_elasticache_cluster": "elasticache_cluster",
    "aws_elasticache_replication_group": "elasticache_replication_group",
    "aws_iam_policy": "iam_policy",
    "aws_iam_role_policy": "iam_policy",
    "aws_iam_user_policy": "iam_policy",
    "aws_iam_group_policy": "iam_policy",
    # Attachments carry a managed policy ARN (ManagedPolicyArns), read by CF-IAM-008.
    "aws_iam_role_policy_attachment": "iam_policy",
    "aws_iam_user_policy_attachment": "iam_policy",
    "aws_iam_group_policy_attachment": "iam_policy",
    "aws_iam_policy_attachment": "iam_policy",
    "aws_iam_role_policy_attachments_exclusive": "iam_policy",
    "aws_iam_user_policy_attachments_exclusive": "iam_policy",
    "aws_iam_group_policy_attachments_exclusive": "iam_policy",
    "aws_iam_role": "iam_role",
    # Resource policies (CF-RP-001). aws_s3_bucket_policy is also merged into its bucket.
    "aws_sqs_queue_policy": "resource_policy",
    "aws_sns_topic_policy": "resource_policy",
    "aws_s3_bucket_policy": "resource_policy",
    "aws_ecr_repository_policy": "resource_policy",
    "aws_ecr_repository": "ecr_repository",
    "aws_ecs_task_definition": "ecs_task_definition",
    "aws_secretsmanager_secret": "secretsmanager_secret",
    "aws_secretsmanager_secret_rotation": "secretsmanager_secret_rotation",
    "aws_cognito_user_pool": "cognito_user_pool",
    "aws_lambda_permission": "lambda_permission",
    # Holds ProvisionedConcurrencyConfig, like AWS::Lambda::Alias (CF-ENV-002).
    "aws_lambda_provisioned_concurrency_config": "lambda_alias",
    "aws_iam_user": "iam_user",
    "aws_iam_group": "iam_group",
}

# S3 settings split into their own resources (AWS provider v4+) -> bucket property.
_S3_PARTS: dict[str, str] = {
    "aws_s3_bucket_public_access_block": "PublicAccessBlockConfiguration",
    "aws_s3_bucket_versioning": "VersioningConfiguration",
    "aws_s3_bucket_server_side_encryption_configuration": "BucketEncryption",
    "aws_s3_bucket_logging": "LoggingConfiguration",
    # Not a CloudFormation bucket property: the policy document, read by CF-S3-005.
    "aws_s3_bucket_policy": "BucketPolicy",
    "aws_s3_bucket_lifecycle_configuration": "LifecycleConfiguration",
    "aws_s3_bucket_intelligent_tiering_configuration": "IntelligentTieringConfigurations",
}

# var/local are module inputs; each/count/self differ per instance. None is known statically.
_UNRESOLVED_REF = re.compile(r"\b(?:var|local|each|count|self)\.[A-Za-z_]")
_BUCKET_REF = re.compile(r"\baws_s3_bucket\.([A-Za-z0-9_-]+)\.")
_ECR_REF = re.compile(r"\baws_ecr_repository\.([A-Za-z0-9_-]+)\.")
# A reference to another managed resource: aws_eip.nat.id -> aws_eip.nat.
_ADDRESS_REF = re.compile(r"(?<![\w.])(aws_[a-z0-9_]+\.[A-Za-z0-9_-]+)(?=\[|\.)")
_META_KEYS = {"__is_block__", "__start_line__", "__end_line__"}


class _Unresolved:
    """A value that depends on var.* or local.*."""

    def __repr__(self) -> str:
        return "<unresolved>"


UNRESOLVED = _Unresolved()


class _Expr(str):
    """A non-literal expression (resource/data reference, function call, template string).

    Truthy, so presence checks (a KMS key or log target is set) see it as set. Arguments
    whose value is compared (bools, enums, ports, lists) read it as unresolved via _v().
    """


class _JsonEncode(_Expr):
    """`jsonencode({...})`. Kept as text even when it mentions var.* or local.*, so a
    policy document can be decoded field by field (see decode_jsonencode)."""


_JSONENCODE = re.compile(r"jsonencode\((.*)\)", re.DOTALL)
_HEREDOC = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)\n(.*)\n\s*\1\s*", re.DOTALL)
_MANAGED_POLICY_REF = re.compile(r"data\.aws_iam_policy\.([A-Za-z0-9_-]+)\.arn")
_POLICY_DOC_REF = re.compile(r"data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.(?:json|minified_json)")
# Leaf of a decoded document whose value the scan cannot see. Not a plain str, so no
# check compares it equal to a literal such as "*".
UNKNOWN = "<unresolved>"


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
            if text in ("true", "false"):  # Terraform coerces "true" to a bool argument
                return text == "true"
            if "${" in text:  # template string
                return UNRESOLVED if _UNRESOLVED_REF.search(text) else _Expr(text)
            return text
        expr = value[2:-1] if value.startswith("${") and value.endswith("}") else value
        if expr in ("true", "false"):
            return expr == "true"
        if _JSONENCODE.fullmatch(expr):
            return _JsonEncode(expr)
        return UNRESOLVED if _UNRESOLVED_REF.search(expr) else _Expr(expr)
    if isinstance(value, list):
        return [_hcl_value(v) for v in value]
    if isinstance(value, dict):
        return {_unquote_key(k): _hcl_value(v) for k, v in value.items() if k not in _META_KEYS}
    return value


def _json_value(value: Any) -> Any:
    """*.tf.json value: "${...}" strings are expressions."""
    if isinstance(value, str):
        if value in ("true", "false"):
            return value == "true"
        inner = value[2:-1] if value.startswith("${") and value.endswith("}") else ""
        if inner and _JSONENCODE.fullmatch(inner):
            return _JsonEncode(inner)
        if "${" in value and _UNRESOLVED_REF.search(value):
            return UNRESOLVED
        if value.startswith("${") and value.endswith("}") and value.count("${") == 1:
            return _Expr(value[2:-1])
        return _Expr(value) if "${" in value else value
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

    def __init__(
        self, rtype: str, name: str, body: dict, file: Path, line: int | None, data: bool = False
    ):
        self.type = rtype
        self.name = name
        self.body = body
        self.file = file
        self.line = line
        self.data = data  # a `data` block, not a managed resource
        # Addresses the block refers to, read from its raw arguments: normalizing turns an
        # expression with var/count/each into UNRESOLVED and would drop the reference.
        self.references: frozenset[str] = frozenset()

    @property
    def address(self) -> str:
        prefix = "data." if self.data else ""
        return f"{prefix}{self.type}.{self.name}"


def _find_line(text: str, rtype: str, name: str, is_json: bool) -> int | None:
    """Line of the resource declaration. For *.tf.json this is the first textual match
    of the type and then the name, so it is approximate."""
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


def _load_tf(path: Path) -> tuple[dict, str, bool, Callable[[Any], Any]]:
    """Parse one *.tf or *.tf.json file: (document, text, is_json, value normalizer)."""
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
    return doc, text, is_json, normalize


@dataclass
class TfVariable:
    """One `variable "name"` block. default is NO_DEFAULT when the block sets none."""

    name: str
    default: Any
    sensitive: Any
    file: str
    line: int | None


NO_DEFAULT = _Unresolved()


def _variable_line(text: str, name: str, is_json: bool) -> int | None:
    if is_json:
        start = text.find('"variable"')
        match = re.compile(rf'"{re.escape(name)}"\s*:').search(text, start) if start >= 0 else None
        at = match.start() if match else -1
    else:
        match = re.search(rf'^\s*variable\s+"?{re.escape(name)}"?\s*\{{', text, re.MULTILINE)
        at = match.start() + len(match.group(0)) - len(match.group(0).lstrip()) if match else -1
    return text.count("\n", 0, at) + 1 if at >= 0 else None


def parse_tf_variables(path: Path) -> list[TfVariable]:
    """The `variable` blocks declared in one file."""
    doc, text, is_json, normalize = _load_tf(path)
    out: list[TfVariable] = []
    for var_map in _iter_type_maps(doc.get("variable")):
        for raw_name, body in var_map.items():
            if isinstance(body, list):  # *.tf.json allows a list of bodies
                body = body[0] if body and isinstance(body[0], dict) else {}
            if not isinstance(body, dict):
                continue
            name = _unquote_key(raw_name)
            norm = normalize(body)
            out.append(TfVariable(
                name=name,
                default=norm.get("default", NO_DEFAULT),
                sensitive=norm.get("sensitive"),
                file=str(path),
                line=_variable_line(text, name, is_json),
            ))
    return out


# provider = aws.west, as parsed ("aws.west") or interpolated ("${aws.west}").
_PROVIDER_ALIAS = re.compile(r"^(?:\$\{)?aws\.([A-Za-z0-9_-]+)\}?$")


def _tag_values(tags: Any) -> dict[str, Any] | None:
    """A Terraform tags map: literal values kept, others marked unknown; None if unreadable."""
    if not isinstance(tags, dict):
        return None
    return {str(k): (v if type(v) is str else UNKNOWN_TAG) for k, v in tags.items() if k not in _META_KEYS}


def parse_tf_default_tags(path: Path) -> dict[str, dict[str, Any] | None]:
    """provider "aws" default_tags in one file: alias ("" for the default) -> tags.

    None for a provider whose default_tags cannot be read (tags from a variable).
    """
    doc, _text, _is_json, normalize = _load_tf(path)
    out: dict[str, dict[str, Any] | None] = {}
    for provider_map in _iter_type_maps(doc.get("provider")):
        for raw_name, body in provider_map.items():
            if _unquote_key(raw_name) != "aws":
                continue
            for item in _iter_type_maps(body):
                norm = normalize(item)
                alias = norm.get("alias")
                key = alias if type(alias) is str else ""
                default_tags = _first_block(norm, "default_tags")
                if not default_tags:
                    out.setdefault(key, {})
                    continue
                out[key] = _tag_values(default_tags.get("tags"))
    return out


def variables_from_terraform(module_dir: Path, warnings: list[str] | None = None) -> list[TfVariable]:
    """The root module's input variables (one directory, non-recursive)."""
    if warnings is None:
        warnings = []
    out: list[TfVariable] = []
    for path in _module_files(module_dir):
        try:
            out.extend(parse_tf_variables(path))
        except (TerraformError, OSError, UnicodeError):
            continue  # resources_from_terraform already warned about this file
    return out


def parse_tf_file(path: Path) -> tuple[list[_Block], list[str]]:
    """Return the resource blocks and local module sources declared in one file."""
    doc, text, is_json, normalize = _load_tf(path)

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
                    block = _Block(rtype, name, norm, path, _find_line(text, rtype, name, is_json))
                    block.references = frozenset(_ADDRESS_REF.findall(json.dumps(body, default=str)))
                    blocks.append(block)

    # Data sources the checks read: policy documents and managed policy lookups, so
    # references to them resolve.
    for type_map in _iter_type_maps(doc.get("data")):
        for raw_type, by_name in type_map.items():
            rtype = _unquote_key(raw_type)
            if rtype not in ("aws_iam_policy_document", "aws_iam_policy"):
                continue
            for name_map in _iter_type_maps(by_name):
                for raw_name, body in name_map.items():
                    if isinstance(body, list):
                        body = body[0] if body and isinstance(body[0], dict) else {}
                    if isinstance(body, dict):
                        blocks.append(
                            _Block(rtype, _unquote_key(raw_name), normalize(body), path, None, data=True)
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


def _v(body: dict, key: str, default: Any = None) -> Any:
    """Argument whose value is compared: an expression is unresolved."""
    value = body.get(key, default)
    return UNRESOLVED if isinstance(value, _Expr) else value


def _ref(body: dict, key: str) -> Any:
    """Argument only checked for presence: a reference counts as set."""
    return body.get(key)


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
        enabled = _v(versioning, "enabled")
        props["VersioningConfiguration"] = (
            UNRESOLVED if enabled is UNRESOLVED else {"Status": "Enabled" if enabled is True else "Suspended"}
        )
    sse = _first_block(body, "server_side_encryption_configuration")
    if sse:
        props["BucketEncryption"] = _s3_encryption(sse)
    logging = _first_block(body, "logging")
    if logging:
        props["LoggingConfiguration"] = {"DestinationBucketName": _ref(logging, "target_bucket")}
    if _blocks(body, "lifecycle_rule"):
        props["LifecycleConfiguration"] = _lifecycle_rules(_blocks(body, "lifecycle_rule"))
    return props


def _s3_encryption(body: dict) -> Any:
    configs = []
    for rule in _blocks(body, "rule"):
        default = _first_block(rule, "apply_server_side_encryption_by_default")
        configs.append({"ServerSideEncryptionByDefault": {"SSEAlgorithm": _v(default, "sse_algorithm")}})
    return {"ServerSideEncryptionConfiguration": configs}


def _s3_part(part_type: str, body: dict) -> Any:
    if part_type == "aws_s3_bucket_public_access_block":
        return {
            "BlockPublicAcls": _v(body, "block_public_acls"),
            "IgnorePublicAcls": _v(body, "ignore_public_acls"),
            "BlockPublicPolicy": _v(body, "block_public_policy"),
            "RestrictPublicBuckets": _v(body, "restrict_public_buckets"),
        }
    if part_type == "aws_s3_bucket_versioning":
        status = _first_block(body, "versioning_configuration").get("status")
        return {"Status": status}
    if part_type == "aws_s3_bucket_server_side_encryption_configuration":
        return _s3_encryption(body)
    if part_type == "aws_s3_bucket_policy":
        return body.get("policy", UNRESOLVED)  # a document once _resolve_iam has run
    if part_type == "aws_s3_bucket_lifecycle_configuration":
        return _lifecycle_rules(_blocks(body, "rule"))
    if part_type == "aws_s3_bucket_intelligent_tiering_configuration":
        return [{"Status": _known(_v(body, "status")) or "Enabled"}]
    return {"DestinationBucketName": _ref(body, "target_bucket")}


def _lifecycle_rules(rules: list[dict]) -> Any:
    """Lifecycle rules in CloudFormation shape: status and the storage classes they move to.

    A dynamic transition block, or a status from a variable, makes the whole configuration
    UNRESOLVED: the S3 storage checks then do not judge the bucket.
    """
    out = []
    for rule in rules:
        if {"transition", "noncurrent_version_transition"} & _dynamic_names(rule):
            return UNRESOLVED
        status = _v(rule, "status")
        enabled = _v(rule, "enabled")  # inline lifecycle_rule (provider < v4)
        if status is UNRESOLVED or enabled is UNRESOLVED:
            return UNRESOLVED
        if status is None and enabled is not None:
            status = "Enabled" if enabled is True else "Disabled"
        transitions = [
            {"StorageClass": _known(_v(t, "storage_class"))}
            for key in ("transition", "noncurrent_version_transition")
            for t in _blocks(rule, key)
        ]
        out.append({"Status": status or "Enabled", "Transitions": transitions})
    return {"Rules": out}


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
    _set(props, "Engine", _v(body, "engine"))
    return props


def _metadata_options(body: dict) -> dict | None:
    """metadata_options -> MetadataOptions. A value from var/local stays a non-literal
    marker instead of UNRESOLVED, so it does not hide the block's other checks."""
    block = _first_block(body, "metadata_options")
    if not block:
        return None
    out: dict = {}
    for tf_key, cf_key in (("http_tokens", "HttpTokens"), ("http_endpoint", "HttpEndpoint")):
        value = _v(block, tf_key)
        if value is UNRESOLVED:
            value = _Expr("<unresolved>")
        _set(out, cf_key, value)
    return out


def _instance(body: dict) -> dict:
    props: dict = {}
    _set(props, "InstanceType", _v(body, "instance_type"))
    _set(props, "MetadataOptions", _metadata_options(body))
    public_ip = _v(body, "associate_public_ip_address")
    if public_ip is not None:
        props["NetworkInterfaces"] = [{"DeviceIndex": 0, "AssociatePublicIpAddress": public_ip}]
    template = _first_block(body, "launch_template")
    if template:
        props["LaunchTemplate"] = {
            "LaunchTemplateId": _ref(template, "id"),
            "LaunchTemplateName": _ref(template, "name"),
        }
    return props


def _launch_template(body: dict) -> dict:
    market = _first_block(body, "instance_market_options")
    data: dict = {}
    if market:
        data["InstanceMarketOptions"] = {"MarketType": _v(market, "market_type")}
    _set(data, "MetadataOptions", _metadata_options(body))
    props: dict = {"LaunchTemplateData": data}
    # Apart from LaunchTemplateData, so an instance type from a variable hides only CF-GEN-001.
    _set(props, "InstanceType", _v(body, "instance_type"))
    # Its own property, so an unknown block device does not hide the Spot or IMDS checks.
    # A device whose encryption or snapshot is unknown is left out on its own, so it does
    # not hide the other devices either.
    devices = []
    for item in _blocks(body, "block_device_mappings"):
        name = item.get("device_name")
        for ebs in _blocks(item, "ebs"):
            encrypted, snapshot = _v(ebs, "encrypted"), _ref(ebs, "snapshot_id")
            if encrypted is UNRESOLVED or _contains_unresolved(snapshot):
                continue
            volume_type = _v(ebs, "volume_type")
            devices.append({
                "DeviceName": name if type(name) is str else None,
                "Ebs": {
                    "Encrypted": encrypted, "SnapshotId": snapshot,
                    # Unknown type stays non-literal, so it hides only the gp2 check.
                    "VolumeType": _Expr("<unresolved>") if volume_type is UNRESOLVED else volume_type,
                    "VolumeSize": _known(_v(ebs, "volume_size")),
                },
            })
    if devices:
        props["BlockDeviceMappings"] = devices
    # Also its own property, like the block devices. An interface whose public IP setting is
    # unknown is left out on its own, so it does not hide the others.
    interfaces = []
    for n in _blocks(body, "network_interfaces"):
        public_ip, index = _v(n, "associate_public_ip_address"), _v(n, "device_index")
        if public_ip is UNRESOLVED:
            continue
        interfaces.append({
            "DeviceIndex": None if index is UNRESOLVED else index,
            "AssociatePublicIpAddress": public_ip,
        })
    if interfaces:
        props["NetworkInterfaces"] = interfaces
    return props


def _subnet(body: dict) -> dict:
    props: dict = {}
    _set(props, "MapPublicIpOnLaunch", _v(body, "map_public_ip_on_launch"))
    return props


def _nat_gateway(body: dict) -> dict:
    """aws_nat_gateway: a private NAT gateway has no route out (CF-VPC-002/003)."""
    props: dict = {}
    _set(props, "ConnectivityType", _v(body, "connectivity_type"))
    return props


def _vpc_endpoint(body: dict) -> dict:
    """aws_vpc_endpoint: the service and type CF-VPC-002/003 read. The service name is
    kept as written: a template string ("com.amazonaws.${...}.s3") still names it."""
    props: dict = {}
    _set(props, "ServiceName", _ref(body, "service_name"))
    _set(props, "VpcEndpointType", _v(body, "vpc_endpoint_type"))
    return props


def _sns_topic(body: dict) -> dict:
    props: dict = {}
    _set(props, "KmsMasterKeyId", _ref(body, "kms_master_key_id"))
    return props


def _ebs_volume(body: dict) -> dict:
    props: dict = {}
    _set(props, "Encrypted", _v(body, "encrypted"))
    _set(props, "SnapshotId", _ref(body, "snapshot_id"))
    _set(props, "VolumeType", _v(body, "type"))
    _set(props, "Size", _v(body, "size"))
    return props


def _eip(body: dict) -> dict:
    props: dict = {}
    _set(props, "InstanceId", _ref(body, "instance"))
    _set(props, "NetworkInterfaceId", _ref(body, "network_interface"))
    _set(props, "PublicIpv4Pool", _v(body, "public_ipv4_pool"))
    return props


def _efs_file_system(body: dict) -> dict:
    props: dict = {}
    _set(props, "Encrypted", _v(body, "encrypted"))
    return props


def _kinesis_stream(body: dict) -> dict:
    """encryption_type defaults to NONE; KMS maps to StreamEncryption."""
    encryption = _v(body, "encryption_type", "NONE")
    if encryption is UNRESOLVED:
        return {"StreamEncryption": UNRESOLVED}
    if type(encryption) is str and encryption.upper() == "KMS":
        return {"StreamEncryption": {"EncryptionType": "KMS", "KeyId": _ref(body, "kms_key_id")}}
    return {}


def _opensearch_domain(body: dict) -> dict:
    props: dict = {}
    for block, key in (("encrypt_at_rest", "EncryptionAtRestOptions"),
                       ("node_to_node_encryption", "NodeToNodeEncryptionOptions")):
        found = _first_block(body, block)
        if found:
            props[key] = {"Enabled": _v(found, "enabled")}
    cluster = _first_block(body, "cluster_config")
    if cluster:
        config: dict = {}
        _set(config, "InstanceType", _v(cluster, "instance_type"))
        _set(config, "DedicatedMasterType", _v(cluster, "dedicated_master_type"))
        props["ClusterConfig"] = config
    return props


def _redshift_cluster(body: dict) -> dict:
    props: dict = {}
    _set(props, "Encrypted", _v(body, "encrypted"))
    _set(props, "SnapshotIdentifier", _ref(body, "snapshot_identifier"))
    return props


def _storage_encrypted_cluster(body: dict) -> dict:
    """aws_docdb_cluster / aws_neptune_cluster."""
    props: dict = {}
    _set(props, "StorageEncrypted", _v(body, "storage_encrypted"))
    _set(props, "SnapshotIdentifier", _ref(body, "snapshot_identifier"))
    _set(props, "SourceDBClusterIdentifier", _ref(body, "replication_source_identifier"))
    return props


def _msk_cluster(body: dict) -> dict:
    info = _first_block(body, "encryption_info")
    if "encryption_in_transit" in _dynamic_names(info):
        return {"EncryptionInfo": UNRESOLVED}
    transit = _first_block(info, "encryption_in_transit")
    if not transit:
        return {}
    # Each field on its own: an unknown client_broker must not hide in_cluster = false.
    fields = {"ClientBroker": _v(transit, "client_broker"), "InCluster": _v(transit, "in_cluster")}
    known = {k: v for k, v in fields.items() if v is not None and v is not UNRESOLVED}
    return {"EncryptionInfo": {"EncryptionInTransit": known}}


def _elasticache_replication_group(body: dict) -> dict:
    props: dict = {}
    _set(props, "AtRestEncryptionEnabled", _v(body, "at_rest_encryption_enabled"))
    _set(props, "TransitEncryptionEnabled", _v(body, "transit_encryption_enabled"))
    _set(props, "Engine", _v(body, "engine"))
    _set(props, "MultiAZEnabled", _v(body, "multi_az_enabled"))
    _set(props, "CacheNodeType", _v(body, "node_type"))
    return props


def _provisioned_concurrency(body: dict) -> dict:
    """aws_lambda_provisioned_concurrency_config, in the CloudFormation alias shape."""
    count = _v(body, "provisioned_concurrent_executions")
    if count is None:
        return {}
    if count is UNRESOLVED:
        return {"ProvisionedConcurrencyConfig": UNRESOLVED}
    return {"ProvisionedConcurrencyConfig": {"ProvisionedConcurrentExecutions": count}}


def _ingress_entries(rule: dict) -> Any:
    entries: list[dict] = []
    protocol = _v(rule, "protocol")
    if protocol is UNRESOLVED:
        return UNRESOLVED
    ports = {"FromPort": _v(rule, "from_port"), "ToPort": _v(rule, "to_port")}
    if protocol in ("-1", -1, "all"):
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
        kind = _v(body, "type")
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
    _set(props, "CidrIp", _v(body, "cidr_ipv4"))
    _set(props, "CidrIpv6", _v(body, "cidr_ipv6"))
    ip_protocol = _v(body, "ip_protocol")
    if ip_protocol is UNRESOLVED:
        return {"CidrIp": UNRESOLVED}
    if ip_protocol in ("-1", -1):
        props["FromPort"] = props["ToPort"] = None
    else:
        props["FromPort"] = _v(body, "from_port")
        props["ToPort"] = _v(body, "to_port")
    return props


def _lb(body: dict) -> dict:
    props: dict = {}
    _set(props, "Type", _v(body, "load_balancer_type"))
    internal = _v(body, "internal")
    if internal is not None:
        props["Scheme"] = UNRESOLVED if internal is UNRESOLVED else (
            "internal" if internal is True else "internet-facing")
    logs = _first_block(body, "access_logs")
    enabled = _v(logs, "enabled", False)  # provider default: false, even with a bucket
    if enabled is UNRESOLVED:
        props["LoadBalancerAttributes"] = UNRESOLVED
        return props
    value = "true" if enabled is True else "false"
    props["LoadBalancerAttributes"] = [{"Key": "access_logs.s3.enabled", "Value": value}]
    return props


# Stands in for one value the scan cannot see, inside a structure whose other values are
# known. Shaped like an intrinsic, so the CloudFormation checks skip it.
_OPAQUE = {"Fn::Unresolved": "terraform"}


def _known(value: Any) -> Any:
    return _OPAQUE if value is UNRESOLVED else value


def _cloudfront_distribution(body: dict) -> dict:
    """The arguments CF-CF-001..003 read, in DistributionConfig shape.

    An unknown value is kept as _OPAQUE, so it does not hide the other checks.
    """
    config: dict = {}
    default = _first_block(body, "default_cache_behavior")
    if default:
        config["DefaultCacheBehavior"] = {"ViewerProtocolPolicy": _known(_v(default, "viewer_protocol_policy"))}
    ordered = _blocks(body, "ordered_cache_behavior")
    if ordered:
        config["CacheBehaviors"] = [
            {"PathPattern": _known(_v(b, "path_pattern")),
             "ViewerProtocolPolicy": _known(_v(b, "viewer_protocol_policy"))}
            for b in ordered
        ]
    cert = _first_block(body, "viewer_certificate")
    if cert:
        version = _v(cert, "minimum_protocol_version")
        config["ViewerCertificate"] = {
            "CloudFrontDefaultCertificate": _known(_v(cert, "cloudfront_default_certificate")),
            **({} if version is None else {"MinimumProtocolVersion": _known(version)}),
        }
    origins = []
    for origin in _blocks(body, "origin"):
        item: dict = {
            "Id": _known(_ref(origin, "origin_id")),
            "DomainName": _known(_ref(origin, "domain_name")),
        }
        oac = _ref(origin, "origin_access_control_id")
        if oac is not None:
            item["OriginAccessControlId"] = _known(oac)
        s3 = _first_block(origin, "s3_origin_config")
        if s3:
            item["S3OriginConfig"] = {"OriginAccessIdentity": _known(_ref(s3, "origin_access_identity"))}
        if _first_block(origin, "custom_origin_config"):
            item["CustomOriginConfig"] = {}
        origins.append(item)
    if origins:
        config["Origins"] = origins
    web_acl = _ref(body, "web_acl_id")
    if web_acl is not None:
        config["WebACLId"] = _known(web_acl)
    return {"DistributionConfig": config}


def _waf_association(body: dict) -> dict:
    props: dict = {}
    _set(props, "ResourceArn", _known(_ref(body, "resource_arn")))
    return props


def _cloudtrail(body: dict) -> dict:
    props: dict = {}
    _set(props, "EnableLogFileValidation", _v(body, "enable_log_file_validation"))
    _set(props, "IsMultiRegionTrail", _v(body, "is_multi_region_trail"))
    _set(props, "KmsKeyId", _ref(body, "kms_key_id"))
    return props


def _kms_key(body: dict) -> dict:
    props: dict = {}
    # Raw value: resolve_policy_document reads it field by field in _resolve_iam.
    _set(props, "KeyPolicy", _ref(body, "policy"))
    return props


def _iam_policy(body: dict) -> dict:
    """Raw `policy` value. resolve_policy_document turns it into a document later,
    once data.aws_iam_policy_document blocks are known."""
    props: dict = {}
    _set(props, "PolicyDocument", body.get("policy"))
    return props


def _iam_role(body: dict) -> dict:
    policies = []
    for item in _blocks(body, "inline_policy"):
        policy = item.get("policy")
        policies.append({
            "PolicyName": item.get("name") if type(item.get("name")) is str else None,
            # One unknown inline policy must not hide findings in the others.
            "PolicyDocument": None if _contains_unresolved(policy) else policy,
        })
    props: dict = {"Policies": policies} if policies else {}
    # Raw value: resolve_policy_document turns it into a document in _resolve_iam.
    _set(props, "AssumeRolePolicyDocument", body.get("assume_role_policy"))
    _set(props, "ManagedPolicyArns", body.get("managed_policy_arns"))
    return props


def _resource_policy(body: dict) -> dict:
    """Raw `policy` value, resolved into a document in _resolve_iam."""
    props: dict = {}
    _set(props, "PolicyDocument", body.get("policy"))
    return props


def _ecr_repository(body: dict) -> dict:
    props: dict = {}
    # Terraform's default is MUTABLE too, so unset stays unset.
    _set(props, "ImageTagMutability", _v(body, "image_tag_mutability"))
    scanning = _first_block(body, "image_scanning_configuration")
    if scanning:
        props["ImageScanningConfiguration"] = {"ScanOnPush": _v(scanning, "scan_on_push")}
    return props


# ECS API container keys (camelCase in Terraform JSON) -> CloudFormation keys.
_CONTAINER_KEYS = {
    "name": "Name", "privileged": "Privileged",
    "readonlyRootFilesystem": "ReadonlyRootFilesystem", "user": "User",
}


def _container_definitions(value: Any) -> Any:
    """container_definitions (jsonencode, JSON string or heredoc) -> ContainerDefinitions.

    Text the scan cannot read, such as file() or templatefile(), is UNRESOLVED.
    """
    if isinstance(value, _JsonEncode):
        decoded = decode_jsonencode(value)
    elif isinstance(value, _Expr):
        heredoc = _HEREDOC.fullmatch(value)
        if not heredoc or _UNRESOLVED_REF.search(value) or "${" in value:
            return UNRESOLVED
        decoded = _json_or_unresolved(heredoc.group(2))
    elif isinstance(value, str):
        heredoc = _HEREDOC.fullmatch(value)
        decoded = _json_or_unresolved(heredoc.group(2) if heredoc else value)
    else:
        return UNRESOLVED
    if not isinstance(decoded, list):
        return UNRESOLVED
    out = []
    for item in decoded:
        if not isinstance(item, dict):
            return UNRESOLVED
        out.append({cf: item[tf] for tf, cf in _CONTAINER_KEYS.items() if tf in item})
    return out


def _json_or_unresolved(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return UNRESOLVED


def _ecs_task_definition(body: dict) -> dict:
    props: dict = {}
    value = body.get("container_definitions")
    if value is not None:
        props["ContainerDefinitions"] = _container_definitions(value)
    platform = _first_block(body, "runtime_platform")
    if "operating_system_family" in platform:
        props["RuntimePlatform"] = {"OperatingSystemFamily": _v(platform, "operating_system_family")}
    return props


def _secretsmanager_secret(body: dict) -> dict:
    props: dict = {}
    name = body.get("name")
    if type(name) is str:  # a literal name; a rotation may point at the secret by it
        props["Name"] = name
    return props


def _secret_rotation(body: dict) -> dict:
    return {"SecretId": _known(_ref(body, "secret_id"))}


def _cognito_user_pool(body: dict) -> dict:
    props: dict = {}
    _set(props, "MfaConfiguration", _v(body, "mfa_configuration"))
    _set(props, "UserPoolTier", _v(body, "user_pool_tier"))
    policy_block = _first_block(body, "password_policy")
    if "password_policy" in body:
        policy: dict = {}
        for tf_key, cf_key in (
            ("minimum_length", "MinimumLength"), ("require_lowercase", "RequireLowercase"),
            ("require_uppercase", "RequireUppercase"), ("require_numbers", "RequireNumbers"),
            ("require_symbols", "RequireSymbols"),
        ):
            _set(policy, cf_key, _v(policy_block, tf_key))
        props["Policies"] = {"PasswordPolicy": policy}
    add_ons = _first_block(body, "user_pool_add_ons")
    if add_ons:
        props["UserPoolAddOns"] = {"AdvancedSecurityMode": _v(add_ons, "advanced_security_mode")}
    return props


def _lambda_permission(body: dict) -> dict:
    props: dict = {}
    _set(props, "Principal", _v(body, "principal"))
    _set(props, "SourceArn", _ref(body, "source_arn"))
    _set(props, "SourceAccount", _ref(body, "source_account"))
    _set(props, "PrincipalOrgID", _ref(body, "principal_org_id"))
    _set(props, "FunctionUrlAuthType", _v(body, "function_url_auth_type"))
    return props


def _policy_attachment(body: dict) -> dict:
    """aws_iam_*_policy_attachment: the attached ARN as a one-item ManagedPolicyArns."""
    arns = body.get("policy_arns")  # aws_iam_*_policy_attachments_exclusive
    if arns is None and body.get("policy_arn") is not None:
        arns = [body.get("policy_arn")]
    props: dict = {}
    _set(props, "ManagedPolicyArns", arns)
    return props


def _lambda(body: dict) -> dict:
    props: dict = {}
    dlq = _first_block(body, "dead_letter_config")
    if dlq:
        props["DeadLetterConfig"] = {"TargetArn": _ref(dlq, "target_arn")}
    tracing = _first_block(body, "tracing_config")
    if tracing:
        props["TracingConfig"] = {"Mode": _v(tracing, "mode")}
    _set(props, "Architectures", _v(body, "architectures"))
    _set(props, "Runtime", _v(body, "runtime"))
    _set(props, "PackageType", _v(body, "package_type"))
    return props


def _dynamodb(body: dict) -> dict:
    props: dict = {}
    pitr = _first_block(body, "point_in_time_recovery")
    if pitr:
        props["PointInTimeRecoverySpecification"] = {"PointInTimeRecoveryEnabled": _v(pitr, "enabled")}
    sse = _first_block(body, "server_side_encryption")
    if sse:
        props["SSESpecification"] = {"SSEEnabled": _v(sse, "enabled")}
    name = body.get("name")
    if type(name) is str:
        props["TableName"] = name
    # Priced for the stack total. Terraform's default billing mode is PROVISIONED too.
    _set(props, "BillingMode", _v(body, "billing_mode"))
    if "read_capacity" in body or "write_capacity" in body:
        props["ProvisionedThroughput"] = {
            "ReadCapacityUnits": _v(body, "read_capacity"),
            "WriteCapacityUnits": _v(body, "write_capacity"),
        }
    return props


def _log_group(body: dict) -> dict:
    props: dict = {}
    retention = _v(body, "retention_in_days")
    if retention != 0:  # 0 means "never expire" in Terraform
        _set(props, "RetentionInDays", retention)
    _set(props, "KmsKeyId", _ref(body, "kms_key_id"))
    return props


def _sqs(body: dict) -> dict:
    props: dict = {}
    _set(props, "SqsManagedSseEnabled", _v(body, "sqs_managed_sse_enabled"))
    _set(props, "KmsMasterKeyId", _ref(body, "kms_master_key_id"))
    redrive = _ref(body, "redrive_policy")
    if isinstance(redrive, _Expr):  # e.g. jsonencode({...}): only its text is known
        redrive = {"deadLetterTargetArn": redrive} if "deadLetterTargetArn" in redrive else UNRESOLVED
    elif isinstance(redrive, str):
        try:
            redrive = json.loads(redrive)
        except ValueError:
            redrive = UNRESOLVED
    _set(props, "RedrivePolicy", redrive)
    return props


def _api_stage(body: dict) -> dict:
    props: dict = {}
    logs = _first_block(body, "access_log_settings")
    if logs:
        props["AccessLogSetting"] = {"DestinationArn": _ref(logs, "destination_arn")}
    _set(props, "TracingEnabled", _v(body, "xray_tracing_enabled"))
    return props


def _apiv2_stage(body: dict) -> dict:
    props: dict = {}
    logs = _first_block(body, "access_log_settings")
    if logs:
        props["AccessLogSettings"] = {"DestinationArn": _ref(logs, "destination_arn")}
    return props


def _asg(body: dict) -> dict:
    mixed = _first_block(body, "mixed_instances_policy")
    if not mixed:
        return {}
    dist = _first_block(mixed, "instances_distribution")
    props: dict = {
        "MixedInstancesPolicy": {
            "InstancesDistribution": {
                "SpotMaxPrice": _ref(dist, "spot_max_price"),
                "SpotAllocationStrategy": _ref(dist, "spot_allocation_strategy"),
            }
        }
    }
    # Override instance types, apart from the policy so an unknown one hides only CF-GEN-001.
    types = [
        _v(item, "instance_type")
        for template in _blocks(mixed, "launch_template")
        for item in _blocks(template, "override")
    ]
    if types:
        props["OverrideInstanceTypes"] = types
    return props


def _scalable_target(body: dict) -> dict:
    """aws_appautoscaling_target: which service and resource it scales (CF-DDB-003)."""
    return {
        "ServiceNamespace": _known(_v(body, "service_namespace")),
        "ResourceId": _known(_ref(body, "resource_id")),
        "ScalableDimension": _known(_v(body, "scalable_dimension")),
    }


def _launch_configuration(body: dict) -> dict:
    props: dict = {}
    _set(props, "InstanceType", _v(body, "instance_type"))
    return props


def _elasticache_cluster(body: dict) -> dict:
    props: dict = {}
    _set(props, "CacheNodeType", _v(body, "node_type"))
    return props


def _ecs_service(body: dict) -> dict:
    props: dict = {}
    _set(props, "LaunchType", _v(body, "launch_type"))
    strategy = [
        {"CapacityProvider": _v(item, "capacity_provider")}
        for item in _blocks(body, "capacity_provider_strategy")
    ]
    if strategy:
        props["CapacityProviderStrategy"] = strategy
    return props


def _eks(body: dict) -> dict:
    props: dict = {}
    types = _v(body, "enabled_cluster_log_types")
    if types is UNRESOLVED:
        props["Logging"] = UNRESOLVED
    else:
        logs = [{"Type": t, "Enabled": True} for t in types] if isinstance(types, list) else []
        props["Logging"] = {"ClusterLogging": logs}
    dynamic = _dynamic_names(body)
    vpc = _first_block(body, "vpc_config")
    if "vpc_config" in dynamic:
        props["ResourcesVpcConfig"] = UNRESOLVED
    else:
        vpc_props: dict = {}
        _set(vpc_props, "EndpointPublicAccess", _v(vpc, "endpoint_public_access"))
        _set(vpc_props, "EndpointPrivateAccess", _v(vpc, "endpoint_private_access"))
        _set(vpc_props, "PublicAccessCidrs", _v(vpc, "public_access_cidrs"))
        props["ResourcesVpcConfig"] = vpc_props
    if "encryption_config" in dynamic:
        props["EncryptionConfig"] = UNRESOLVED
    else:
        configs = []
        for item in _blocks(body, "encryption_config"):
            provider = _first_block(item, "provider")
            configs.append({
                "Provider": {"KeyArn": _ref(provider, "key_arn")},
                "Resources": _v(item, "resources"),
            })
        if configs:
            props["EncryptionConfig"] = configs
    version = _v(body, "version")
    # Unknown version is not UNRESOLVED: it only chooses the severity, not whether to report.
    props["Version"] = _Expr("<unresolved>") if version is UNRESOLVED else version
    if props["Version"] is None:
        del props["Version"]
    return props


_ADAPTERS: dict[str, Callable[[dict], dict]] = {
    "aws_s3_bucket": _s3_bucket,
    "aws_db_instance": _db,
    "aws_rds_cluster": _db,
    "aws_instance": _instance,
    "aws_subnet": _subnet,
    "aws_launch_template": _launch_template,
    "aws_security_group": _security_group,
    "aws_lb": _lb,
    "aws_alb": _lb,
    "aws_cloudtrail": _cloudtrail,
    "aws_kms_key": _kms_key,
    "aws_lambda_function": _lambda,
    "aws_dynamodb_table": _dynamodb,
    "aws_appautoscaling_target": _scalable_target,
    "aws_cloudwatch_log_group": _log_group,
    "aws_sqs_queue": _sqs,
    "aws_api_gateway_stage": _api_stage,
    "aws_apigatewayv2_stage": _apiv2_stage,
    "aws_autoscaling_group": _asg,
    "aws_ecs_service": _ecs_service,
    "aws_eks_cluster": _eks,
    "aws_iam_policy": _iam_policy,
    "aws_iam_role_policy": _iam_policy,
    "aws_iam_user_policy": _iam_policy,
    "aws_iam_group_policy": _iam_policy,
    "aws_iam_role": _iam_role,
    "aws_sns_topic": _sns_topic,
    "aws_ebs_volume": _ebs_volume,
    "aws_eip": _eip,
    "aws_nat_gateway": _nat_gateway,
    "aws_vpc_endpoint": _vpc_endpoint,
    "aws_efs_file_system": _efs_file_system,
    "aws_kinesis_stream": _kinesis_stream,
    "aws_elasticache_replication_group": _elasticache_replication_group,
    "aws_opensearch_domain": _opensearch_domain,
    "aws_elasticache_cluster": _elasticache_cluster,
    "aws_launch_configuration": _launch_configuration,
    "aws_redshift_cluster": _redshift_cluster,
    "aws_docdb_cluster": _storage_encrypted_cluster,
    "aws_neptune_cluster": _storage_encrypted_cluster,
    "aws_msk_cluster": _msk_cluster,
    "aws_cloudfront_distribution": _cloudfront_distribution,
    "aws_wafv2_web_acl_association": _waf_association,
    "aws_wafregional_web_acl_association": _waf_association,
    "aws_sqs_queue_policy": _resource_policy,
    "aws_sns_topic_policy": _resource_policy,
    "aws_s3_bucket_policy": _resource_policy,
    "aws_ecr_repository_policy": _resource_policy,
    "aws_ecr_repository": _ecr_repository,
    "aws_ecs_task_definition": _ecs_task_definition,
    "aws_lambda_provisioned_concurrency_config": _provisioned_concurrency,
    "aws_secretsmanager_secret": _secretsmanager_secret,
    "aws_secretsmanager_secret_rotation": _secret_rotation,
    "aws_cognito_user_pool": _cognito_user_pool,
    "aws_lambda_permission": _lambda_permission,
    "aws_iam_role_policy_attachment": _policy_attachment,
    "aws_iam_user_policy_attachment": _policy_attachment,
    "aws_iam_group_policy_attachment": _policy_attachment,
    "aws_iam_policy_attachment": _policy_attachment,
    "aws_iam_role_policy_attachments_exclusive": _policy_attachment,
    "aws_iam_user_policy_attachments_exclusive": _policy_attachment,
    "aws_iam_group_policy_attachments_exclusive": _policy_attachment,
}


# Nested block name -> CloudFormation property it feeds. A `dynamic` block of that name
# is built from input the scan cannot see.
_BLOCK_PROPERTY: dict[str, str] = {
    "lifecycle_rule": "LifecycleConfiguration",
    "password_policy": "Policies",
    "user_pool_add_ons": "UserPoolAddOns",
    "image_scanning_configuration": "ImageScanningConfiguration",
    "runtime_platform": "RuntimePlatform",
    "versioning": "VersioningConfiguration",
    "server_side_encryption_configuration": "BucketEncryption",
    "logging": "LoggingConfiguration",
    "instance_market_options": "LaunchTemplateData",
    # Not LaunchTemplateData: an unknown metadata block must not hide the Spot check.
    "metadata_options": "MetadataOptions",
    "ingress": "SecurityGroupIngress",
    "access_logs": "LoadBalancerAttributes",
    "dead_letter_config": "DeadLetterConfig",
    "tracing_config": "TracingConfig",
    "point_in_time_recovery": "PointInTimeRecoverySpecification",
    "server_side_encryption": "SSESpecification",
    "mixed_instances_policy": "MixedInstancesPolicy",
    "capacity_provider_strategy": "CapacityProviderStrategy",
    "inline_policy": "Policies",
    "block_device_mappings": "BlockDeviceMappings",
    "encrypt_at_rest": "EncryptionAtRestOptions",
    "node_to_node_encryption": "NodeToNodeEncryptionOptions",
    "encryption_info": "EncryptionInfo",
    "default_cache_behavior": "DistributionConfig",
    "ordered_cache_behavior": "DistributionConfig",
    "viewer_certificate": "DistributionConfig",
    "origin": "DistributionConfig",
    "network_interfaces": "NetworkInterfaces",
}


# --- IAM policy documents -----------------------------------------------------


def _mark_unknown(value: Any) -> Any:
    """Replace UNRESOLVED leaves so a partly known document keeps its known fields."""
    if value is UNRESOLVED:
        return _Expr(UNKNOWN)
    if isinstance(value, list):
        return [_mark_unknown(v) for v in value]
    if isinstance(value, dict):
        return {k: _mark_unknown(v) for k, v in value.items()}
    return value


def decode_jsonencode(expr: str) -> Any:
    """Decode the HCL object inside `jsonencode(...)` into JSON-shaped data.

    Known literals keep their value; references and var/local become non-literal
    leaves. Text python-hcl2 cannot parse returns UNRESOLVED.
    """
    match = _JSONENCODE.fullmatch(expr)
    if not match:
        return UNRESOLVED
    import hcl2  # deferred: only Terraform scans need the parser

    try:
        doc = hcl2.loads(f"__v = {match.group(1)}\n")
    except Exception:  # noqa: BLE001 - any parser error means "cannot read"
        return UNRESOLVED
    if not isinstance(doc, dict) or "__v" not in doc:
        return UNRESOLVED
    return _mark_unknown(_hcl_value(doc["__v"]))


def _policy_document_block(body: dict) -> dict:
    """data "aws_iam_policy_document" -> a policy document. `dynamic` statements and
    source/override documents are not read; their statements are simply absent."""
    statements = []
    for stmt in _blocks(body, "statement"):
        out: dict = {"Effect": stmt.get("effect", "Allow")}
        for tf_key, cf_key in (
            ("actions", "Action"), ("not_actions", "NotAction"),
            ("resources", "Resource"), ("not_resources", "NotResource"),
        ):
            if tf_key in stmt:
                out[cf_key] = stmt[tf_key]
        for tf_key, cf_key in (("principals", "Principal"), ("not_principals", "NotPrincipal")):
            blocks = _blocks(stmt, tf_key)
            if blocks:
                out[cf_key] = {b.get("type"): b.get("identifiers") for b in blocks}
        conditions: dict = {}
        for cond in _blocks(stmt, "condition"):
            conditions.setdefault(cond.get("test"), {})[cond.get("variable")] = cond.get("values")
        if conditions:
            out["Condition"] = conditions
        statements.append(out)
    doc: dict = _mark_unknown({"Version": "2012-10-17", "Statement": statements})
    return doc


def resolve_policy_document(value: Any, data_docs: dict[str, dict]) -> dict | None:
    """A policy argument -> document dict, or None when it cannot be read."""
    if isinstance(value, _JsonEncode):
        decoded = decode_jsonencode(value)
        return decoded if isinstance(decoded, dict) else None
    if isinstance(value, _Expr):
        ref = _POLICY_DOC_REF.fullmatch(value.strip())
        if ref:
            return data_docs.get(ref.group(1))
        heredoc = _HEREDOC.fullmatch(value)  # heredoc with ${...} interpolation
        if heredoc and not _UNRESOLVED_REF.search(value):
            value = heredoc.group(2)
        else:
            return None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        heredoc = _HEREDOC.fullmatch(value)
        text = heredoc.group(2) if heredoc else value
        try:
            doc = json.loads(text)
        except ValueError:
            return None
        return doc if isinstance(doc, dict) else None
    return None


def _managed_policy_arn(body: dict) -> str | None:
    """ARN a `data "aws_iam_policy"` looks up, when its arn or AWS managed name is literal."""
    arn, name = body.get("arn"), body.get("name")
    if type(arn) is str:
        return arn
    if type(name) is str and body.get("path_prefix") in (None, "/"):
        return f"arn:aws:iam::aws:policy/{name}"  # a name lookup is read as the AWS managed policy
    return None


def _resolve_managed_arn(value: Any, managed_arns: dict[str, str | None]) -> Any:
    """`data.aws_iam_policy.<name>.arn` -> the ARN it looks up, else the value unchanged."""
    if isinstance(value, _Expr):
        ref = _MANAGED_POLICY_REF.fullmatch(value.strip())
        if ref and managed_arns.get(ref.group(1)):
            return managed_arns[ref.group(1)]
    return value


def _resolve_iam(resources: dict[str, Resource], blocks: list[_Block]) -> None:
    """Turn raw policy arguments on IAM resources and S3 bucket policies into documents."""
    data_docs = {
        b.name: _policy_document_block(b.body)
        for b in blocks if b.data and b.type == "aws_iam_policy_document"
    }
    managed_arns = {
        b.name: _managed_policy_arn(b.body)
        for b in blocks if b.data and b.type == "aws_iam_policy"
    }
    for res in resources.values():
        arns = res.properties.get("ManagedPolicyArns")
        if isinstance(arns, list):
            res.properties["ManagedPolicyArns"] = [_resolve_managed_arn(a, managed_arns) for a in arns]
        if res.type == "s3_bucket" and "BucketPolicy" in res.properties:
            doc = resolve_policy_document(res.properties["BucketPolicy"], data_docs)
            if doc is None:  # unreadable: the bucket's policy is unknown, not absent
                res.properties.pop("BucketPolicy")
                res.unresolved = res.unresolved | {"BucketPolicy"}
            else:
                res.properties["BucketPolicy"] = doc
        if res.type == "kms_key" and isinstance(res.properties.get("KeyPolicy"), str):
            doc = resolve_policy_document(res.properties["KeyPolicy"], data_docs)
            if doc is None:  # unreadable: the key policy is unknown, not absent
                res.properties.pop("KeyPolicy")
                res.unresolved = res.unresolved | {"KeyPolicy"}
            else:
                res.properties["KeyPolicy"] = doc
        if res.type not in ("iam_policy", "iam_role", "resource_policy"):
            continue
        if "AssumeRolePolicyDocument" in res.properties:
            trust = resolve_policy_document(res.properties["AssumeRolePolicyDocument"], data_docs)
            if trust is None:  # unreadable: report nothing rather than guess
                res.properties.pop("AssumeRolePolicyDocument")
            else:
                res.properties["AssumeRolePolicyDocument"] = trust
        if "PolicyDocument" in res.properties:
            doc = resolve_policy_document(res.properties["PolicyDocument"], data_docs)
            if doc is None:
                res.properties.pop("PolicyDocument")
            else:
                res.properties["PolicyDocument"] = doc
        for item in res.properties.get("Policies") or []:
            if isinstance(item, dict):
                item["PolicyDocument"] = resolve_policy_document(item.get("PolicyDocument"), data_docs)


def _split_unresolved(props: dict) -> tuple[dict, frozenset[str]]:
    """Drop properties that depend on var/local and name them."""
    unresolved = frozenset(k for k, v in props.items() if _contains_unresolved(v))
    return {k: v for k, v in props.items() if k not in unresolved}, unresolved


def _resource_tags(block: _Block) -> Any:
    """`tags` (and aws_autoscaling_group `tag` blocks) as a map; UNRESOLVED when unreadable.

    A value from var/local keeps its key (the tag is set) with an unknown value. A whole
    map from an expression (var.tags, merge(...)) or a dynamic tag block is unreadable.
    """
    if {"tag", "tags"} & _dynamic_names(block.body):
        return UNRESOLVED
    raw = block.body.get("tags")
    if raw is not None and not isinstance(raw, dict):
        return UNRESOLVED
    tags = _tag_values(raw or {}) or {}
    for item in _blocks(block.body, "tag"):
        key = item.get("key")
        if type(key) is not str:
            return UNRESOLVED
        value = item.get("value")
        tags[key] = value if type(value) is str else UNKNOWN_TAG
    return tags


def _to_resource(block: _Block) -> Resource:
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
    if block.type in TF_TAGGABLE:
        props["Tags"] = _resource_tags(block)
    for name in _dynamic_names(block.body):
        cf_key = _BLOCK_PROPERTY.get(name)
        if cf_key is not None and canonical is not None:
            props[cf_key] = UNRESOLVED
        if name == "access_log_settings" and canonical is not None:
            key = "AccessLogSettings" if block.type == "aws_apigatewayv2_stage" else "AccessLogSetting"
            props[key] = UNRESOLVED
    clean, unresolved = _split_unresolved(props)
    return Resource(
        type=canonical,
        name=block.address,
        properties=clean,
        file=str(block.file),
        line=block.line,
        source_type=block.type,
        unresolved=unresolved,
        policies=_lifecycle_policies(block.body),
        references=block.references,
    )


def _lifecycle_policies(body: dict) -> dict:
    """lifecycle.prevent_destroy as CloudFormation policies: true blocks destroy and replace."""
    lifecycle = _first_block(body, "lifecycle")
    if "prevent_destroy" not in lifecycle:
        return {}
    keep = _v(lifecycle, "prevent_destroy")
    if keep is True:
        value: Any = "Retain"
    elif keep is False:
        value = "Delete"
    else:
        value = UNRESOLVED
    return {"DeletionPolicy": value, "UpdateReplacePolicy": value}


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
        value = UNRESOLVED if _dynamic_names(block.body) else _s3_part(block.type, block.body)
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


def _merge_ecr_lifecycle(blocks: list[_Block], resources: dict[str, Resource]) -> None:
    """Attach aws_ecr_lifecycle_policy to its aws_ecr_repository as LifecyclePolicy.

    A policy that names no repository the scan can find may belong to any of them, so
    none is reported for a missing lifecycle policy.
    """
    repos = {
        r.name.split(".", 1)[1]: r for r in resources.values() if r.source_type == "aws_ecr_repository"
    }
    by_literal = {
        b.body.get("name"): repos[b.name]
        for b in blocks
        if b.type == "aws_ecr_repository" and isinstance(b.body.get("name"), str)
        and not isinstance(b.body.get("name"), _Expr) and b.name in repos
    }
    unlinked = False
    for block in blocks:
        if block.type != "aws_ecr_lifecycle_policy":
            continue
        ref = block.body.get("repository")
        target = None
        if isinstance(ref, str):
            match = _ECR_REF.search(ref)
            target = repos.get(match.group(1)) if match else by_literal.get(ref)
        if target is None:
            unlinked = True
            continue
        target.properties["LifecyclePolicy"] = {"LifecyclePolicyText": block.body.get("policy")}
        target.unresolved = target.unresolved - {"LifecyclePolicy"}
    if unlinked:
        for repo in repos.values():
            if "LifecyclePolicy" not in repo.properties:
                repo.unresolved = repo.unresolved | {"LifecyclePolicy"}


# --- terraform show -json ------------------------------------------------------


def load_plan_values(path: Path) -> dict[str, dict]:
    """Root-module resource values from `terraform show -json`, keyed by address.

    Reads a plan (`planned_values`) or a state (`values`). Data sources and indexed
    instances (count / for_each) are left out: here one block is one Resource.
    Child modules are left out, as they are when parsing HCL.
    """
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise TerraformError(f"Failed to read Terraform plan {path}: {exc}") from exc
    section = None
    if isinstance(doc, dict):
        section = doc.get("planned_values") or doc.get("values")
    root = section.get("root_module") if isinstance(section, dict) else None
    if not isinstance(root, dict):
        raise TerraformError(f"Terraform plan {path} has no planned_values.root_module")
    out: dict[str, dict] = {}
    for item in root.get("resources") or []:
        if not isinstance(item, dict) or item.get("mode", "managed") != "managed":
            continue
        if "index" in item:
            continue
        address, values = item.get("address"), item.get("values")
        if isinstance(address, str) and isinstance(values, dict):
            out[address] = values
    return out


def _needs_plan(value: Any) -> bool:
    return isinstance(value, _Expr) or _contains_unresolved(value)


def _is_block_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, dict) for v in value)


def _fill_from_plan(body: dict, planned: dict, keep: frozenset[str] = frozenset()) -> dict:
    """Replace unresolved arguments of a block body with known planned values.

    Only arguments the block sets are filled: provider defaults stay with the adapters.
    An unknown value is absent from the plan, so it stays unresolved. A `dynamic` block
    the plan expanded becomes a plain block. Several blocks of one name are not paired
    by position (set-typed blocks such as ingress are not in config order in the plan):
    if any of them is unresolved, the planned list replaces them all.
    """
    out = dict(body)
    expanded: set[str] = set()
    for name in _dynamic_names(body):
        if _is_block_list(planned.get(name)):
            out[name] = planned[name]
            expanded.add(name)
    if expanded:
        remaining = [
            {k: v for k, v in item.items() if k not in expanded}
            for item in _blocks(body, "dynamic")
        ]
        remaining = [item for item in remaining if item]
        if remaining:
            out["dynamic"] = remaining
        else:
            out.pop("dynamic", None)
    for key, value in body.items():
        if key == "dynamic" or key in keep or key in expanded or key not in planned:
            continue
        plan_value = planned[key]
        single = _is_block_list(value) and len(value) == 1
        if single and _is_block_list(plan_value) and len(plan_value) == 1:
            out[key] = [_fill_from_plan(value[0], plan_value[0])]
        elif isinstance(value, dict) and isinstance(plan_value, dict):
            out[key] = _fill_from_plan(value, plan_value)
        elif _needs_plan(value):
            out[key] = plan_value
    return out


def _plan_keep(block: _Block) -> frozenset[str]:
    """Arguments the plan must not replace. A split S3 resource links to its bucket
    through `aws_s3_bucket.<name>` in `bucket`; the planned bucket name would lose that.
    A `bucket` set from var/local is filled, and then links by the planned name."""
    ref = block.body.get("bucket")
    if block.type in _S3_PARTS and isinstance(ref, str) and _BUCKET_REF.search(ref):
        return frozenset({"bucket"})
    repo = block.body.get("repository")
    if block.type == "aws_ecr_lifecycle_policy" and isinstance(repo, str) and _ECR_REF.search(repo):
        return frozenset({"repository"})
    return frozenset()


def resources_from_terraform(
    module_dir: Path,
    warnings: list[str] | None = None,
    plan_values: dict[str, dict] | None = None,
) -> list[Resource]:
    """Parse one root module directory (non-recursive) into Resource records.

    plan_values (from load_plan_values) fills arguments that depend on var/local or
    other expressions, for blocks whose address is in the plan.
    """
    if warnings is None:
        warnings = []
    blocks: list[_Block] = []
    default_tags: dict[str, dict[str, Any] | None] = {}
    for path in _module_files(module_dir):
        try:
            file_blocks, _sources = parse_tf_file(path)
            default_tags.update(parse_tf_default_tags(path))
        except (TerraformError, OSError, UnicodeError) as exc:
            warnings.append(str(exc))
            continue
        blocks.extend(file_blocks)
    if plan_values:
        for block in blocks:
            planned = plan_values.get(block.address)
            if planned is not None:
                block.body = _fill_from_plan(block.body, planned, _plan_keep(block))
    resources: dict[str, Resource] = {}
    for block in blocks:
        if block.data:
            continue
        resource = _to_resource(block)
        resource.inherited_tags = _inherited_tags(block, default_tags)
        planned_tags = (plan_values or {}).get(block.address, {}).get("tags_all")
        if block.type in TF_TAGGABLE and isinstance(planned_tags, dict):
            # The plan's tags_all is the resource's tags merged with default_tags: use it whole.
            resource.properties["Tags"] = _tag_values(planned_tags) or {}
            resource.unresolved = resource.unresolved - {"Tags"}
            resource.inherited_tags = {}
        resources[resource.name] = resource
    _merge_s3_parts(blocks, resources)
    _merge_ecr_lifecycle(blocks, resources)
    _resolve_iam(resources, blocks)
    return list(resources.values())


def _inherited_tags(block: _Block, default_tags: dict[str, dict[str, Any] | None]) -> dict[str, Any] | None:
    """The provider default_tags that apply to a block. A provider set from an expression
    other than aws.<alias>, or an alias with no provider block, gives None (unknown)."""
    provider = block.body.get("provider")
    if provider is None:
        return default_tags.get("", {})
    match = _PROVIDER_ALIAS.match(str(provider))
    if match is None:
        return None
    return default_tags.get(match.group(1))


def find_modules(files: list[Path]) -> tuple[list[Path], list[Path]]:
    """Return (root modules, local child modules) among dirs holding *.tf / *.tf.json.

    A child is a directory another module uses as a local `source` (./ or ../).
    """
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
                continue  # reported when the module itself is scanned
            children.update((module_dir / source).resolve() for source in sources)
    return [d for d in dirs if d not in children], [d for d in dirs if d in children]


def find_root_modules(files: list[Path]) -> list[Path]:
    """Directories holding *.tf / *.tf.json, minus those used as local child modules."""
    return find_modules(files)[0]
