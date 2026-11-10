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

from aws_arch_agent.rules.resource_model import TF_MODULE_CALL, Resource
from aws_arch_agent.rules.secret_names import is_literal_secret
from aws_arch_agent.rules.tag_policy import TF_TAGGABLE
from aws_arch_agent.rules.tag_policy import UNKNOWN as UNKNOWN_TAG

TF_TYPE_TO_CANONICAL: dict[str, str] = {
    "aws_s3_bucket": "s3_bucket",
    "aws_db_instance": "db_instance",
    "aws_rds_cluster": "rds_cluster",
    "aws_rds_cluster_instance": "db_instance",
    "aws_db_parameter_group": "db_parameter_group",
    "aws_rds_cluster_parameter_group": "rds_cluster_parameter_group",
    "aws_instance": "instance",
    "aws_launch_template": "launch_template",
    "aws_security_group": "security_group",
    "aws_vpc_security_group_ingress_rule": "security_group_ingress_rule",
    "aws_vpc_security_group_egress_rule": "security_group_egress_rule",
    # type = "egress" maps to security_group_egress_rule in _to_resource.
    "aws_security_group_rule": "security_group_ingress_rule",
    "aws_network_acl": "network_acl",
    "aws_network_acl_rule": "network_acl_entry",
    "aws_ec2_transit_gateway": "transit_gateway",
    "aws_route": "route",
    "aws_route_table": "route_table",
    "aws_route_table_association": "route_table_association",
    "aws_vpc": "vpc",
    "aws_subnet": "subnet",
    "aws_vpc_endpoint": "vpc_endpoint",
    "aws_flow_log": "flow_log",
    "aws_nat_gateway": "nat_gateway",
    "aws_eip": "eip",
    "aws_lb": "lb",
    "aws_alb": "lb",
    "aws_lb_listener": "lb_listener",
    "aws_alb_listener": "lb_listener",
    "aws_lb_target_group": "lb_target_group",
    "aws_alb_target_group": "lb_target_group",
    "aws_elb": "elb",
    "aws_cloudtrail": "cloudtrail",
    "aws_kms_key": "kms_key",
    "aws_ssm_parameter": "ssm_parameter",
    "aws_ssm_patch_baseline": "ssm_patch_baseline",
    "aws_ssm_association": "ssm_association",
    "aws_ssm_maintenance_window_task": "ssm_maintenance_window_task",
    "aws_ssmincidents_response_plan": "ssm_incidents_response_plan",
    "aws_ssmcontacts_contact": "ssm_contacts_contact",
    "aws_ssmcontacts_plan": "ssm_contacts_plan",
    "aws_lambda_function": "lambda_function",
    "aws_dynamodb_table": "dynamodb_table",
    "aws_cloudwatch_log_group": "cloudwatch_log_group",
    "aws_sqs_queue": "sqs_queue",
    "aws_sns_topic": "sns_topic",
    "aws_ebs_volume": "ebs_volume",
    "aws_efs_file_system": "efs_file_system",
    "aws_efs_access_point": "efs_access_point",
    "aws_efs_backup_policy": "efs_backup_policy",
    "aws_kinesis_stream": "kinesis_stream",
    "aws_kinesis_stream_consumer": "kinesis_stream_consumer",
    "aws_kinesisanalyticsv2_application": "kinesis_analytics_application",
    "aws_kinesis_firehose_delivery_stream": "firehose_delivery_stream",
    "aws_athena_workgroup": "athena_workgroup",
    "aws_glue_job": "glue_job",
    "aws_glue_security_configuration": "glue_security_configuration",
    "aws_emr_cluster": "emr_cluster",
    "aws_emr_security_configuration": "emr_security_configuration",
    "aws_dms_replication_instance": "dms_replication_instance",
    "aws_dms_endpoint": "dms_endpoint",
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
    "aws_codebuild_project": "codebuild_project",
    "aws_codepipeline": "codepipeline",
    "aws_codestarnotifications_notification_rule": "codestar_notification_rule",
    "aws_cloudwatch_event_rule": "events_rule",
    "aws_cloudwatch_event_target": "events_target",
    "aws_cloudwatch_event_permission": "event_bus_policy",
    "aws_sfn_state_machine": "sfn_state_machine",
    "aws_backup_vault": "backup_vault",
    "aws_backup_vault_lock_configuration": "backup_vault_lock",
    "aws_backup_plan": "backup_plan",
    "aws_backup_selection": "backup_selection",
    "aws_fsx_lustre_file_system": "fsx_file_system",
    "aws_fsx_windows_file_system": "fsx_file_system",
    "aws_fsx_ontap_file_system": "fsx_file_system",
    "aws_fsx_openzfs_file_system": "fsx_file_system",
    "aws_fsx_data_repository_association": "fsx_data_repository_association",
    "aws_sagemaker_notebook_instance": "sagemaker_notebook_instance",
    "aws_sagemaker_endpoint_configuration": "sagemaker_endpoint_config",
    "aws_route53_zone": "route53_hosted_zone",
    "aws_route53_record": "route53_record_set",
    "aws_route53_hosted_zone_dnssec": "route53_dnssec",
    "aws_route53_key_signing_key": "route53_key_signing_key",
    "aws_route53_query_log": "route53_query_log",
    "aws_acm_certificate": "acm_certificate",
    "aws_cloudwatch_metric_alarm": "cloudwatch_alarm",
    "aws_cloudwatch_composite_alarm": "cloudwatch_composite_alarm",
    "aws_cloudwatch_dashboard": "cloudwatch_dashboard",
    "aws_guardduty_detector": "guardduty_detector",
    "aws_guardduty_detector_feature": "guardduty_detector_feature",
    "aws_securityhub_account": "securityhub_hub",
    "aws_securityhub_standards_subscription": "securityhub_standard",
    "aws_securityhub_configuration_policy": "securityhub_configuration_policy",
    "aws_config_configuration_recorder": "config_configuration_recorder",
    "aws_macie2_account": "macie_session",
    "aws_budgets_budget": "budgets_budget",
    "aws_budgets_budget_action": "budgets_action",
    "aws_globalaccelerator_endpoint_group": "globalaccelerator_endpoint_group",
    "aws_appsync_graphql_api": "appsync_graphql_api",
    "aws_appsync_api_cache": "appsync_api_cache",
    "aws_transfer_server": "transfer_server",
    "aws_apprunner_service": "apprunner_service",
    "aws_elastic_beanstalk_environment": "elastic_beanstalk_environment",
    "aws_elastic_beanstalk_configuration_template": "elastic_beanstalk_configuration_template",
    "aws_api_gateway_method": "api_gateway_method",
    "aws_api_gateway_domain_name": "api_gateway_domain_name",
    "aws_api_gateway_usage_plan": "api_gateway_usage_plan",
    "aws_apigatewayv2_domain_name": "apigatewayv2_domain_name",
    "aws_apigatewayv2_route": "apigatewayv2_route",
    "aws_autoscaling_group": "autoscaling_group",
    "aws_launch_configuration": "launch_configuration",
    "aws_autoscaling_policy": "autoscaling_policy",
    "aws_autoscaling_schedule": "autoscaling_schedule",
    "aws_autoscaling_attachment": "autoscaling_attachment",
    "aws_appautoscaling_target": "scalable_target",
    "aws_ecs_cluster": "ecs_cluster",
    "aws_ecs_service": "ecs_service",
    "aws_eks_cluster": "eks_cluster",
    "aws_cloudfront_distribution": "cloudfront_distribution",
    "aws_cloudwatch_log_delivery_source": "cloudwatch_log_delivery_source",
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
    "aws_cloudwatch_event_bus_policy": "resource_policy",
    "aws_sns_topic_policy": "resource_policy",
    "aws_s3_bucket_policy": "resource_policy",
    "aws_ecr_repository_policy": "resource_policy",
    "aws_ecr_repository": "ecr_repository",
    "aws_ecs_task_definition": "ecs_task_definition",
    "aws_secretsmanager_secret": "secretsmanager_secret",
    "aws_secretsmanager_secret_rotation": "secretsmanager_secret_rotation",
    "aws_cognito_user_pool": "cognito_user_pool",
    "aws_lambda_permission": "lambda_permission",
    "aws_lambda_function_url": "lambda_url",
    "aws_lambda_event_source_mapping": "lambda_event_source_mapping",
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
    "aws_s3_bucket_ownership_controls": "OwnershipControls",
    "aws_s3_bucket_acl": "AccessControl",
    "aws_s3_bucket_replication_configuration": "ReplicationConfiguration",
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


def _module_call_bodies(path: Path) -> list[tuple[str, dict]]:
    """The label and body of each `module` block in one file."""
    doc, _text, _is_json, normalize = _load_tf(path)
    calls: list[tuple[str, dict]] = []
    for module_map in _iter_type_maps(doc.get("module")):
        for raw_name, body in module_map.items():
            for item in _iter_type_maps(body):
                calls.append((_unquote_key(raw_name), normalize(item)))
    return calls


def _call_resource_types(source: Any, module_dir: Path, seen: set[Path]) -> set[str] | None:
    """The resource types a module call defines, its own calls included. None when any part is
    remote or cannot be read."""
    if type(source) is not str or not source.startswith(("./", "../")):
        return None
    child = (module_dir / source).resolve()
    if child in seen:
        return set()
    seen.add(child)
    if not child.is_dir():
        return None
    types: set[str] = set()
    try:
        for path in _module_files(child):
            types.update(block.type for block in parse_tf_file(path)[0] if not block.data)
            for _label, body in _module_call_bodies(path):
                nested = _call_resource_types(body.get("source"), child, seen)
                if nested is None:
                    return None
                types |= nested
    except (TerraformError, OSError, UnicodeError):
        return None
    return types


def _module_call_records(module_dir: Path) -> list[Resource]:
    """One record per `module` call, for checks that ask what a stack may define out of sight."""
    out: list[Resource] = []
    for path in _module_files(module_dir):
        try:
            calls = _module_call_bodies(path)
        except (TerraformError, OSError, UnicodeError):
            continue  # resources_from_terraform already warned about this file
        for label, body in calls:
            types = _call_resource_types(body.get("source"), module_dir, set())
            out.append(Resource(
                type=None, name=f"module.{label}", file=str(path), source_type=TF_MODULE_CALL,
                properties={} if types is None else {"ResourceTypes": sorted(types)},
                unresolved=frozenset({"ResourceTypes"}) if types is None else frozenset(),
                references=frozenset(_ADDRESS_REF.findall(json.dumps(body, default=str))),
            ))
    return out


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
    if type(body.get("bucket")) is str:
        props["BucketName"] = body["bucket"]
    _set(props, "AccessControl", _s3_acl(body))
    replication = _first_block(body, "replication_configuration")
    if replication:
        props["ReplicationConfiguration"] = _s3_replication(replication, "rules")
    return props


def _s3_encryption(body: dict) -> Any:
    configs = []
    for rule in _blocks(body, "rule"):
        default = _first_block(rule, "apply_server_side_encryption_by_default")
        config: dict = {"ServerSideEncryptionByDefault": {"SSEAlgorithm": _v(default, "sse_algorithm")}}
        if "bucket_key_enabled" in rule:  # an unknown value must not hide the algorithm from CF-S3-002
            config["BucketKeyEnabled"] = _known(_v(rule, "bucket_key_enabled"))
        configs.append(config)
    return {"ServerSideEncryptionConfiguration": configs}


# Terraform canned ACL -> CloudFormation AccessControl.
_S3_CANNED_ACLS: dict[str, str] = {
    "private": "Private",
    "public-read": "PublicRead",
    "public-read-write": "PublicReadWrite",
    "aws-exec-read": "AwsExecRead",
    "authenticated-read": "AuthenticatedRead",
    "bucket-owner-read": "BucketOwnerRead",
    "bucket-owner-full-control": "BucketOwnerFullControl",
    "log-delivery-write": "LogDeliveryWrite",
}


def _s3_acl(body: dict) -> Any:
    """The canned ACL as AccessControl. Grants are not read: the bucket's ACL is then unknown."""
    if {"grant", "access_control_policy"} & (body.keys() | _dynamic_names(body)):
        return UNRESOLVED
    acl = _v(body, "acl")
    if acl is None or acl is UNRESOLVED:
        return acl
    return _S3_CANNED_ACLS.get(acl, UNRESOLVED) if type(acl) is str else UNRESOLVED


def _s3_replication(body: dict, rule_key: str) -> Any:
    """Replication rules in CloudFormation shape. rule_key is `rule`, or `rules` on the inline
    block (provider < v4). A dynamic rule makes the whole configuration unknown. One unknown
    value is kept as _OPAQUE: the bucket still has replication, and its other rules can be read."""
    if rule_key in _dynamic_names(body):
        return UNRESOLVED
    rules = []
    for rule in _blocks(body, rule_key):
        destination = _first_block(rule, "destination")
        if not destination or "destination" in _dynamic_names(rule):
            rules.append({"Status": _known(_v(rule, "status")), "Destination": _OPAQUE})
            continue
        item: dict = {"Bucket": _known(_ref(destination, "bucket"))}
        for block, cf_key in (("metrics", "Metrics"), ("replication_time", "ReplicationTime")):
            if block in _dynamic_names(destination):
                item[cf_key] = _OPAQUE
            elif _first_block(destination, block):
                item[cf_key] = {"Status": _known(_v(_first_block(destination, block), "status"))}
        rules.append({"Status": _known(_v(rule, "status")), "Destination": item})
    return {"Rules": rules}


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
    if part_type == "aws_s3_bucket_ownership_controls":
        return {"Rules": [{"ObjectOwnership": _v(rule, "object_ownership")} for rule in _blocks(body, "rule")]}
    if part_type == "aws_s3_bucket_acl":
        return _s3_acl(body)
    if part_type == "aws_s3_bucket_replication_configuration":
        return _s3_replication(body, "rule")
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
    """aws_db_instance, aws_rds_cluster and aws_rds_cluster_instance (an Aurora member: it
    has cluster_identifier, like a CloudFormation DBInstance with DBClusterIdentifier)."""
    props: dict = {}
    for tf_key, cf_key in (
        ("storage_encrypted", "StorageEncrypted"),
        ("backup_retention_period", "BackupRetentionPeriod"),
        ("multi_az", "MultiAZ"),
        ("deletion_protection", "DeletionProtection"),
        ("publicly_accessible", "PubliclyAccessible"),
        ("instance_class", "DBInstanceClass"),
        ("db_cluster_instance_class", "DBClusterInstanceClass"),
        ("cluster_identifier", "DBClusterIdentifier"),
        ("engine_version", "EngineVersion"),
        ("monitoring_interval", "MonitoringInterval"),
        ("iam_database_authentication_enabled", "EnableIAMDatabaseAuthentication"),
        ("auto_minor_version_upgrade", "AutoMinorVersionUpgrade"),
        ("copy_tags_to_snapshot", "CopyTagsToSnapshot"),
        ("enabled_cloudwatch_logs_exports", "EnableCloudwatchLogsExports"),
        ("port", "Port"),
        ("username", "MasterUsername"),
        ("master_username", "MasterUsername"),
        ("snapshot_identifier", "SnapshotIdentifier"),
        ("replicate_source_db", "SourceDBInstanceIdentifier"),
        ("parameter_group_name", "DBParameterGroupName"),
        ("db_cluster_parameter_group_name", "DBClusterParameterGroupName"),
    ):
        _set(props, cf_key, body.get(tf_key))
    _set(props, "Engine", _v(body, "engine"))
    return props


def _db_parameter_group(body: dict) -> dict:
    """aws_db_parameter_group / aws_rds_cluster_parameter_group: name, family and the
    parameters as a CloudFormation Parameters map (CF-RDS-006)."""
    props: dict = {}
    _set(props, "Name", _v(body, "name"))
    _set(props, "Family", _v(body, "family"))
    if "parameter" in _dynamic_names(body):
        props["Parameters"] = UNRESOLVED
        return props
    params: dict = {}
    for item in _blocks(body, "parameter"):
        name, value = _v(item, "name"), _v(item, "value")
        if name is UNRESOLVED:
            props["Parameters"] = UNRESOLVED
            return props
        if isinstance(name, str):
            params[name] = _OPAQUE if value is UNRESOLVED else value
    props["Parameters"] = params
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
    _set(props, "AvailabilityZone", _v(body, "availability_zone"))
    _set(props, "AvailabilityZoneId", _v(body, "availability_zone_id"))
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
    _set(props, "AvailabilityZoneName", _ref(body, "availability_zone_name"))
    if "lifecycle_policy" in _dynamic_names(body):
        props["LifecyclePolicies"] = UNRESOLVED
    else:
        policies = [{"TransitionToIA": _ref(p, "transition_to_ia")} for p in _blocks(body, "lifecycle_policy")]
        if policies:
            props["LifecyclePolicies"] = policies
    return props


def _efs_backup_policy(body: dict) -> dict:
    """aws_efs_backup_policy: Terraform sets a file system's policy from a resource of its own."""
    if "backup_policy" in _dynamic_names(body):
        return {"BackupPolicy": UNRESOLVED}
    return {"BackupPolicy": {"Status": _ref(_first_block(body, "backup_policy"), "status")}}


def _efs_access_point(body: dict) -> dict:
    props: dict = {}
    names = _dynamic_names(body)
    root = _first_block(body, "root_directory")
    if "root_directory" in names:
        props["RootDirectory"] = UNRESOLVED
    elif root:
        props["RootDirectory"] = {"Path": _ref(root, "path")} if "path" in root else {}
    posix = _first_block(body, "posix_user")
    if "posix_user" in names:
        props["PosixUser"] = UNRESOLVED
    elif posix:
        props["PosixUser"] = {"Uid": _ref(posix, "uid"), "Gid": _ref(posix, "gid")}
    return props


def _kinesis_stream(body: dict) -> dict:
    """encryption_type defaults to NONE; KMS maps to StreamEncryption."""
    props: dict = {}
    encryption = _v(body, "encryption_type", "NONE")
    if encryption is UNRESOLVED:
        props["StreamEncryption"] = UNRESOLVED
    elif type(encryption) is str and encryption.upper() == "KMS":
        props["StreamEncryption"] = {"EncryptionType": "KMS", "KeyId": _ref(body, "kms_key_id")}
    _set(props, "RetentionPeriodHours", _v(body, "retention_period"))
    return props


def _opensearch_domain(body: dict) -> dict:
    props: dict = {}
    for block, key in (("encrypt_at_rest", "EncryptionAtRestOptions"),
                       ("node_to_node_encryption", "NodeToNodeEncryptionOptions")):
        found = _first_block(body, block)
        if found:
            props[key] = {"Enabled": _v(found, "enabled")}
    dynamic = _dynamic_names(body)
    cluster = _first_block(body, "cluster_config")
    if "cluster_config" in dynamic:
        props["ClusterConfig"] = UNRESOLVED
    elif cluster:
        config: dict = {}
        _set(config, "InstanceType", _v(cluster, "instance_type"))
        _set(config, "DedicatedMasterType", _v(cluster, "dedicated_master_type"))
        _set(config, "InstanceCount", _known(_v(cluster, "instance_count")))
        _set(config, "ZoneAwarenessEnabled", _known(_v(cluster, "zone_awareness_enabled")))
        props["ClusterConfig"] = config
    if "vpc_options" in dynamic:
        props["VPCOptions"] = UNRESOLVED
    elif _first_block(body, "vpc_options"):
        props["VPCOptions"] = {"SubnetIds": _known(_ref(_first_block(body, "vpc_options"), "subnet_ids"))}
    security = _first_block(body, "advanced_security_options")
    if "advanced_security_options" in dynamic:
        props["AdvancedSecurityOptions"] = UNRESOLVED
    elif security:
        props["AdvancedSecurityOptions"] = {"Enabled": _v(security, "enabled")}
    endpoint = _first_block(body, "domain_endpoint_options")
    if "domain_endpoint_options" in dynamic:
        props["DomainEndpointOptions"] = UNRESOLVED
    elif endpoint:
        # In this block the provider defaults enforce_https to true.
        options: dict = {"EnforceHTTPS": _known(_v(endpoint, "enforce_https", True))}
        _set(options, "TLSSecurityPolicy", _known(_v(endpoint, "tls_security_policy")))
        props["DomainEndpointOptions"] = options
    if "log_publishing_options" in dynamic:
        props["LogPublishingOptions"] = UNRESOLVED
    else:
        logs: dict = {}
        for item in _blocks(body, "log_publishing_options"):
            log_type = _v(item, "log_type")
            if log_type is UNRESOLVED:
                logs = UNRESOLVED
                break
            logs[log_type] = {"Enabled": _known(_v(item, "enabled", True))}
        props["LogPublishingOptions"] = logs
    return props


def _redshift_cluster(body: dict) -> dict:
    props: dict = {}
    _set(props, "Encrypted", _v(body, "encrypted"))
    _set(props, "SnapshotIdentifier", _ref(body, "snapshot_identifier"))
    _set(props, "PubliclyAccessible", _v(body, "publicly_accessible"))
    _set(props, "AutomatedSnapshotRetentionPeriod", _v(body, "automated_snapshot_retention_period"))
    _set(props, "AllowVersionUpgrade", _v(body, "allow_version_upgrade"))
    _set(props, "EnhancedVpcRouting", _v(body, "enhanced_vpc_routing"))
    _set(props, "MasterUsername", _v(body, "master_username"))
    _set(props, "DBName", _v(body, "database_name", "dev"))  # Redshift's default database
    # Older providers log from this block; aws_redshift_logging is read by _warehouse_findings.
    logging = _first_block(body, "logging")
    if "logging" in _dynamic_names(body) or _v(logging, "enable") is UNRESOLVED:
        props["LoggingProperties"] = UNRESOLVED
    elif _v(logging, "enable") is True:
        props["LoggingProperties"] = {"Enabled": True}
    return props


def _storage_encrypted_cluster(body: dict) -> dict:
    """aws_docdb_cluster / aws_neptune_cluster."""
    props: dict = {}
    _set(props, "StorageEncrypted", _v(body, "storage_encrypted"))
    _set(props, "SnapshotIdentifier", _ref(body, "snapshot_identifier"))
    _set(props, "SourceDBClusterIdentifier", _ref(body, "replication_source_identifier"))
    _set(props, "BackupRetentionPeriod", _v(body, "backup_retention_period"))
    _set(props, "DeletionProtection", _v(body, "deletion_protection"))
    _set(props, "IamAuthEnabled", _v(body, "iam_database_authentication_enabled"))
    # DocumentDB spells it enabled_..., Neptune enable_...
    exports = "enabled_cloudwatch_logs_exports" if "enabled_cloudwatch_logs_exports" in body \
        else "enable_cloudwatch_logs_exports"
    _set(props, "EnableCloudwatchLogsExports", _v(body, exports))
    return props


def _msk_cluster(body: dict) -> dict:
    props = _msk_encryption(body)
    authentication = _first_block(body, "client_authentication")
    if "client_authentication" in _dynamic_names(body) or {"sasl", "tls"} & _dynamic_names(authentication):
        props["ClientAuthentication"] = UNRESOLVED
    elif authentication:
        sasl = _first_block(authentication, "sasl")
        props["ClientAuthentication"] = {
            "Unauthenticated": {"Enabled": _known(_v(authentication, "unauthenticated"))},
            "Sasl": {"Iam": {"Enabled": _known(_v(sasl, "iam"))}, "Scram": {"Enabled": _known(_v(sasl, "scram"))}},
            "Tls": {"Enabled": "tls" in authentication},
        }
    connectivity = _first_block(_first_block(body, "broker_node_group_info"), "connectivity_info")
    public = _v(_first_block(connectivity, "public_access"), "type")
    if public is not None:
        props["BrokerNodeGroupInfo"] = {"ConnectivityInfo": {"PublicAccess": {"Type": _known(public)}}}
    return props


def _msk_encryption(body: dict) -> dict:
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
    _set(props, "AutomaticFailoverEnabled", _v(body, "automatic_failover_enabled"))
    _set(props, "SnapshotRetentionLimit", _v(body, "snapshot_retention_limit"))
    _set(props, "AutoMinorVersionUpgrade", _v(body, "auto_minor_version_upgrade"))
    _set(props, "EngineVersion", _v(body, "engine_version"))
    _set(props, "CacheSubnetGroupName", _ref(body, "subnet_group_name"))
    if body.get("auth_token") is not None:
        props["AuthToken"] = _OPAQUE  # only checked for presence: keep the secret out of the model
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


def _sg_rules(body: dict, kind: str) -> Any:
    """Inline ingress or egress blocks as CloudFormation rule entries, or UNRESOLVED."""
    if kind in _dynamic_names(body):
        return UNRESOLVED
    rules: list = []
    for rule in _blocks(body, kind):
        entries = _ingress_entries(rule)
        if entries is UNRESOLVED:
            return UNRESOLVED
        rules.extend(entries)
    return rules


def _security_group(body: dict) -> dict:
    """Terraform removes the AWS default allow-all egress, so no egress block means none."""
    return {
        "SecurityGroupIngress": _sg_rules(body, "ingress"),
        "SecurityGroupEgress": _sg_rules(body, "egress"),
    }


def _sg_rule(rtype: str, body: dict) -> tuple[str, dict] | None:
    """aws_security_group_rule, aws_vpc_security_group_ingress_rule or _egress_rule as
    (canonical type, CloudFormation-shaped props)."""
    if rtype == "aws_security_group_rule":
        kind = _v(body, "type")
        if kind is UNRESOLVED:
            return "security_group_ingress_rule", {"CidrIp": UNRESOLVED}
        canonical = {"ingress": "security_group_ingress_rule",
                     "egress": "security_group_egress_rule"}.get(kind)
        if canonical is None:
            return None
        entries = _ingress_entries(body)
        if entries is UNRESOLVED:
            return canonical, {"CidrIp": UNRESOLVED}
        open_entry = next(
            (e for e in entries if e.get("CidrIp") == "0.0.0.0/0" or e.get("CidrIpv6") == "::/0"),
            entries[0] if entries else {},
        )
        return canonical, dict(open_entry)
    canonical = TF_TYPE_TO_CANONICAL[rtype]
    props: dict = {}
    _set(props, "CidrIp", _v(body, "cidr_ipv4"))
    _set(props, "CidrIpv6", _v(body, "cidr_ipv6"))
    ip_protocol = _v(body, "ip_protocol")
    if ip_protocol is UNRESOLVED:
        return canonical, {"CidrIp": UNRESOLVED}
    if ip_protocol in ("-1", -1):
        props["FromPort"] = props["ToPort"] = None
    else:
        props["FromPort"] = _v(body, "from_port")
        props["ToPort"] = _v(body, "to_port")
    return canonical, props


def _nacl_entry(body: dict, egress: Any) -> dict:
    """One aws_network_acl_rule, or an inline aws_network_acl ingress/egress block, in the
    AWS::EC2::NetworkAclEntry shape."""
    props: dict = {"Egress": egress}
    _set(props, "RuleAction", _v(body, "rule_action", _v(body, "action")))
    _set(props, "CidrBlock", _v(body, "cidr_block"))
    _set(props, "Ipv6CidrBlock", _v(body, "ipv6_cidr_block"))
    _set(props, "Protocol", _v(body, "protocol"))
    low, high = _v(body, "from_port"), _v(body, "to_port")
    if low is not None or high is not None:
        props["PortRange"] = UNRESOLVED if UNRESOLVED in (low, high) else {"From": low, "To": high}
    return props


def _network_acl_rule(body: dict) -> dict:
    return _nacl_entry(body, _v(body, "egress", False))


def _network_acl(body: dict) -> dict:
    """aws_network_acl: inline ingress blocks as Entries (CF-NACL-001)."""
    if "ingress" in _dynamic_names(body):
        return {"Entries": UNRESOLVED}
    return {"Entries": [_nacl_entry(rule, False) for rule in _blocks(body, "ingress")]}


def _transit_gateway(body: dict) -> dict:
    props: dict = {}
    _set(props, "AutoAcceptSharedAttachments", _v(body, "auto_accept_shared_attachments"))
    return props


def _flow_log(body: dict) -> dict:
    """aws_flow_log on a transit gateway, in the AWS::EC2::FlowLog shape (CF-TGW-002)."""
    tgw = _ref(body, "transit_gateway_id")
    if tgw is None:
        return {}
    return {"ResourceType": "TransitGateway", "ResourceId": tgw}


def _lb(body: dict) -> dict:
    props: dict = {}
    _set(props, "Type", _v(body, "load_balancer_type"))
    internal = _v(body, "internal")
    if internal is not None:
        props["Scheme"] = UNRESOLVED if internal is UNRESOLVED else (
            "internal" if internal is True else "internet-facing")
    logs = _first_block(body, "access_logs")
    attributes = []
    # Provider defaults: logs off (even with a bucket), headers kept, no deletion
    # protection, desync mode defensive.
    for key, value in (
        ("access_logs.s3.enabled", _v(logs, "enabled", False)),
        ("routing.http.drop_invalid_header_fields.enabled", _v(body, "drop_invalid_header_fields", False)),
        ("deletion_protection.enabled", _v(body, "enable_deletion_protection", False)),
        ("routing.http.desync_mitigation_mode", _v(body, "desync_mitigation_mode", "defensive")),
    ):
        if value is UNRESOLVED:
            value = _OPAQUE
        elif isinstance(value, bool):
            value = "true" if value else "false"
        attributes.append({"Key": key, "Value": value})
    props["LoadBalancerAttributes"] = attributes
    return props


def _lb_listener(body: dict) -> dict:
    """aws_lb_listener in the AWS::ElasticLoadBalancingV2::Listener shape: protocol, TLS
    policy and default actions (CF-ALB-002, CF-ALB-003)."""
    props: dict = {}
    _set(props, "Protocol", _v(body, "protocol"))
    _set(props, "SslPolicy", _v(body, "ssl_policy"))
    if "default_action" in _dynamic_names(body):
        props["DefaultActions"] = UNRESOLVED
        return props
    actions = []
    for action in _blocks(body, "default_action"):
        kind = _v(action, "type")
        item: dict = {"Type": _OPAQUE if kind is UNRESOLVED else kind}
        redirect = _first_block(action, "redirect")
        if redirect:
            protocol = _v(redirect, "protocol", "#{protocol}")
            item["RedirectConfig"] = {"Protocol": _OPAQUE if protocol is UNRESOLVED else protocol}
        actions.append(item)
    props["DefaultActions"] = actions
    return props


def _lb_target_group(body: dict) -> dict:
    """aws_lb_target_group: protocol, target type and health check (CF-ALB-007)."""
    props: dict = {}
    _set(props, "Protocol", _v(body, "protocol"))
    _set(props, "TargetType", _v(body, "target_type", "instance"))
    if "health_check" in _dynamic_names(body):
        props["HealthCheckEnabled"] = UNRESOLVED
        return props
    check = _first_block(body, "health_check")
    _set(props, "HealthCheckEnabled", _v(check, "enabled"))
    _set(props, "HealthCheckPath", _v(check, "path"))
    return props


def _elb(body: dict) -> dict:
    """aws_elb in the AWS::ElasticLoadBalancing::LoadBalancer shape (CF-CLB-001..005).
    Provider defaults: cross-zone on, connection draining off, access logs on when the
    block is present."""
    props: dict = {}
    if "listener" in _dynamic_names(body):
        props["Listeners"] = UNRESOLVED
    else:
        props["Listeners"] = [
            {"Protocol": _v(item, "lb_protocol"), "SSLCertificateId": _ref(item, "ssl_certificate_id")}
            for item in _blocks(body, "listener")
        ]
    if "access_logs" in _dynamic_names(body):
        props["AccessLoggingPolicy"] = UNRESOLVED
    elif _blocks(body, "access_logs"):
        props["AccessLoggingPolicy"] = {"Enabled": _v(_first_block(body, "access_logs"), "enabled", True)}
    props["CrossZone"] = _v(body, "cross_zone_load_balancing", True)
    props["ConnectionDrainingPolicy"] = {"Enabled": _v(body, "connection_draining", False)}
    return props


# Stands in for one value the scan cannot see, inside a structure whose other values are
# known. Shaped like an intrinsic, so the CloudFormation checks skip it.
_OPAQUE = {"Fn::Unresolved": "terraform"}


def _known(value: Any) -> Any:
    return _OPAQUE if value is UNRESOLVED else value


def _cloudfront_associations(block: dict, key: str) -> Any:
    """Function associations on a behavior, keeping only the event type."""
    if key in _dynamic_names(block):
        return _OPAQUE
    return [{"EventType": _known(_v(a, "event_type"))} for a in _blocks(block, key)]


def _cloudfront_behavior(block: dict) -> dict:
    item = {
        "ViewerProtocolPolicy": _known(_v(block, "viewer_protocol_policy")),
        "TargetOriginId": _known(_ref(block, "target_origin_id")),
    }
    for prop, value in (
        ("Compress", _v(block, "compress")),
        ("CachePolicyId", _v(block, "cache_policy_id")),
        ("RealtimeLogConfigArn", _ref(block, "realtime_log_config_arn")),
    ):
        if value is not None:
            item[prop] = _known(value)
    for prop, key in (("FunctionAssociations", "function_association"),
                      ("LambdaFunctionAssociations", "lambda_function_association")):
        associations = _cloudfront_associations(block, key)
        if associations:
            item[prop] = associations
    return item


def _cloudfront_origin_group(group: dict) -> dict:
    members: Any = {"Items": [{"OriginId": _known(_ref(m, "origin_id"))} for m in _blocks(group, "member")]}
    if "member" in _dynamic_names(group):
        members = _OPAQUE
    return {"Id": _known(_ref(group, "origin_id")), "Members": members}


def _cloudfront_distribution(body: dict) -> dict:
    """The arguments the CF-CF checks read, in DistributionConfig shape.

    An unknown value is kept as _OPAQUE, so it does not hide the other checks.
    """
    config: dict = {}
    default = _first_block(body, "default_cache_behavior")
    if default:
        config["DefaultCacheBehavior"] = _cloudfront_behavior(default)
    ordered = [
        {"PathPattern": _known(_v(b, "path_pattern")), **_cloudfront_behavior(b)}
        for b in _blocks(body, "ordered_cache_behavior")
    ]
    if ordered:
        config["CacheBehaviors"] = ordered
    cert = _first_block(body, "viewer_certificate")
    if cert:
        version = _v(cert, "minimum_protocol_version")
        support = _v(cert, "ssl_support_method")
        config["ViewerCertificate"] = {
            "CloudFrontDefaultCertificate": _known(_v(cert, "cloudfront_default_certificate")),
            **({} if version is None else {"MinimumProtocolVersion": _known(version)}),
            **({} if support is None else {"SslSupportMethod": _known(support)}),
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
        custom = _first_block(origin, "custom_origin_config")
        if "custom_origin_config" in _dynamic_names(origin):
            item["CustomOriginConfig"] = _OPAQUE
        elif custom:
            protocols = _v(custom, "origin_ssl_protocols")
            item["CustomOriginConfig"] = {
                "OriginProtocolPolicy": _known(_v(custom, "origin_protocol_policy")),
                # One unknown entry does not hide a literal SSLv3 next to it.
                "OriginSSLProtocols": ([_known(_v({"p": p}, "p")) for p in protocols]
                                       if isinstance(protocols, list) else _known(protocols)),
            }
        origins.append(item)
    if origins:
        config["Origins"] = origins
    if "origin_group" in _dynamic_names(body):
        config["OriginGroups"] = _OPAQUE
    else:
        groups = _blocks(body, "origin_group")
        if groups:
            config["OriginGroups"] = {"Items": [_cloudfront_origin_group(g) for g in groups]}
    root = _ref(body, "default_root_object")
    if root is not None:
        config["DefaultRootObject"] = _known(root)
    price = _v(body, "price_class")
    if price is not None:
        config["PriceClass"] = _known(price)
    web_acl = _ref(body, "web_acl_id")
    if web_acl is not None:
        config["WebACLId"] = _known(web_acl)
    if "logging_config" in _dynamic_names(body):
        config["Logging"] = {"Bucket": _OPAQUE}
    elif _first_block(body, "logging_config"):
        config["Logging"] = {"Bucket": _known(_ref(_first_block(body, "logging_config"), "bucket"))}
    return {"DistributionConfig": config}


def _sagemaker_notebook(body: dict) -> dict:
    props: dict = {}
    _set(props, "DirectInternetAccess", _v(body, "direct_internet_access"))
    _set(props, "RootAccess", _v(body, "root_access"))
    _set(props, "SubnetId", _ref(body, "subnet_id"))
    _set(props, "KmsKeyId", _ref(body, "kms_key_id"))
    return props


def _sagemaker_variants(body: dict, key: str) -> Any:
    """Variants of an endpoint config. An unknown value is kept as _OPAQUE, so one does not hide the others."""
    if key in _dynamic_names(body):
        return UNRESOLVED
    variants = []
    for block in _blocks(body, key):
        item: dict = {}
        _set(item, "VariantName", _known(_v(block, "variant_name")))
        _set(item, "InstanceType", _known(_v(block, "instance_type")))
        _set(item, "InitialInstanceCount", _known(_v(block, "initial_instance_count")))
        if "serverless_config" in _dynamic_names(block) or _first_block(block, "serverless_config"):
            item["ServerlessConfig"] = _OPAQUE
        variants.append(item)
    return variants or None


def _sagemaker_endpoint_config(body: dict) -> dict:
    """aws_sagemaker_endpoint_configuration. Its key argument is kms_key_arn."""
    props: dict = {}
    _set(props, "KmsKeyId", _ref(body, "kms_key_arn"))
    _set(props, "ProductionVariants", _sagemaker_variants(body, "production_variants"))
    _set(props, "ShadowProductionVariants", _sagemaker_variants(body, "shadow_production_variants"))
    return props


def _fsx_file_system(kind: str, block: str) -> Callable[[dict], dict]:
    """aws_fsx_*_file_system: flat arguments, in the shape of AWS::FSx::FileSystem with its per-type block."""

    def adapter(body: dict) -> dict:
        config: dict = {}
        _set(config, "AutomaticBackupRetentionDays", _known(_v(body, "automatic_backup_retention_days")))
        if kind != "ONTAP":
            _set(config, "CopyTagsToBackups", _known(_v(body, "copy_tags_to_backups")))
        if kind == "LUSTRE":
            _set(config, "DeploymentType", _known(_v(body, "deployment_type")))
            _set(config, "ImportPath", _known(_ref(body, "import_path")))
            _set(config, "ExportPath", _known(_ref(body, "export_path")))
        props: dict = {"FileSystemType": kind, block: config}
        _set(props, "KmsKeyId", _ref(body, "kms_key_id"))
        _set(props, "BackupId", _ref(body, "backup_id"))
        return props

    return adapter


def _fsx_data_repository_association(body: dict) -> dict:
    return {"FileSystemId": _known(_ref(body, "file_system_id"))}


def _block_is_unknown(body: dict, key: str) -> bool:
    """True when a block comes from a dynamic block or an expression, so the scan cannot read it."""
    return key in _dynamic_names(body) or isinstance(body.get(key), _Expr)


def _route53_zone(body: dict) -> dict:
    """aws_route53_zone. A vpc block makes the zone private."""
    if _block_is_unknown(body, "vpc"):
        return {"VPCs": UNRESOLVED}
    return {"VPCs": _OPAQUE} if _blocks(body, "vpc") else {}


def _route53_zone_link(key: str) -> Callable[[dict], dict]:
    """A resource that points at a zone. HostedZoneId is compared, so each.key or var.x is unknown."""

    def adapt(body: dict) -> dict:
        return {"HostedZoneId": _known(_ref(body, key))}

    return adapt


def _route53_record(body: dict) -> dict:
    """aws_route53_record, in the shape of AWS::Route53::RecordSet."""
    props: dict = {}
    _set(props, "HealthCheckId", _ref(body, "health_check_id"))
    if _block_is_unknown(body, "failover_routing_policy"):
        props["Failover"] = UNRESOLVED
    elif block := _first_block(body, "failover_routing_policy"):
        _set(props, "Failover", _v(block, "type"))
    if _block_is_unknown(body, "weighted_routing_policy"):
        props["Weight"] = UNRESOLVED
    elif block := _first_block(body, "weighted_routing_policy"):
        _set(props, "Weight", _v(block, "weight"))
    if _block_is_unknown(body, "alias"):
        props["AliasTarget"] = UNRESOLVED
    elif block := _first_block(body, "alias"):
        props["AliasTarget"] = {"EvaluateTargetHealth": _known(_v(block, "evaluate_target_health"))}
    return props


def _acm_certificate(body: dict) -> dict:
    """aws_acm_certificate. The imported key and body are kept only as present: never their value."""
    props: dict = {}
    _set(props, "ValidationMethod", _v(body, "validation_method"))
    _set(props, "KeyAlgorithm", _v(body, "key_algorithm"))
    _set(props, "CertificateAuthorityArn", _ref(body, "certificate_authority_arn"))
    if body.get("private_key") is not None:
        props["PrivateKey"] = _OPAQUE
    if body.get("certificate_body") is not None:
        props["CertificateBody"] = _OPAQUE
    if _block_is_unknown(body, "options"):
        props["CertificateTransparencyLoggingPreference"] = UNRESOLVED
    elif block := _first_block(body, "options"):
        _set(props, "CertificateTransparencyLoggingPreference",
             _v(block, "certificate_transparency_logging_preference"))
    return props


def _globalaccelerator_endpoint_group(body: dict) -> dict:
    props: dict = {}
    _set(props, "HealthCheckProtocol", _ref(body, "health_check_protocol"))
    _set(props, "HealthCheckPath", _ref(body, "health_check_path"))
    _set(props, "HealthCheckPort", _ref(body, "health_check_port"))
    if _block_is_unknown(body, "endpoint_configuration"):
        props["EndpointConfigurations"] = UNRESOLVED
    else:
        endpoints = [{"EndpointId": _known(_ref(block, "endpoint_id"))}
                     for block in _blocks(body, "endpoint_configuration")]
        _set(props, "EndpointConfigurations", endpoints or None)
    return props


def _appsync_graphql_api(body: dict) -> dict:
    """aws_appsync_graphql_api. A WAF web ACL is attached by aws_wafv2_web_acl_association: there is
    no inline argument."""
    props: dict = {}
    _set(props, "AuthenticationType", _v(body, "authentication_type"))
    _set(props, "ApiType", _v(body, "api_type"))
    _set(props, "Visibility", _v(body, "visibility"))
    if _block_is_unknown(body, "log_config"):
        props["LogConfig"] = UNRESOLVED
    elif log := _first_block(body, "log_config"):
        props["LogConfig"] = {"FieldLogLevel": _known(_v(log, "field_log_level"))}
    if _block_is_unknown(body, "additional_authentication_provider"):
        props["AdditionalAuthenticationProviders"] = UNRESOLVED
    else:
        providers = [{"AuthenticationType": _known(_v(block, "authentication_type"))}
                     for block in _blocks(body, "additional_authentication_provider")]
        _set(props, "AdditionalAuthenticationProviders", providers or None)
    return props


def _appsync_api_cache(body: dict) -> dict:
    return {"ApiId": _known(_ref(body, "api_id"))}


def _transfer_server(body: dict) -> dict:
    """aws_transfer_server. The provider documents endpoint_type as defaulting to PUBLIC. Logging
    arguments are only checked for presence."""
    props: dict = {}
    _set(props, "Protocols", _v(body, "protocols"))
    default = None if body.get("endpoint_details") or "endpoint_details" in _dynamic_names(body) else "PUBLIC"
    _set(props, "EndpointType", _v(body, "endpoint_type", default))
    _set(props, "LoggingRole", _ref(body, "logging_role"))
    _set(props, "StructuredLogDestinations", _ref(body, "structured_log_destinations"))
    return props


def _apprunner_service(body: dict) -> dict:
    if _block_is_unknown(body, "observability_configuration"):
        return {"ObservabilityConfiguration": UNRESOLVED}
    block = _first_block(body, "observability_configuration")
    if not block:
        return {}
    return {"ObservabilityConfiguration": {"ObservabilityEnabled": _known(_v(block, "observability_enabled"))}}


def _beanstalk_option_settings(body: dict) -> Any:
    """Repeated setting blocks, in the shape of OptionSettings. One unknown value stays _OPAQUE, so
    it does not hide the other settings."""
    if _block_is_unknown(body, "setting"):
        return UNRESOLVED
    settings = []
    for block in _blocks(body, "setting"):
        item: dict = {}
        _set(item, "Namespace", _known(_v(block, "namespace")))
        _set(item, "OptionName", _known(_v(block, "name")))
        _set(item, "Value", _known(_v(block, "value")))
        settings.append(item)
    return settings or None


def _beanstalk_environment(body: dict) -> dict:
    props: dict = {}
    _set(props, "OptionSettings", _beanstalk_option_settings(body))
    _set(props, "TemplateName", _ref(body, "template_name"))
    return props


def _beanstalk_configuration_template(body: dict) -> dict:
    """aws_elastic_beanstalk_configuration_template. Name is Terraform only: an environment can use
    the template by this literal name."""
    props: dict = {}
    _set(props, "Name", _v(body, "name"))
    _set(props, "OptionSettings", _beanstalk_option_settings(body))
    _set(props, "EnvironmentId", _ref(body, "environment_id"))
    return props


def _log_delivery_source(body: dict) -> dict:
    return {"ResourceArn": _known(_ref(body, "resource_arn"))}


def _waf_association(body: dict) -> dict:
    props: dict = {}
    _set(props, "ResourceArn", _known(_ref(body, "resource_arn")))
    return props


def _cloudtrail(body: dict) -> dict:
    props: dict = {}
    _set(props, "EnableLogFileValidation", _v(body, "enable_log_file_validation"))
    _set(props, "IsMultiRegionTrail", _v(body, "is_multi_region_trail"))
    _set(props, "KmsKeyId", _ref(body, "kms_key_id"))
    _set(props, "CloudWatchLogsLogGroupArn", _ref(body, "cloud_watch_logs_group_arn"))
    _set(props, "S3BucketName", _ref(body, "s3_bucket_name"))
    names = _dynamic_names(body)
    if "event_selector" in names:
        props["EventSelectors"] = UNRESOLVED
    elif "event_selector" in body:
        props["EventSelectors"] = [_trail_event_selector(item) for item in _blocks(body, "event_selector")]
    if "advanced_event_selector" in names:
        props["AdvancedEventSelectors"] = UNRESOLVED
    elif "advanced_event_selector" in body:
        props["AdvancedEventSelectors"] = [
            _trail_advanced_selector(item) for item in _blocks(body, "advanced_event_selector")]
    return props


def _trail_event_selector(block: dict) -> Any:
    if "data_resource" in _dynamic_names(block):
        return UNRESOLVED
    return {"DataResources": [{"Type": _ref(item, "type"), "Values": _ref(item, "values")}
                              for item in _blocks(block, "data_resource")]}


_FIELD_OPERATORS = {"equals": "Equals", "not_equals": "NotEquals", "starts_with": "StartsWith",
                    "not_starts_with": "NotStartsWith", "ends_with": "EndsWith", "not_ends_with": "NotEndsWith"}


def _trail_advanced_selector(block: dict) -> Any:
    if "field_selector" in _dynamic_names(block):
        return UNRESOLVED
    fields = []
    for item in _blocks(block, "field_selector"):
        field: dict = {"Field": _ref(item, "field")}
        for key, cf_key in _FIELD_OPERATORS.items():
            _set(field, cf_key, _ref(item, key))
        fields.append(field)
    return {"FieldSelectors": fields}


def _alarm_dimensions(body: dict) -> Any:
    """`dimensions` as CloudFormation's Name and Value list. A whole map from an expression stays
    as it is, so the check can see it cannot read it."""
    raw = _ref(body, "dimensions")
    if not isinstance(raw, dict):
        return raw
    return [{"Name": _unquote_key(str(key)), "Value": value} for key, value in raw.items()]


def _metric_query(block: dict) -> Any:
    if "metric" in _dynamic_names(block):
        return UNRESOLVED
    query: dict = {}
    _set(query, "Expression", _ref(block, "expression"))
    metric = _first_block(block, "metric")
    if metric:
        fields: dict = {}
        _set(fields, "Namespace", _ref(metric, "namespace"))
        _set(fields, "Dimensions", _alarm_dimensions(metric))
        query["MetricStat"] = {"Metric": fields}
    return query


def _metric_alarm(body: dict) -> dict:
    props: dict = {}
    _set(props, "AlarmName", _ref(body, "alarm_name"))
    _set(props, "AlarmActions", _ref(body, "alarm_actions"))
    _set(props, "ActionsEnabled", _v(body, "actions_enabled"))
    _set(props, "Namespace", _ref(body, "namespace"))
    _set(props, "Dimensions", _alarm_dimensions(body))
    if "metric_query" in _dynamic_names(body):
        props["Metrics"] = UNRESOLVED
    elif "metric_query" in body:
        props["Metrics"] = [_metric_query(item) for item in _blocks(body, "metric_query")]
    return props


def _composite_alarm(body: dict) -> dict:
    props: dict = {}
    _set(props, "AlarmName", _ref(body, "alarm_name"))
    _set(props, "AlarmActions", _ref(body, "alarm_actions"))
    _set(props, "ActionsEnabled", _v(body, "actions_enabled"))
    _set(props, "AlarmRule", _ref(body, "alarm_rule"))
    return props


def _kms_key(body: dict) -> dict:
    props: dict = {}
    # Raw value: resolve_policy_document reads it field by field in _resolve_iam.
    _set(props, "KeyPolicy", _ref(body, "policy"))
    _set(props, "EnableKeyRotation", _v(body, "enable_key_rotation"))
    _set(props, "KeySpec", _v(body, "customer_master_key_spec"))
    _set(props, "CustomKeyStoreId", _ref(body, "custom_key_store_id"))
    _set(props, "PendingWindowInDays", _v(body, "deletion_window_in_days"))
    return props


def _ssm_parameter(body: dict) -> dict:
    """aws_ssm_parameter. insecure_value is the provider's plain text form of value."""
    props: dict = {}
    _set(props, "Name", _v(body, "name"))
    _set(props, "Type", _v(body, "type"))
    _set(props, "Tier", _v(body, "tier"))
    _set(props, "DataType", _v(body, "data_type"))
    key = "value" if "value" in body else "insecure_value"
    raw = body.get(key)
    # A resource's ARN is not a secret, and an unknown value should not hide the other arguments.
    arn = isinstance(raw, _Expr) and raw.strip("${} ").endswith(".arn")
    _set(props, "Value", "arn:from-a-reference" if arn else _known(_v(body, key)))
    return props


def _ssm_association(body: dict) -> dict:
    """aws_ssm_association: name is the SSM document it runs."""
    props: dict = {}
    _set(props, "Name", _v(body, "name"))
    return props


def _ssm_maintenance_window_task(body: dict) -> dict:
    """aws_ssm_maintenance_window_task: task_arn is the document or ARN it runs."""
    props: dict = {}
    _set(props, "TaskArn", _v(body, "task_arn"))
    return props


def _ssmincidents_response_plan(body: dict) -> dict:
    """aws_ssmincidents_response_plan: engagements are the contacts it pages."""
    props: dict = {}
    _set(props, "Engagements", _ref(body, "engagements"))
    return props


def _ssmcontacts_contact(body: dict) -> dict:
    """aws_ssmcontacts_contact: PERSONAL, ESCALATION or ONCALL_SCHEDULE."""
    props: dict = {}
    _set(props, "Type", _v(body, "type"))
    return props


def _ssmcontacts_plan(body: dict) -> dict:
    """aws_ssmcontacts_plan: one Stages entry per stage block, or unresolved when dynamic."""
    props: dict = {}
    if "stage" in _dynamic_names(body):
        props["Stages"] = UNRESOLVED
    elif "stage" in body:
        props["Stages"] = [{} for _ in _blocks(body, "stage")]
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
        container = {cf: item[tf] for tf, cf in _CONTAINER_KEYS.items() if tf in item}
        if "environment" in item:
            container["Environment"] = _container_environment(item["environment"])
        if "logConfiguration" in item:
            container["LogConfiguration"] = _container_logs(item["logConfiguration"])
        out.append(container)
    return out


# Stands for a literal environment value, so that the secret stays out of the model.
_LITERAL_VALUE = "<literal>"


def _container_environment(value: Any) -> Any:
    """environment -> Environment, with each value reduced to whether it is a literal secret."""
    if not isinstance(value, list):
        return _OPAQUE
    return [
        {"Name": item.get("name"), "Value": _LITERAL_VALUE if is_literal_secret(item.get("value")) else _OPAQUE}
        for item in value if isinstance(item, dict)
    ]


def _container_logs(value: Any) -> Any:
    """logConfiguration -> LogConfiguration, with only the driver: options may hold secrets."""
    if not isinstance(value, dict):
        return _OPAQUE
    return {"LogDriver": value.get("logDriver")}


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
    _set(props, "NetworkMode", _v(body, "network_mode"))
    _set(props, "PidMode", _v(body, "pid_mode"))
    _set(props, "RequiresCompatibilities", _v(body, "requires_compatibilities"))
    _set(props, "Cpu", _v(body, "cpu"))
    _set(props, "Memory", _v(body, "memory"))
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
    # Provider defaults: 3 second timeout, -1 (no reserved concurrency).
    _set(props, "Timeout", _v(body, "timeout", 3))
    reserved = _v(body, "reserved_concurrent_executions", -1)
    if reserved not in (-1, "-1"):
        props["ReservedConcurrentExecutions"] = reserved
    if "environment" in _dynamic_names(body):
        props["Environment"] = UNRESOLVED
    else:
        variables = _first_block(body, "environment").get("variables")
        if isinstance(variables, dict):
            # One value from var/local must not hide the literal ones (CF-LAM-005).
            props["Environment"] = {"Variables": {
                k: _OPAQUE if v is UNRESOLVED else v for k, v in variables.items()}}
        elif variables is not None:
            props["Environment"] = UNRESOLVED
    vpc = _first_block(body, "vpc_config")
    if vpc:
        props["VpcConfig"] = {"SubnetIds": _ref(vpc, "subnet_ids")}
    return props


def _lambda_url(body: dict) -> dict:
    props: dict = {}
    _set(props, "AuthType", _v(body, "authorization_type"))
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
    _set(props, "DeletionProtectionEnabled", _v(body, "deletion_protection_enabled"))
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
    _set(props, "VisibilityTimeout", _v(body, "visibility_timeout_seconds"))
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
    _set(props, "CacheClusterEnabled", _v(body, "cache_cluster_enabled"))
    _set(props, "ClientCertificateId", _ref(body, "client_certificate_id"))
    # aws_api_gateway_method_settings blocks are merged in by _merge_method_settings.
    props["MethodSettings"] = []
    return props


def _apiv2_stage(body: dict) -> dict:
    props: dict = {}
    logs = _first_block(body, "access_log_settings")
    if logs:
        props["AccessLogSettings"] = {"DestinationArn": _ref(logs, "destination_arn")}
    if "default_route_settings" in _dynamic_names(body):
        props["DefaultRouteSettings"] = UNRESOLVED
    else:
        route = _first_block(body, "default_route_settings")
        settings: dict = {}
        _set(settings, "ThrottlingRateLimit", _v(route, "throttling_rate_limit"))
        _set(settings, "ThrottlingBurstLimit", _v(route, "throttling_burst_limit"))
        props["DefaultRouteSettings"] = settings
    return props


def _codebuild_project(body: dict) -> dict:
    """aws_codebuild_project in the AWS::CodeBuild::Project shape (CF-CB-001..005). A
    dynamic environment_variable or source block is not read; the static ones still are."""
    props: dict = {}
    if "environment" in _dynamic_names(body):
        props["Environment"] = UNRESOLVED
    else:
        env = _first_block(body, "environment")
        environment: dict = {}
        _set(environment, "PrivilegedMode", _known(_v(env, "privileged_mode")))
        environment["EnvironmentVariables"] = [
            {
                "Name": _known(_v(item, "name")),
                "Type": _known(_v(item, "type", "PLAINTEXT")),
                "Value": _known(_v(item, "value")),
            }
            for item in _blocks(env, "environment_variable")
        ]
        props["Environment"] = environment
    props["Source"] = {"Location": _known(_v(_first_block(body, "source"), "location"))}
    props["SecondarySources"] = [
        {"Location": _known(_v(item, "location"))} for item in _blocks(body, "secondary_sources")
    ]
    if "logs_config" in _dynamic_names(body):
        props["LogsConfig"] = UNRESOLVED
    else:
        logs = _first_block(body, "logs_config")
        config: dict = {}
        if {"cloudwatch_logs", "s3_logs"} & _dynamic_names(logs):
            config["CloudWatchLogs"] = UNRESOLVED
        cloudwatch = _first_block(logs, "cloudwatch_logs")
        if cloudwatch:
            config.setdefault("CloudWatchLogs", {"Status": _v(cloudwatch, "status", "ENABLED")})
        s3_logs = _first_block(logs, "s3_logs")
        if s3_logs:
            s3: dict = {"Status": _v(s3_logs, "status", "DISABLED")}
            _set(s3, "EncryptionDisabled", _v(s3_logs, "encryption_disabled"))
            config["S3Logs"] = s3
        props["LogsConfig"] = config
    return props


def _codepipeline(body: dict) -> dict:
    """aws_codepipeline in the AWS::CodePipeline::Pipeline shape (CF-CP-001..003)."""
    props: dict = {}
    _set(props, "Name", _v(body, "name"))
    if "artifact_store" in _dynamic_names(body):
        props["ArtifactStores"] = UNRESOLVED
    else:
        stores = []
        for item in _blocks(body, "artifact_store"):
            store: dict = {}
            if "encryption_key" in _dynamic_names(item):
                store["EncryptionKey"] = _OPAQUE
            elif _first_block(item, "encryption_key"):
                store["EncryptionKey"] = {"Id": _ref(_first_block(item, "encryption_key"), "id")}
            stores.append({"ArtifactStore": store})
        props["ArtifactStores"] = stores
    if "stage" in _dynamic_names(body) or any(
        "action" in _dynamic_names(stage) for stage in _blocks(body, "stage")
    ):
        props["Stages"] = UNRESOLVED
    else:
        props["Stages"] = [
            {
                "Name": _known(_v(stage, "name")),
                "Actions": [
                    {
                        "ActionTypeId": {"Category": _v(action, "category")},
                        "RunOrder": _v(action, "run_order", 1),
                    }
                    for action in _blocks(stage, "action")
                ],
            }
            for stage in _blocks(body, "stage")
        ]
    return props


def _notification_rule(body: dict) -> dict:
    props: dict = {}
    _set(props, "Resource", _ref(body, "resource"))
    return props


def _event_rule(body: dict) -> dict:
    """An expression that names no event source (file(), data.*, a source from var.*) may
    match any, so it is not read."""
    value = _ref(body, "event_pattern")
    props: dict = {}
    _set(props, "EventPattern", _OPAQUE if isinstance(value, _Expr) and "aws." not in value else value)
    return props


def _event_target(body: dict) -> dict:
    """aws_cloudwatch_event_target in the shape of one entry in a rule's Targets."""
    props: dict = {}
    names = _dynamic_names(body)
    dead_letter = _first_block(body, "dead_letter_config")
    if "dead_letter_config" in names:
        props["DeadLetterConfig"] = UNRESOLVED
    elif dead_letter:
        props["DeadLetterConfig"] = {"Arn": _ref(dead_letter, "arn")}
    retry = _first_block(body, "retry_policy")
    if "retry_policy" in names:
        props["RetryPolicy"] = UNRESOLVED
    elif retry:
        props["RetryPolicy"] = {"MaximumRetryAttempts": _v(retry, "maximum_retry_attempts")}
    return props


def _backup_vault(body: dict) -> dict:
    props: dict = {}
    _set(props, "BackupVaultName", _ref(body, "name"))
    _set(props, "EncryptionKeyArn", _ref(body, "kms_key_arn"))
    return props


def _backup_vault_lock(body: dict) -> dict:
    """aws_backup_vault_lock_configuration: Terraform locks a vault from a resource of its own."""
    props: dict = {}
    _set(props, "BackupVaultName", _ref(body, "backup_vault_name"))
    return props


def _backup_plan(body: dict) -> dict:
    """aws_backup_plan in the shape of AWS::Backup::BackupPlan. Values stay as written, so one
    rule from a variable does not hide the others; _backup_findings skips what it cannot read."""
    if "rule" in _dynamic_names(body):
        return {"BackupPlan": UNRESOLVED}
    rules = []
    for rule in _blocks(body, "rule"):
        names = _dynamic_names(rule)
        item: dict = {"RuleName": _ref(rule, "rule_name")}
        lifecycle = _first_block(rule, "lifecycle")
        if "lifecycle" in names:
            item["Lifecycle"] = _OPAQUE
        elif lifecycle:
            item["Lifecycle"] = {"DeleteAfterDays": _ref(lifecycle, "delete_after")}
        item["CopyActions"] = _OPAQUE if "copy_action" in names else [
            {"DestinationBackupVaultArn": _ref(c, "destination_vault_arn")}
            for c in _blocks(rule, "copy_action")
        ]
        rules.append(item)
    return {"BackupPlan": {"BackupPlanRule": rules}}


def _backup_selection(body: dict) -> dict:
    """aws_backup_selection in the shape of AWS::Backup::BackupSelection."""
    names = _dynamic_names(body)
    selection: dict = {}
    _set(selection, "Resources", _ref(body, "resources"))
    selection["ListOfTags"] = _OPAQUE if "selection_tag" in names else [
        {"ConditionKey": _ref(t, "key"), "ConditionValue": _ref(t, "value")}
        for t in _blocks(body, "selection_tag")
    ]
    equals: list[dict] = []
    for condition in _blocks(body, "condition"):
        equals += [{"ConditionKey": _ref(e, "key"), "ConditionValue": _ref(e, "value")}
                   for e in _blocks(condition, "string_equals")]
    if equals:
        selection["Conditions"] = {"StringEquals": equals}
    return {"BackupSelection": selection}


def _event_permission(body: dict) -> dict:
    """aws_cloudwatch_event_permission: the older Principal and Condition form of a bus policy."""
    props: dict = {}
    _set(props, "Principal", _v(body, "principal"))
    _set(props, "Action", _v(body, "action"))
    if "condition" in _dynamic_names(body):
        props["Condition"] = UNRESOLVED
    elif _first_block(body, "condition"):
        props["Condition"] = _first_block(body, "condition")
    return props


def _state_machine_definition(value: Any) -> Any:
    """definition (jsonencode, JSON string or heredoc) -> data. file() and templatefile() are
    UNRESOLVED. An interpolation inside a JSON string does not change the states around it."""
    if isinstance(value, _JsonEncode):
        decoded = decode_jsonencode(value)
    elif isinstance(value, str):
        heredoc = _HEREDOC.fullmatch(value)
        if isinstance(value, _Expr) and not heredoc:
            return UNRESOLVED
        decoded = _json_or_unresolved(heredoc.group(2) if heredoc else value)
    else:
        return UNRESOLVED
    return decoded if isinstance(decoded, dict) else UNRESOLVED


def _state_machine(body: dict) -> dict:
    props: dict = {}
    if body.get("definition") is not None:
        props["Definition"] = _state_machine_definition(body["definition"])
    names = _dynamic_names(body)
    tracing = _first_block(body, "tracing_configuration")
    if "tracing_configuration" in names:
        props["TracingConfiguration"] = UNRESOLVED
    elif tracing:
        props["TracingConfiguration"] = {"Enabled": _v(tracing, "enabled")}
    logging = _first_block(body, "logging_configuration")
    if "logging_configuration" in names:
        props["LoggingConfiguration"] = UNRESOLVED
    elif logging:
        props["LoggingConfiguration"] = {"Level": _v(logging, "level", "OFF")}
    return props


def _api_method(body: dict) -> dict:
    """aws_api_gateway_method in the AWS::ApiGateway::Method shape (CF-APIGW-003/006/008)."""
    props: dict = {}
    _set(props, "HttpMethod", _v(body, "http_method"))
    _set(props, "AuthorizationType", _v(body, "authorization"))
    _set(props, "ApiKeyRequired", _v(body, "api_key_required"))
    _set(props, "RequestValidatorId", _ref(body, "request_validator_id"))
    return props


def _api_rest_api(body: dict) -> dict:
    """aws_api_gateway_rest_api: an explicit TLS policy only (CF-APIGW-004). The default
    is not judged for Terraform, whose provider may not expose the setting."""
    props: dict = {}
    _set(props, "SecurityPolicy", _v(body, "security_policy"))
    _set(props, "DisableExecuteApiEndpoint", _v(body, "disable_execute_api_endpoint"))
    return props


def _api_domain_name(body: dict) -> dict:
    props: dict = {}
    _set(props, "SecurityPolicy", _v(body, "security_policy"))
    return props


def _apiv2_domain_name(body: dict) -> dict:
    if "domain_name_configuration" in _dynamic_names(body):
        return {"DomainNameConfigurations": UNRESOLVED}
    configs = []
    for item in _blocks(body, "domain_name_configuration"):
        config: dict = {}
        _set(config, "SecurityPolicy", _v(item, "security_policy"))
        configs.append(config)
    return {"DomainNameConfigurations": configs}


def _api_usage_plan(body: dict) -> dict:
    """aws_api_gateway_usage_plan: whether it throttles, on the plan or per stage (REL-006)."""
    # A dynamic block may throttle, so it counts.
    throttled = bool(_blocks(body, "throttle_settings")) or any(
        _blocks(stage, "throttle") or "throttle" in _dynamic_names(stage)
        for stage in _blocks(body, "api_stages")
    ) or bool({"throttle_settings", "api_stages"} & set(_dynamic_names(body)))
    return {"Throttle": {"Set": True}} if throttled else {}


def _apiv2_api(body: dict) -> dict:
    props: dict = {}
    _set(props, "ProtocolType", _v(body, "protocol_type"))
    return props


def _apiv2_route(body: dict) -> dict:
    props: dict = {}
    _set(props, "RouteKey", _v(body, "route_key"))
    _set(props, "AuthorizationType", _v(body, "authorization_type", "NONE"))
    return props


def _entries(value: Any) -> Any:
    """A list keeps its length when an entry comes from a variable, which would otherwise hide the
    whole list. A list that is itself a variable stays UNRESOLVED."""
    if isinstance(value, list):
        return [_Expr("<unresolved>") if item is UNRESOLVED else item for item in value]
    return value


def _asg(body: dict) -> dict:
    props: dict = {}
    _set(props, "AutoScalingGroupName", _v(body, "name"))
    _set(props, "HealthCheckType", _v(body, "health_check_type"))
    _set(props, "MinSize", _v(body, "min_size"))
    _set(props, "MaxSize", _v(body, "max_size"))
    _set(props, "TargetGroupARNs", _entries(_ref(body, "target_group_arns")))
    _set(props, "LoadBalancerNames", _entries(_ref(body, "load_balancers")))
    _set(props, "AvailabilityZones", _entries(_ref(body, "availability_zones")))
    _set(props, "VPCZoneIdentifier", _entries(_ref(body, "vpc_zone_identifier")))
    _set(props, "LaunchConfigurationName", _ref(body, "launch_configuration"))
    mixed = _first_block(body, "mixed_instances_policy")
    if not mixed:
        return props
    dist = _first_block(mixed, "instances_distribution")
    props["MixedInstancesPolicy"] = {
        "InstancesDistribution": {
            "SpotMaxPrice": _ref(dist, "spot_max_price"),
            "SpotAllocationStrategy": _ref(dist, "spot_allocation_strategy"),
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
    _set(props, "MetadataOptions", _metadata_options(body))
    _set(props, "AssociatePublicIpAddress", _v(body, "associate_public_ip_address"))
    return props


def _athena_workgroup(body: dict) -> dict:
    """aws_athena_workgroup. One unknown value must not hide the others, so each is kept apart."""
    if "configuration" in _dynamic_names(body):
        return {"WorkGroupConfiguration": UNRESOLVED}
    config = _first_block(body, "configuration")
    dynamic = _dynamic_names(config)
    props: dict = {}
    _set(props, "EnforceWorkGroupConfiguration", _known(_v(config, "enforce_workgroup_configuration")))
    if "result_configuration" in dynamic:
        props["ResultConfiguration"] = _OPAQUE
    elif "result_configuration" in config:
        result = _first_block(config, "result_configuration")
        if "encryption_configuration" in _dynamic_names(result):
            props["ResultConfiguration"] = {"EncryptionConfiguration": _OPAQUE}
        elif "encryption_configuration" in result:
            encryption = _first_block(result, "encryption_configuration")
            props["ResultConfiguration"] = {"EncryptionConfiguration": {
                "EncryptionOption": _known(_v(encryption, "encryption_option"))}}
        else:
            props["ResultConfiguration"] = {}
    if "managed_query_results_configuration" in dynamic:
        props["ManagedQueryResultsConfiguration"] = _OPAQUE
    elif "managed_query_results_configuration" in config:
        managed = _first_block(config, "managed_query_results_configuration")
        props["ManagedQueryResultsConfiguration"] = {"Enabled": _known(_v(managed, "enabled"))}
    if "engine_version" in dynamic:
        props["EngineVersion"] = _OPAQUE
    elif "engine_version" in config:
        engine = _first_block(config, "engine_version")
        props["EngineVersion"] = {"SelectedEngineVersion": _known(_v(engine, "selected_engine_version"))}
    return {"WorkGroupConfiguration": props} if props else {}


# Only the arguments the checks read: another argument may hold a secret.
_GLUE_ARGUMENTS = ("--enable-metrics", "--job-bookmark-option")


def _glue_arguments(body: dict, key: str) -> Any:
    """A job's argument map. A map from an expression, or with a computed key, may hold any argument."""
    value = body.get(key)
    if value is None:
        return None
    if not isinstance(value, dict) or any("${" in name for name in value):
        return UNRESOLVED
    return {name: _known(value[name]) for name in _GLUE_ARGUMENTS if name in value}


def _glue_job(body: dict) -> dict:
    props: dict = {}
    _set(props, "SecurityConfiguration", _ref(body, "security_configuration"))
    _set(props, "DefaultArguments", _glue_arguments(body, "default_arguments"))
    _set(props, "NonOverridableArguments", _glue_arguments(body, "non_overridable_arguments"))
    if "command" in _dynamic_names(body):
        props["Command"] = UNRESOLVED
    else:
        # The provider defaults the job type to a Spark ETL job.
        props["Command"] = {"Name": _v(_first_block(body, "command"), "name", "glueetl")}
    return props


_GLUE_ENCRYPTIONS = (
    ("cloudwatch_encryption", "cloudwatch_encryption_mode", "CloudWatchEncryption", "CloudWatchEncryptionMode"),
    ("job_bookmarks_encryption", "job_bookmarks_encryption_mode", "JobBookmarksEncryption",
     "JobBookmarksEncryptionMode"),
)


def _glue_security_configuration(body: dict) -> dict:
    """aws_glue_security_configuration. An unset mode is DISABLED in the provider. One unknown mode
    must not hide the others, so each is kept apart."""
    if "encryption_configuration" in _dynamic_names(body):
        return {"EncryptionConfiguration": UNRESOLVED}
    encryption = _first_block(body, "encryption_configuration")
    dynamic = _dynamic_names(encryption)
    props: dict = {}
    for block, mode, cf_block, cf_mode in _GLUE_ENCRYPTIONS:
        props[cf_block] = _OPAQUE if block in dynamic else {
            cf_mode: _known(_v(_first_block(encryption, block), mode))}
    props["S3Encryptions"] = _OPAQUE if "s3_encryption" in dynamic else [
        {"S3EncryptionMode": _known(_v(_first_block(encryption, "s3_encryption"), "s3_encryption_mode"))}]
    return {"EncryptionConfiguration": props}


def _emr_cluster(body: dict) -> dict:
    props: dict = {}
    _set(props, "SecurityConfiguration", _ref(body, "security_configuration"))
    if "ec2_attributes" in _dynamic_names(body):
        props["Instances"] = UNRESOLVED
    else:
        subnet = _ref(_first_block(body, "ec2_attributes"), "subnet_id")
        if subnet is not None:
            props["Instances"] = {"Ec2SubnetId": subnet}
    return props


def _emr_security_configuration(body: dict) -> dict:
    """aws_emr_security_configuration. configuration is a JSON string, often jsonencode; a document
    from file() or a variable is UNRESOLVED."""
    value = body.get("configuration")
    return {} if value is None else {"SecurityConfiguration": _state_machine_definition(value)}


def _dms_replication_instance(body: dict) -> dict:
    """aws_dms_replication_instance. The provider sends false when these are unset, unlike
    CloudFormation, where public access and minor upgrades default to true."""
    props: dict = {
        "PubliclyAccessible": _v(body, "publicly_accessible", False),
        "AutoMinorVersionUpgrade": _v(body, "auto_minor_version_upgrade", False),
    }
    _set(props, "MultiAZ", _v(body, "multi_az"))
    return props


def _dms_endpoint(body: dict) -> dict:
    """aws_dms_endpoint. Extra attributes may hold a secret, so only their presence is kept."""
    props: dict = {}
    _set(props, "EngineName", _v(body, "engine_name"))
    _set(props, "SslMode", _v(body, "ssl_mode"))
    _set(props, "SecretsManagerSecretId", _ref(body, "secrets_manager_arn"))
    _set(props, "CertificateArn", _ref(body, "certificate_arn"))
    if body.get("extra_connection_attributes") is not None:
        props["ExtraConnectionAttributes"] = _OPAQUE
    return props


_FIREHOSE_SOURCE = "_source_configuration"


def _firehose_delivery_stream(body: dict) -> dict:
    """aws_kinesis_firehose_delivery_stream. A *_source_configuration block marks a stream that is
    not direct put. server_side_encryption is off unless enabled is true."""
    props: dict = {}
    dynamic = _dynamic_names(body)
    if any(name.endswith(_FIREHOSE_SOURCE) for name in dynamic):
        props["DeliveryStreamType"] = UNRESOLVED
    elif any(name.endswith(_FIREHOSE_SOURCE) for name in body):
        props["DeliveryStreamType"] = "AsSource"
    if "server_side_encryption" in dynamic:
        props["DeliveryStreamEncryptionConfigurationInput"] = UNRESOLVED
    else:
        enabled = _v(_first_block(body, "server_side_encryption"), "enabled")
        if enabled is UNRESOLVED:
            props["DeliveryStreamEncryptionConfigurationInput"] = UNRESOLVED
        elif enabled is True:
            props["DeliveryStreamEncryptionConfigurationInput"] = {"KeyType": "set"}
    return props


def _asg_link(body: dict) -> dict:
    """aws_autoscaling_policy, _schedule and _attachment: Terraform sets these from resources of
    their own, and each names its group (CF-ASG-001, CF-ASG-006)."""
    props: dict = {}
    _set(props, "AutoScalingGroupName", _ref(body, "autoscaling_group_name"))
    return props


def _elasticache_cluster(body: dict) -> dict:
    props: dict = {}
    _set(props, "CacheNodeType", _v(body, "node_type"))
    _set(props, "Engine", _v(body, "engine"))
    _set(props, "SnapshotRetentionLimit", _v(body, "snapshot_retention_limit"))
    _set(props, "AutoMinorVersionUpgrade", _v(body, "auto_minor_version_upgrade"))
    _set(props, "CacheSubnetGroupName", _ref(body, "subnet_group_name"))
    # A member of a replication group: the group holds its settings.
    _set(props, "ReplicationGroupId", _ref(body, "replication_group_id"))
    return props


def _ecs_cluster(body: dict) -> dict:
    if "setting" in _dynamic_names(body):
        return {"ClusterSettings": UNRESOLVED}
    settings = [{"Name": _v(item, "name"), "Value": _v(item, "value")} for item in _blocks(body, "setting")]
    return {"ClusterSettings": settings} if settings else {}


def _assign_public_ip(body: dict) -> Any:
    """network_configuration.assign_public_ip -> ENABLED or DISABLED, or None when unset."""
    value = _v(_first_block(body, "network_configuration"), "assign_public_ip")
    if value is None or value is UNRESOLVED:
        return value
    text = str(value).lower()
    return {"true": "ENABLED", "false": "DISABLED"}.get(text, UNRESOLVED)


def _ecs_service(body: dict) -> dict:
    props: dict = {}
    _set(props, "LaunchType", _v(body, "launch_type"))
    _set(props, "PlatformVersion", _v(body, "platform_version"))
    if "network_configuration" in _dynamic_names(body):
        props["NetworkConfiguration"] = UNRESOLVED
    else:
        assign = _assign_public_ip(body)
        if assign is not None:
            props["NetworkConfiguration"] = {"AwsvpcConfiguration": {"AssignPublicIp": assign}}
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


def _guardduty_detector(body: dict) -> dict:
    """aws_guardduty_detector. Values stay as written, so one from a variable does not hide the
    other features; the check only reads a literal."""
    props: dict = {}
    _set(props, "Enable", _ref(body, "enable"))
    if _block_is_unknown(body, "datasources"):
        props["DataSources"] = UNRESOLVED
        return props
    sources = _first_block(body, "datasources")
    if sources:
        audit_logs = _first_block(_first_block(sources, "kubernetes"), "audit_logs")
        scan = _first_block(_first_block(sources, "malware_protection"), "scan_ec2_instance_with_findings")
        props["DataSources"] = {
            "S3Logs": {"Enable": _ref(_first_block(sources, "s3_logs"), "enable")},
            "Kubernetes": {"AuditLogs": {"Enable": _ref(audit_logs, "enable")}},
            "MalwareProtection": {"ScanEc2InstanceWithFindings": {
                "EbsVolumes": _ref(_first_block(scan, "ebs_volumes"), "enable")}},
        }
    return props


def _guardduty_detector_feature(body: dict) -> dict:
    """aws_guardduty_detector_feature: Terraform sets a feature from a resource of its own."""
    return {"Name": _ref(body, "name"), "Status": _ref(body, "status")}


def _securityhub_account(body: dict) -> dict:
    props: dict = {}
    _set(props, "EnableDefaultStandards", _ref(body, "enable_default_standards"))
    return props


def _securityhub_standards_subscription(body: dict) -> dict:
    return {"StandardsArn": _ref(body, "standards_arn")}


def _config_recorder(body: dict) -> dict:
    """aws_config_configuration_recorder. Only all_supported is compared; the rest is presence."""
    if _block_is_unknown(body, "recording_group"):
        return {"RecordingGroup": UNRESOLVED}
    group = _first_block(body, "recording_group")
    if not group:
        return {}
    props = {"AllSupported": _ref(group, "all_supported"), "ResourceTypes": _ref(group, "resource_types")}
    for block, key in (("exclusion_by_resource_types", "ExclusionByResourceTypes"),
                       ("recording_strategy", "RecordingStrategy")):
        if _block_is_unknown(group, block) or _blocks(group, block):
            props[key] = _OPAQUE
    return {"RecordingGroup": props}


def _macie2_account(body: dict) -> dict:
    props: dict = {}
    _set(props, "Status", _ref(body, "status"))
    return props


def _budgets_budget(body: dict) -> dict:
    """aws_budgets_budget. A notification block holds what CloudFormation calls NotificationsWithSubscribers."""
    if _block_is_unknown(body, "notification"):
        return {"NotificationsWithSubscribers": UNRESOLVED}
    return {"NotificationsWithSubscribers": _OPAQUE} if _blocks(body, "notification") else {}


_ADAPTERS: dict[str, Callable[[dict], dict]] = {
    "aws_guardduty_detector": _guardduty_detector,
    "aws_guardduty_detector_feature": _guardduty_detector_feature,
    "aws_securityhub_account": _securityhub_account,
    "aws_securityhub_standards_subscription": _securityhub_standards_subscription,
    "aws_config_configuration_recorder": _config_recorder,
    "aws_macie2_account": _macie2_account,
    "aws_budgets_budget": _budgets_budget,
    "aws_athena_workgroup": _athena_workgroup,
    "aws_glue_job": _glue_job,
    "aws_glue_security_configuration": _glue_security_configuration,
    "aws_emr_cluster": _emr_cluster,
    "aws_emr_security_configuration": _emr_security_configuration,
    "aws_dms_replication_instance": _dms_replication_instance,
    "aws_dms_endpoint": _dms_endpoint,
    "aws_kinesis_firehose_delivery_stream": _firehose_delivery_stream,
    "aws_s3_bucket": _s3_bucket,
    "aws_db_instance": _db,
    "aws_rds_cluster": _db,
    "aws_rds_cluster_instance": _db,
    "aws_db_parameter_group": _db_parameter_group,
    "aws_rds_cluster_parameter_group": _db_parameter_group,
    "aws_instance": _instance,
    "aws_subnet": _subnet,
    "aws_launch_template": _launch_template,
    "aws_security_group": _security_group,
    "aws_lb": _lb,
    "aws_alb": _lb,
    "aws_lb_listener": _lb_listener,
    "aws_alb_listener": _lb_listener,
    "aws_lb_target_group": _lb_target_group,
    "aws_alb_target_group": _lb_target_group,
    "aws_elb": _elb,
    "aws_cloudtrail": _cloudtrail,
    "aws_kms_key": _kms_key,
    "aws_ssm_parameter": _ssm_parameter,
    "aws_ssm_association": _ssm_association,
    "aws_ssm_maintenance_window_task": _ssm_maintenance_window_task,
    "aws_ssmincidents_response_plan": _ssmincidents_response_plan,
    "aws_ssmcontacts_contact": _ssmcontacts_contact,
    "aws_ssmcontacts_plan": _ssmcontacts_plan,
    "aws_lambda_function": _lambda,
    "aws_dynamodb_table": _dynamodb,
    "aws_appautoscaling_target": _scalable_target,
    "aws_cloudwatch_log_group": _log_group,
    "aws_sqs_queue": _sqs,
    "aws_api_gateway_stage": _api_stage,
    "aws_apigatewayv2_stage": _apiv2_stage,
    "aws_codebuild_project": _codebuild_project,
    "aws_codepipeline": _codepipeline,
    "aws_codestarnotifications_notification_rule": _notification_rule,
    "aws_cloudwatch_event_rule": _event_rule,
    "aws_cloudwatch_event_target": _event_target,
    "aws_backup_vault": _backup_vault,
    "aws_backup_vault_lock_configuration": _backup_vault_lock,
    "aws_backup_plan": _backup_plan,
    "aws_backup_selection": _backup_selection,
    "aws_cloudwatch_event_permission": _event_permission,
    "aws_sfn_state_machine": _state_machine,
    "aws_api_gateway_rest_api": _api_rest_api,
    "aws_api_gateway_method": _api_method,
    "aws_api_gateway_domain_name": _api_domain_name,
    "aws_api_gateway_usage_plan": _api_usage_plan,
    "aws_apigatewayv2_domain_name": _apiv2_domain_name,
    "aws_apigatewayv2_route": _apiv2_route,
    "aws_apigatewayv2_api": _apiv2_api,
    "aws_autoscaling_group": _asg,
    "aws_autoscaling_policy": _asg_link,
    "aws_autoscaling_schedule": _asg_link,
    "aws_autoscaling_attachment": _asg_link,
    "aws_ecs_cluster": _ecs_cluster,
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
    "aws_network_acl": _network_acl,
    "aws_network_acl_rule": _network_acl_rule,
    "aws_ec2_transit_gateway": _transit_gateway,
    "aws_flow_log": _flow_log,
    "aws_vpc_endpoint": _vpc_endpoint,
    "aws_efs_file_system": _efs_file_system,
    "aws_efs_access_point": _efs_access_point,
    "aws_efs_backup_policy": _efs_backup_policy,
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
    "aws_cloudwatch_log_delivery_source": _log_delivery_source,
    "aws_sagemaker_notebook_instance": _sagemaker_notebook,
    "aws_sagemaker_endpoint_configuration": _sagemaker_endpoint_config,
    "aws_fsx_lustre_file_system": _fsx_file_system("LUSTRE", "LustreConfiguration"),
    "aws_fsx_windows_file_system": _fsx_file_system("WINDOWS", "WindowsConfiguration"),
    "aws_fsx_ontap_file_system": _fsx_file_system("ONTAP", "OntapConfiguration"),
    "aws_fsx_openzfs_file_system": _fsx_file_system("OPENZFS", "OpenZFSConfiguration"),
    "aws_fsx_data_repository_association": _fsx_data_repository_association,
    "aws_route53_zone": _route53_zone,
    "aws_route53_record": _route53_record,
    "aws_route53_hosted_zone_dnssec": _route53_zone_link("hosted_zone_id"),
    "aws_route53_key_signing_key": _route53_zone_link("hosted_zone_id"),
    "aws_route53_query_log": _route53_zone_link("zone_id"),
    "aws_acm_certificate": _acm_certificate,
    "aws_cloudwatch_metric_alarm": _metric_alarm,
    "aws_cloudwatch_composite_alarm": _composite_alarm,
    "aws_globalaccelerator_endpoint_group": _globalaccelerator_endpoint_group,
    "aws_appsync_graphql_api": _appsync_graphql_api,
    "aws_appsync_api_cache": _appsync_api_cache,
    "aws_transfer_server": _transfer_server,
    "aws_apprunner_service": _apprunner_service,
    "aws_elastic_beanstalk_environment": _beanstalk_environment,
    "aws_elastic_beanstalk_configuration_template": _beanstalk_configuration_template,
    "aws_wafv2_web_acl_association": _waf_association,
    "aws_wafregional_web_acl_association": _waf_association,
    "aws_sqs_queue_policy": _resource_policy,
    "aws_cloudwatch_event_bus_policy": _resource_policy,
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
    "aws_lambda_function_url": _lambda_url,
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
    "replication_configuration": "ReplicationConfiguration",
    "instance_market_options": "LaunchTemplateData",
    # Not LaunchTemplateData: an unknown metadata block must not hide the Spot check.
    "metadata_options": "MetadataOptions",
    "ingress": "SecurityGroupIngress",
    "egress": "SecurityGroupEgress",
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
    if block.type in ("aws_security_group_rule", "aws_vpc_security_group_ingress_rule",
                      "aws_vpc_security_group_egress_rule"):
        rule = _sg_rule(block.type, block.body)
        canonical, props = rule if rule is not None else (None, {})
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


def _merge_method_settings(blocks: list[_Block], resources: dict[str, Resource]) -> None:
    """Attach aws_api_gateway_method_settings to its aws_api_gateway_stage as a
    MethodSettings entry (CF-APIGW-005/007/008).

    Settings that point at no stage the scan can find may belong to any of them, so the
    stages' MethodSettings become unresolved and those checks report nothing.
    """
    stages = [r for r in resources.values() if r.source_type == "aws_api_gateway_stage"]
    unlinked = False
    for block in blocks:
        if block.type != "aws_api_gateway_method_settings":
            continue
        targets = [s for s in stages if s.name in block.references]
        if not targets or "settings" in _dynamic_names(block.body):
            unlinked = True
            continue
        settings = _first_block(block.body, "settings")
        entry: dict = {"ResourcePath": _v(block.body, "method_path")}
        for tf_key, cf_key in (
            ("throttling_rate_limit", "ThrottlingRateLimit"),
            ("throttling_burst_limit", "ThrottlingBurstLimit"),
            ("caching_enabled", "CachingEnabled"),
            ("cache_data_encrypted", "CacheDataEncrypted"),
        ):
            value = _v(settings, tf_key)
            if value is not None:
                entry[cf_key] = _OPAQUE if value is UNRESOLVED else value
        for stage in targets:
            stage.properties.setdefault("MethodSettings", []).append(entry)
    if unlinked:
        for stage in stages:
            stage.unresolved = stage.unresolved | {"MethodSettings"}


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
    _merge_method_settings(blocks, resources)
    _resolve_iam(resources, blocks)
    return [*resources.values(), *_module_call_records(module_dir)]


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
