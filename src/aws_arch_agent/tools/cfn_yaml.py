"""Read CloudFormation templates: short-tag YAML, JSON, and real-template detection."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from aws_arch_agent.tools.files import read_text_safe

TEMPLATE_SUFFIXES = frozenset({".json", ".yaml", ".yml", ".template"})
TEMPLATE_MAX_BYTES = 5_000_000
_CF_VERSION_KEY = re.compile(r"""^\s*["']?AWSTemplateFormatVersion["']?\s*:""", re.MULTILINE)


class CfnLoader(yaml.SafeLoader):
    """SafeLoader that turns short tags into long-form intrinsics.

    `!Ref X` -> {"Ref": "X"}, `!GetAtt A.B` -> {"Fn::GetAtt": ["A", "B"]},
    `!Sub ...` -> {"Fn::Sub": ...}. Matches what `cdk synth` JSON looks like,
    so the template checks see the same shapes for both.
    """


def _construct_tag(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> dict[str, Any]:
    value: Any
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)  # type: ignore[arg-type]
    if suffix == "Ref":
        return {"Ref": value}
    if suffix == "Condition":
        return {"Condition": value}
    if suffix == "GetAtt" and isinstance(value, str):
        resource, _, attribute = value.partition(".")
        return {"Fn::GetAtt": [resource, attribute]}
    return {f"Fn::{suffix}": value}


CfnLoader.add_multi_constructor("!", _construct_tag)


def load_cfn_yaml(text: str) -> Any:
    """Parse CloudFormation YAML (short tags allowed)."""
    return yaml.load(text, Loader=CfnLoader)  # noqa: S506 - SafeLoader subclass


def parse_template_text(path: Path, text: str) -> Any:
    """Parse template text by suffix: JSON for .json, CloudFormation YAML otherwise."""
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return load_cfn_yaml(text)


def is_cf_template(path: Path) -> bool:
    """True for a CloudFormation template.

    Needs AWSTemplateFormatVersion, or a Resources entry whose Type starts with AWS::.
    Other YAML and JSON (GitHub Actions, package.json) is not a template.
    """
    if path.suffix.lower() not in TEMPLATE_SUFFIXES:
        return False
    text = read_text_safe(path, max_bytes=TEMPLATE_MAX_BYTES)
    if "AWSTemplateFormatVersion" not in text and "AWS::" not in text:
        return False
    try:
        doc = parse_template_text(path, text)
    except (ValueError, yaml.YAMLError):
        # Unparseable (e.g. truncated): fall back to a top-level version key.
        return bool(_CF_VERSION_KEY.search(text))
    if not isinstance(doc, dict):
        return False
    if "AWSTemplateFormatVersion" in doc:
        return True
    resources = doc.get("Resources")
    if not isinstance(resources, dict):
        return False
    return any(
        isinstance(res, dict) and isinstance(res.get("Type"), str) and res["Type"].startswith("AWS::")
        for res in resources.values()
    )
