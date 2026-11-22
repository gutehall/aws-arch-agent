"""Read CloudFormation templates: short-tag YAML, JSON, and real-template detection."""
from __future__ import annotations

import bisect
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
    if text.lstrip().startswith("{"):
        # JSON in a .template file; PyYAML rejects tab indentation that JSON allows.
        try:
            return json.loads(text)
        except ValueError:
            pass
    return load_cfn_yaml(text)


_JSON_WS = re.compile(r"[ \t\n\r]*")


def _resource_lines_json(text: str) -> dict[str, int]:
    """1-based line of each logical ID under the top-level "Resources" object of JSON text.

    Walks only the top-level object and the Resources object; every other value is
    skipped with raw_decode. Returns {} when the text is not shaped as expected.
    """
    decoder = json.JSONDecoder()
    newlines = [i for i, ch in enumerate(text) if ch == "\n"]

    def line_at(pos: int) -> int:
        return bisect.bisect_right(newlines, pos) + 1

    def skip(pos: int) -> int:
        return _JSON_WS.match(text, pos).end()  # type: ignore[union-attr]

    def keys(pos: int, on_key: Any) -> int:
        """Walk the object starting at pos; call on_key(key, key_pos, value_pos); return its end."""
        pos = skip(pos)
        if text[pos:pos + 1] != "{":
            raise ValueError("not an object")
        pos = skip(pos + 1)
        if text[pos:pos + 1] == "}":
            return pos + 1
        while True:
            if text[pos:pos + 1] != '"':
                raise ValueError("expected a key")
            key, end = json.decoder.scanstring(text, pos + 1)  # type: ignore[attr-defined]
            end = skip(end)
            if text[end:end + 1] != ":":
                raise ValueError("expected ':'")
            value_pos = skip(end + 1)
            pos = skip(on_key(key, pos, value_pos))
            if text[pos:pos + 1] == ",":
                pos = skip(pos + 1)
                continue
            if text[pos:pos + 1] == "}":
                return pos + 1
            raise ValueError("expected ',' or '}'")

    lines: dict[str, int] = {}

    def resource(key: str, key_pos: int, value_pos: int) -> int:
        lines[key] = line_at(key_pos)
        return decoder.raw_decode(text, value_pos)[1]

    def top(key: str, key_pos: int, value_pos: int) -> int:
        if key == "Resources" and text[value_pos:value_pos + 1] == "{":
            lines.clear()  # a duplicate key wins, as json.loads keeps the last one
            return keys(value_pos, resource)
        return decoder.raw_decode(text, value_pos)[1]

    try:
        keys(0, top)
    except (ValueError, IndexError):
        return {}
    return lines


def _load_yaml_with_lines(text: str) -> tuple[Any, dict[str, int]]:
    """Compose CloudFormation YAML once: the document, and each Resources key's 1-based line."""
    loader = CfnLoader(text)
    try:
        node = loader.get_single_node()
        doc = loader.construct_document(node) if node is not None else None
    finally:
        loader.dispose()
    lines: dict[str, int] = {}
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            if getattr(key_node, "value", None) == "Resources" and isinstance(value_node, yaml.MappingNode):
                # Count "\n" before the key, as every other line number in a scan does. PyYAML's
                # own mark.line also breaks on \r, \x85 and \u2028, which would shift the line.
                lines = {
                    str(k.value): text.count("\n", 0, k.start_mark.index) + 1
                    for k, _ in value_node.value
                    if isinstance(k, yaml.ScalarNode)
                }
    return doc, lines


def parse_template_with_lines(path: Path, text: str) -> tuple[Any, dict[str, int]]:
    """Parse template text like parse_template_text, plus the 1-based line of each logical ID
    under Resources. Lines are best effort: a resource the scan cannot place is left out."""
    if path.suffix.lower() == ".json":
        return json.loads(text), _resource_lines_json(text)
    if text.lstrip().startswith("{"):
        try:
            return json.loads(text), _resource_lines_json(text)
        except ValueError:
            pass
    return _load_yaml_with_lines(text)


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
    except Exception:  # noqa: BLE001 - any parse failure means "not readable as a template"
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
