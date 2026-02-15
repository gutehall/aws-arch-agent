"""Tests for CDK synth helpers (list_cf_templates, load_json, summarize_templates)."""
import json
from pathlib import Path

import pytest

from aws_arch_agent.tools.cdk_synth import (
    list_cf_templates,
    load_json,
    summarize_templates,
)


def test_list_cf_templates_empty_dir(tmp_path: Path) -> None:
    """Empty or missing cdk.out returns empty list."""
    assert list_cf_templates(tmp_path) == []
    (tmp_path / "cdk.out").mkdir()
    assert list_cf_templates(tmp_path / "cdk.out") == []


def test_list_cf_templates_finds_json(tmp_path: Path) -> None:
    """Finds *.template.json under cdk.out."""
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    (cdk_out / "Stack.template.json").write_text("{}", encoding="utf-8")
    (cdk_out / "Other.template.json").write_text("{}", encoding="utf-8")
    (cdk_out / "notemplate.txt").write_text("x", encoding="utf-8")
    paths = list_cf_templates(cdk_out)
    assert len(paths) == 2
    names = [p.name for p in paths]
    assert "Stack.template.json" in names
    assert "Other.template.json" in names


def test_load_json_valid(tmp_path: Path) -> None:
    """load_json returns dict for valid JSON file."""
    f = tmp_path / "a.json"
    f.write_text('{"Resources": {"A": {"Type": "AWS::S3::Bucket"}}}', encoding="utf-8")
    data = load_json(f)
    assert data["Resources"]["A"]["Type"] == "AWS::S3::Bucket"


def test_load_json_invalid_returns_empty(tmp_path: Path) -> None:
    """load_json returns empty dict on invalid JSON."""
    f = tmp_path / "bad.json"
    f.write_text("not json", encoding="utf-8")
    assert load_json(f) == {}


def test_summarize_templates_empty(tmp_path: Path) -> None:
    """summarize_templates with no templates returns message."""
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    out = summarize_templates(cdk_out)
    assert "No synthesized templates" in out or "cdk.out" in out


def test_summarize_templates_with_fixture(tmp_path: Path) -> None:
    """summarize_templates produces summary lines for template files."""
    cdk_out = tmp_path / "cdk.out"
    cdk_out.mkdir()
    template = {"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}
    (cdk_out / "MyStack.template.json").write_text(json.dumps(template), encoding="utf-8")
    out = summarize_templates(cdk_out)
    assert "Synthesized CloudFormation" in out or "Summary" in out
    assert "MyStack" in out or "template" in out
    assert "S3" in out or "Resources" in out
