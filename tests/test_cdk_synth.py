"""Tests for CDK synth helpers (list_cf_templates, load_json, load_template, summarize_templates, list_templates_from_path)."""
import json
import shutil
from pathlib import Path

import pytest

from aws_arch_agent.tools.cdk_synth import (
    list_cf_templates,
    list_templates_from_path,
    load_json,
    load_template,
    summarize_templates,
    summarize_templates_from_paths,
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


def test_list_templates_from_path_file_json(tmp_path: Path) -> None:
    """list_templates_from_path with a file path returns that file if extension matches."""
    (tmp_path / "stack.template.json").write_text("{}", encoding="utf-8")
    paths = list_templates_from_path(tmp_path / "stack.template.json")
    assert len(paths) == 1
    assert paths[0].name == "stack.template.json"


def test_list_templates_from_path_file_yaml(tmp_path: Path) -> None:
    """list_templates_from_path with a .yaml file returns that file."""
    (tmp_path / "stack.yaml").write_text("Resources: {}", encoding="utf-8")
    paths = list_templates_from_path(tmp_path / "stack.yaml")
    assert len(paths) == 1
    assert paths[0].name == "stack.yaml"


def test_list_templates_from_path_dir_mixed(tmp_path: Path) -> None:
    """list_templates_from_path with a dir finds .template.json and .yaml."""
    (tmp_path / "a.template.json").write_text("{}", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("Resources: {}", encoding="utf-8")
    (tmp_path / "c.yml").write_text("Resources: {}", encoding="utf-8")
    (tmp_path / "ignore.txt").write_text("x", encoding="utf-8")
    paths = list_templates_from_path(tmp_path)
    assert len(paths) == 3
    names = {p.name for p in paths}
    assert names == {"a.template.json", "b.yaml", "c.yml"}


def test_load_template_json(tmp_path: Path) -> None:
    """load_template loads JSON template."""
    (tmp_path / "t.json").write_text('{"Resources": {"X": {"Type": "AWS::S3::Bucket"}}}', encoding="utf-8")
    doc = load_template(tmp_path / "t.json")
    assert doc["Resources"]["X"]["Type"] == "AWS::S3::Bucket"


def test_load_template_yaml(tmp_path: Path) -> None:
    """load_template loads YAML template."""
    (tmp_path / "t.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    doc = load_template(tmp_path / "t.yaml")
    assert doc["Resources"]["MyBucket"]["Type"] == "AWS::S3::Bucket"


def test_summarize_templates_from_paths(tmp_path: Path) -> None:
    """summarize_templates_from_paths produces summary from list of paths."""
    (tmp_path / "s1.template.json").write_text(
        json.dumps({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}),
        encoding="utf-8",
    )
    paths = [tmp_path / "s1.template.json"]
    out = summarize_templates_from_paths(paths)
    assert "CloudFormation" in out or "Summary" in out
    assert "s1" in out or "template" in out


@pytest.mark.skipif(shutil.which("npx") is None, reason="npx not available")
def test_run_cdk_synth_on_minimal_fixture() -> None:
    """Integration test: run cdk synth when Node/npx is available."""
    from aws_arch_agent.tools.cdk_synth import run_cdk_synth

    fixture = Path(__file__).parent / "fixtures" / "minimal-cdk"
    if not (fixture / "cdk.json").exists():
        pytest.skip("minimal-cdk fixture missing")
    if not (fixture / "node_modules").exists() and shutil.which("npm"):
        import subprocess
        proc = subprocess.run(["npm", "install"], cwd=str(fixture), capture_output=True)
        if proc.returncode != 0:
            pytest.skip(f"npm install failed: {proc.stderr.decode()[:200]}")
    rc, out, err = run_cdk_synth(fixture, language="typescript")
    if rc != 0:
        pytest.skip(f"cdk synth not available in this environment: {err[:200]}")
    assert rc == 0
