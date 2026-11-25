"""Scanner hardening: symlinks, read caps, string booleans, fail-closed filters, verdict cache."""
import json
import os
from pathlib import Path

import pytest

from aws_arch_agent import baseline as baseline_mod
from aws_arch_agent.agent import verdicts
from aws_arch_agent.agent.v2_graph import analyze_v2
from aws_arch_agent.rules import cf_template, regions
from aws_arch_agent.rules import terraform_model as tf
from aws_arch_agent.rules.cf_template import run_cf_rules_from_paths
from aws_arch_agent.rules.runner import filter_by_severity
from aws_arch_agent.tools import cdk_synth
from aws_arch_agent.tools import rg as rg_mod
from aws_arch_agent.tools.files import FileTooLargeError, read_text_capped, walk_files
from aws_arch_agent.tools.llm import LLMResult

needs_symlinks = pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")

CF_TEMPLATE = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- file walk -------------------------------------------------------------------------


@needs_symlinks
def test_walk_skips_symlinked_dirs_and_links_leaving_the_repo(tmp_path: Path) -> None:
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    _write(outside / "secret.py", "x = 1\n")
    _write(repo / "app.py", "y = 2\n")
    (repo / "linked_dir").symlink_to(outside, target_is_directory=True)
    (repo / "escape.py").symlink_to(outside / "secret.py")
    (repo / "alias.py").symlink_to(repo / "app.py")

    files, _ = walk_files(repo)

    names = sorted(p.name for p in files)
    assert names == ["alias.py", "app.py"]  # a link inside the repo stays


def test_read_text_capped_refuses_files_over_the_cap(tmp_path: Path) -> None:
    path = _write(tmp_path / "big.txt", "a" * 11)
    assert read_text_capped(path, 11) == "a" * 11
    with pytest.raises(FileTooLargeError):
        read_text_capped(path, 10)


# --- template listing and loading --------------------------------------------------------


@needs_symlinks
def test_template_listing_skips_symlinked_dirs(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    _write(outside / "evil.yaml", "a: 1\n")
    root = tmp_path / "templates"
    _write(root / "stack.yaml", "a: 1\n")
    (root / "linked").symlink_to(outside, target_is_directory=True)

    found = cdk_synth.list_templates_from_path(root)

    assert [p.name for p in found] == ["stack.yaml"]


def test_template_loaders_refuse_oversize_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cdk_synth, "TEMPLATE_MAX_BYTES", 10)
    big_json = _write(tmp_path / "a.template.json", json.dumps(CF_TEMPLATE))
    big_yaml = _write(tmp_path / "b.yaml", "AWSTemplateFormatVersion: '2010-09-09'\n")
    assert cdk_synth.load_json(big_json) == {}
    assert cdk_synth.load_template(big_yaml) == {}


def test_cf_rules_warn_on_an_oversize_template(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(cf_template, "TEMPLATE_MAX_BYTES", 10)
    path = _write(tmp_path / "stack.template.json", json.dumps(CF_TEMPLATE))
    warnings: list[str] = []

    findings = run_cf_rules_from_paths([path], warnings=warnings)

    assert findings == []
    assert any("limit" in w for w in warnings), warnings


def test_v2_templates_skip_files_that_are_not_cloudformation(tmp_path: Path) -> None:
    templates = tmp_path / "mixed"
    _write(templates / "ci.yml", "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
    bucket = {"AWSTemplateFormatVersion": "2010-09-09",
              "Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {}}}}
    _write(templates / "stack.template.json", json.dumps(bucket))

    _r, _ctx, findings, warnings = analyze_v2(
        tmp_path, use_llm=False, templates_path=str(templates), rules_include=["CF-S3-001"])

    files = {Path(f.file).name for f in findings if f.file}
    assert "ci.yml" not in files
    assert "stack.template.json" in files
    assert not any("ci.yml" in w for w in warnings)


# --- string booleans in CF rules --------------------------------------------------------


def _cf_ids(tmp_path: Path, resources: dict) -> set[str]:
    path = _write(tmp_path / "stack.template.json",
                  json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}))
    return {f.id for f in run_cf_rules_from_paths([path])}


def test_s3_public_access_block_accepts_string_booleans(tmp_path: Path) -> None:
    keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    bucket = {"Type": "AWS::S3::Bucket",
              "Properties": {"PublicAccessBlockConfiguration": {k: "true" for k in keys}}}
    assert "CF-S3-001" not in _cf_ids(tmp_path, {"B": bucket})


def test_s3_public_access_block_with_one_false_string_still_fires(tmp_path: Path) -> None:
    block = {"BlockPublicAcls": "true", "IgnorePublicAcls": "true",
             "BlockPublicPolicy": "false", "RestrictPublicBuckets": True}
    bucket = {"Type": "AWS::S3::Bucket", "Properties": {"PublicAccessBlockConfiguration": block}}
    assert "CF-S3-001" in _cf_ids(tmp_path, {"B": bucket})


@pytest.mark.parametrize("value", [True, "true", "True"])
def test_rds_publicly_accessible_string_boolean_fires(tmp_path: Path, value) -> None:
    db = {"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": value}}
    assert "CF-RDS-004" in _cf_ids(tmp_path, {"Db": db})


def test_rds_publicly_accessible_false_string_is_quiet(tmp_path: Path) -> None:
    db = {"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": "false"}}
    assert "CF-RDS-004" not in _cf_ids(tmp_path, {"Db": db})


# --- Terraform ---------------------------------------------------------------------------


def test_terraform_region_keeps_looking_past_an_unreadable_provider(tmp_path: Path) -> None:
    module = tmp_path / "infra"
    _write(module / "a.tf", 'variable "r" {}\nprovider "aws" {\n  region = var.r\n}\n')
    _write(module / "b.tf", 'provider "aws" {\n  region = "eu-west-1"\n}\n')
    assert regions.terraform_provider_region(module) == "eu-west-1"


def test_terraform_loads_refuse_oversize_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(tf, "TF_FILE_MAX_CHARS", 10)
    monkeypatch.setattr(tf, "TF_PLAN_MAX_CHARS", 10)
    hcl = _write(tmp_path / "main.tf", 'provider "aws" {\n  region = "eu-west-1"\n}\n')
    plan = _write(tmp_path / "plan.json", json.dumps({"planned_values": {"root_module": {}}}))
    with pytest.raises(tf.TerraformError, match="limit"):
        tf._load_tf(hcl)
    with pytest.raises(tf.TerraformError, match="limit"):
        tf.load_plan_modules(plan)
    assert regions.terraform_plan_region(plan) is None


# --- baseline, rg fallback, severity threshold -------------------------------------------


def test_baseline_over_the_cap_is_an_error(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(baseline_mod, "BASELINE_MAX_CHARS", 10)
    path = _write(tmp_path / "baseline.json", json.dumps({"accepted": []}))
    with pytest.raises(baseline_mod.BaselineError, match="limit"):
        baseline_mod.load_baseline(path)
    assert baseline_mod.load_cost_snapshot(path) is None


def test_rg_fallback_skips_files_over_the_cap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(rg_mod, "FALLBACK_MAX_CHARS", 20)
    _write(tmp_path / "small.py", "needle = 1\n")
    _write(tmp_path / "big.py", "needle = 1\n" + "#" * 50 + "\n")

    hits = rg_mod._fallback_search(tmp_path, "needle", "**/*.py", 10, ())

    assert [h[0] for h in hits] == ["small.py"]


def test_unknown_severity_threshold_fails_closed() -> None:
    with pytest.raises(ValueError, match="severity_threshold"):
        filter_by_severity([], "hhigh")


# --- V2 graph ----------------------------------------------------------------------------


def test_v2_unreadable_repo_root_is_a_warning(tmp_path: Path, monkeypatch) -> None:
    real_iterdir = Path.iterdir

    def iterdir(self: Path):
        if self == tmp_path:
            raise PermissionError("denied")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    _r, ctx, _findings, warnings = analyze_v2(tmp_path, use_llm=False, skip_synth=True)

    assert ctx.notes["top_level"] == []
    assert any("repo root" in w for w in warnings), warnings


def test_verdict_cache_is_keyed_by_repo_and_bounded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(verdicts, "VERDICT_CACHE_MAX", 2)
    cache: verdicts.VerdictCache = {}
    for key in ("a", "b", "c"):
        verdicts._remember(cache, key, ({}, None))  # type: ignore[arg-type]
    assert list(cache) == ["b", "c"]

    prompts: list[str] = []

    class FakeLLM:
        def prompt_chars(self, limit: int) -> int:
            return limit

        def polish(self, prompt: str, **_kw):
            prompts.append(prompt)
            return LLMResult(text="{}", status="ok")

    monkeypatch.setattr(verdicts, "build_prompt", lambda *_a, **_k: "same prompt")
    monkeypatch.setattr(verdicts, "parse_reply", lambda *_a, **_k: {})
    shared: verdicts.VerdictCache = {}
    for repo in (tmp_path / "one", tmp_path / "two", tmp_path / "one"):
        repo.mkdir(exist_ok=True)
        verdicts.judge_batch(FakeLLM(), [], repo, cache=shared)  # type: ignore[arg-type]
    assert len(prompts) == 2  # the second repo asks again; the first repo's rerun is cached


@needs_symlinks
def test_real_template_discovery_skips_file_links_leaving_the_tree(tmp_path: Path) -> None:
    outside = _write(tmp_path / "outside" / "evil.template.json", json.dumps(CF_TEMPLATE))
    root = tmp_path / "templates"
    _write(root / "stack.template.json", json.dumps(CF_TEMPLATE))
    (root / "escape.template.json").symlink_to(outside)

    found = cdk_synth.list_templates_from_path(root, real_only=True)

    assert [p.name for p in found] == ["stack.template.json"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this platform")
def test_read_text_capped_refuses_a_fifo_instead_of_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe.json"
    os.mkfifo(fifo)
    with pytest.raises(OSError, match="not a regular file"):
        read_text_capped(fifo, 100)


def test_v2_rejects_an_unknown_severity_threshold_before_scanning(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="severity_threshold"):
        analyze_v2(tmp_path, use_llm=False, skip_synth=True, severity_threshold="hhigh")
