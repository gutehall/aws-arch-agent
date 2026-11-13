"""SUS 4: classification (REPO-151), access patterns (REPO-152), elastic block storage
(REPO-153), deleting unneeded data (REPO-154), shared storage (REPO-155) and backups of data
that is cheap to recreate (REPO-156)."""
from pathlib import Path

import pytest

from aws_arch_agent.agent.v1 import analyze_v1
from aws_arch_agent.rules.wa_map import NOT_CHECKED, RULE_BEST_PRACTICES

_RULES = (("REPO-151", "SUS04-BP01"), ("REPO-152", "SUS04-BP02"), ("REPO-153", "SUS04-BP04"),
          ("REPO-154", "SUS04-BP05"), ("REPO-155", "SUS04-BP06"), ("REPO-156", "SUS04-BP08"))
_VOLUME = 'resource "aws_ebs_volume" "{n}" {{\n  availability_zone = "a"\n  size = {size}\n}}\n'
_BUCKET = 'resource "aws_s3_bucket" "{n}" {{\n  bucket = "{n}"\n}}\n'
_PLAN = 'resource "aws_backup_selection" "s" {\n  name = "s"\n}\n'


def _scan(root: Path, files: dict[str, str]) -> list:
    for rel, text in files.items():
        path = root / "prod" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _report, _ctx, findings, _w = analyze_v1(root, use_llm=False)
    return findings


def _hits(findings: list, rule_id: str) -> list:
    return [f for f in findings if f.id == rule_id]


def test_rules_answer_sus4() -> None:
    for rule_id, bp in _RULES:
        assert RULE_BEST_PRACTICES[rule_id] == (bp,)
        assert bp not in NOT_CHECKED


def test_classification_is_the_repo_039_search(tmp_path: Path) -> None:
    findings = _scan(tmp_path, {"b.tf": _BUCKET.format(n="b")})
    (hit,) = _hits(findings, "REPO-151")
    assert hit.question == "SUS 4" and hit.severity == "Low"
    assert _hits(findings, "REPO-039")
    tagged = 'resource "aws_s3_bucket" "b" {\n  tags = {\n    DataClassification = "x"\n  }\n}\n'
    assert not _hits(_scan(tmp_path / "t", {"b.tf": tagged}), "REPO-151")


@pytest.mark.parametrize(
    "files",
    [
        {"i.tf": 'resource "aws_instance" "w" {\n  instance_type = "i3.large"\n}\n'},
        {"i.tf": 'resource "aws_instance" "w" {\n  instance_type = "m5d.xlarge"\n}\n'},
        {"i.json": '{"Resources": {"I": {"Type": "AWS::EC2::Instance", "Properties": '
                   '{"BlockDeviceMappings": [{"VirtualName": "ephemeral0"}]}}}}'},
    ],
    ids=["i3", "m5d", "ephemeral"],
)
def test_instance_store_without_a_durable_store_fires(tmp_path: Path, files: dict) -> None:
    (hit,) = _hits(_scan(tmp_path, files), "REPO-152")
    assert hit.question == "SUS 4" and hit.severity == "Low"


def test_instance_store_with_a_durable_store_passes(tmp_path: Path) -> None:
    files = {"i.tf": 'resource "aws_instance" "w" {\n  instance_type = "i3.large"\n}\n',
             "b.tf": _BUCKET.format(n="b")}
    assert not _hits(_scan(tmp_path, files), "REPO-152")


@pytest.mark.parametrize("kind", ["t3.large", "m6g.large", "c7g.xlarge"])
def test_plain_instances_do_not_count_as_instance_store(tmp_path: Path, kind: str) -> None:
    files = {"i.tf": f'resource "aws_instance" "w" {{\n  instance_type = "{kind}"\n}}\n'}
    assert not _hits(_scan(tmp_path, files), "REPO-152")


def test_large_fixed_volume_fires(tmp_path: Path) -> None:
    (hit,) = _hits(_scan(tmp_path, {"v.tf": _VOLUME.format(n="d", size=1000)}), "REPO-153")
    assert "1000 GiB" in hit.evidence and hit.question == "SUS 4"


@pytest.mark.parametrize(
    ("files", "fires"),
    [
        ({"v.tf": _VOLUME.format(n="d", size=100)}, False),
        ({"v.tf": _VOLUME.format(n="d", size=1000) + "# runs ebs-autoscale on boot\n"}, False),
        ({"v.tf": _VOLUME.format(n="d", size=10) + "  max_size = 900\n  MaxSize: 900\n"}, False),
        ({"v.tf": _VOLUME.format(n="d", size=1000), "u.sh": "x"}, True),
    ],
    ids=["small", "autoscale", "max-size-is-not-a-volume", "large-and-fixed"],
)
def test_large_fixed_volume_fires_only_when_nothing_grows_it(
    tmp_path: Path, files: dict, fires: bool
) -> None:
    assert bool(_hits(_scan(tmp_path, files), "REPO-153")) is fires


def test_bucket_without_retention_fires(tmp_path: Path) -> None:
    (hit,) = _hits(_scan(tmp_path, {"b.tf": _BUCKET.format(n="b")}), "REPO-154")
    assert hit.question == "SUS 4" and "prod/b.tf" in hit.evidence


def test_bucket_with_lifecycle_passes(tmp_path: Path) -> None:
    text = _BUCKET.format(n="b") + 'resource "aws_s3_bucket_lifecycle_configuration" "l" {}\n'
    assert not _hits(_scan(tmp_path, {"b.tf": text}), "REPO-154")


def test_two_volumes_without_shared_storage_fire(tmp_path: Path) -> None:
    files = {"v.tf": _VOLUME.format(n="a", size=10) + _VOLUME.format(n="b", size=10)}
    (hit,) = _hits(_scan(tmp_path, files), "REPO-155")
    assert "2 EBS volumes" in hit.evidence


@pytest.mark.parametrize(
    "extra",
    [{"e.tf": 'resource "aws_efs_file_system" "e" {}\n'}, {"b.tf": _BUCKET.format(n="b")}],
    ids=["efs", "s3"],
)
def test_shared_storage_passes(tmp_path: Path, extra: dict) -> None:
    files = {"v.tf": _VOLUME.format(n="a", size=10) + _VOLUME.format(n="b", size=10), **extra}
    assert not _hits(_scan(tmp_path, files), "REPO-155")


def test_one_volume_passes(tmp_path: Path) -> None:
    assert not _hits(_scan(tmp_path, {"v.tf": _VOLUME.format(n="a", size=10)}), "REPO-155")


@pytest.mark.parametrize(
    "resource",
    [
        'resource "aws_elasticache_cluster" "c" {\n  engine = "redis"\n}\n',
        'resource "aws_s3_bucket" "scratch" {\n  bucket = "app-scratch"\n}\n',
        'resource "aws_s3_bucket" "tmp" {\n  bucket = "app-tmp"\n}\n',
    ],
    ids=["cache", "scratch-bucket", "tmp-bucket"],
)
def test_backup_of_recreatable_data_fires(tmp_path: Path, resource: str) -> None:
    (hit,) = _hits(_scan(tmp_path, {"b.tf": _PLAN + resource}), "REPO-156")
    assert hit.question == "SUS 4" and hit.line


@pytest.mark.parametrize("name", ["attempts", "user-templates", "cachet"])
def test_bucket_name_containing_a_word_part_passes(tmp_path: Path, name: str) -> None:
    text = _PLAN + f'resource "aws_s3_bucket" "b" {{\n  bucket = "{name}"\n}}\n'
    assert not _hits(_scan(tmp_path, {"b.tf": text}), "REPO-156")


def test_backup_of_durable_data_passes(tmp_path: Path) -> None:
    text = _PLAN + 'resource "aws_dynamodb_table" "t" {\n  name = "orders"\n}\n'
    assert not _hits(_scan(tmp_path, {"b.tf": text}), "REPO-156")


def test_cache_without_a_backup_selection_passes(tmp_path: Path) -> None:
    text = 'resource "aws_elasticache_cluster" "c" {\n  engine = "redis"\n}\n'
    assert not _hits(_scan(tmp_path, {"b.tf": text}), "REPO-156")
