"""Which environment a stack is for."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent.cli import app
from aws_arch_agent.config import ConfigError, load_config
from aws_arch_agent.report.schema import REPORT_SCHEMA
from aws_arch_agent.rules import environments
from aws_arch_agent.rules.environments import from_words, resolve, use_environments
from aws_arch_agent.rules.resource_model import Resource

DB = {"Type": "AWS::RDS::DBInstance", "Properties": {
    "DBInstanceClass": "db.t3.micro", "Engine": "postgres", "StorageEncrypted": True,
    "BackupRetentionPeriod": 7}}

BUCKET = {"Type": "AWS::S3::Bucket", "Properties": {}}


def _repo(root: Path) -> Path:
    for env in ("dev", "prod"):
        d = root / "infra" / env
        d.mkdir(parents=True)
        (d / "stack.json").write_text(json.dumps({"AWSTemplateFormatVersion": "2010-09-09",
                                                  "Resources": {"Db": DB, "Bucket": BUCKET}}),
                                       encoding="utf-8")
    return root


def _scan(repo: Path) -> list[dict]:
    out = repo / "r.json"
    result = CliRunner().invoke(app, ["--repo", str(repo), "--no-llm", "--format", "json", "--out", str(out)])
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text(encoding="utf-8"))["findings"]


def test_infra_dev_and_prod_get_their_environment(tmp_path: Path) -> None:
    """Done when: each finding has the right environment, and a prod-only rule skips dev."""
    findings = _scan(_repo(tmp_path))
    by_file: dict[str, set[str]] = {}
    for f in findings:
        by_file.setdefault(f["file"], set()).add(f["environment"])
    assert by_file == {"infra/dev/stack.json": {"dev"}, "infra/prod/stack.json": {"prod"}}
    multi_az = {f["file"] for f in findings if f["id"] == "CF-RDS-003"}
    assert multi_az == {"infra/prod/stack.json"}  # Multi-AZ advice is prod-only


def test_config_overrides_detection(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".aws-arch-agent.yaml").write_text(
        "environments:\n  'infra/prod/**': staging\n  'infra/dev/**': prod\n", encoding="utf-8")
    findings = _scan(repo)
    assert {f["file"]: f["environment"] for f in findings} == {
        "infra/dev/stack.json": "prod", "infra/prod/stack.json": "staging"}
    # Multi-AZ advice is prod-only: the dev dir is configured as prod, prod as staging.
    assert {f["file"] for f in findings if f["id"] == "CF-RDS-003"} == {"infra/dev/stack.json"}


def test_dev_softens_durability_rules(tmp_path: Path) -> None:
    d = tmp_path / "dev"
    d.mkdir()
    (d / "stack.json").write_text(json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": {
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}), encoding="utf-8")
    findings = {f["id"]: f for f in _scan(tmp_path)}
    assert findings["CF-S3-003"]["severity"] == "Low" and findings["CF-S3-003"]["environment"] == "dev"
    assert "CF-DEL-001" not in findings  # retain-on-delete is skipped in dev


@pytest.mark.parametrize("texts,expected", [
    (("infra/prod/stack.json",), "prod"),
    (("MyAppDevStack",), "dev"),
    (("services/payments-staging",), "staging"),
    (("envs/sandbox/main.tf",), "dev"),
    (("uat.yaml",), "staging"),
    (("prod-to-dev-migration",), "prod"),  # prod wins
    (("products/devices",), None),          # whole words only
    (("infra/network",), None),
])
def test_words(texts, expected) -> None:
    assert from_words(*texts) == expected


def _res(tags=None, inherited=None) -> Resource:
    return Resource(type="s3_bucket", name="B", properties={} if tags is None else {"Tags": tags},
                    source_type="AWS::S3::Bucket", inherited_tags=inherited if inherited is not None else {})


def test_resolve_order(tmp_path: Path) -> None:
    template = tmp_path / "stack.json"
    tagged = [_res([{"Key": "Environment", "Value": "Development"}]), _res()]
    with use_environments(None, tmp_path):
        assert resolve(template, tagged) == "dev"   # the tag, with no word in the path
        assert resolve(template, [_res()]) == "unknown"
        mixed = [_res({"Environment": "prod"}), _res({"Environment": "dev"})]
        assert resolve(template, mixed) == "prod"  # tags disagree: the most-prod one wins
        # Inherited (default_tags) count; a prod file name still wins over a dev tag.
        assert resolve(template, [_res(inherited={"Environment": "dev"})]) == "dev"
        assert resolve(tmp_path / "prod.json", [_res(inherited={"Environment": "dev"})]) == "prod"
    with use_environments({"tag:Development": "staging", "*.json": "prod"}, tmp_path):
        assert resolve(template, tagged) == "staging"  # first matching key wins
        assert resolve(template, [_res()]) == "prod"
    with use_environments(None, None):
        # Outside a repo only the file name counts, not the directories above it.
        assert resolve(tmp_path / "test_dir" / "stack.json", []) == "unknown"


def test_unknown_and_prod_are_never_softened() -> None:
    from aws_arch_agent.models import Finding

    for env in ("unknown", "prod"):
        f = Finding(id="CF-RDS-003", title="t", severity="Medium", recommendation="r")
        with use_environments({"*": env} if env != "unknown" else None, None):
            kept = environments.apply([f], Path("stack.json"), [])
        assert kept == [f] and f.severity == "Medium" and f.environment == env


def test_config_validation(tmp_path: Path) -> None:
    assert load_config(tmp_path).environments is None
    (tmp_path / ".aws-arch-agent.yaml").write_text("environments:\n  'infra/dev/**': dev\n", encoding="utf-8")
    assert load_config(tmp_path).environments == {"infra/dev/**": "dev"}
    for bad in ("environments: [dev]\n", "environments:\n  x: production\n"):
        (tmp_path / ".aws-arch-agent.yaml").write_text(bad, encoding="utf-8")
        with pytest.raises(ConfigError, match="environments"):
            load_config(tmp_path)


def test_reports_show_the_environment(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    out = repo / "r.md"
    result = CliRunner().invoke(app, ["--repo", str(repo), "--no-llm", "--out", str(out)])
    assert result.exit_code == 0, result.output
    md = out.read_text(encoding="utf-8")
    assert "- Environment: **dev**" in md and "- Environment: **prod**" in md
    out_html = repo / "r.html"
    CliRunner().invoke(app, ["--repo", str(repo), "--no-llm", "--format", "html", "--out", str(out_html)])
    assert "Environment: <b>dev</b>" in out_html.read_text(encoding="utf-8")
    out_sarif = repo / "r.sarif"
    CliRunner().invoke(app, ["--repo", str(repo), "--no-llm", "--format", "sarif", "--out", str(out_sarif)])
    results = json.loads(out_sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
    assert {r["properties"]["environment"] for r in results} == {"dev", "prod"}
    assert "environment" in REPORT_SCHEMA["properties"]["findings"]["items"]["properties"]


def test_terraform_module_directory(tmp_path: Path) -> None:
    for env in ("staging", "prod"):
        d = tmp_path / "envs" / env
        d.mkdir(parents=True)
        (d / "main.tf").write_text(
            'resource "aws_db_instance" "db" {\n  engine = "postgres"\n  instance_class = "db.t3.micro"\n'
            '  storage_encrypted = true\n  backup_retention_period = 7\n}\n'
            'variable "db_password" {\n  type = string\n}\n', encoding="utf-8")
    findings = _scan(tmp_path)
    envs = {(f["file"].split("/")[1], f["id"]): f["environment"] for f in findings}
    assert envs[("staging", "CF-PAR-001")] == "staging"  # variable findings too
    assert {e for (d, _), e in envs.items() if d == "prod"} == {"prod"}


def test_signals_never_make_a_prod_stack_dev(tmp_path: Path) -> None:
    """Unknown must lean prod: any prod signal, or a tag the scan cannot read, wins."""
    dev_dir = tmp_path / "infra" / "dev"
    template = dev_dir / "stack.json"
    with use_environments(None, tmp_path):
        assert resolve(template, [_res()]) == "dev"
        assert resolve(template, [_res({"Environment": "production"})]) == "prod"  # prod tag in a dev dir
        assert resolve(tmp_path / "prod" / "s.json", [_res({"Environment": "dev"})]) == "prod"  # stray dev tag
        ref = [_res([{"Key": "Environment", "Value": {"Ref": "Env"}}]), _res({"Environment": "dev"})]
        assert resolve(template, ref) == "prod"  # one tag from a parameter: could be prod
        if_tags = [_res({"Fn::If": ["IsProd", {"Environment": "prod"}, {"Environment": "dev"}]})]
        assert resolve(template, if_tags) == "prod"
        unresolved = Resource(type="s3_bucket", name="aws_s3_bucket.b", properties={}, source_type="aws_s3_bucket",
                              unresolved=frozenset({"Tags"}))
        assert resolve(template, [unresolved]) == "prod"  # tags = var.tags
        assert resolve(template, [_res({"Environment": "blue"})]) == "prod"  # unrecognised value


def test_globs_stay_inside_a_segment(tmp_path: Path) -> None:
    nested = tmp_path / "infra" / "prod" / "team" / "app.template.json"
    with use_environments({"infra/*": "dev"}, tmp_path):
        assert resolve(nested, []) == "prod"  # infra/* does not reach infra/prod/team/...
    with use_environments({"infra/**": "dev"}, tmp_path):
        assert resolve(nested, []) == "dev"
    with use_environments({"**/team/*.template.json": "staging"}, tmp_path):
        assert resolve(nested, []) == "staging"


def test_config_globs_are_repo_relative(tmp_path: Path) -> None:
    (tmp_path / ".aws-arch-agent.yaml").write_text(
        "environments:\n  './infra/dev/**': dev\n  '/infra/qa/**': staging\n  'tag:Live': prod\n",
        encoding="utf-8")
    assert load_config(tmp_path).environments == {"infra/dev/**": "dev", "infra/qa/**": "staging", "tag:Live": "prod"}


def test_cdk_source_findings_are_unknown(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    findings = _scan(tmp_path)
    assert findings and {f["environment"] for f in findings} == {"unknown"}
