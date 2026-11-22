"""Cost diffing, CI budget guardrails, and the FinOps CLI and config options."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aws_arch_agent import pricing
from aws_arch_agent.cli import app
from aws_arch_agent.config import ConfigError, load_config
from aws_arch_agent.rules import cost_diff
from aws_arch_agent.rules.cost_diff import Budget

runner = CliRunner()
NAT_MONTH = 32.85  # 730 h × $0.045 in the test prices


def _cost(resources: list[tuple[str, float]], stack: str = "t.json", **extra: object) -> dict:
    return {
        "region": "us-east-1",
        "total_monthly_usd": round(sum(usd for _, usd in resources), 2),
        "stacks": [{"name": stack, "monthly_usd": round(sum(usd for _, usd in resources), 2)}],
        "resources": [{"stack": stack, "name": n, "type": "AWS::X", "monthly_usd": usd} for n, usd in resources],
        **extra,
    }


def test_diff_lists_added_removed_and_changed() -> None:
    before = cost_diff.snapshot(_cost([("Web", 70.08), ("Old", 10.0), ("Db", 100.0)]))
    after = _cost([("Web", 140.16), ("Db", 100.0), ("New", 5.0)])
    change = cost_diff.diff(before, after, "base.json")
    assert change["previous_monthly_usd"] == 180.08 and change["current_monthly_usd"] == 245.16
    assert change["delta_monthly_usd"] == 65.08 and change["delta_percent"] == 36.1
    assert [r["name"] for r in change["added"]] == ["New"]
    assert [r["name"] for r in change["removed"]] == ["Old"]
    assert change["changed"] == [{"stack": "t.json", "name": "Web", "type": "AWS::X", "previous_monthly_usd": 70.08,
                                  "current_monthly_usd": 140.16, "delta_monthly_usd": 70.08}]
    assert cost_diff.diff({"total_monthly_usd": 0, "resources": []}, after)["delta_percent"] is None


def test_snapshot_adds_fixed_and_usage_cost_of_one_resource() -> None:
    cost = _cost([("Nat", 32.85)])
    cost["resources"].append({"stack": "t.json", "name": "Nat", "type": "AWS::X", "monthly_usd": 45.0,
                              "usage_assumed": True})
    assert cost_diff.snapshot(cost)["resources"] == [
        {"stack": "t.json", "name": "Nat", "type": "AWS::X", "monthly_usd": 77.85}]


@pytest.mark.parametrize("budget, total, delta, pct, passed, words", [
    (Budget(max_monthly_usd=100), 120.0, None, None, False, "over the $100.00/month budget"),
    (Budget(max_monthly_usd=200), 120.0, None, None, True, ""),
    (Budget(max_increase_usd=50), 120.0, 60.0, 100.0, False, "rises $60.00/month"),
    (Budget(max_increase_percent=10), 120.0, 60.0, 100.0, False, "rises 100%"),
    (Budget(max_increase_percent=10), 120.0, 5.0, None, False, "from $0.00"),
    (Budget(max_increase_usd=50, max_increase_percent=200), 120.0, 20.0, 20.0, True, ""),
])
def test_budget_evaluation(budget: Budget, total: float, delta: float | None, pct: float | None,
                           passed: bool, words: str) -> None:
    cost = {"total_monthly_usd": total}
    if delta is not None:
        cost["diff"] = {"delta_monthly_usd": delta, "delta_percent": pct}
    result = cost_diff.evaluate(budget, cost)
    assert result["passed"] is passed
    assert all(words in line for line in result["breaches"]) and bool(result["breaches"]) is not passed


def test_increase_limit_without_a_comparison_is_not_checked() -> None:
    result = cost_diff.evaluate(Budget(max_increase_usd=1), {"total_monthly_usd": 500.0})
    assert result["passed"] and result["not_checked"] == ["cost increase (no --compare-cost to compare with)"]


def test_load_previous(tmp_path: Path) -> None:
    (tmp_path / "base.json").write_text(json.dumps({"accepted": [], "cost_snapshot": {"total_monthly_usd": 9}}))
    assert cost_diff.load_previous(tmp_path / "base.json") == {"total_monthly_usd": 9}
    (tmp_path / "report.json").write_text(json.dumps({"context": {"notes": {"cost": _cost([("Web", 1.5)])}}}))
    assert cost_diff.load_previous(tmp_path / "report.json")["resources"][0]["name"] == "Web"
    (tmp_path / "old.json").write_text(json.dumps({"accepted": []}))  # a baseline from before cost snapshots
    for name, words in (("old.json", "no cost data"), ("missing.json", "cannot read"), ("bad.json", "not JSON")):
        if name == "bad.json":
            (tmp_path / name).write_text("{", encoding="utf-8")
        with pytest.raises(ConfigError, match=words):
            cost_diff.load_previous(tmp_path / name)


# --- Config ---------------------------------------------------------------------


def test_config_keys(tmp_path: Path) -> None:
    cfg = load_config(tmp_path)
    assert (cfg.pricing_source, cfg.price_cache_ttl_hours, cfg.usage_file) == ("auto", 24.0, None)
    assert (cfg.budget_max_monthly_usd, cfg.budget_max_increase_usd, cfg.budget_max_increase_percent) == (None,) * 3
    (tmp_path / ".aws-arch-agent.yaml").write_text(
        "pricing:\n  source: bulk\n  cache_ttl_hours: 6\nusage_file: finops/usage.yaml\n"
        "budget:\n  max_monthly_usd: 500\n  max_monthly_increase_usd: 50\n  max_increase_percent: 10\n",
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert (cfg.pricing_source, cfg.price_cache_ttl_hours) == ("bulk", 6.0)
    assert cfg.usage_file == str((tmp_path / "finops" / "usage.yaml").resolve())
    assert (cfg.budget_max_monthly_usd, cfg.budget_max_increase_usd, cfg.budget_max_increase_percent) == (500, 50, 10)
    # Flags win.
    cfg = load_config(tmp_path, pricing_source="off", price_cache_ttl_hours=1, max_monthly_cost=100,
                      max_cost_increase="5%", usage_file="u.yaml")
    assert (cfg.pricing_source, cfg.price_cache_ttl_hours, cfg.budget_max_monthly_usd) == ("off", 1.0, 100.0)
    assert (cfg.budget_max_increase_usd, cfg.budget_max_increase_percent) == (None, 5.0)
    assert cfg.usage_file == str(Path("u.yaml").resolve())
    assert load_config(tmp_path, max_cost_increase="$25").budget_max_increase_usd == 25.0


@pytest.mark.parametrize("text, words", [
    ("pricing:\n  source: sometimes\n", "pricing.source"),
    ("pricing:\n  cache_ttl_hours: -1\n", "zero or more"),
    ("pricing:\n  ttl: 1\n", "unknown key"),
    ("pricing: bulk\n", "must be a mapping"),
    ("budget:\n  max_monthly_usd: lots\n", "must be a number"),
    ("budget:\n  monthly: 1\n", "unknown key"),
    ("budget: 5\n", "must be a mapping"),
    ("budget:\n  max_monthly_usd: .nan\n", "must be a number"),
])
def test_bad_config(tmp_path: Path, text: str, words: str) -> None:
    (tmp_path / ".aws-arch-agent.yaml").write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match=words):
        load_config(tmp_path)
    with pytest.raises(ConfigError, match="--max-cost-increase"):
        load_config(tmp_path / "none", max_cost_increase="ten")


# --- CLI ------------------------------------------------------------------------


def _repo(root: Path, nats: int = 1) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    resources = {f"Nat{i}": {"Type": "AWS::EC2::NatGateway", "Properties": {"SubnetId": "s"}} for i in range(nats)}
    (root / "app.template.json").write_text(json.dumps({"Resources": resources}), encoding="utf-8")
    return root


V2 = ["--mode", "v2", "--templates"]


def _args(root: Path, mode: str, *extra: str) -> list[str]:
    scan = ["--repo", str(root)] if mode == "v1" else [*V2, str(root)]
    return [*scan, "--no-llm", "--format", "json", "--out", str(root / "report.json"), *extra]


def _notes(root: Path) -> dict:
    return json.loads((root / "report.json").read_text(encoding="utf-8"))["context"]["notes"]


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_budget_breach_fails_the_run(tmp_path: Path, mode: str) -> None:
    root = _repo(tmp_path / "r", nats=2)
    result = runner.invoke(app, _args(root, mode, "--max-monthly-cost", "50"))
    assert result.exit_code == 1, result.output
    assert "Budget breached: estimated $65.70/month is over the $50.00/month budget" in result.output
    budget = _notes(root)["cost"]["budget"]
    assert budget["passed"] is False and budget["max_monthly_usd"] == 50
    result = runner.invoke(app, _args(root, mode, "--max-monthly-cost", "100"))
    assert result.exit_code == 0, result.output
    assert "Budget: within limits" in result.output


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_compare_cost_against_a_baseline(tmp_path: Path, mode: str) -> None:
    root = _repo(tmp_path / "r", nats=1)
    base = root / "base.json"
    result = runner.invoke(app, _args(root, mode, "--baseline", str(base), "--update-baseline"))
    assert result.exit_code == 0, result.output
    snapshot = json.loads(base.read_text(encoding="utf-8"))["cost_snapshot"]
    assert snapshot["total_monthly_usd"] == NAT_MONTH and len(snapshot["resources"]) == 1

    _repo(root, nats=3)
    result = runner.invoke(app, _args(root, mode, "--compare-cost", str(base), "--max-cost-increase", "50"))
    assert result.exit_code == 1, result.output
    assert f"Cost vs {base}: $32.85 -> $98.55/month (+65.70, +200%); 2 added, 0 removed, 0 changed" in result.output
    assert "Budget breached: cost rises $65.70/month, over the $50.00/month limit" in result.output
    change = _notes(root)["cost"]["diff"]
    assert [r["name"] for r in change["added"]] == ["Nat1", "Nat2"] and change["delta_percent"] == 200.0
    result = runner.invoke(app, _args(root, mode, "--compare-cost", str(base), "--max-cost-increase", "250%"))
    assert result.exit_code == 0, result.output


def test_compare_cost_against_an_earlier_report(tmp_path: Path) -> None:
    root = _repo(tmp_path / "r", nats=2)
    assert runner.invoke(app, _args(root, "v1")).exit_code == 0
    earlier = root / "earlier.json"
    (root / "report.json").rename(earlier)
    _repo(root, nats=1)
    result = runner.invoke(app, _args(root, "v1", "--compare-cost", str(earlier)))
    assert result.exit_code == 0, result.output
    change = _notes(root)["cost"]["diff"]
    assert [r["name"] for r in change["removed"]] == ["Nat1"] and change["delta_monthly_usd"] == -NAT_MONTH


def test_update_baseline_keeps_old_baselines_loading(tmp_path: Path) -> None:
    root = _repo(tmp_path / "r")
    base = root / "base.json"
    base.write_text(json.dumps({"accepted": [{"id": "CF-X", "file": "template.json", "evidence_hash": None}]}))
    result = runner.invoke(app, _args(root, "v1", "--baseline", str(base), "--enforce-baseline"))
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, _args(root, "v1", "--compare-cost", str(base)))
    assert result.exit_code != 0 and "no cost data" in result.output


def test_save_baseline_keeps_or_replaces_the_snapshot(tmp_path: Path) -> None:
    from aws_arch_agent.baseline import load_baseline, load_cost_snapshot, save_baseline

    path = tmp_path / "base.json"
    save_baseline(path, set(), {"total_monthly_usd": 1})
    save_baseline(path, set())  # a scan with no cost keeps the earlier snapshot
    assert load_cost_snapshot(path) == {"total_monthly_usd": 1} and load_baseline(path) == set()
    save_baseline(path, set(), {"total_monthly_usd": 2})
    assert load_cost_snapshot(path) == {"total_monthly_usd": 2}
    assert load_cost_snapshot(tmp_path / "missing.json") is None


def test_bad_compare_file_is_a_usage_error(tmp_path: Path) -> None:
    root = _repo(tmp_path / "r")
    result = runner.invoke(app, _args(root, "v1", "--compare-cost", str(root / "nope.json")))
    assert result.exit_code != 0 and "--compare-cost: cannot read" in result.output


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_pricing_flags_reach_the_provider(tmp_path: Path, mode: str) -> None:
    root = _repo(tmp_path / "r")
    result = runner.invoke(app, _args(root, mode, "--pricing-source", "bulk", "--price-cache-ttl", "2",
                                      "--refresh-prices"))
    assert result.exit_code == 0, result.output
    assert pricing.provider().calls[-1] == {"source": "bulk", "ttl_hours": 2.0, "refresh": True}  # type: ignore[attr-defined]
    result = runner.invoke(app, _args(root, mode, "--pricing-source", "off"))
    assert result.exit_code == 0, result.output
    cost = _notes(root)["cost"]  # nothing priced
    assert cost["total_monthly_usd"] == 0 and cost["stacks"][0]["resources_priced"] == 0
    result = runner.invoke(app, _args(root, mode, "--pricing-source", "sometimes"))
    assert result.exit_code != 0 and "--pricing-source" in result.output


def test_real_configure_builds_the_hybrid_provider(tmp_path: Path) -> None:
    real = pricing.provider().real_configure  # type: ignore[attr-defined]
    hybrid = real("bulk", 2, refresh=True, cache_path=tmp_path / "c.sqlite3")
    assert isinstance(hybrid, pricing.HybridPriceProvider) and hybrid.source == "bulk"
    assert hybrid.cache.ttl_seconds == 7200 and hybrid.cache.path == tmp_path / "c.sqlite3"
    assert isinstance(real("off"), pricing.OffPriceProvider)


@pytest.mark.parametrize("mode", ["v1", "v2"])
def test_usage_file_flag_and_default_file(tmp_path: Path, mode: str) -> None:
    root = _repo(tmp_path / "r")
    usage = root / "u.yaml"
    usage.write_text("defaults:\n  nat_gateway:\n    monthly_data_processed_gb: 100\n", encoding="utf-8")
    result = runner.invoke(app, _args(root, mode, "--usage-file", str(usage)))
    assert result.exit_code == 0, result.output
    cost = _notes(root)["cost"]
    assert cost["usage_monthly_usd"] == 4.5 and cost["fixed_monthly_usd"] == NAT_MONTH
    assert cost["usage_file"] == str(usage)
    usage.rename(root / ".aws-arch-agent-usage.yaml")
    assert runner.invoke(app, _args(root, mode)).exit_code == 0
    assert _notes(root)["cost"]["usage_monthly_usd"] == 4.5
    (root / ".aws-arch-agent-usage.yaml").write_text("defaults:\n  nat_gateway:\n    x: 1\n", encoding="utf-8")
    result = runner.invoke(app, _args(root, mode))
    assert result.exit_code != 0 and "unknown key" in result.output


def test_cdk_in_v1_gets_a_cost_hint(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"dependencies": {"aws-cdk-lib": "2"}}', encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "stack.ts").write_text('new s3.Bucket(this, "B");', encoding="utf-8")
    result = runner.invoke(app, ["--repo", str(tmp_path), "--no-llm", "--format", "json",
                                 "--out", str(tmp_path / "report.json"), "--max-monthly-cost", "1"])
    assert result.exit_code == 0, result.output
    assert "CDK source is not priced in V1: run --mode v2" in result.output
    assert "No stack was priced, so the cost comparison and budget were not checked." in result.output
    assert "--mode v2" in _notes(tmp_path)["cost_hint"]
