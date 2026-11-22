"""Cost diffing against an earlier scan, and CI budget guardrails.

An earlier scan's costs come from a baseline file's `cost_snapshot` (written by
--update-baseline) or from a JSON report's `context.notes.cost`; --compare-cost names
either. The diff lists resources added, removed and changed (resized, or rescaled) by
stack and name, and the total and percentage change.

A budget (--max-monthly-cost, --max-cost-increase, config budget.*) is checked against
the estimated total and the diff. A breach fails the run with exit code 1.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aws_arch_agent.config import ConfigError

SNAPSHOT_VERSION = 1


@dataclass(frozen=True)
class Budget:
    max_monthly_usd: float | None = None
    max_increase_usd: float | None = None
    max_increase_percent: float | None = None

    def is_set(self) -> bool:
        return any(v is not None for v in (self.max_monthly_usd, self.max_increase_usd, self.max_increase_percent))


def _resources(cost: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """(stack, name) -> {type, monthly_usd}: fixed and usage-assumed cost added together."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for r in cost.get("resources") or []:
        key = (str(r.get("stack", "")), str(r.get("name", "")))
        entry = out.setdefault(key, {"type": r.get("type", ""), "monthly_usd": 0.0})
        entry["monthly_usd"] = round(entry["monthly_usd"] + float(r.get("monthly_usd") or 0.0), 2)
    return out


def snapshot(cost: dict[str, Any]) -> dict[str, Any]:
    """What a baseline keeps of a scan's cost: totals, stacks, and every priced resource."""
    return {
        "version": SNAPSHOT_VERSION,
        "region": cost.get("region"),
        "total_monthly_usd": cost.get("total_monthly_usd", 0.0),
        "stacks": [{"name": s["name"], "monthly_usd": s["monthly_usd"]} for s in cost.get("stacks") or []],
        "resources": [
            {"stack": stack, "name": name, **entry} for (stack, name), entry in sorted(_resources(cost).items())
        ],
    }


def load_previous(path: Path) -> dict[str, Any]:
    """The cost snapshot in a baseline file or a JSON report. Raises ConfigError."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"--compare-cost: cannot read {path}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"--compare-cost: {path} is not JSON: {exc}") from exc
    if isinstance(data, dict) and isinstance(data.get("cost_snapshot"), dict):
        return dict(data["cost_snapshot"])
    cost = ((data.get("context") or {}).get("notes") or {}).get("cost") if isinstance(data, dict) else None
    if isinstance(cost, dict):
        return snapshot(cost)
    raise ConfigError(
        f"--compare-cost: {path} has no cost data (a baseline written by --update-baseline "
        "from a priced scan, or a JSON report with an estimated cost)"
    )


def diff(previous: dict[str, Any], current: dict[str, Any], source: str = "") -> dict[str, Any]:
    """How the current cost differs from a snapshot: totals and per-resource changes."""
    before = {(str(r["stack"]), str(r["name"])): r for r in previous.get("resources") or []}
    after = _resources(current)
    prev_total = round(float(previous.get("total_monthly_usd") or 0.0), 2)
    cur_total = round(float(current.get("total_monthly_usd") or 0.0), 2)
    delta = round(cur_total - prev_total, 2)

    def item(stack: str, name: str, usd: float, rtype: str) -> dict[str, Any]:
        return {"stack": stack, "name": name, "type": rtype, "monthly_usd": usd}

    added = [item(s, n, e["monthly_usd"], e["type"]) for (s, n), e in sorted(after.items()) if (s, n) not in before]
    removed = [
        item(s, n, round(float(r.get("monthly_usd") or 0.0), 2), str(r.get("type", "")))
        for (s, n), r in sorted(before.items()) if (s, n) not in after
    ]
    changed = []
    for (s, n), e in sorted(after.items()):
        old = before.get((s, n))
        if old is None:
            continue
        was = round(float(old.get("monthly_usd") or 0.0), 2)
        if abs(e["monthly_usd"] - was) >= 0.01:
            changed.append({"stack": s, "name": n, "type": e["type"], "previous_monthly_usd": was,
                            "current_monthly_usd": e["monthly_usd"], "delta_monthly_usd": round(e["monthly_usd"] - was, 2)})
    return {
        "source": source,
        "previous_monthly_usd": prev_total,
        "current_monthly_usd": cur_total,
        "delta_monthly_usd": delta,
        "delta_percent": round(delta / prev_total * 100, 1) if prev_total else None,
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def evaluate(budget: Budget, cost: dict[str, Any]) -> dict[str, Any]:
    """The budget check: limits, whether each held, and a line per breach."""
    total = float(cost.get("total_monthly_usd") or 0.0)
    change = cost.get("diff")
    breaches: list[str] = []
    not_checked: list[str] = []
    if budget.max_monthly_usd is not None and total > budget.max_monthly_usd:
        breaches.append(f"estimated ${total:,.2f}/month is over the ${budget.max_monthly_usd:,.2f}/month budget")
    if budget.max_increase_usd is not None or budget.max_increase_percent is not None:
        if not isinstance(change, dict):
            not_checked.append("cost increase (no --compare-cost to compare with)")
        else:
            delta, pct = float(change["delta_monthly_usd"]), change.get("delta_percent")
            if budget.max_increase_usd is not None and delta > budget.max_increase_usd:
                breaches.append(
                    f"cost rises ${delta:,.2f}/month, over the ${budget.max_increase_usd:,.2f}/month limit"
                )
            if budget.max_increase_percent is not None and (
                (pct is not None and pct > budget.max_increase_percent) or (pct is None and delta > 0)
            ):
                shown = f"{pct:g}%" if pct is not None else "from $0.00"
                breaches.append(f"cost rises {shown}, over the {budget.max_increase_percent:g}% limit")
    return {
        "max_monthly_usd": budget.max_monthly_usd,
        "max_increase_usd": budget.max_increase_usd,
        "max_increase_percent": budget.max_increase_percent,
        "passed": not breaches,
        "breaches": breaches,
        "not_checked": not_checked,
    }
