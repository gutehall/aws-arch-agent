"""Positive/negative coverage test for every rule in ALL_RULES."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aws_arch_agent.rules.registry import ALL_RULES

CASES_PATH = Path(__file__).parent / "fixtures" / "rule_cases.json"
RULE_BY_ID = {r.id: r for r in ALL_RULES}


def _load_cases() -> dict[str, dict[str, str | None]]:
    return json.loads(CASES_PATH.read_text(encoding="utf-8"))


def _write_repo(tmp_path: Path, lang: str, content: str) -> None:
    if lang == "typescript":
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        lib = tmp_path / "lib"
        lib.mkdir(exist_ok=True)
        (lib / "stack.ts").write_text(content, encoding="utf-8")
    else:
        (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
        (tmp_path / "app.py").write_text(content, encoding="utf-8")


def _lang_from_key(key: str) -> str:
    return "python" if key.endswith("_py") else "typescript"


CASES = _load_cases()
RULE_IDS = [r.id for r in ALL_RULES]


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_positive_case(tmp_path: Path, rule_id: str) -> None:
    """Rule should fire on its positive snippet."""
    case = CASES.get(rule_id, {})
    pos_key = next((k for k in ("positive_ts", "positive_py") if case.get(k)), None)
    if not pos_key:
        pytest.skip(f"No positive case for {rule_id}")
    lang = _lang_from_key(pos_key)
    _write_repo(tmp_path, lang, case[pos_key] or "")
    rule = RULE_BY_ID[rule_id]
    findings = rule.run(tmp_path, lang)
    assert any(f.id == rule_id for f in findings), (
        f"{rule_id} did not fire on positive case: {case[pos_key]!r}"
    )


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_negative_case(tmp_path: Path, rule_id: str) -> None:
    """Rule should not fire on its negative snippet (when provided)."""
    case = CASES.get(rule_id, {})
    neg_key = next((k for k in ("negative_ts", "negative_py") if case.get(k)), None)
    if not neg_key:
        pytest.skip(f"No negative case for {rule_id}")
    lang = _lang_from_key(neg_key)
    _write_repo(tmp_path, lang, case[neg_key] or "")
    rule = RULE_BY_ID[rule_id]
    findings = rule.run(tmp_path, lang)
    assert not any(f.id == rule_id for f in findings), (
        f"{rule_id} false positive on negative case: {case[neg_key]!r}"
    )
