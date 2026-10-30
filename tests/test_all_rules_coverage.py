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


def _snippet_keys(case: dict[str, str | None], kind: str) -> list[str]:
    return [key for key in (f"{kind}_ts", f"{kind}_py") if case.get(key)]


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_positive_case(tmp_path: Path, rule_id: str) -> None:
    """Rule should fire on each positive snippet, including Python."""
    case = CASES.get(rule_id, {})
    keys = _snippet_keys(case, "positive")
    if not keys:
        pytest.skip(f"No positive case for {rule_id}")
    rule = RULE_BY_ID[rule_id]
    for key in keys:
        lang = _lang_from_key(key)
        repo = tmp_path / key
        repo.mkdir()
        _write_repo(repo, lang, case[key] or "")
        findings = rule.run(repo, lang)
        assert any(f.id == rule_id for f in findings), (
            f"{rule_id} did not fire on {key}: {case[key]!r}"
        )


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_negative_case(tmp_path: Path, rule_id: str) -> None:
    """Rule should not fire on each negative snippet (when provided)."""
    case = CASES.get(rule_id, {})
    keys = _snippet_keys(case, "negative")
    if not keys:
        pytest.skip(f"No negative case for {rule_id}")
    rule = RULE_BY_ID[rule_id]
    for key in keys:
        lang = _lang_from_key(key)
        repo = tmp_path / key
        repo.mkdir()
        _write_repo(repo, lang, case[key] or "")
        findings = rule.run(repo, lang)
        assert not any(f.id == rule_id for f in findings), (
            f"{rule_id} false positive on {key}: {case[key]!r}"
        )
