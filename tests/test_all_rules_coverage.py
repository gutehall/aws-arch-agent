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

# Rules changed in the same-file, IAM/TLS, Python-kwargs, and tracing work.
# CloudFormation Aurora and tracing negatives live in tests/test_cf_template.py.
PROJECT_TOUCHED = frozenset({
    "SEC-005", "SEC-008", "SEC-035", "REL-006", "REL-009", "REL-010",
    "SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-007", "SEC-011", "SEC-012", "SEC-018", "SEC-064",
    "REL-001", "REL-008", "SEC-013", "SEC-014", "SEC-020", "SEC-023", "SEC-054",
    "OPS-003",
    "BP-002", "BP-003", "PERF-002",
    "SEC-066", "SEC-067", "SEC-068", "OPS-026", "OPS-011", "OPS-027", "REPO-004", "REPO-005",
    "SEC-069", "SEC-070", "SEC-071", "REPO-006", "REPO-007", "REPO-008", "REPO-009",
    "REPO-010", "REPO-011", "REPO-012", "REPO-013", "REL-032", "REPO-014",
    "REL-033", "REPO-015", "REPO-016", "REPO-017", "REPO-018", "REPO-019", "REPO-020",
    "REPO-021", "REPO-022", "REPO-023", "REPO-024", "REPO-025", "REPO-026",
    "REPO-027", "REPO-028", "REPO-029", "REPO-030", "REPO-031", "REPO-032", "REPO-033",
    "REPO-034", "REPO-035", "REPO-036", "REPO-037", "REPO-038",
    "REPO-039", "REPO-040", "REPO-041", "REPO-042", "REPO-043", "REPO-044",
    "REPO-045", "REPO-046", "REPO-047", "REPO-048",
    "REPO-049", "REPO-050", "REPO-051", "REPO-052", "REPO-053", "REPO-054", "REPO-055",
    "REPO-056", "REPO-057", "REPO-058", "REPO-059", "REPO-060", "REPO-061", "REPO-062",
    "REPO-063",
    "REPO-064", "REPO-065", "REPO-066", "REPO-067", "REPO-068",
    "REPO-069", "REPO-070", "REPO-071", "REPO-072",
    "REPO-073", "REPO-074", "REPO-075", "REPO-076", "REPO-077", "REPO-078", "REPO-079",
    "REPO-080", "REPO-081", "REPO-082", "REPO-083", "REPO-084", "REPO-085",
    "REPO-086", "REPO-087", "REPO-088", "REPO-089",
    "REPO-090", "REPO-091", "REPO-092", "REPO-093",
    "REPO-094", "REPO-095",
    "REPO-096", "REPO-097", "REPO-098", "REPO-099", "REPO-100", "REPO-101", "REPO-102",
    "REPO-103", "REPO-104", "REPO-105", "REPO-106", "REPO-107", "REPO-108",
    "REPO-109", "REPO-110", "REPO-111", "REPO-112",
    "REPO-113", "REPO-114", "REPO-115", "REPO-116",
    "REPO-117", "REPO-118", "REPO-119", "REPO-120", "REPO-121",
    "REPO-122", "REPO-123", "REPO-124", "REPO-125", "REPO-126", "REPO-127", "REPO-128",
    "REPO-129", "REPO-130", "REPO-131", "REPO-132", "REPO-133", "REPO-134",
    "REPO-135", "REPO-136", "REPO-137", "REPO-138", "REPO-139",
    "REPO-140", "REPO-141", "REPO-142", "REPO-143", "REPO-144", "REPO-145",
    "REPO-146", "REPO-147", "REPO-148",
    "REPO-149", "REPO-150", "REPO-151", "REPO-152", "REPO-153", "REPO-154", "REPO-155",
    "REPO-156", "REPO-157", "REPO-158", "REPO-159",
    "REPO-160",
    "REPO-161",
    "REPO-162",
    "REPO-163",
    "REPO-164",
    "REPO-165",
    "REPO-166",
    "REPO-167",
    "REPO-168",
    "REPO-169",
    "REPO-170",
    "REPO-171",
    "REPO-172",
    "REPO-173",
    "REPO-174",
    "REPO-175",
})


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


def test_project_rules_have_negative_fixtures() -> None:
    """A rule touched in this project cannot land without a negative snippet."""
    missing = sorted(
        rule_id
        for rule_id in PROJECT_TOUCHED
        if not _snippet_keys(CASES.get(rule_id, {}), "negative")
    )
    assert not missing, f"missing negative fixture: {missing}"


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_negative_case(tmp_path: Path, rule_id: str) -> None:
    """Rule should not fire on each negative snippet (when provided)."""
    case = CASES.get(rule_id, {})
    keys = _snippet_keys(case, "negative")
    if not keys:
        if rule_id in PROJECT_TOUCHED:
            pytest.fail(f"{rule_id} is missing a negative fixture")
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
