"""Docs stay aligned with the scanner."""
from pathlib import Path

from aws_arch_agent.rules.registry import ALL_RULES

ROOT = Path(__file__).resolve().parents[1]


def test_rag_sample_file_exists() -> None:
    assert (ROOT / "docs" / "waf-snippets.md").is_file()


def test_config_examples_point_at_that_file() -> None:
    for rel in ("README.md", "docs/CONFIG.md", "docs/example-config.json"):
        assert "docs/waf-snippets.md" in (ROOT / rel).read_text(encoding="utf-8")


def test_reference_points_at_the_full_rule_list() -> None:
    text = (ROOT / "docs" / "REFERENCE.md").read_text(encoding="utf-8")
    assert "CF_RULES.md" in text
    assert "| OPS-001 |" not in text


def test_v2_doc_matches_shipped_rag_and_cloudformation() -> None:
    text = (ROOT / "docs" / "V2_LANGGRAPH.md").read_text(encoding="utf-8")
    assert "Add RAG" not in text
    assert "builds one instance" in text
    assert "CF-S3-001" in text
    assert "SEC-005" in text


def test_operational_excellence_count_matches_the_registry() -> None:
    count = sum(1 for rule in ALL_RULES if rule.category == "Operational Excellence")
    assert f"| **Operational Excellence** | {count} |" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"### Operational Excellence ({count} rules)" in (ROOT / "docs" / "CF_RULES.md").read_text(
        encoding="utf-8"
    )
    assert f"# Operational Excellence ({count} rules)" in (
        ROOT / "src" / "aws_arch_agent" / "rules" / "registry.py"
    ).read_text(encoding="utf-8")
