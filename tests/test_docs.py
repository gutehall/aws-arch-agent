"""Docs stay aligned with the scanner."""
import re
from pathlib import Path

from typer.main import get_command

from aws_arch_agent import __version__
from aws_arch_agent.cli import app
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


def test_readme_pillar_counts_match_the_registry() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    names = {"Cost": "Cost Optimization"}
    categories = {rule.category for rule in ALL_RULES}
    for category in categories:
        count = sum(1 for rule in ALL_RULES if rule.category == category)
        assert f"| **{names.get(category, category)}** | {count} |" in readme, category
    assert f"{len(ALL_RULES)} static rules" in readme


def test_operational_excellence_count_matches_the_registry() -> None:
    count = sum(1 for rule in ALL_RULES if rule.category == "Operational Excellence")
    assert f"### Operational Excellence ({count} rules)" in (ROOT / "docs" / "CF_RULES.md").read_text(
        encoding="utf-8"
    )
    assert f"# Operational Excellence ({count} rules)" in (
        ROOT / "src" / "aws_arch_agent" / "rules" / "registry.py"
    ).read_text(encoding="utf-8")


def test_rule_reference_count_matches_the_registry_and_lists_each_rule_once() -> None:
    text = (ROOT / "docs" / "CF_RULES.md").read_text(encoding="utf-8")
    assert f"**{len(ALL_RULES)} static analysis rules**" in text
    static = text.split("## CloudFormation", 1)[0]
    listed = re.findall(r"^- ([A-Z]+-\d+):", static, flags=re.MULTILINE)
    dupes = sorted({rule_id for rule_id in listed if listed.count(rule_id) > 1})
    assert dupes == []
    # OPS-024 is a note: the rule was folded into REL-027 and is not registered.
    assert set(listed) - {"OPS-024"} == {rule.id for rule in ALL_RULES}


def test_readme_pins_the_action_to_the_current_release() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f".github/actions/aws-arch-agent@v{__version__}" in readme
    assert f'pip install "git+https://github.com/gutehall/aws-arch-agent@v{__version__}"' in readme
    assert f"releases/tag/v{__version__}" in readme
    assert "aws-arch-agent@main" not in readme


def test_reference_pins_the_action_and_lists_every_cli_option() -> None:
    text = (ROOT / "docs" / "REFERENCE.md").read_text(encoding="utf-8")
    assert f".github/actions/aws-arch-agent@v{__version__}" in text
    for param in get_command(app).params:
        for opt in param.opts:
            if opt.startswith("--"):
                assert f"`{opt}`" in text, opt
