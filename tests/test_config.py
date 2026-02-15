"""Tests for config loading and CLI overrides."""
from pathlib import Path

import pytest

from aws_arch_agent.config import load_config, RunConfig


def test_load_config_no_file(tmp_path: Path) -> None:
    """With no config file, defaults are used."""
    cfg = load_config(tmp_path)
    assert cfg.format == "markdown"
    assert cfg.fail_on == "none"
    assert cfg.no_llm is False
    assert cfg.out == "report.md"
    assert cfg.rules_include is None
    assert cfg.rules_exclude is None
    assert cfg.rag_path is None
    assert cfg.rag_use_embeddings is False
    assert cfg.rag_embedding_provider is None
    assert cfg.rag_embedding_model is None


def test_load_config_cli_overrides_file(tmp_path: Path) -> None:
    """CLI flags override config file values."""
    config_file = tmp_path / ".aws-arch-agent.json"
    config_file.write_text(
        '{"format": "json", "fail_on": "high", "no_llm": true, "out": "out.json"}',
        encoding="utf-8",
    )
    cfg = load_config(
        tmp_path,
        format="markdown",
        fail_on="low",
        no_llm=False,
        out="report.md",
    )
    assert cfg.format == "markdown"
    assert cfg.fail_on == "low"
    assert cfg.no_llm is False
    assert cfg.out == "report.md"


def test_load_config_from_file(tmp_path: Path) -> None:
    """Config file values are applied when no CLI override."""
    config_file = tmp_path / ".aws-arch-agent.json"
    config_file.write_text(
        '{"format": "json", "fail_on": "medium", "no_llm": true, '
        '"rules": {"exclude": ["BP-001"]}, "rag": {"path": "./docs/waf.md"}}',
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert cfg.format == "json"
    assert cfg.fail_on == "medium"
    assert cfg.no_llm is True
    assert cfg.rules_exclude == ["BP-001"]
    assert cfg.rag_path == "./docs/waf.md"


def test_load_config_explicit_path(tmp_path: Path) -> None:
    """Explicit config path is used when provided."""
    repo = tmp_path / "repo"
    repo.mkdir()
    other = tmp_path / "other.json"
    other.write_text('{"format": "json", "out": "other.md"}', encoding="utf-8")
    cfg = load_config(repo, config_path=other)
    assert cfg.format == "json"
    assert cfg.out == "other.md"


def test_load_config_rag_embeddings(tmp_path: Path) -> None:
    """Config with rag.use_embeddings and embedding_provider is loaded."""
    config_file = tmp_path / ".aws-arch-agent.json"
    config_file.write_text(
        '{"rag": {"path": "./waf.md", "use_embeddings": true, '
        '"embedding_provider": "sentence-transformers", "embedding_model": "all-MiniLM-L6-v2"}}',
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert cfg.rag_path == "./waf.md"
    assert cfg.rag_use_embeddings is True
    assert cfg.rag_embedding_provider == "sentence-transformers"
    assert cfg.rag_embedding_model == "all-MiniLM-L6-v2"
