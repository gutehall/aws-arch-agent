"""Tests for config loading and CLI overrides."""
from pathlib import Path

import pytest

from aws_arch_agent.config import ConfigError, load_config


def test_load_config_no_file(tmp_path: Path) -> None:
    """With no config file, defaults are used."""
    cfg = load_config(tmp_path)
    assert cfg.format == "markdown"
    assert cfg.fail_on == "none"
    assert cfg.no_llm is False
    assert cfg.out == "report.md"
    assert cfg.rules_include is None
    assert cfg.rules_exclude is None
    assert cfg.rules_org is False
    assert cfg.templates is None
    assert cfg.no_synth is False
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


def test_load_config_rules_org(tmp_path: Path) -> None:
    config_file = tmp_path / ".aws-arch-agent.json"
    config_file.write_text('{"rules": {"org": true}}', encoding="utf-8")
    cfg = load_config(tmp_path)
    assert cfg.rules_org is True


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


def test_yaml_string_false_stays_false(tmp_path: Path) -> None:
    """A quoted YAML false must not become True via bool("false")."""
    cfg_file = tmp_path / "aws-arch-agent.yaml"
    cfg_file.write_text('no_llm: "false"\nno_synth: "false"\n', encoding="utf-8")
    cfg = load_config(tmp_path, cfg_file)
    assert cfg.no_llm is False
    assert cfg.no_synth is False


def test_rules_exclude_must_be_list_of_strings(tmp_path: Path) -> None:
    cfg_file = tmp_path / ".aws-arch-agent.json"
    cfg_file.write_text('{"rules": {"exclude": "BP-001"}}', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)

    cfg_file.write_text('{"rules": {"exclude": 1}}', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_unknown_severity_threshold_fails(tmp_path: Path) -> None:
    cfg_file = tmp_path / ".aws-arch-agent.json"
    cfg_file.write_text('{"severity_threshold": "critical"}', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_missing_explicit_config_fails(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(ConfigError):
        load_config(tmp_path, config_path=missing)


def test_invalid_config_file_fails(tmp_path: Path) -> None:
    cfg_file = tmp_path / ".aws-arch-agent.json"
    cfg_file.write_text('{"fail_on":', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_cwd_config_is_not_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / ".aws-arch-agent.json").write_text(
        '{"fail_on": "high", "no_llm": true, "rules": {"exclude": ["BP-001"]}}',
        encoding="utf-8",
    )
    monkeypatch.chdir(cwd)
    cfg = load_config(repo)
    assert cfg.fail_on == "none"
    assert cfg.no_llm is False
    assert cfg.rules_exclude is None
