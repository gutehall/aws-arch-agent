"""YAML config loading tests."""
from pathlib import Path

from aws_arch_agent.config import load_config


def test_load_yaml_config(tmp_path: Path) -> None:
    cfg_file = tmp_path / "aws-arch-agent.yaml"
    cfg_file.write_text(
        "format: json\nfail_on: high\nno_llm: true\nout: out.json\n",
        encoding="utf-8",
    )
    cfg = load_config(tmp_path, cfg_file)
    assert cfg.format == "json"
    assert cfg.fail_on == "high"
    assert cfg.no_llm is True
    assert cfg.out == "out.json"
