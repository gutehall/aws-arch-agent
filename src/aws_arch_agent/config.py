"""Optional config file and resolved options for the analyzer."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

SeverityThreshold = Literal["high", "medium", "low", "none"]
OutputFormat = Literal["markdown", "json"]


def _find_config(repo_path: Path, config_path: Path | None) -> Path | None:
    """Locate config file: explicit path, then repo .aws-arch-agent.json, then cwd."""
    if config_path is not None:
        p = Path(config_path).expanduser().resolve()
        return p if p.exists() else None
    for name in (".aws-arch-agent.json", "aws-arch-agent.json"):
        in_repo = repo_path / name
        if in_repo.exists():
            return in_repo
        in_cwd = Path.cwd() / name
        if in_cwd.exists():
            return in_cwd
    return None


def load_config(
    repo_path: Path,
    config_path: Path | None = None,
    *,
    format: OutputFormat | None = None,
    fail_on: SeverityThreshold | None = None,
    no_llm: bool | None = None,
    out: str | None = None,
    rag_path: str | None = None,
) -> "RunConfig":
    """Load config from file and override with CLI flags. CLI wins over file."""
    cfg_path = _find_config(repo_path, config_path)
    file_cfg: dict = {}
    if cfg_path:
        try:
            file_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Failed to load config from %s: %s", cfg_path, e)

    def _get(key: str, default: str | bool | None):
        val = file_cfg.get(key, default)
        if key == "format" and format is not None:
            return format
        if key == "fail_on" and fail_on is not None:
            return fail_on
        if key == "no_llm" and no_llm is not None:
            return no_llm
        if key == "out" and out is not None:
            return out
        if key == "rag_path" and rag_path is not None:
            return rag_path
        return val

    file_rag = file_cfg.get("rag")
    if isinstance(file_rag, dict):
        resolved_rag = file_rag.get("path")
        rag_use_embeddings = bool(file_rag.get("use_embeddings", False))
        rag_embedding_provider = file_rag.get("embedding_provider") or None
        if rag_embedding_provider is not None:
            rag_embedding_provider = str(rag_embedding_provider).strip().lower() or None
        rag_embedding_model = file_rag.get("embedding_model") or None
    else:
        resolved_rag = None
        rag_use_embeddings = False
        rag_embedding_provider = None
        rag_embedding_model = None
    if rag_path is not None:
        resolved_rag = rag_path

    file_rules = file_cfg.get("rules")
    if not isinstance(file_rules, dict):
        file_rules = {}

    return RunConfig(
        format=_get("format", "markdown") or "markdown",
        fail_on=_get("fail_on", "none") or "none",
        no_llm=bool(_get("no_llm", False)),
        out=str(_get("out", "report.md") or "report.md"),
        rules_include=file_rules.get("include"),
        rules_exclude=file_rules.get("exclude"),
        severity_threshold=file_cfg.get("severity_threshold"),
        rag_path=resolved_rag,
        rag_use_embeddings=rag_use_embeddings,
        rag_embedding_provider=rag_embedding_provider,
        rag_embedding_model=rag_embedding_model,
    )


class RunConfig:
    """Resolved run options (file + CLI)."""

    __slots__ = (
        "format",
        "fail_on",
        "no_llm",
        "out",
        "rules_include",
        "rules_exclude",
        "severity_threshold",
        "rag_path",
        "rag_use_embeddings",
        "rag_embedding_provider",
        "rag_embedding_model",
    )

    def __init__(
        self,
        *,
        format: OutputFormat = "markdown",
        fail_on: SeverityThreshold = "none",
        no_llm: bool = False,
        out: str = "report.md",
        rules_include: list[str] | None = None,
        rules_exclude: list[str] | None = None,
        severity_threshold: str | None = None,
        rag_path: str | None = None,
        rag_use_embeddings: bool = False,
        rag_embedding_provider: str | None = None,
        rag_embedding_model: str | None = None,
    ):
        self.format = format
        self.fail_on = fail_on
        self.no_llm = no_llm
        self.out = out
        self.rules_include = rules_include
        self.rules_exclude = rules_exclude
        self.severity_threshold = severity_threshold
        self.rag_path = rag_path
        self.rag_use_embeddings = rag_use_embeddings
        self.rag_embedding_provider = rag_embedding_provider
        self.rag_embedding_model = rag_embedding_model
