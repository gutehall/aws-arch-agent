"""Optional config file and resolved options for the analyzer."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, cast

import yaml

SeverityThreshold = Literal["high", "medium", "low", "none"]
OutputFormat = Literal["markdown", "json", "sarif"]
LLMMode = Literal["full", "compact"]

_FORMATS = ("markdown", "json", "sarif")
_FAIL_ON = ("high", "medium", "low", "none")
_LLM_MODES = ("full", "compact")
_SEVERITY = {"high": "High", "medium": "Medium", "low": "Low"}
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
_CONFIG_NAMES = (
    ".aws-arch-agent.json",
    "aws-arch-agent.json",
    ".aws-arch-agent.yaml",
    "aws-arch-agent.yaml",
    ".aws-arch-agent.yml",
    "aws-arch-agent.yml",
)


class ConfigError(ValueError):
    """Config file is missing, unreadable, or invalid."""


def _as_bool(value: Any, key: str) -> bool:
    """Parse a config boolean. Quoted YAML "false" stays false."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _TRUE:
            return True
        if token in _FALSE:
            return False
    raise ConfigError(f"{key} must be a boolean, got {value!r}")


def _as_string_list(value: Any, key: str) -> list[str] | None:
    """Require a list of strings. None means the key is unset."""
    if value is None:
        return None
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ConfigError(f"{key} must be a list of strings, got {value!r}")


def _choice(value: Any, allowed: tuple[str, ...], key: str) -> str:
    if isinstance(value, str):
        token = value.strip().lower()
        if token in allowed:
            return token
    allowed_text = ", ".join(allowed)
    raise ConfigError(f"{key} must be one of {allowed_text}, got {value!r}")


def _severity_threshold(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        mapped = _SEVERITY.get(value.strip().lower())
        if mapped is not None:
            return mapped
    raise ConfigError(f"severity_threshold must be high, medium, or low, got {value!r}")


def _optional_str(value: Any, key: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise ConfigError(f"{key} must be a string, got {value!r}")


def _load_config_file(path: Path) -> dict[str, Any]:
    """Load config from JSON or YAML file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Failed to read config {path}: {exc}") from exc
    suffix = path.suffix.lower()
    try:
        if suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"Invalid config {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"Config {path} must be a mapping")
    return dict(data)


def _find_config(repo_path: Path, config_path: Path | None) -> Path | None:
    """Locate config file: explicit path, otherwise a file in the repo root.

    An explicit path that is missing raises ConfigError. A same-named file in
    the current working directory is not used.
    """
    if config_path is not None:
        path = Path(config_path).expanduser().resolve()
        if not path.is_file():
            raise ConfigError(f"Config file not found: {path}")
        return path
    for name in _CONFIG_NAMES:
        in_repo = repo_path / name
        if in_repo.is_file():
            return in_repo
    return None


def _pick_choice(
    file_cfg: dict[str, Any],
    key: str,
    override: str | None,
    default: str,
    allowed: tuple[str, ...],
) -> str:
    if override is not None:
        return _choice(override, allowed, key)
    if key in file_cfg:
        return _choice(file_cfg[key], allowed, key)
    return default


def _pick_bool(file_cfg: dict[str, Any], key: str, override: bool | None, default: bool) -> bool:
    if override is not None:
        return override
    if key in file_cfg:
        return _as_bool(file_cfg[key], key)
    return default


def load_config(
    repo_path: Path,
    config_path: Path | None = None,
    *,
    format: OutputFormat | None = None,
    fail_on: SeverityThreshold | None = None,
    no_llm: bool | None = None,
    out: str | None = None,
    templates: str | None = None,
    no_synth: bool | None = None,
    rag_path: str | None = None,
    llm_mode: LLMMode | None = None,
) -> "RunConfig":
    """Load config from file and override with CLI flags that were passed.

    A None argument means the flag was not passed, so the file value applies.
    """
    cfg_path = _find_config(repo_path, config_path)
    file_cfg: dict[str, Any] = {}
    if cfg_path:
        file_cfg = _load_config_file(cfg_path)

    file_rag = file_cfg.get("rag")
    if isinstance(file_rag, dict):
        resolved_rag = _optional_str(file_rag.get("path"), "rag.path")
        rag_use_embeddings = _as_bool(file_rag.get("use_embeddings", False), "rag.use_embeddings")
        rag_embedding_provider = file_rag.get("embedding_provider") or None
        if rag_embedding_provider is not None:
            if not isinstance(rag_embedding_provider, str):
                raise ConfigError(
                    f"rag.embedding_provider must be a string, got {rag_embedding_provider!r}"
                )
            rag_embedding_provider = rag_embedding_provider.strip().lower() or None
        rag_embedding_model = file_rag.get("embedding_model") or None
        if rag_embedding_model is not None and not isinstance(rag_embedding_model, str):
            raise ConfigError(f"rag.embedding_model must be a string, got {rag_embedding_model!r}")
    elif file_rag is None:
        resolved_rag = None
        rag_use_embeddings = False
        rag_embedding_provider = None
        rag_embedding_model = None
    else:
        raise ConfigError(f"rag must be a mapping, got {file_rag!r}")
    if rag_path is not None:
        resolved_rag = rag_path

    file_rules = file_cfg.get("rules", {})
    if file_rules is None:
        file_rules = {}
    if not isinstance(file_rules, dict):
        raise ConfigError(f"rules must be a mapping, got {file_rules!r}")
    rules_include = (
        _as_string_list(file_rules["include"], "rules.include") if "include" in file_rules else None
    )
    rules_exclude = (
        _as_string_list(file_rules["exclude"], "rules.exclude") if "exclude" in file_rules else None
    )

    if "severity_threshold" in file_cfg:
        severity_threshold = _severity_threshold(file_cfg["severity_threshold"])
    else:
        severity_threshold = None

    resolved_out = out if out is not None else file_cfg.get("out", "report.md")
    if resolved_out is None:
        resolved_out = "report.md"
    if not isinstance(resolved_out, str) or not resolved_out:
        raise ConfigError(f"out must be a string, got {resolved_out!r}")

    return RunConfig(
        format=cast(OutputFormat, _pick_choice(file_cfg, "format", format, "markdown", _FORMATS)),
        fail_on=cast(SeverityThreshold, _pick_choice(file_cfg, "fail_on", fail_on, "none", _FAIL_ON)),
        no_llm=_pick_bool(file_cfg, "no_llm", no_llm, False),
        out=resolved_out,
        rules_include=rules_include,
        rules_exclude=rules_exclude,
        severity_threshold=severity_threshold,
        templates=_optional_str(
            templates if templates is not None else file_cfg.get("templates"),
            "templates",
        ),
        no_synth=_pick_bool(file_cfg, "no_synth", no_synth, False),
        rag_path=resolved_rag,
        rag_use_embeddings=rag_use_embeddings,
        rag_embedding_provider=rag_embedding_provider,
        rag_embedding_model=rag_embedding_model,
        llm_mode=_pick_choice(file_cfg, "llm_mode", llm_mode, "full", _LLM_MODES),
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
        "templates",
        "no_synth",
        "rag_path",
        "rag_use_embeddings",
        "rag_embedding_provider",
        "rag_embedding_model",
        "llm_mode",
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
        templates: str | None = None,
        no_synth: bool = False,
        rag_path: str | None = None,
        rag_use_embeddings: bool = False,
        rag_embedding_provider: str | None = None,
        rag_embedding_model: str | None = None,
        llm_mode: str = "full",
    ):
        self.format = format
        self.fail_on = fail_on
        self.no_llm = no_llm
        self.out = out
        self.rules_include = rules_include
        self.rules_exclude = rules_exclude
        self.severity_threshold = severity_threshold
        self.templates = templates
        self.no_synth = no_synth
        self.rag_path = rag_path
        self.rag_use_embeddings = rag_use_embeddings
        self.rag_embedding_provider = rag_embedding_provider
        self.rag_embedding_model = rag_embedding_model
        self.llm_mode = llm_mode
