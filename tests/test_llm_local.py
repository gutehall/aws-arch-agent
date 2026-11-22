"""A plain scan uses a local Ollama when one answers; nothing else is assumed."""
from __future__ import annotations

import pytest

from aws_arch_agent.tools import llm


class _Resp:
    def __init__(self, data: dict) -> None:
        self.data = data

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self.data


def _probe(monkeypatch: pytest.MonkeyPatch, models: tuple[str, ...]) -> None:
    monkeypatch.setattr(llm, "local_ollama_models", lambda: models)
    for name in llm.CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)


def test_the_probe_reads_ollama_tags(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = llm.local_ollama_models.real  # type: ignore[attr-defined]  # conftest stubs the probe out
    calls: list[tuple[str, float]] = []

    def get(url: str, timeout: float) -> _Resp:
        calls.append((url, timeout))
        return _Resp({"models": [{"name": "qwen2.5:7b"}, {"name": "llama3:8b"}, {"x": 1}]})

    monkeypatch.setattr(llm.requests, "get", get)
    probe.cache_clear()
    try:
        assert probe() == ("qwen2.5:7b", "llama3:8b")
        assert probe() == ("qwen2.5:7b", "llama3:8b")
        assert calls == [("http://localhost:11434/api/tags", 1.0)]  # asked once per process

        def refused(url: str, timeout: float) -> _Resp:
            raise ConnectionError("refused")

        monkeypatch.setattr(llm.requests, "get", refused)
        probe.cache_clear()
        assert probe() == ()
    finally:
        probe.cache_clear()


@pytest.mark.parametrize("models, configured, model", [
    ((), False, "llama3:8b"),
    (("llama3:8b", "qwen2.5:7b"), True, "llama3:8b"),
    (("qwen2.5:7b",), True, "qwen2.5:7b"),
])
def test_local_ollama_is_used_when_nothing_is_set(monkeypatch: pytest.MonkeyPatch, models, configured, model) -> None:
    _probe(monkeypatch, models)
    assert llm.llm_configured() is configured
    client = llm.LLMClient()
    assert client.provider == "ollama" and client.ollama_host == "http://localhost:11434"
    assert client.ollama_model == model


def test_env_settings_win_over_the_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    _probe(monkeypatch, ("qwen2.5:7b",))
    monkeypatch.setenv("OLLAMA_HOST", "http://gpu-box:11434")
    assert llm.LLMClient().ollama_model == "llama3:8b"
    monkeypatch.setenv("OLLAMA_MODEL", "mistral")
    assert llm.LLMClient().ollama_model == "mistral"


def test_no_server_skips_without_sending(monkeypatch: pytest.MonkeyPatch) -> None:
    _probe(monkeypatch, ())
    result = llm.LLMClient().polish("prompt", "system")
    assert result.status == "skipped" and "run Ollama on localhost:11434" in (result.reason or "")


def test_embedding_models_are_not_picked(monkeypatch: pytest.MonkeyPatch) -> None:
    _probe(monkeypatch, ("nomic-embed-text:latest", "qwen2.5:7b"))
    assert llm.LLMClient().ollama_model == "qwen2.5:7b"
    _probe(monkeypatch, ("nomic-embed-text:latest",))
    assert llm.LLMClient().ollama_model == "llama3:8b"


def test_building_a_client_probes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> tuple[str, ...]:
        raise AssertionError("probed")

    monkeypatch.setattr(llm, "local_ollama_models", boom)
    for name in llm.CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    llm.LLMClient()  # --no-llm paths build a client and never call it
