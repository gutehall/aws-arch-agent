"""Tests for LLM client fallback behavior."""
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from aws_arch_agent.tools.llm import (
    DEFAULT_OLLAMA_NUM_CTX,
    NO_LLM,
    LLMClient,
    LLMResult,
    aggregate_results,
)


def test_ollama_fallback_on_failure() -> None:
    client = LLMClient()
    client.provider = "ollama"
    with patch("aws_arch_agent.tools.llm.requests.post", side_effect=ConnectionError("down")):
        result = client.polish("original markdown", "system")
    assert result.text == "original markdown"
    assert result.status == "fallback"
    assert result.reason == "Ollama request failed"
    assert result.line == "LLM: fallback (Ollama request failed)"


def _ollama_reply(body: dict) -> MagicMock:
    response = MagicMock()
    response.json.return_value = body
    return response


def _client(monkeypatch: pytest.MonkeyPatch, provider: str) -> LLMClient:
    monkeypatch.setenv("LLM_PROVIDER", provider)
    monkeypatch.setenv("OLLAMA_MODEL", "llama3:8b")
    monkeypatch.setenv("LLM_BASE_URL", "http://models.internal:8000/v1/")
    monkeypatch.setenv("LLM_MODEL", "qwen")
    return LLMClient()


def test_ollama_success_reports_provider_and_model(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, "ollama")
    reply = _ollama_reply({"message": {"content": "polished"}})
    with patch("aws_arch_agent.tools.llm.requests.post", return_value=reply):
        result = client.polish("prompt", "system")
    assert (result.text, result.status, result.provider, result.model, result.reason) == (
        "polished", "ok", "ollama", "llama3:8b", None,
    )
    assert result.line == "LLM: ollama/llama3:8b responded"


@pytest.mark.parametrize("provider", ["openai", "anthropic", "mystery"])
def test_other_providers_are_refused_without_a_call(
    monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    client = _client(monkeypatch, provider)
    with patch("aws_arch_agent.tools.llm.requests.post") as post:
        result = client.polish("prompt", "system")
    post.assert_not_called()
    assert (result.status, result.text) == ("fallback", "prompt")
    assert result.line == "LLM: fallback (unsupported LLM_PROVIDER, use ollama or selfhosted)"


def test_no_cloud_sdk_in_the_source_or_the_dependencies() -> None:
    root = Path(__file__).resolve().parents[1]
    importing = re.compile(r"^\s*(?:from|import)\s+(?:openai|anthropic)\b", re.MULTILINE)
    assert [p for p in (root / "src").rglob("*.py") if importing.search(p.read_text())] == []
    pyproject = (root / "pyproject.toml").read_text()
    assert '"openai' not in pyproject and '"anthropic' not in pyproject


def test_failure_reason_holds_no_exception_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://secret-host:1")
    client = _client(monkeypatch, "ollama")
    error = requests.ConnectionError("http://secret-host:1 refused key=abc")
    with patch("aws_arch_agent.tools.llm.requests.post", side_effect=error):
        result = client.polish("prompt", "system")
    assert result.reason == "Ollama request failed"
    assert "secret-host" not in result.line
    assert "secret-host" not in str(result.to_dict())


@pytest.mark.parametrize("body", [
    {"message": {"content": ""}},
    {"message": {"content": "  \n"}},
    {"message": {}},
    {},
])
def test_ollama_empty_reply_is_invalid(monkeypatch: pytest.MonkeyPatch, body: dict) -> None:
    client = _client(monkeypatch, "ollama")
    with patch("aws_arch_agent.tools.llm.requests.post", return_value=_ollama_reply(body)):
        result = client.polish("prompt", "system")
    assert result.status == "invalid"
    assert result.text == "prompt"
    assert result.line == "LLM: invalid (Ollama returned an empty reply)"


def _selfhosted_reply(content: object) -> MagicMock:
    return _ollama_reply({"choices": [{"message": {"content": content}}]})


def test_selfhosted_success_reports_provider_and_model(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, "selfhosted")
    with patch(
        "aws_arch_agent.tools.llm.requests.post", return_value=_selfhosted_reply("answer")
    ) as post:
        result = client.polish("prompt", "system")
    assert (result.text, result.status) == ("answer", "ok")
    assert result.line == "LLM: selfhosted/qwen responded"
    assert post.call_args.args[0] == "http://models.internal:8000/v1/chat/completions"
    assert post.call_args.kwargs["timeout"] == 120
    payload = post.call_args.kwargs["json"]
    assert payload["model"] == "qwen"
    assert payload["max_tokens"] == 4096
    assert payload["messages"][1] == {"role": "user", "content": "prompt"}


@pytest.mark.parametrize("variable, reason", [
    ("LLM_BASE_URL", "LLM_BASE_URL not set"),
    ("LLM_MODEL", "LLM_MODEL not set"),
])
def test_selfhosted_settings_are_required(
    monkeypatch: pytest.MonkeyPatch, variable: str, reason: str
) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "selfhosted")
    monkeypatch.setenv("LLM_BASE_URL", "http://models.internal:8000/v1")
    monkeypatch.setenv("LLM_MODEL", "qwen")
    monkeypatch.delenv(variable)
    with patch("aws_arch_agent.tools.llm.requests.post") as post:
        result = LLMClient().polish("prompt", "system")
    post.assert_not_called()
    assert (result.status, result.reason, result.text) == ("fallback", reason, "prompt")


def test_selfhosted_failure_and_empty_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, "selfhosted")
    with patch("aws_arch_agent.tools.llm.requests.post", side_effect=ConnectionError("down")):
        failed = client.polish("prompt", "system")
    assert (failed.status, failed.reason) == ("fallback", "Self-hosted LLM request failed")
    with patch("aws_arch_agent.tools.llm.requests.post", return_value=_selfhosted_reply(None)):
        empty = client.polish("prompt", "system")
    assert (empty.status, empty.text) == ("invalid", "prompt")
    assert empty.reason == "Self-hosted LLM returned an empty reply"


OK = LLMResult("a", "ok", "ollama", "llama3:8b")
FALLBACK = LLMResult("b", "fallback", "ollama", "llama3:8b", "Ollama request failed")
INVALID = LLMResult("c", "invalid", "ollama", "llama3:8b", "Ollama returned an empty reply")


def test_aggregate_all_ok() -> None:
    run = aggregate_results([OK, OK])
    assert run.status == "ok"
    assert run.line == "LLM: ollama/llama3:8b responded"
    assert run.text == ""


def test_aggregate_mixed_reports_first_non_ok() -> None:
    mixed = aggregate_results([OK, FALLBACK, INVALID])
    assert mixed.line == "LLM: fallback (Ollama request failed)"
    assert aggregate_results([INVALID, OK, FALLBACK]).status == "invalid"
    assert aggregate_results([OK, OK, FALLBACK]).reason == "Ollama request failed"


def test_aggregate_all_skipped() -> None:
    assert aggregate_results([NO_LLM, NO_LLM]).line == "LLM: skipped (--no-llm)"


def test_aggregate_no_calls_never_claims_responded() -> None:
    assert aggregate_results([]).line == "LLM: skipped (no LLM call made)"


def test_to_dict_leaves_the_text_out() -> None:
    assert FALLBACK.to_dict() == {
        "status": "fallback",
        "provider": "ollama",
        "model": "llama3:8b",
        "reason": "Ollama request failed",
    }


def _sent_num_ctx(client: LLMClient) -> int:
    reply = _ollama_reply({"message": {"content": "ok"}})
    with patch("aws_arch_agent.tools.llm.requests.post", return_value=reply) as post:
        client.polish("prompt", "system")
    return post.call_args.kwargs["json"]["options"]["num_ctx"]


def test_ollama_context_fits_the_largest_prompt_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLLAMA_NUM_CTX", raising=False)
    assert _sent_num_ctx(_client(monkeypatch, "ollama")) == DEFAULT_OLLAMA_NUM_CTX


def test_ollama_context_can_be_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_NUM_CTX", "8192")
    assert _sent_num_ctx(_client(monkeypatch, "ollama")) == 8192


@pytest.mark.parametrize("value", ["0", "-1", "lots", "1.5"])
def test_a_bad_ollama_context_falls_back_to_the_default(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("OLLAMA_NUM_CTX", value)
    assert _sent_num_ctx(_client(monkeypatch, "ollama")) == DEFAULT_OLLAMA_NUM_CTX
