"""Tests for LLM client fallback behavior."""
from unittest.mock import MagicMock, patch

import pytest
import requests

from aws_arch_agent.tools.llm import NO_LLM, LLMClient, LLMResult, aggregate_results


def test_ollama_fallback_on_failure() -> None:
    client = LLMClient()
    client.provider = "ollama"
    with patch("aws_arch_agent.tools.llm.requests.post", side_effect=ConnectionError("down")):
        result = client.polish("original markdown")
    assert result.text == "original markdown"
    assert result.status == "fallback"
    assert result.reason == "Ollama request failed"
    assert result.line == "LLM: fallback (Ollama request failed)"


def test_openai_client_receives_timeout() -> None:
    client = LLMClient()
    mock_openai = MagicMock()
    choice = MagicMock()
    choice.message.content = "polished"
    mock_openai.return_value.chat.completions.create.return_value.choices = [choice]
    with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
        with patch.dict("sys.modules", {"openai": MagicMock(OpenAI=mock_openai)}):
            assert client._openai("prompt", "system").text == "polished"
    assert mock_openai.call_args.kwargs["timeout"] == 120


def test_anthropic_client_receives_timeout() -> None:
    client = LLMClient()
    mock_mod = MagicMock()
    mock_mod.Anthropic.return_value.messages.create.return_value.content = []
    with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant"}):
        with patch.dict("sys.modules", {"anthropic": mock_mod}):
            client._anthropic("prompt", "system")
    assert mock_mod.Anthropic.call_args.kwargs["timeout"] == 120


def test_openai_fallback_on_api_error() -> None:
    client = LLMClient()
    client.provider = "openai"
    mock_openai = MagicMock()
    mock_openai.return_value.chat.completions.create.side_effect = RuntimeError("api error")
    with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
        with patch.dict("sys.modules", {"openai": MagicMock(OpenAI=mock_openai)}):
            result = client._openai("prompt", "system")
    assert result.text == "prompt"
    assert result.status == "fallback"
    assert result.reason == "OpenAI request failed"


def _ollama_reply(body: dict) -> MagicMock:
    response = MagicMock()
    response.json.return_value = body
    return response


def _client(monkeypatch: pytest.MonkeyPatch, provider: str) -> LLMClient:
    monkeypatch.setenv("LLM_PROVIDER", provider)
    monkeypatch.setenv("OLLAMA_MODEL", "llama3:8b")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-x")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-x")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return LLMClient()


def test_ollama_success_reports_provider_and_model(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, "ollama")
    reply = _ollama_reply({"message": {"content": "polished"}})
    with patch("aws_arch_agent.tools.llm.requests.post", return_value=reply):
        result = client.polish("prompt")
    assert (result.text, result.status, result.provider, result.model, result.reason) == (
        "polished", "ok", "ollama", "llama3:8b", None,
    )
    assert result.line == "LLM: ollama/llama3:8b responded"


def test_unknown_provider_falls_through_and_reports_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, "mystery")
    reply = _ollama_reply({"message": {"content": "polished"}})
    with patch("aws_arch_agent.tools.llm.requests.post", return_value=reply):
        result = client.polish("prompt")
    assert result.provider == "ollama"
    assert result.status == "ok"


def test_failure_reason_holds_no_exception_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://secret-host:1")
    client = _client(monkeypatch, "ollama")
    error = requests.ConnectionError("http://secret-host:1 refused key=abc")
    with patch("aws_arch_agent.tools.llm.requests.post", side_effect=error):
        result = client.polish("prompt")
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
        result = client.polish("prompt")
    assert result.status == "invalid"
    assert result.text == "prompt"
    assert result.line == "LLM: invalid (Ollama returned an empty reply)"


@pytest.mark.parametrize("provider, module, reason", [
    ("openai", "openai", "OpenAI SDK not installed"),
    ("anthropic", "anthropic", "Anthropic SDK not installed"),
])
def test_missing_sdk_is_fallback(
    monkeypatch: pytest.MonkeyPatch, provider: str, module: str, reason: str
) -> None:
    client = _client(monkeypatch, provider)
    with patch.dict("sys.modules", {module: None}):  # None makes the import raise ImportError
        result = client.polish("prompt")
    assert (result.status, result.reason, result.text) == ("fallback", reason, "prompt")
    assert result.provider == provider


@pytest.mark.parametrize("provider, reason", [
    ("openai", "OPENAI_API_KEY not set"),
    ("anthropic", "ANTHROPIC_API_KEY not set"),
])
def test_missing_key_is_fallback(
    monkeypatch: pytest.MonkeyPatch, provider: str, reason: str
) -> None:
    client = _client(monkeypatch, provider)
    with patch.dict("sys.modules", {provider: MagicMock()}):
        result = client.polish("prompt")
    assert (result.status, result.reason, result.text) == ("fallback", reason, "prompt")


def test_openai_empty_reply_is_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    mock_openai = MagicMock()
    choice = MagicMock()
    choice.message.content = None
    mock_openai.return_value.chat.completions.create.return_value.choices = [choice]
    with patch.dict("sys.modules", {"openai": MagicMock(OpenAI=mock_openai)}):
        result = client.polish("prompt")
    assert (result.status, result.text) == ("invalid", "prompt")
    assert result.reason == "OpenAI returned an empty reply"


def test_anthropic_empty_reply_and_request_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    mock_mod = MagicMock()
    mock_mod.Anthropic.return_value.messages.create.return_value.content = []
    with patch.dict("sys.modules", {"anthropic": mock_mod}):
        empty = client.polish("prompt")
        mock_mod.Anthropic.return_value.messages.create.side_effect = RuntimeError("boom")
        failed = client.polish("prompt")
    assert (empty.status, empty.text) == ("invalid", "prompt")
    assert empty.reason == "Anthropic returned an empty reply"
    assert (failed.status, failed.reason) == ("fallback", "Anthropic request failed")


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
