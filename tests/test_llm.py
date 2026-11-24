"""Tests for LLM client fallback behavior."""
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from aws_arch_agent.tools.llm import (
    CONFIG_VARS,
    DEFAULT_OLLAMA_NUM_CTX,
    NOT_CONFIGURED,
    NO_LLM,
    LLMClient,
    LLMResult,
    aggregate_results,
)


def test_no_server_configured_makes_no_call(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    with patch("aws_arch_agent.tools.llm.requests.post") as post:
        result = LLMClient().polish("the prompt", "system")
    post.assert_not_called()
    assert (result.status, result.text, result.reason) == ("skipped", "the prompt", NOT_CONFIGURED)


@pytest.mark.parametrize("name, value", [
    ("OLLAMA_HOST", "http://models.internal:11434"),
    ("LLM_BASE_URL", "http://models.internal:8000/v1"),
])
def test_a_configured_server_is_called(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    for var in CONFIG_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(name, value)
    monkeypatch.setenv("LLM_MODEL", "qwen")
    reply = MagicMock()
    reply.json.return_value = {"message": {"content": "ok"}, "choices": [{"message": {"content": "ok"}}]}
    client = LLMClient()
    if name == "LLM_BASE_URL":
        client.provider = "selfhosted"
    with patch("aws_arch_agent.tools.llm.requests.post", return_value=reply) as post:
        result = client.polish("p", "s")
    # Ollama is also asked once for the model's context length (/api/show).
    assert [c for c in post.call_args_list if not c.args[0].endswith("/api/show")] == [post.call_args]
    assert result.status == "ok"


def test_ollama_fallback_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
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
    assert post.call_args.kwargs["timeout"] == 300
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


def test_ollama_calls_take_turns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Six pillars in parallel never have two HTTP calls open against one Ollama."""
    import threading
    import time

    client = _client(monkeypatch, "ollama")
    open_calls, most = 0, 0
    guard = threading.Lock()

    def post(*_a: object, **_k: object) -> MagicMock:
        nonlocal open_calls, most
        with guard:
            open_calls += 1
            most = max(most, open_calls)
        time.sleep(0.02)
        with guard:
            open_calls -= 1
        return _ollama_reply({"message": {"content": "ok"}})

    with patch("aws_arch_agent.tools.llm.requests.post", side_effect=post):
        threads = [threading.Thread(target=client.polish, args=("p", "s")) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert most == 1


def test_the_progress_line_names_the_call_in_flight(monkeypatch: pytest.MonkeyPatch) -> None:
    from aws_arch_agent.tools import llm

    client = _client(monkeypatch, "ollama")
    seen: list[str] = []
    monkeypatch.setattr(llm, "report", lambda line: seen.append(line))
    with patch("aws_arch_agent.tools.llm.requests.post", return_value=_ollama_reply({"message": {"content": "ok"}})):
        with llm.activity("Reviewing Security"):
            client.polish("p", "s")
        client.polish("p", "s")  # no activity: nothing printed
    assert seen == ["Reviewing Security"]


@pytest.mark.parametrize("value, expected", [(None, 300), ("45", 45), ("0", 300), ("soon", 300), ("inf", 300)])
def test_timeout_defaults_to_300_and_can_be_set(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: float
) -> None:
    client = _client(monkeypatch, "ollama")
    if value is None:
        monkeypatch.delenv("LLM_TIMEOUT_S", raising=False)
    else:
        monkeypatch.setenv("LLM_TIMEOUT_S", value)
    with patch("aws_arch_agent.tools.llm.requests.post", return_value=_ollama_reply({"message": {"content": "ok"}})) as post:
        client.polish("p", "s")
    assert post.call_args.kwargs["timeout"] == expected


def test_json_reply_asks_ollama_for_json(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, "ollama")
    with patch("aws_arch_agent.tools.llm.requests.post", return_value=_ollama_reply({"message": {"content": "{}"}})) as post:
        client.polish("p", "s", json_reply=True)
        assert post.call_args.kwargs["json"]["format"] == "json"
        client.polish("p", "s")
        assert "format" not in post.call_args.kwargs["json"]


def test_aggregate_partial_keeps_what_answered() -> None:
    ok = LLMResult("a", "ok", "ollama", "llama3:8b")
    bad = LLMResult("p", "invalid", "ollama", "llama3:8b", "reply is not JSON")
    assert aggregate_results([ok, bad]).status == "invalid"  # default unchanged
    run = aggregate_results([ok, ok, bad], allow_partial=True)
    assert run.status == "partial" and run.line == "LLM: partial (2 of 3 calls answered; reply is not JSON)"
    assert aggregate_results([ok, ok], allow_partial=True).status == "ok"
    assert aggregate_results([bad], allow_partial=True).status == "invalid"


def _ollama_with_context(trained: int | None):
    """requests.post for an Ollama whose model was trained on `trained` tokens."""
    def post(url: str, **kwargs):
        if url.endswith("/api/show"):
            info = {"general.architecture": "llama"}
            if trained is not None:
                info["llama.context_length"] = trained
            return _ollama_reply({"model_info": info})
        return _ollama_reply({"message": {"content": "ok"}})
    return post


def test_ollama_context_is_capped_at_the_trained_length(monkeypatch: pytest.MonkeyPatch) -> None:
    # llama3:8b: Ollama runs 8192 whatever num_ctx asks, and cuts a longer prompt from the middle.
    client = _client(monkeypatch, "ollama")
    with patch("aws_arch_agent.tools.llm.requests.post", side_effect=_ollama_with_context(8192)) as post:
        client.polish("text", system="s")
        assert client.prompt_chars(48_000) == (8192 - 2048) * 7 // 2
    chat = [c for c in post.call_args_list if c.args[0].endswith("/api/chat")]
    assert chat[0].kwargs["json"]["options"]["num_ctx"] == 8192
    assert sum(c.args[0].endswith("/api/show") for c in post.call_args_list) == 1  # asked once


@pytest.mark.parametrize("trained", [None, 131072])
def test_a_long_or_unknown_context_keeps_the_full_prompt(monkeypatch: pytest.MonkeyPatch, trained) -> None:
    client = _client(monkeypatch, "ollama")
    with patch("aws_arch_agent.tools.llm.requests.post", side_effect=_ollama_with_context(trained)):
        assert client.context_tokens() == DEFAULT_OLLAMA_NUM_CTX
        assert client.prompt_chars(48_000) == 48_000


def test_a_selfhosted_server_keeps_the_full_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    with patch("aws_arch_agent.tools.llm.requests.post") as post:
        assert _client(monkeypatch, "selfhosted").prompt_chars(48_000) == 48_000
    post.assert_not_called()
