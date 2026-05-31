"""Tests for LLM client fallback behavior."""
from unittest.mock import MagicMock, patch

from aws_arch_agent.tools.llm import LLMClient


def test_ollama_fallback_on_failure() -> None:
    client = LLMClient()
    client.provider = "ollama"
    with patch("aws_arch_agent.tools.llm.requests.post", side_effect=ConnectionError("down")):
        result = client.polish("original markdown")
    assert result == "original markdown"


def test_openai_fallback_on_api_error() -> None:
    client = LLMClient()
    client.provider = "openai"
    mock_openai = MagicMock()
    mock_openai.return_value.chat.completions.create.side_effect = RuntimeError("api error")
    with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
        with patch.dict("sys.modules", {"openai": MagicMock(OpenAI=mock_openai)}):
            result = client._openai("prompt", "system")
    assert result == "prompt"
