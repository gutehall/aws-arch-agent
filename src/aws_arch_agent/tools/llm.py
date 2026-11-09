"""LLM client for self-hosted models only: Ollama or an OpenAI-compatible server."""
from __future__ import annotations

from dataclasses import dataclass, replace
import logging
import os
from typing import Any, Iterable, Literal

import requests

logger = logging.getLogger(__name__)

# The same bound on every request, so a stalled model cannot hang a scan.
LLM_TIMEOUT_S = 120
# Room for a full batch of verdicts, so the reply is not cut off into invalid JSON.
MAX_REPLY_TOKENS = 4096

LLMStatus = Literal["ok", "fallback", "skipped", "invalid"]


@dataclass(frozen=True)
class LLMResult:
    """What one LLM call, or one whole run, did. A failed call keeps the prompt as its text."""

    text: str
    status: LLMStatus
    provider: str | None = None
    model: str | None = None
    reason: str | None = None

    @property
    def line(self) -> str:
        """The one line the console and the Markdown report both print."""
        if self.status == "ok":
            return f"LLM: {self.provider}/{self.model} responded"
        return f"LLM: {self.status} ({self.reason})"

    def to_dict(self) -> dict[str, str | None]:
        """The JSON report's `llm` object. The text is the report itself, so it stays out."""
        return {
            "status": self.status,
            "provider": self.provider,
            "model": self.model,
            "reason": self.reason,
        }


NO_LLM = LLMResult("", "skipped", reason="--no-llm")
NO_CALL = LLMResult("", "skipped", reason="no LLM call made")


def aggregate_results(results: Iterable[LLMResult]) -> LLMResult:
    """One run-level result with no text: the first non-ok call, otherwise the first ok call.

    A partial failure never reports `responded`. No calls at all is NO_CALL.
    """
    calls = list(results)
    if not calls:
        return NO_CALL
    return replace(next((c for c in calls if c.status != "ok"), calls[0]), text="")


class LLMClient:
    """Calls the configured self-hosted model. There is no cloud provider, by design."""

    def __init__(self) -> None:
        self.provider = os.getenv("LLM_PROVIDER", "ollama").lower()
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3:8b")
        self.selfhosted_url = os.getenv("LLM_BASE_URL", "")
        self.selfhosted_model = os.getenv("LLM_MODEL", "")

    def polish(self, markdown: str, system: str) -> LLMResult:
        """Send content to LLM with system prompt; a failure returns the original as its text."""
        if self.provider == "ollama":
            return self._ollama(markdown, system)
        if self.provider == "selfhosted":
            return self._selfhosted(markdown, system)
        # No fall-through: a leftover setting must not send the prompt somewhere unexpected.
        logger.warning("Unsupported LLM_PROVIDER: %s", self.provider)
        return LLMResult(
            markdown, "fallback", reason="unsupported LLM_PROVIDER, use ollama or selfhosted"
        )

    def _ollama(self, prompt: str, system: str) -> LLMResult:
        model = self.ollama_model
        url = f"{self.ollama_host}/api/chat"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        try:
            r = requests.post(url, json=payload, timeout=LLM_TIMEOUT_S)
            r.raise_for_status()
            data = r.json()
            reply = data.get("message", {}).get("content")
            return _from_reply(reply, prompt, "ollama", model, "Ollama")
        except Exception as e:
            logger.warning("Ollama request failed: %s", e)
            return LLMResult(prompt, "fallback", "ollama", model, "Ollama request failed")

    def _selfhosted(self, prompt: str, system: str) -> LLMResult:
        """vLLM, llama.cpp, LM Studio, LocalAI: anything serving /chat/completions."""
        model = self.selfhosted_model
        if not self.selfhosted_url:
            return LLMResult(prompt, "fallback", "selfhosted", model, "LLM_BASE_URL not set")
        if not model:
            return LLMResult(prompt, "fallback", "selfhosted", None, "LLM_MODEL not set")
        url = f"{self.selfhosted_url.rstrip('/')}/chat/completions"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": MAX_REPLY_TOKENS,
            "stream": False,
        }
        try:
            r = requests.post(url, json=payload, timeout=LLM_TIMEOUT_S)
            r.raise_for_status()
            reply = r.json()["choices"][0]["message"]["content"]
            return _from_reply(reply, prompt, "selfhosted", model, "Self-hosted LLM")
        except Exception as e:
            logger.warning("Self-hosted LLM request failed: %s", e)
            return LLMResult(
                prompt, "fallback", "selfhosted", model, "Self-hosted LLM request failed"
            )


def _from_reply(reply: Any, prompt: str, provider: str, model: str, label: str) -> LLMResult:
    """An answered request: ok with its text, or invalid when the reply holds nothing."""
    if isinstance(reply, str) and reply.strip():
        return LLMResult(reply, "ok", provider, model)
    logger.warning("%s returned an empty reply", label)
    return LLMResult(prompt, "invalid", provider, model, f"{label} returned an empty reply")
