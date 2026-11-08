"""LLM client for Ollama, OpenAI, and Anthropic (polish/review prompts)."""
from __future__ import annotations

from dataclasses import dataclass, replace
import logging
import os
from typing import Any, Iterable, Literal

import requests

logger = logging.getLogger(__name__)

# Same bound as the Ollama request. A stalled cloud call must not use the SDK default.
LLM_TIMEOUT_S = 120

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
    """Calls configured LLM provider (Ollama, OpenAI, or Anthropic) to polish or generate markdown."""

    def __init__(self) -> None:
        self.provider = os.getenv("LLM_PROVIDER", "ollama").lower()
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3:8b")
        self.openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.anthropic_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")

    def polish(self, markdown: str, system: str) -> LLMResult:
        """Send content to LLM with system prompt; a failure returns the original as its text."""
        if self.provider == "openai":
            return self._openai(markdown, system)
        if self.provider == "anthropic":
            return self._anthropic(markdown, system)
        return self._ollama(markdown, system)

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

    def _openai(self, prompt: str, system: str) -> LLMResult:
        model = self.openai_model
        # Optional dependency
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as e:
            logger.debug("OpenAI package not installed: %s", e)
            return LLMResult(prompt, "fallback", "openai", model, "OpenAI SDK not installed")
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OPENAI_API_KEY not set; skipping LLM polish")
            return LLMResult(prompt, "fallback", "openai", model, "OPENAI_API_KEY not set")
        try:
            client = OpenAI(api_key=api_key, timeout=LLM_TIMEOUT_S)
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            )
            return _from_reply(resp.choices[0].message.content, prompt, "openai", model, "OpenAI")
        except Exception as e:
            logger.warning("OpenAI request failed: %s", e)
            return LLMResult(prompt, "fallback", "openai", model, "OpenAI request failed")

    def _anthropic(self, prompt: str, system: str) -> LLMResult:
        model = self.anthropic_model
        try:
            import anthropic  # type: ignore
        except ImportError as e:
            logger.debug("Anthropic package not installed: %s", e)
            return LLMResult(prompt, "fallback", "anthropic", model, "Anthropic SDK not installed")
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning("ANTHROPIC_API_KEY not set; skipping LLM polish")
            return LLMResult(prompt, "fallback", "anthropic", model, "ANTHROPIC_API_KEY not set")
        try:
            client = anthropic.Anthropic(api_key=api_key, timeout=LLM_TIMEOUT_S)
            msg = client.messages.create(
                model=model,
                system=system,
                max_tokens=4096,  # 20 verdicts must not be cut into invalid JSON
                messages=[{"role": "user", "content": prompt}],
            )
            reply = "".join([b.text for b in msg.content if hasattr(b, "text")])
            return _from_reply(reply, prompt, "anthropic", model, "Anthropic")
        except Exception as e:
            logger.warning("Anthropic request failed: %s", e)
            return LLMResult(prompt, "fallback", "anthropic", model, "Anthropic request failed")


def _from_reply(reply: Any, prompt: str, provider: str, model: str, label: str) -> LLMResult:
    """An answered request: ok with its text, or invalid when the reply holds nothing."""
    if isinstance(reply, str) and reply.strip():
        return LLMResult(reply, "ok", provider, model)
    logger.warning("%s returned an empty reply", label)
    return LLMResult(prompt, "invalid", provider, model, f"{label} returned an empty reply")
