"""LLM client for Ollama, OpenAI, and Anthropic (polish/review prompts)."""
from __future__ import annotations

import logging
import os
from typing import cast

import requests

logger = logging.getLogger(__name__)

DEFAULT_SYSTEM = """You are an AWS Solutions Architect reviewer.
You will receive findings from static analysis of a CDK repo.
Rewrite them into crisp, actionable recommendations.
Do NOT invent resources. If unsure, say so.
Return Markdown only."""


class LLMClient:
    """Calls configured LLM provider (Ollama, OpenAI, or Anthropic) to polish or generate markdown."""

    def __init__(self) -> None:
        self.provider = os.getenv("LLM_PROVIDER", "ollama").lower()
        self.ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3:8b")
        self.openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self.anthropic_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")

    def polish(self, markdown: str, system: str = DEFAULT_SYSTEM) -> str:
        """Send content to LLM with system prompt; return model output or original on failure."""
        if self.provider == "openai":
            return self._openai(markdown, system)
        if self.provider == "anthropic":
            return self._anthropic(markdown, system)
        return self._ollama(markdown, system)

    def _ollama(self, prompt: str, system: str) -> str:
        url = f"{self.ollama_host}/api/chat"
        payload = {
            "model": self.ollama_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        try:
            r = requests.post(url, json=payload, timeout=120)
            r.raise_for_status()
            data = r.json()
            return cast(str, data.get("message", {}).get("content", prompt))
        except Exception as e:
            logger.warning("Ollama request failed: %s", e)
            return prompt

    def _openai(self, prompt: str, system: str) -> str:
        # Optional dependency
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as e:
            logger.debug("OpenAI package not installed: %s", e)
            return prompt
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OPENAI_API_KEY not set; skipping LLM polish")
            return prompt
        try:
            client = OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model=self.openai_model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            )
            return resp.choices[0].message.content or prompt
        except Exception as e:
            logger.warning("OpenAI request failed: %s", e)
            return prompt

    def _anthropic(self, prompt: str, system: str) -> str:
        try:
            import anthropic  # type: ignore
        except ImportError as e:
            logger.debug("Anthropic package not installed: %s", e)
            return prompt
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning("ANTHROPIC_API_KEY not set; skipping LLM polish")
            return prompt
        try:
            client = anthropic.Anthropic(api_key=api_key)
            msg = client.messages.create(
                model=self.anthropic_model,
                system=system,
                max_tokens=1200,
                messages=[{"role": "user", "content": prompt}],
            )
            return "".join([b.text for b in msg.content if hasattr(b, "text")]) or prompt
        except Exception as e:
            logger.warning("Anthropic request failed: %s", e)
            return prompt
