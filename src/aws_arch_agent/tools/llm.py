"""LLM client for self-hosted models only: Ollama or an OpenAI-compatible server."""
from __future__ import annotations

import functools
from contextlib import contextmanager
from dataclasses import dataclass, replace
import logging
import math
import os
import threading
from typing import Any, Iterable, Iterator, Literal

import requests

from aws_arch_agent.progress import report

logger = logging.getLogger(__name__)

# The same bound on every request, so a stalled model cannot hang a scan. A local model
# answering a full verdict batch can take minutes; LLM_TIMEOUT_S overrides it.
DEFAULT_LLM_TIMEOUT_S = 300
# Room for a full batch of verdicts, so the reply is not cut off into invalid JSON.
MAX_REPLY_TOKENS = 4096
# Ollama silently cuts a prompt longer than its context, and its default is far below the
# hypothesis prompt: about 41k characters of catalog plus the source, and room for the reply.
# Ollama also caps this at the model's trained context, so verdict and hypothesis prompts are
# sized to LLMClient.prompt_chars, which knows both.
DEFAULT_OLLAMA_NUM_CTX = 24576
# Characters per token when sizing a prompt to a context, as a fraction: llama3 measured
# about 4 on verdict prompts, so 3.5 leaves some room.
CHARS_PER_TOKEN = (7, 2)
SHOW_TIMEOUT_S = 10

LLMStatus = Literal["ok", "fallback", "skipped", "invalid", "partial"]

# One local Ollama answers one request at a time and queues the rest, so parallel callers
# would spend their timeout waiting in its queue. Calls take turns here instead.
_OLLAMA_LOCK = threading.Lock()
_activity = threading.local()


@contextmanager
def activity(label: str) -> Iterator[None]:
    """Name this thread's LLM calls. The progress line shows it once a call starts, so it
    names the call in flight rather than one still waiting for its turn."""
    previous = getattr(_activity, "label", None)
    _activity.label = label
    try:
        yield
    finally:
        _activity.label = previous


def _announce() -> None:
    label = getattr(_activity, "label", None)
    if label:
        report(label)


def llm_timeout_s() -> float:
    """LLM_TIMEOUT_S when it is a positive number of seconds, otherwise the default."""
    raw = os.getenv("LLM_TIMEOUT_S", "").strip()
    if not raw:
        return DEFAULT_LLM_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        value = 0
    if math.isfinite(value) and value > 0:
        return value
    logger.warning("Ignoring LLM_TIMEOUT_S=%r: not a positive number of seconds", raw)
    return DEFAULT_LLM_TIMEOUT_S


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
NOT_CONFIGURED = "no LLM configured: set OLLAMA_HOST or LLM_BASE_URL, or run Ollama on localhost:11434"
# Any of these means the user chose a model server. With none set, a local Ollama is used
# when one answers on its default port with at least one model pulled.
CONFIG_VARS = ("OLLAMA_HOST", "OLLAMA_MODEL", "LLM_BASE_URL", "LLM_MODEL", "LLM_PROVIDER")
LOCAL_OLLAMA = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3:8b"
LOCAL_PROBE_TIMEOUT_S = 1.0


@functools.lru_cache(maxsize=1)
def local_ollama_models() -> tuple[str, ...]:
    """The models a local Ollama has pulled; empty when none answers (asked once per process)."""
    try:
        r = requests.get(f"{LOCAL_OLLAMA}/api/tags", timeout=LOCAL_PROBE_TIMEOUT_S)
        r.raise_for_status()
        models = r.json().get("models") or []
    except Exception:  # not running, refused, not Ollama: no LLM
        return ()
    return tuple(str(m.get("name")) for m in models if isinstance(m, dict) and m.get("name"))


def llm_configured() -> bool:
    """True when the environment names a model server, or a local Ollama answers with a model."""
    return any(os.getenv(name, "").strip() for name in CONFIG_VARS) or bool(local_ollama_models())


def _default_ollama_model() -> str:
    """OLLAMA_MODEL, else llama3:8b when a local Ollama has it (or is not asked), else its first model."""
    if os.getenv("OLLAMA_MODEL", "").strip() or os.getenv("OLLAMA_HOST", "").strip():
        return os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
    local = local_ollama_models()
    if not local or DEFAULT_OLLAMA_MODEL in local:
        return DEFAULT_OLLAMA_MODEL
    # An embedding model cannot answer a chat request.
    chat = [name for name in local if "embed" not in name.lower()]
    return chat[0] if chat else DEFAULT_OLLAMA_MODEL


def aggregate_results(results: Iterable[LLMResult], allow_partial: bool = False) -> LLMResult:
    """One run-level result with no text: the first non-ok call, otherwise the first ok call.

    A partial failure never reports `responded`. With allow_partial, some ok calls and some
    failed ones are `partial`, so the caller can keep what the ok calls returned. No calls
    at all is NO_CALL.
    """
    calls = list(results)
    if not calls:
        return NO_CALL
    failed = [c for c in calls if c.status != "ok"]
    ok = [c for c in calls if c.status == "ok"]
    if allow_partial and ok and failed:
        return LLMResult("", "partial", ok[0].provider, ok[0].model,
                         f"{len(ok)} of {len(calls)} calls answered; {failed[0].reason}")
    return replace(failed[0] if failed else calls[0], text="")


class LLMClient:
    """Calls the configured self-hosted model. There is no cloud provider, by design."""

    def __init__(self) -> None:
        self.provider = os.getenv("LLM_PROVIDER", "ollama").lower()
        self.ollama_host = os.getenv("OLLAMA_HOST", LOCAL_OLLAMA)
        self._ollama_model: str | None = None  # resolved on first use: building a client probes nothing
        self.ollama_num_ctx = _ollama_num_ctx()
        self._context_tokens: int | None = None  # asked of Ollama until it answers
        self.selfhosted_url = os.getenv("LLM_BASE_URL", "")
        self.selfhosted_model = os.getenv("LLM_MODEL", "")

    @property
    def ollama_model(self) -> str:
        if self._ollama_model is None:
            self._ollama_model = _default_ollama_model()
        return self._ollama_model

    @ollama_model.setter
    def ollama_model(self, value: str) -> None:
        self._ollama_model = value

    def context_tokens(self) -> int | None:
        """The context Ollama really runs: OLLAMA_NUM_CTX, capped at what the model was trained
        on. Ollama caps it too, then cuts a longer prompt from the middle, instructions and all.
        None for a self-hosted server, which does not say."""
        if self.provider != "ollama":
            return None
        if self._context_tokens is None:
            trained = _ollama_context_length(self.ollama_host, self.ollama_model)
            if trained is None:
                return self.ollama_num_ctx  # not known yet: ask again on the next call
            self._context_tokens = min(self.ollama_num_ctx, trained)
        return self._context_tokens

    def prompt_chars(self, cap: int) -> int:
        """The longest prompt, in characters, that leaves the model room to reply; at most cap."""
        if not llm_configured():
            return cap
        tokens = self.context_tokens()
        if tokens is None:
            return cap
        reply = min(MAX_REPLY_TOKENS, tokens // 4)
        num, den = CHARS_PER_TOKEN
        return max(min(cap, (tokens - reply) * num // den), 0)

    def polish(self, markdown: str, system: str, json_reply: bool = False) -> LLMResult:
        """Send content to LLM with system prompt; a failure returns the original as its text.

        With no server configured nothing is sent: the result is skipped, with the prompt as text.
        json_reply asks Ollama for a JSON body (its `format: json`); the caller still parses it.
        """
        if not llm_configured():
            return LLMResult(markdown, "skipped", reason=NOT_CONFIGURED)
        if self.provider == "ollama":
            with _OLLAMA_LOCK:
                _announce()
                return self._ollama(markdown, system, json_reply)
        if self.provider == "selfhosted":
            _announce()
            return self._selfhosted(markdown, system)
        # No fall-through: a leftover setting must not send the prompt somewhere unexpected.
        logger.warning("Unsupported LLM_PROVIDER: %s", self.provider)
        return LLMResult(
            markdown, "fallback", reason="unsupported LLM_PROVIDER, use ollama or selfhosted"
        )

    def _ollama(self, prompt: str, system: str, json_reply: bool = False) -> LLMResult:
        model = self.ollama_model
        url = f"{self.ollama_host}/api/chat"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "options": {"num_ctx": self.context_tokens()},
            "stream": False,
            **({"format": "json"} if json_reply else {}),
        }
        try:
            r = requests.post(url, json=payload, timeout=llm_timeout_s())
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
            r = requests.post(url, json=payload, timeout=llm_timeout_s())
            r.raise_for_status()
            reply = r.json()["choices"][0]["message"]["content"]
            return _from_reply(reply, prompt, "selfhosted", model, "Self-hosted LLM")
        except Exception as e:
            logger.warning("Self-hosted LLM request failed: %s", e)
            return LLMResult(
                prompt, "fallback", "selfhosted", model, "Self-hosted LLM request failed"
            )


def _ollama_context_length(host: str, model: str) -> int | None:
    """The context length the model was trained on, from Ollama's /api/show; None when unknown."""
    try:
        r = requests.post(f"{host}/api/show", json={"model": model}, timeout=SHOW_TIMEOUT_S)
        r.raise_for_status()
        info = r.json().get("model_info") or {}
    except Exception:  # an older Ollama, a model not pulled yet: keep OLLAMA_NUM_CTX
        return None
    if not isinstance(info, dict):
        return None
    for key, value in info.items():
        if str(key).endswith(".context_length") and isinstance(value, int) and value > 0:
            return value
    return None


def _ollama_num_ctx() -> int:
    """OLLAMA_NUM_CTX when it is a positive whole number, otherwise the default."""
    raw = os.getenv("OLLAMA_NUM_CTX", "").strip()
    if not raw:
        return DEFAULT_OLLAMA_NUM_CTX
    if raw.isdecimal() and int(raw) > 0:
        return int(raw)
    logger.warning("Ignoring OLLAMA_NUM_CTX=%r: not a positive whole number", raw)
    return DEFAULT_OLLAMA_NUM_CTX


def _from_reply(reply: Any, prompt: str, provider: str, model: str, label: str) -> LLMResult:
    """An answered request: ok with its text, or invalid when the reply holds nothing."""
    if isinstance(reply, str) and reply.strip():
        return LLMResult(reply, "ok", provider, model)
    logger.warning("%s returned an empty reply", label)
    return LLMResult(prompt, "invalid", provider, model, f"{label} returned an empty reply")
