"""Embedding-based RAG (local sentence-transformers) for better retrieval relevance."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from aws_arch_agent.rag.simple import _chunk_by_headers

logger = logging.getLogger(__name__)


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    """Cosine similarity between two vectors."""
    import math
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1e-9
    nb = math.sqrt(sum(y * y for y in b)) or 1e-9
    return dot / (na * nb)


class EmbeddingRAG:
    """RAG that embeds chunks and query, then returns top-k by similarity. Uses sentence-transformers, locally."""

    def __init__(
        self,
        path: Path | None = None,
        text: str | None = None,
        provider: str = "sentence-transformers",
        model_name: str | None = None,
    ) -> None:
        if path is not None and path.exists():
            raw = path.read_text(encoding="utf-8")
            self.chunks = _chunk_by_headers(raw)
        elif text:
            self.chunks = _chunk_by_headers(text)
        else:
            self.chunks = []
        self.provider = (provider or "sentence-transformers").lower()
        self.model_name = model_name
        self._embeddings: List[List[float]] | None = None
        self._model = None

    def ensure_chunk_embeddings(self) -> None:
        """Embed document chunks once. Later retrieves only embed the query."""
        if not self.chunks or self._embeddings is not None:
            return
        self._get_embeddings_sentence_transformers()

    def _get_embeddings_sentence_transformers(self) -> List[List[float]]:
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
        except ImportError:
            logger.warning("sentence-transformers not installed; pip install sentence-transformers")
            return []
        if self._model is None:
            name = self.model_name or "all-MiniLM-L6-v2"
            self._model = SentenceTransformer(name)
        if self._embeddings is None:
            model = self._model
            if model is None:
                return []
            encoded = model.encode(self.chunks, convert_to_numpy=False)
            self._embeddings = [list(row) for row in encoded]
        return self._embeddings

    def retrieve(self, query: str, k: int = 3) -> str:
        """Return up to k chunks that best match the query by embedding similarity."""
        if not self.chunks:
            return ""
        q_vec: List[float]
        chunk_embs: List[List[float]]
        chunk_embs = self._get_embeddings_sentence_transformers()
        if not chunk_embs:
            return self._fallback_keyword(query, k)
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            return self._fallback_keyword(query, k)
        model = self._model
        if model is None:
            name = self.model_name or "all-MiniLM-L6-v2"
            model = SentenceTransformer(name)
            self._model = model
        q = model.encode(query, convert_to_numpy=False)
        q_vec = q.tolist() if hasattr(q, "tolist") else list(q)

        sims = [_cosine_similarity(q_vec, ce) for ce in chunk_embs]
        pairs = list(zip(sims, self.chunks))
        pairs.sort(key=lambda x: -x[0])
        top = [chunk for _, chunk in pairs[:k]]
        return "\n\n---\n\n".join(top)

    def _fallback_keyword(self, query: str, k: int) -> str:
        """Fallback to simple keyword overlap when embeddings unavailable."""
        words = set(w.lower() for w in query.split() if len(w) > 1)
        scored = []
        for c in self.chunks:
            cl = c.lower()
            score = sum(1 for w in words if w in cl)
            scored.append((score, c))
        scored.sort(key=lambda x: -x[0])
        top = [c for s, c in scored[:k] if s > 0] or ([scored[0][1]] if scored else [])
        return "\n\n---\n\n".join(top)
