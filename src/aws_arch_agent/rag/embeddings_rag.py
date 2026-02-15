"""Embedding-based RAG (sentence-transformers or OpenAI) for better retrieval relevance."""
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
    """RAG that embeds chunks and query, then returns top-k by similarity. Uses sentence-transformers (local) or OpenAI."""

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
            self._embeddings = self._model.encode(self.chunks, convert_to_numpy=False)
            if hasattr(self._embeddings, "tolist"):
                self._embeddings = [row.tolist() for row in self._embeddings]
            else:
                self._embeddings = [list(row) for row in self._embeddings]
        return self._embeddings

    def _get_embeddings_openai(self, texts: List[str]) -> List[List[float]]:
        import os
        try:
            from openai import OpenAI  # type: ignore
        except ImportError:
            logger.warning("openai not installed for embeddings")
            return []
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            logger.warning("OPENAI_API_KEY not set for RAG embeddings")
            return []
        client = OpenAI(api_key=key)
        model = self.model_name or "text-embedding-3-small"
        out: List[List[float]] = []
        # API accepts batch; 100 at a time is safe
        for i in range(0, len(texts), 100):
            batch = texts[i : i + 100]
            resp = client.embeddings.create(model=model, input=batch)
            for e in resp.data:
                out.append(e.embedding)
        return out

    def retrieve(self, query: str, k: int = 3) -> str:
        """Return up to k chunks that best match the query by embedding similarity."""
        if not self.chunks:
            return ""
        q_vec: List[float]
        chunk_embs: List[List[float]]
        if self.provider == "openai":
            query_emb = self._get_embeddings_openai([query])
            if not query_emb:
                return self._fallback_keyword(query, k)
            chunk_embs = self._get_embeddings_openai(self.chunks)
            if len(chunk_embs) != len(self.chunks):
                return self._fallback_keyword(query, k)
            q_vec = query_emb[0]
        else:
            chunk_embs = self._get_embeddings_sentence_transformers()
            if not chunk_embs:
                return self._fallback_keyword(query, k)
            try:
                from sentence_transformers import SentenceTransformer  # type: ignore
            except ImportError:
                return self._fallback_keyword(query, k)
            if self._model is None:
                name = self.model_name or "all-MiniLM-L6-v2"
                self._model = SentenceTransformer(name)
            q = self._model.encode(query, convert_to_numpy=False)
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
