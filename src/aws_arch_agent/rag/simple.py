"""Simple in-memory RAG (keyword-based, no embeddings) for WAF or custom docs."""
from __future__ import annotations

from pathlib import Path


def _chunk_by_headers(text: str, max_chunk_size: int = 1500) -> list[str]:
    """Split text by ## or ### and keep chunks under max size."""
    chunks: list[str] = []
    current: list[str] = []
    size = 0
    for line in text.splitlines():
        if line.startswith("##") and current:
            chunk = "\n".join(current)
            if chunk.strip():
                chunks.append(chunk)
            current = []
            size = 0
        current.append(line)
        size += len(line) + 1
        if size >= max_chunk_size and current:
            chunk = "\n".join(current)
            if chunk.strip():
                chunks.append(chunk)
            current = []
            size = 0
    if current:
        chunk = "\n".join(current)
        if chunk.strip():
            chunks.append(chunk)
    return chunks


class SimpleRAG:
    """Load a doc and retrieve chunks by keyword overlap (no embeddings)."""

    def __init__(self, path: Path | None = None, text: str | None = None) -> None:
        if path is not None and path.exists():
            self.chunks = _chunk_by_headers(path.read_text(encoding="utf-8"))
        elif text:
            self.chunks = _chunk_by_headers(text)
        else:
            self.chunks = []

    def retrieve(self, query: str, k: int = 3) -> str:
        """Return up to k chunks that best match query words (simple word overlap)."""
        if not self.chunks:
            return ""
        words = set(q.lower() for q in query.split() if len(q) > 1)
        scored = []
        for c in self.chunks:
            c_lower = c.lower()
            score = sum(1 for w in words if w in c_lower)
            scored.append((score, c))
        scored.sort(key=lambda x: -x[0])
        top = [c for _, c in scored[:k] if _ > 0]
        if not top and scored:
            top = [scored[0][1]]
        return "\n\n---\n\n".join(top)
