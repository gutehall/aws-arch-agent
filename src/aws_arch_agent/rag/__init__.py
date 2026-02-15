"""Optional RAG for Well-Architected or custom docs (keyword or embedding-based)."""
from pathlib import Path
from typing import Union

from aws_arch_agent.rag.simple import SimpleRAG
from aws_arch_agent.rag.embeddings_rag import EmbeddingRAG

__all__ = ["SimpleRAG", "EmbeddingRAG", "get_rag"]


def get_rag(
    path: Path,
    use_embeddings: bool = False,
    embedding_provider: str | None = None,
    embedding_model: str | None = None,
) -> Union[SimpleRAG, EmbeddingRAG]:
    """Build RAG instance: EmbeddingRAG if use_embeddings and provider set, else SimpleRAG."""
    if use_embeddings and embedding_provider:
        return EmbeddingRAG(
            path=path,
            provider=embedding_provider,
            model_name=embedding_model,
        )
    return SimpleRAG(path=path)
