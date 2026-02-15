"""Tests for SimpleRAG, EmbeddingRAG, and get_rag."""
from pathlib import Path

import pytest

from aws_arch_agent.rag.simple import SimpleRAG, _chunk_by_headers
from aws_arch_agent.rag import get_rag, EmbeddingRAG


def test_chunk_by_headers_splits_on_headers() -> None:
    """Headers (## / ###) start new chunks."""
    text = """## First
content one

## Second
content two
"""
    chunks = _chunk_by_headers(text)
    assert len(chunks) >= 2
    assert "First" in chunks[0]
    assert "Second" in chunks[1]


def test_rag_from_text_retrieve_keyword_match() -> None:
    """retrieve returns chunks that contain query words."""
    text = """## Security
Use IAM least privilege and encrypt S3.

## Cost
Set log retention and right-size instances.
"""
    rag = SimpleRAG(text=text)
    out = rag.retrieve("security encrypt", k=2)
    assert "Security" in out or "encrypt" in out.lower()
    assert out


def test_rag_from_path(tmp_path: Path) -> None:
    """RAG loads from file path."""
    doc = tmp_path / "doc.md"
    doc.write_text("## Operational Excellence\nCloudTrail and Flow Logs.", encoding="utf-8")
    rag = SimpleRAG(path=doc)
    out = rag.retrieve("operational cloudtrail", k=1)
    assert "CloudTrail" in out or "Operational" in out


def test_rag_empty_returns_empty_string() -> None:
    """Empty RAG (no path/text) returns empty string from retrieve."""
    rag = SimpleRAG()
    assert rag.retrieve("anything", k=3) == ""


def test_get_rag_keyword_by_default(tmp_path: Path) -> None:
    """get_rag with use_embeddings=False returns SimpleRAG."""
    (tmp_path / "doc.md").write_text("## Foo\nbar", encoding="utf-8")
    rag = get_rag(tmp_path / "doc.md", use_embeddings=False)
    assert isinstance(rag, SimpleRAG)
    assert "Foo" in rag.retrieve("foo", k=1)


def test_get_rag_embedding_when_requested(tmp_path: Path) -> None:
    """get_rag with use_embeddings=True and provider returns EmbeddingRAG."""
    (tmp_path / "doc.md").write_text("## Foo\nbar", encoding="utf-8")
    rag = get_rag(tmp_path / "doc.md", use_embeddings=True, embedding_provider="sentence-transformers")
    assert isinstance(rag, EmbeddingRAG)
    # Without sentence-transformers installed, falls back to keyword; still returns content
    out = rag.retrieve("foo bar", k=1)
    assert out


def test_embedding_rag_fallback_keyword(tmp_path: Path) -> None:
    """EmbeddingRAG with provider that fails to load falls back to keyword retrieval."""
    (tmp_path / "doc.md").write_text("## Security\nUse IAM least privilege.", encoding="utf-8")
    # Use openai without key to force fallback, or sentence-transformers without install
    rag = EmbeddingRAG(path=tmp_path / "doc.md", provider="sentence-transformers")
    out = rag.retrieve("security IAM", k=1)
    # Fallback returns best keyword match
    assert out and ("Security" in out or "IAM" in out)
