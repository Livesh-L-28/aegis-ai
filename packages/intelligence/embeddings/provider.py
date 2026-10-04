import hashlib
import math

# Standard lightweight embedding dimension (compatible with fast deterministic testing and local vector stores)
DEFAULT_EMBEDDING_DIM = 64


def deterministic_text_embedding(text: str, dim: int = DEFAULT_EMBEDDING_DIM) -> list[float]:
    """Generates a deterministic normalized unit vector embedding using stable hashing.

    Provides reproducible semantic vectors for tests, hybrid retrieval, and local setups
    without external API or heavy GPU requirements, strictly satisfying Phase 3 boundaries.
    """
    if not text.strip():
        return [0.0] * dim

    words = text.lower().split()
    vector = [0.0] * dim

    for i, word in enumerate(words):
        h = int(hashlib.sha256(word.encode("utf-8")).hexdigest(), 16)
        idx = (h + i) % dim
        val = ((h >> 8) % 1000) / 1000.0 - 0.5
        vector[idx] += val

    # L2 normalize
    norm = math.sqrt(sum(x * x for x in vector))
    if norm > 0:
        vector = [x / norm for x in vector]
    return vector


def cosine_similarity(v1: list[float], v2: list[float]) -> float:
    """Compute cosine similarity between two normalized vectors."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    return sum(a * b for a, b in zip(v1, v2, strict=False))


class EmbeddingProvider:
    """Pluggable embedding provider abstraction."""

    def __init__(self, dim: int = DEFAULT_EMBEDDING_DIM) -> None:
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        return deterministic_text_embedding(text, self.dim)

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]


default_embedding_provider = EmbeddingProvider()
