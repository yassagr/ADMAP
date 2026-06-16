from __future__ import annotations
import pytest
import math
from admap_m5.core.embedder import CosineEmbedder


def test_fit_and_transform_basic():
    embedder = CosineEmbedder()
    docs = [["T1059", "T1071"], ["T1059", "T1027"]]
    embedder.fit(docs)
    vec = embedder.transform(["T1059"])
    assert isinstance(vec, list)
    assert all(isinstance(v, float) for v in vec)


def test_cosine_similarity_identical():
    embedder = CosineEmbedder()
    v1 = [0.5, 0.5]
    v2 = [0.5, 0.5]
    assert math.isclose(embedder.cosine_similarity(v1, v2), 1.0, abs_tol=1e-5)


def test_cosine_similarity_orthogonal():
    embedder = CosineEmbedder()
    v1 = [1.0, 0.0]
    v2 = [0.0, 1.0]
    assert embedder.cosine_similarity(v1, v2) == 0.0


def test_cosine_similarity_zero_vector():
    embedder = CosineEmbedder()
    v1 = [0.0, 0.0]
    v2 = [1.0, 1.0]
    assert embedder.cosine_similarity(v1, v2) == 0.0


def test_transform_before_fit_raises():
    embedder = CosineEmbedder()
    with pytest.raises(RuntimeError):
        embedder.transform(["T1059"])


def test_fit_empty_corpus():
    embedder = CosineEmbedder()
    embedder.fit([])
    assert embedder._fitted is False


def test_vector_dimension_mismatch():
    embedder = CosineEmbedder()
    with pytest.raises(ValueError):
        embedder.cosine_similarity([1.0], [1.0, 2.0])


def test_normalize_l2():
    embedder = CosineEmbedder()
    docs = [["T1059", "T1071"], ["T1059", "T1027"]]
    embedder.fit(docs)
    vec = embedder.transform(["T1059", "T1071"])
    norm = math.sqrt(sum(v * v for v in vec))
    assert norm <= 1.0 + 1e-5
