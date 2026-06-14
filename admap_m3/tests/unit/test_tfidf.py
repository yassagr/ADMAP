"""
Tests unitaires pour le moteur TF-IDF discriminant (admap_m3.core.tfidf).
"""
from __future__ import annotations

import pytest

from admap_m3.config import Settings
from admap_m3.core.tfidf import TFIDFEngine
from admap_m3.models.token import TokenFeature


@pytest.fixture
def engine(settings: Settings) -> TFIDFEngine:
    return TFIDFEngine(settings=settings)


class TestTFIDFEngine:
    """Tests du moteur TF-IDF discriminant."""

    def test_delta_computation_basic(
        self,
        engine: TFIDFEngine,
        sample_malware_token_lists: list[list[str]],
        sample_benign_token_lists: list[list[str]],
    ) -> None:
        """Δ(CreateRemoteThread) > 0.30 : token exclusif au malware."""
        features: list[TokenFeature] = engine.compute_corpus_tfidf(
            sample_malware_token_lists,
            sample_benign_token_lists,
            corpus_id="test_corpus",
        )

        crt_features: list[TokenFeature] = [
            f for f in features if f.token == "CreateRemoteThread"
        ]
        assert len(crt_features) == 1
        assert crt_features[0].delta_score > 0.0
        # CreateRemoteThread est absent des bénins → tf_benign_max = 0.0
        assert crt_features[0].tf_benign_max == 0.0

    def test_delta_computation_common_token(
        self,
        engine: TFIDFEngine,
    ) -> None:
        """Un token présent dans malware ET bénin avec tf similaire → Δ ≈ 0."""
        malware: list[list[str]] = [
            ["common_token", "other_a", "other_b"],
            ["common_token", "other_c", "other_d"],
        ]
        benign: list[list[str]] = [
            ["common_token", "safe_a", "safe_b"],
            ["common_token", "safe_c", "safe_d"],
        ]

        features: list[TokenFeature] = engine.compute_corpus_tfidf(
            malware, benign, "test_common"
        )

        ct: list[TokenFeature] = [f for f in features if f.token == "common_token"]
        assert len(ct) == 1
        # tf similaire dans les deux corpus → Δ ≈ 0
        assert abs(ct[0].delta_score) < 0.15

    def test_absent_benign_token_max_delta(
        self,
        engine: TFIDFEngine,
    ) -> None:
        """Token présent uniquement dans malware → tf_benign_max = 0.0."""
        malware: list[list[str]] = [
            ["exclusive_malware_token", "other"],
        ]
        benign: list[list[str]] = [
            ["safe_token", "another"],
        ]

        features: list[TokenFeature] = engine.compute_corpus_tfidf(
            malware, benign, "test_absent"
        )

        emt: list[TokenFeature] = [
            f for f in features if f.token == "exclusive_malware_token"
        ]
        assert len(emt) == 1
        assert emt[0].tf_benign_max == 0.0
        assert emt[0].delta_score > 0.0

    def test_tokenize_counter(self, engine: TFIDFEngine) -> None:
        """_tokenize([\"a\", \"b\", \"a\"]) → {\"a\": 2, \"b\": 1}."""
        result: dict[str, int] = engine._tokenize(["a", "b", "a"])
        assert result == {"a": 2, "b": 1}

    def test_empty_corpus_returns_empty(self, engine: TFIDFEngine) -> None:
        """compute_corpus_tfidf([], []) → []."""
        features: list[TokenFeature] = engine.compute_corpus_tfidf([], [], "empty")
        assert features == []
