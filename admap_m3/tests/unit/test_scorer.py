"""
Tests unitaires pour le scorer de tokens (admap_m3.core.scorer).
"""
from __future__ import annotations

import pytest

from admap_m3.config import Settings
from admap_m3.core.scorer import TokenScorer, score_to_confidence
from admap_m3.models.token import TokenFeature, TokenScore


class TestScoreToConfidence:
    """Tests du mapping Δ → confiance."""

    def test_score_to_confidence_low(self) -> None:
        """Δ = 0.25 → 0 (sous le seuil)."""
        assert score_to_confidence(0.25) == 0

    def test_score_to_confidence_medium(self) -> None:
        """Δ = 0.40 → valeur entre 40 et 70."""
        result: int = score_to_confidence(0.40)
        assert 40 <= result < 70

    def test_score_to_confidence_high(self) -> None:
        """Δ = 0.75 → valeur entre 70 et 90."""
        result: int = score_to_confidence(0.75)
        assert 70 <= result < 90

    def test_score_to_confidence_max(self) -> None:
        """Δ = 1.00 → 100."""
        result: int = score_to_confidence(1.00)
        assert result == 100


class TestTokenScorer:
    """Tests du filtrage et scoring des tokens."""

    @pytest.fixture
    def scorer(self, settings: Settings) -> TokenScorer:
        return TokenScorer(settings=settings)

    def _make_feature(
        self,
        token: str = "test_token_long_enough",
        delta_score: float = 0.50,
        df_malware: int = 2,
        df_benign: int = 0,
    ) -> TokenFeature:
        return TokenFeature(
            token=token,
            token_type="string",
            tf_malware=delta_score,
            tf_benign_max=0.0,
            delta_score=delta_score,
            df_malware=df_malware,
            df_benign=df_benign,
            corpus_id="test",
        )

    def test_filter_rejects_short_token(self, scorer: TokenScorer) -> None:
        """Token de longueur 4 → rejected, reason=token_too_short."""
        feature: TokenFeature = self._make_feature(token="abcd", delta_score=0.50)
        scores: list[TokenScore] = scorer.filter_and_score([feature])
        assert len(scores) == 1
        assert scores[0].selected is False
        assert scores[0].rejection_reason == "token_too_short"

    def test_filter_rejects_below_threshold(self, scorer: TokenScorer) -> None:
        """delta_score=0.20 → rejected, reason=delta_below_threshold."""
        feature: TokenFeature = self._make_feature(delta_score=0.20)
        scores: list[TokenScore] = scorer.filter_and_score([feature])
        assert len(scores) == 1
        assert scores[0].selected is False
        assert scores[0].rejection_reason == "delta_below_threshold"

    def test_filter_rejects_present_in_benign(self, scorer: TokenScorer) -> None:
        """df_benign=1, max_df_benign=0 → rejected, reason=present_in_benign."""
        feature: TokenFeature = self._make_feature(df_benign=1)
        scores: list[TokenScore] = scorer.filter_and_score([feature])
        assert len(scores) == 1
        assert scores[0].selected is False
        assert scores[0].rejection_reason == "present_in_benign"

    def test_top_n_returns_sorted(self, scorer: TokenScorer) -> None:
        """top_n retourne les N meilleurs par delta_score DESC."""
        features: list[TokenFeature] = [
            self._make_feature(token="token_low_score_xx", delta_score=0.35),
            self._make_feature(token="token_high_score_x", delta_score=0.90),
            self._make_feature(token="token_mid_score_xx", delta_score=0.60),
        ]
        scores: list[TokenScore] = scorer.filter_and_score(features)
        top: list[TokenScore] = scorer.top_n(scores, 3)

        assert len(top) == 3
        assert top[0].delta_score >= top[1].delta_score >= top[2].delta_score
