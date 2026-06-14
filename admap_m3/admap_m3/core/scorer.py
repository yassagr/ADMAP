"""
Module   : admap_m3.core.scorer
Version  : 1.0.0
Dépend   : [admap_m3.config, admap_m3.models.token, structlog]

Scoring des tokens et filtrage selon les critères de sélection pour
l'inclusion dans les règles YARA.
"""
from __future__ import annotations

import structlog

from admap_m3.config import Settings
from admap_m3.models.token import TokenFeature, TokenScore

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


def score_to_confidence(delta: float) -> int:
    """Mapping canonique Δ → confiance (0-100).

    Règle de calcul (piecewise linear, JAMAIS de valeur hardcodée
    pour un token spécifique) :

    - Δ < 0.30           → 0
    - 0.30 ≤ Δ < 0.50    → 40 + int((Δ − 0.30) / 0.20 × 30)   ∈ [40, 70[
    - 0.50 ≤ Δ < 0.80    → 70 + int((Δ − 0.50) / 0.30 × 20)   ∈ [70, 90[
    - Δ ≥ 0.80           → 90 + min(10, int((Δ − 0.80) / 0.20 × 10))  ∈ [90, 100]
    """
    if delta < 0.30:
        return 0

    if delta < 0.50:
        return 40 + int((delta - 0.30) / 0.20 * 30)

    if delta < 0.80:
        return 70 + int((delta - 0.50) / 0.30 * 20)

    return min(100, 90 + round((delta - 0.80) / 0.20 * 10))


class TokenScorer:
    """Filtre et score les tokens selon les critères de sélection.

    Les 4 critères de rejet sont évalués **dans l'ordre** :
    1. ``delta_score`` ≥ ``delta_threshold``
    2. ``len(token)`` ≥ ``min_token_length``
    3. ``df_benign`` ≤ ``max_df_benign``
    4. ``df_malware`` ≥ ``min_df_malware``

    La première raison de rejet rencontrée est retenue.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings: Settings = settings

    def filter_and_score(
        self,
        features: list[TokenFeature],
    ) -> list[TokenScore]:
        """Applique les critères de sélection et retourne la liste COMPLÈTE.

        Les tokens sélectionnés ET rejetés sont retournés pour
        traçabilité.

        Args:
            features: Liste de ``TokenFeature`` à évaluer.

        Returns:
            Liste de ``TokenScore`` avec ``selected`` et
            ``rejection_reason`` renseignés.
        """
        results: list[TokenScore] = []

        for feature in features:
            rejection: str | None = None
            selected: bool = True

            # Critère 1 : delta_score ≥ delta_threshold
            if feature.delta_score < self._settings.delta_threshold:
                selected = False
                rejection = "delta_below_threshold"

            # Critère 2 : longueur ≥ min_token_length
            elif len(feature.token) < self._settings.min_token_length:
                selected = False
                rejection = "token_too_short"

            # Critère 3 : df_benign ≤ max_df_benign
            elif feature.df_benign > self._settings.max_df_benign:
                selected = False
                rejection = "present_in_benign"

            # Critère 4 : df_malware ≥ min_df_malware
            elif feature.df_malware < self._settings.min_df_malware:
                selected = False
                rejection = "insufficient_malware_coverage"

            confidence: int = score_to_confidence(feature.delta_score)

            results.append(
                TokenScore(
                    token=feature.token,
                    delta_score=feature.delta_score,
                    confidence=confidence,
                    selected=selected,
                    rejection_reason=rejection,
                )
            )

        selected_count: int = sum(1 for r in results if r.selected)
        logger.info(
            "token_scoring_complete",
            total_tokens=len(results),
            selected=selected_count,
            rejected=len(results) - selected_count,
        )

        return results

    def top_n(
        self,
        scores: list[TokenScore],
        n: int,
    ) -> list[TokenScore]:
        """Retourne les *n* meilleurs tokens ``selected=True``, triés par
        ``delta_score`` décroissant.

        Args:
            scores: Liste complète de ``TokenScore``.
            n: Nombre maximum de tokens à retourner.

        Returns:
            Sous-liste triée par ``delta_score`` DESC.
        """
        selected: list[TokenScore] = [s for s in scores if s.selected]
        selected.sort(key=lambda s: s.delta_score, reverse=True)
        return selected[:n]
