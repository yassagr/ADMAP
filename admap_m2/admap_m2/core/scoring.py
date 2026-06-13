"""
Module   : admap_m2.core.scoring
Version  : 1.0.0
Dépend   : [admap_m2.models.alert]
"""
from __future__ import annotations

from admap_m2.models.alert import AlertSeverity


def score_to_severity(score: int) -> AlertSeverity:
    """
    Convertit un score de confiance (0-100) en niveau de sévérité.

    Mapping canonique partagé par BaseDetector, C2Scorer et IOCCorrelator :
    - 80-100 : CRITICAL (C2 actif confirmé)
    - 60-79  : HIGH (très probable C2)
    - 40-59  : MEDIUM (suspect)
    - 20-39  : LOW (anomalie faible)
    - 0-19   : INFO (informatif seulement)

    Args:
        score: Score de confiance entre 0 et 100.

    Returns:
        AlertSeverity correspondante.
    """
    if score >= 80:
        return AlertSeverity.CRITICAL
    if score >= 60:
        return AlertSeverity.HIGH
    if score >= 40:
        return AlertSeverity.MEDIUM
    if score >= 20:
        return AlertSeverity.LOW
    return AlertSeverity.INFO
