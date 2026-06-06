"""
Module   : admap_m2.scorers.c2_scorer
Version  : 1.0.0
Dépend   : [admap_m2.models.alert]
"""
from __future__ import annotations

from collections import defaultdict

from admap_m2.models.alert import AlertSeverity, C2Alert


class C2Scorer:
    """
    Calcule un score de suspicion agrégé.
    Le score peut être calculé par IP source, par IP de destination ou globalement.
    """

    def aggregate_by_src_ip(self, alerts: list[C2Alert]) -> dict[str, int]:
        """Retourne le score maximum par IP source."""
        scores = defaultdict(int)
        for alert in alerts:
            scores[alert.src_ip] = max(scores[alert.src_ip], alert.confidence_score)
        return dict(scores)

    def aggregate_by_dst_ip(self, alerts: list[C2Alert]) -> dict[str, int]:
        """Retourne le score maximum par IP destination."""
        scores = defaultdict(int)
        for alert in alerts:
            scores[alert.dst_ip] = max(scores[alert.dst_ip], alert.confidence_score)
        return dict(scores)

    def compute_global_score(self, alerts: list[C2Alert]) -> int:
        """Score global de l'analyse PCAP (le pire score trouvé)."""
        if not alerts:
            return 0
        return max(a.confidence_score for a in alerts)

    def group_by_severity(self, alerts: list[C2Alert]) -> dict[str, int]:
        """Compte les alertes par sévérité."""
        counts = {s.value: 0 for s in AlertSeverity}
        for alert in alerts:
            counts[alert.severity.value] += 1
        return counts
