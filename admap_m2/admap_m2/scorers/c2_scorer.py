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
    Agrège et fusionne les alertes de plusieurs détecteurs pour un même flux.

    Logique de fusion :
    - Grouper par (src_ip, dst_ip, dst_port)
    - Si N alertes pour le même endpoint :
      score_final = min(100, s1 + s2*0.7 + s3*0.5 + ...)
    - Créer une alerte agrégée avec types et preuves fusionnés.
    """

    @staticmethod
    def aggregate_alerts(alerts: list[C2Alert]) -> list[C2Alert]:
        """
        Agrège les alertes dupliquées de types différents sur le même endpoint.

        Args:
            alerts: Liste brute d'alertes de tous les détecteurs.

        Returns:
            Liste dédupliquée et triée par score décroissant.
        """
        if not alerts:
            return []

        groups: dict[tuple[str, str, int], list[C2Alert]] = defaultdict(list)
        for alert in alerts:
            key = (alert.src_ip, alert.dst_ip, alert.dst_port)
            groups[key].append(alert)

        result: list[C2Alert] = []
        for _key, group in groups.items():
            if len(group) == 1:
                result.append(group[0])
                continue

            sorted_scores = sorted([a.confidence_score for a in group], reverse=True)
            aggregated_score = sorted_scores[0]
            for i, score in enumerate(sorted_scores[1:], 1):
                aggregated_score += score * (0.7 ** i)
            aggregated_score = min(100, int(aggregated_score))

            all_evidence: list[str] = []
            all_types: list[str] = []
            for a in group:
                all_evidence.extend(a.evidence)
                all_types.append(a.alert_type.value)

            base = group[0]
            severity = C2Scorer._score_to_severity(aggregated_score)

            merged = C2Alert(
                id=base.id,
                alert_type=base.alert_type,
                severity=severity,
                confidence_score=aggregated_score,
                src_ip=base.src_ip,
                dst_ip=base.dst_ip,
                src_port=base.src_port,
                dst_port=base.dst_port,
                protocol=base.protocol,
                first_seen=min(a.first_seen for a in group),
                last_seen=max(a.last_seen for a in group),
                packet_count=sum(a.packet_count for a in group),
                byte_count=sum(a.byte_count for a in group),
                description=f"[{'/'.join(all_types)}] {base.description}",
                evidence=list(dict.fromkeys(all_evidence)),
                ioc_matches=list({m for a in group for m in a.ioc_matches}),
                metadata={"aggregated_types": all_types, "component_count": len(group)},
            )
            result.append(merged)

        return sorted(result, key=lambda a: a.confidence_score, reverse=True)

    @staticmethod
    def _score_to_severity(score: int) -> AlertSeverity:
        """
        Convertit un score entier en niveau de sévérité.

        Args:
            score: Score de 0 à 100.

        Returns:
            AlertSeverity correspondant.
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

    def group_by_severity(self, alerts: list[C2Alert]) -> dict[str, int]:
        """
        Compte les alertes par sévérité.

        Args:
            alerts: Liste d'alertes.

        Returns:
            Dictionnaire {severity_value: count}.
        """
        counts: dict[str, int] = {s.value: 0 for s in AlertSeverity}
        for alert in alerts:
            counts[alert.severity.value] += 1
        return counts
