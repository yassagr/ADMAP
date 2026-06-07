"""
Module   : admap_m2.detectors.beaconing_detector
Version  : 1.0.0
Dépend   : [collections, admap_m2.detectors.base]
"""
from __future__ import annotations

from collections import defaultdict

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class BeaconingDetector(BaseDetector):
    """
    Détecte les patterns de beaconing C2.

    Algorithme :
    1. Grouper les flux par (dst_ip, dst_port)
    2. Pour chaque groupe avec >= MIN_OCCURRENCES flux :
       a. Extraire les timestamps first_seen de chaque flux
       b. Calculer les intervalles entre flux consécutifs
       c. Si coefficient de variation (CV = std/mean) <= JITTER_TOLERANCE :
          → Pattern de beaconing détecté
    3. Score basé sur : nombre de répétitions, CV, intervalle moyen
    """

    @property
    def detector_name(self) -> str:
        return "beaconing"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        """
        Analyse les flux pour détecter des patterns de beaconing.

        Args:
            flows: Liste des flux reconstruits depuis le PCAP.

        Returns:
            Liste de C2Alert de type BEACONING.
        """
        alerts: list[C2Alert] = []
        groups: dict[tuple[str, int], list[NetworkFlow]] = defaultdict(list)

        for flow in flows:
            groups[(flow.dst_ip, flow.dst_port)].append(flow)

        min_occ = self._settings.BEACONING_MIN_OCCURRENCES
        jitter_tol = self._settings.BEACONING_JITTER_TOLERANCE

        for (dst_ip, dst_port), group_flows in groups.items():
            if len(group_flows) < min_occ:
                continue

            sorted_flows = sorted(group_flows, key=lambda f: f.first_seen)
            timestamps = [f.first_seen.timestamp() for f in sorted_flows]
            intervals = [
                timestamps[i + 1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]

            if len(intervals) < 2:
                continue

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 1.0:
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            cv = std_dev / mean_interval

            if cv <= jitter_tol:
                score = self._calculate_score(len(group_flows), cv, mean_interval)
                description = (
                    f"Beaconing detected: {len(group_flows)} connections "
                    f"to {dst_ip}:{dst_port} every "
                    f"{mean_interval:.1f}s ± {cv * 100:.1f}%"
                )
                evidence = [
                    f"Occurrences: {len(group_flows)}",
                    f"Mean interval: {mean_interval:.2f}s",
                    f"CV (jitter): {cv:.3f} ({cv * 100:.1f}%)",
                    f"Std dev: {std_dev:.2f}s",
                    f"Duration: {(timestamps[-1] - timestamps[0]):.0f}s",
                ]
                alerts.append(self._build_alert(
                    sorted_flows[0],
                    AlertType.BEACONING,
                    score,
                    description,
                    evidence,
                    metadata={
                        "mean_interval_s": round(mean_interval, 2),
                        "cv": round(cv, 4),
                        "occurrences": len(group_flows),
                        "total_duration_s": round(timestamps[-1] - timestamps[0], 0),
                    },
                ))

        return alerts

    def _calculate_score(
        self, occurrences: int, cv: float, mean_interval: float
    ) -> int:
        """
        Calcule un score de confiance de 0 à 100.
        """
        score = 40
        if occurrences >= 10:
            score += 20
        if occurrences >= 50:
            score += 20
            
        if cv <= 0.05:
            score += 20
        elif cv <= 0.10:
            score += 10
            
        return min(100, score)
