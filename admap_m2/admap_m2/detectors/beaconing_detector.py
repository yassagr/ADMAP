"""
Module   : admap_m2.detectors.beaconing_detector
Version  : 1.0.0
Dépend   : [numpy, admap_m2.detectors.base]
"""
from __future__ import annotations

import numpy as np

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class BeaconingDetector(BaseDetector):
    """
    Détecte le beaconing C2.
    Analyse les intervalles inter-paquets.
    Si les intervalles sont très réguliers (faible écart-type par rapport à la moyenne),
    il est probable qu'il s'agisse d'un malware qui "call home" à intervalles réguliers.
    """

    @property
    def detector_name(self) -> str:
        return "beaconing_detector"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        alerts = []
        min_occ = self._settings.BEACONING_MIN_OCCURRENCES
        jitter_tol = self._settings.BEACONING_JITTER_TOLERANCE

        for flow in flows:
            intervals = flow.inter_packet_intervals
            if len(intervals) < min_occ:
                continue

            # Calculer moyenne et écart-type
            arr = np.array(intervals)
            mean_interval = np.mean(arr)
            std_interval = np.std(arr)

            # Si la moyenne est très faible, ce n'est pas un beacon mais un transfert de fichier (stream)
            if mean_interval < 1.0:
                continue

            # Jitter = écart-type / moyenne
            jitter = std_interval / mean_interval if mean_interval > 0 else 0.0

            if jitter <= jitter_tol:
                # Régularité suspecte
                score = 80 - int(jitter * 100)  # Moins il y a de jitter, plus le score est haut
                evidence = [
                    f"Found {len(intervals)} intervals",
                    f"Mean interval: {mean_interval:.2f}s",
                    f"Jitter: {jitter:.2f} (tolerance: {jitter_tol})"
                ]
                alert = self._build_alert(
                    flow=flow,
                    alert_type=AlertType.BEACONING,
                    score=score,
                    description=f"Suspected C2 Beaconing (interval ~{mean_interval:.1f}s)",
                    evidence=evidence,
                    metadata={"mean_interval": mean_interval, "jitter": jitter, "count": len(intervals)}
                )
                alerts.append(alert)

        return alerts
