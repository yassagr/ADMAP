"""
Module   : admap_m2.detectors.tls_detector
Version  : 1.0.0
Dépend   : [admap_m2.detectors.base]
"""
from __future__ import annotations

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class TLSDetector(BaseDetector):
    """
    Détecte le TLS suspect:
    - Pure IP SNI
    - SNI manquant
    """

    @property
    def detector_name(self) -> str:
        return "tls_detector"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        alerts = []

        for flow in flows:
            if not flow.tls_info:
                continue

            suspicious_score = 0
            evidence = []

            sni = flow.tls_info.sni
            if not sni:
                suspicious_score += 40
                evidence.append("Missing SNI in TLS ClientHello")
            elif sni.replace('.', '').isdigit():
                suspicious_score += 50
                evidence.append(f"Pure IP SNI: {sni}")

            if suspicious_score > 0:
                score = min(100, suspicious_score)
                alert = self._build_alert(
                    flow=flow,
                    alert_type=AlertType.TLS_SUSPECT,
                    score=score,
                    description=f"Suspected TLS Connection (score: {score})",
                    evidence=evidence,
                    metadata={"sni": sni}
                )
                alerts.append(alert)

        return alerts
