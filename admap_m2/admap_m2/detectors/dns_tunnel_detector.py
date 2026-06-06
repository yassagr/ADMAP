"""
Module   : admap_m2.detectors.dns_tunnel_detector
Version  : 1.0.0
Dépend   : [admap_m2.detectors.base]
"""
from __future__ import annotations

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class DNSTunnelDetector(BaseDetector):
    """
    Détecte le tunneling DNS (exfiltration ou C2) en analysant
    la longueur des sous-domaines dans les requêtes DNS et la fréquence.
    """

    @property
    def detector_name(self) -> str:
        return "dns_tunnel_detector"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        alerts = []
        length_threshold = self._settings.DNS_TUNNEL_QUERY_LENGTH
        min_queries = self._settings.DNS_TUNNEL_MIN_QUERIES

        for flow in flows:
            if len(flow.dns_queries) < min_queries:
                continue

            # Trouver la longueur moyenne des noms de domaine
            total_len = sum(len(q.query_name) for q in flow.dns_queries)
            avg_len = total_len / len(flow.dns_queries)

            if avg_len >= length_threshold:
                # Suspect !
                score = min(100, 50 + int((avg_len - length_threshold) * 2))
                evidence = [
                    f"DNS Queries count: {len(flow.dns_queries)}",
                    f"Average query length: {avg_len:.1f} chars (threshold: {length_threshold})"
                ]
                alert = self._build_alert(
                    flow=flow,
                    alert_type=AlertType.DNS_TUNNEL,
                    score=score,
                    description=f"Suspected DNS Tunneling (avg query len: {avg_len:.1f})",
                    evidence=evidence,
                    metadata={"query_count": len(flow.dns_queries), "avg_query_length": avg_len}
                )
                alerts.append(alert)

        return alerts
