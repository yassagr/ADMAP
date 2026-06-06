"""
Module   : admap_m2.detectors.dga_detector
Version  : 1.0.0
Dépend   : [math, admap_m2.detectors.base]
"""
from __future__ import annotations

import math

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class DGADetector(BaseDetector):
    """
    Détecte les Domain Generation Algorithms (DGA) en calculant l'entropie
    de Shannon sur les requêtes DNS et les hostnames HTTP/TLS.
    """

    @property
    def detector_name(self) -> str:
        return "dga_detector"

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freqs = {}
        for char in data:
            freqs[char] = freqs.get(char, 0) + 1
        for freq in freqs.values():
            p = freq / length
            entropy -= p * math.log2(p)
        return entropy

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        alerts = []
        entropy_threshold = self._settings.DGA_ENTROPY_THRESHOLD
        min_length = self._settings.DGA_MIN_DOMAIN_LENGTH

        for flow in flows:
            domains_to_check = set()

            # DNS Queries
            for dns in flow.dns_queries:
                domains_to_check.add(dns.query_name)

            # HTTP Host
            for http in flow.http_requests:
                if http.host:
                    domains_to_check.add(http.host)

            # TLS SNI
            if flow.tls_info and flow.tls_info.sni:
                domains_to_check.add(flow.tls_info.sni)

            for domain in domains_to_check:
                # Extraire le sous-domaine/domaine sans le TLD pour le calcul (simplification)
                parts = domain.split('.')
                main_part = parts[0] if len(parts) > 0 else domain

                if len(main_part) < min_length:
                    continue

                entropy = self._shannon_entropy(main_part)
                if entropy >= entropy_threshold:
                    score = int(min(100, 40 + (entropy - entropy_threshold) * 20))
                    evidence = [
                        f"Domain: {domain}",
                        f"Entropy: {entropy:.2f} (threshold: {entropy_threshold})"
                    ]
                    alert = self._build_alert(
                        flow=flow,
                        alert_type=AlertType.DGA,
                        score=score,
                        description=f"Suspected DGA Domain: {domain}",
                        evidence=evidence,
                        metadata={"domain": domain, "entropy": entropy}
                    )
                    alerts.append(alert)

        return alerts
