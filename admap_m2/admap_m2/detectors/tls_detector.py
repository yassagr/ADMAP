"""
Module   : admap_m2.detectors.tls_detector
Version  : 1.0.0
Dépend   : [ipaddress, admap_m2.detectors.base,
            admap_m2.models.alert, admap_m2.models.flow]
"""
from __future__ import annotations

import ipaddress
from typing import ClassVar

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class TLSDetector(BaseDetector):
    """
    Détecte les sessions TLS suspectes.

    Indicateurs :
    1. SNI absent
    2. SNI = adresse IP directe
    3. JA3 fingerprint connu pour C2 (Cobalt Strike, Metasploit...)
    4. Certificat auto-signé (issuer == subject)
    5. Certificat valide très longtemps (> 10 ans)
    6. TLS sur port non-standard
    """

    KNOWN_C2_JA3: ClassVar[set[str]] = {
        "e7d705a3286e19ea42f587b344ee6865",  # Cobalt Strike default
        "de9f102177e45f360bbea2c9cc09a49d",  # Metasploit
        "6daf0000bab10bbb0eb21a6df86ed9e4",  # Quasar RAT
        "d8f7c1a5c73b04fdbdd3ebbf68be77ed",  # AsyncRAT
    }

    STANDARD_TLS_PORTS: ClassVar[set[int]] = {443, 8443, 993, 995, 465, 587}

    @property
    def detector_name(self) -> str:
        return "tls_suspect"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        """
        Détecte les sessions TLS suspectes.

        Args:
            flows: Liste des flux réseau.

        Returns:
            Liste de C2Alert de type TLS_SUSPECT.
        """
        alerts: list[C2Alert] = []

        for flow in flows:
            if flow.tls_info is None:
                continue
            score, evidence = self._analyze_tls(flow)
            if score >= 20:
                description = (
                    f"Suspicious TLS session to {flow.dst_ip}:{flow.dst_port}"
                )
                if flow.tls_info.sni:
                    description += f" (SNI: {flow.tls_info.sni})"
                alerts.append(self._build_alert(
                    flow,
                    AlertType.TLS_SUSPECT,
                    score,
                    description,
                    evidence,
                    metadata={
                        "sni": flow.tls_info.sni,
                        "ja3": flow.tls_info.ja3,
                        "cert_issuer": flow.tls_info.cert_issuer,
                    },
                ))

        return alerts

    def _analyze_tls(self, flow: NetworkFlow) -> tuple[int, list[str]]:
        """
        Analyse une session TLS et calcule le score de suspicion.

        Args:
            flow: Flux réseau avec informations TLS.

        Returns:
            Tuple (score_0_100, liste_evidence).
        """
        score = 0
        evidence: list[str] = []
        tls = flow.tls_info

        # 1. SNI absent
        if not tls.sni:
            score += 15
            evidence.append("Missing SNI (Server Name Indication)")
        else:
            # 2. SNI = IP directe (utilise ipaddress pour validation correcte)
            try:
                ipaddress.ip_address(tls.sni)
                score += 25
                evidence.append(f"IP address used as SNI: {tls.sni}")
            except ValueError:
                pass

        # 3. JA3 connu C2
        if tls.ja3 and tls.ja3.lower() in self.KNOWN_C2_JA3:
            score += 50
            evidence.append(f"Known C2 JA3 fingerprint: {tls.ja3}")

        # 4. Certificat auto-signé (issuer == subject)
        if tls.cert_issuer and tls.cert_subject:
            if tls.cert_issuer == tls.cert_subject:
                score += 20
                evidence.append("Self-signed certificate detected")

        # 5. Certificat valide trop longtemps (> 10 ans)
        if tls.cert_validity_days > 3650:
            score += 15
            evidence.append(
                f"Certificate valid for {tls.cert_validity_days} days (>10 years)"
            )

        # 6. Port TLS non-standard
        if flow.dst_port not in self.STANDARD_TLS_PORTS:
            score += 15
            evidence.append(f"TLS on non-standard port: {flow.dst_port}")

        return min(100, score), evidence
