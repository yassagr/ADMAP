"""
Module   : admap_m2.detectors.http_c2_detector
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


class HTTPC2Detector(BaseDetector):
    """
    Détecte le trafic C2 via HTTP/HTTPS.

    Indicateurs :
    1. User-Agent absent ou générique (curl, python-requests, Go-http...)
    2. Requêtes POST fréquentes vers même endpoint
    3. URIs très répétitifs (polling C2)
    4. Host header = adresse IP directe (sans nom de domaine)
    """

    SUSPICIOUS_UAS: ClassVar[set[str]] = {
        "curl", "wget", "python-requests", "python-urllib",
        "go-http-client", "java/", "apache-httpclient",
        "libcurl", "okhttp", "axios", "node-fetch",
        "powershell", "lwp-trivial", "perl", "ruby",
        "winhttp", "bitsadmin", "certutil",
    }

    @property
    def detector_name(self) -> str:
        return "http_c2"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        """
        Détecte le trafic HTTP C2 dans les flux.

        Args:
            flows: Liste des flux réseau.

        Returns:
            Liste de C2Alert de type HTTP_C2.
        """
        alerts: list[C2Alert] = []

        for flow in flows:
            if not flow.http_requests:
                continue
            score, evidence = self._analyze_http_flow(flow)
            if score >= 20:
                alerts.append(self._build_alert(
                    flow,
                    AlertType.HTTP_C2,
                    score,
                    f"HTTP C2 suspected: {len(flow.http_requests)} requests "
                    f"to {flow.dst_ip}:{flow.dst_port}",
                    evidence,
                    metadata={
                        "request_count": len(flow.http_requests),
                        "methods": list(set(r.method for r in flow.http_requests)),
                        "hosts": list(set(r.host for r in flow.http_requests)),
                    },
                ))

        return alerts

    def _analyze_http_flow(self, flow: NetworkFlow) -> tuple[int, list[str]]:
        """
        Analyse un flux HTTP et calcule le score de suspicion.

        Args:
            flow: Flux réseau contenant des requêtes HTTP.

        Returns:
            Tuple (score_0_100, liste_evidence).
        """
        score = 0
        evidence: list[str] = []
        requests = flow.http_requests

        # 1. User-Agents suspects
        uas = {r.user_agent.lower() for r in requests}
        for ua in uas:
            if not ua:
                score += 15
                evidence.append("Empty User-Agent")
                break
            for sus_ua in self.SUSPICIOUS_UAS:
                if sus_ua in ua:
                    score += 20
                    evidence.append(f"Suspicious User-Agent: {ua[:50]}")
                    break

        # 2. Fréquence de POST
        post_count = sum(1 for r in requests if r.method == "POST")
        if post_count >= 10:
            score += 20
            evidence.append(f"High POST frequency: {post_count}")
        elif post_count >= 5:
            score += 10
            evidence.append(f"Moderate POST frequency: {post_count}")

        # 3. URIs répétitifs (polling)
        uris = [r.uri for r in requests]
        if len(uris) > 3:
            unique_ratio = len(set(uris)) / len(uris)
            if unique_ratio < 0.3:
                score += 20
                evidence.append(
                    f"Repetitive URI pattern (uniqueness: {unique_ratio:.2f})"
                )

        # 4. Host = adresse IP directe (utilise ipaddress pour validation correcte)
        for req in requests:
            host_clean = req.host.split(":")[0]
            try:
                ipaddress.ip_address(host_clean)
                score += 20
                evidence.append(f"Direct IP as Host: {req.host}")
                break
            except ValueError:
                pass

        return min(100, score), evidence
