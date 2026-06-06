"""
Module   : admap_m2.detectors.http_c2_detector
Version  : 1.0.0
Dépend   : [admap_m2.detectors.base]
"""
from __future__ import annotations

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class HTTPC2Detector(BaseDetector):
    """
    Détecte le trafic HTTP C2:
    - User-Agents suspects ou vides
    - Hôtes purement IP
    - Requêtes POST sans Referer
    """

    SUSPICIOUS_UAS = {
        "python-requests", "curl", "wget", "powershell", "winhttp",
        "bitsadmin", "certutil"
    }

    @property
    def detector_name(self) -> str:
        return "http_c2_detector"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        alerts = []

        for flow in flows:
            if not flow.http_requests:
                continue

            suspicious_score = 0
            evidence = []

            for req in flow.http_requests:
                ua = req.user_agent.lower()
                
                # Check empty UA
                if not ua:
                    suspicious_score += 20
                    evidence.append(f"Empty User-Agent for {req.method} {req.uri}")
                # Check suspicious UA
                elif any(s_ua in ua for s_ua in self.SUSPICIOUS_UAS):
                    suspicious_score += 50
                    evidence.append(f"Suspicious User-Agent: {req.user_agent}")

                # Pure IP Host
                if req.host.replace('.', '').isdigit():
                    suspicious_score += 30
                    evidence.append(f"Pure IP Host header: {req.host}")

                # POST without Referer
                if req.method == "POST" and "referer" not in req.headers:
                    suspicious_score += 10
                    evidence.append(f"POST request without Referer to {req.uri}")

            if suspicious_score > 0:
                score = min(100, suspicious_score)
                alert = self._build_alert(
                    flow=flow,
                    alert_type=AlertType.HTTP_C2,
                    score=score,
                    description=f"Suspected HTTP C2 Traffic",
                    evidence=list(set(evidence))[:5],  # Top 5 unique evidence
                    metadata={"max_score": score}
                )
                alerts.append(alert)

        return alerts
