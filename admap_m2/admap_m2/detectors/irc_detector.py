"""
Module   : admap_m2.detectors.irc_detector
Version  : 1.0.0
Dépend   : [admap_m2.detectors.base]
"""
from __future__ import annotations

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow, Protocol


class IRCDetector(BaseDetector):
    """
    Détecte le trafic IRC potentiellement C2.
    Vérifie les ports classiques ou la présence de commandes IRC dans le payload.
    """

    IRC_COMMANDS = {b"USER", b"NICK", b"JOIN", b"PRIVMSG", b"PING", b"PONG"}

    @property
    def detector_name(self) -> str:
        return "irc_detector"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        alerts = []

        for flow in flows:
            suspicious_score = 0
            evidence = []

            is_irc_port = flow.protocol == Protocol.IRC

            if is_irc_port:
                suspicious_score += 40
                evidence.append(f"Standard IRC Port Used ({flow.dst_port})")

            # Check payload for IRC commands
            if flow.payload_sample:
                matches = 0
                for cmd in self.IRC_COMMANDS:
                    if cmd in flow.payload_sample:
                        matches += 1
                if matches >= 2:
                    suspicious_score += 50
                    evidence.append(f"Found {matches} IRC commands in payload")

            if suspicious_score >= 50:
                score = min(100, suspicious_score)
                alert = self._build_alert(
                    flow=flow,
                    alert_type=AlertType.IRC_C2,
                    score=score,
                    description=f"Suspected IRC C2 Traffic",
                    evidence=evidence,
                )
                alerts.append(alert)

        return alerts
