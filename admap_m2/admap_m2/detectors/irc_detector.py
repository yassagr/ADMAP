"""
Module   : admap_m2.detectors.irc_detector
Version  : 1.0.0
Dépend   : [admap_m2.detectors.base, admap_m2.models.alert, admap_m2.models.flow]
"""
from __future__ import annotations

from typing import ClassVar

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow, Protocol


class IRCDetector(BaseDetector):
    """
    Détecte le trafic C2 via IRC.

    Indicateurs :
    1. Port IRC connu (6667, 6668, 6669, 7000, 194, 6697)
    2. Commandes IRC dans le payload (NICK, USER, JOIN, PRIVMSG...)
    3. Indicateurs de channels botnet (#botnet, #cmd, #control...)
    """

    IRC_PORTS: ClassVar[set[int]] = {6667, 6668, 6669, 7000, 194, 6697}

    IRC_COMMANDS: ClassVar[set[bytes]] = {
        b"NICK ", b"USER ", b"JOIN ", b"PRIVMSG ",
        b"PING ", b"PONG ", b"MODE ", b"PART ", b"QUIT ", b"NOTICE ",
    }

    BOT_CHANNEL_INDICATORS: ClassVar[list[str]] = [
        "botnet", "bot", "cmd", "control", "ddos", "spam",
        "flood", "hack", "crack", "shell", "zombies",
    ]

    @property
    def detector_name(self) -> str:
        return "irc_c2"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        """
        Détecte le trafic IRC C2.

        Args:
            flows: Liste des flux réseau.

        Returns:
            Liste de C2Alert de type IRC_C2.
        """
        alerts: list[C2Alert] = []

        for flow in flows:
            score, evidence = self._analyze_irc(flow)
            if score >= 30:
                alerts.append(self._build_alert(
                    flow,
                    AlertType.IRC_C2,
                    score,
                    f"IRC C2 activity detected from {flow.src_ip} "
                    f"to {flow.dst_ip}:{flow.dst_port}",
                    evidence,
                    metadata={"dst_port": flow.dst_port},
                ))

        return alerts

    def _analyze_irc(self, flow: NetworkFlow) -> tuple[int, list[str]]:
        """
        Analyse un flux pour détecter IRC C2.

        Args:
            flow: Flux réseau à analyser.

        Returns:
            Tuple (score_0_100, liste_evidence).
        """
        score = 0
        evidence: list[str] = []

        # Port IRC connu ou protocole IRC
        if flow.dst_port in self.IRC_PORTS or flow.protocol == Protocol.IRC:
            score += 30
            evidence.append(f"Known IRC port: {flow.dst_port}")

        # Commandes IRC dans le payload
        if flow.payload_sample:
            payload = flow.payload_sample
            found_cmds = [
                cmd.decode().strip()
                for cmd in self.IRC_COMMANDS
                if cmd in payload
            ]
            if found_cmds:
                score += 40
                evidence.append(f"IRC commands detected: {found_cmds[:3]}")

                # Channels suspects
                for indicator in self.BOT_CHANNEL_INDICATORS:
                    if indicator.encode() in payload.lower():
                        score += 20
                        evidence.append(f"Botnet channel indicator: {indicator}")
                        break

        return min(100, score), evidence
