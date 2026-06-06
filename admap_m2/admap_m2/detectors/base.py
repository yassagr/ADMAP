"""
Module   : admap_m2.detectors.base
Version  : 1.0.0
Dépend   : [abc, admap_m2.models.flow, admap_m2.models.alert]
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from admap_m2.core.config import Settings
from admap_m2.core.logging import get_logger
from admap_m2.models.alert import AlertSeverity, AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class BaseDetector(ABC):
    """
    Interface commune pour tous les détecteurs C2.
    Chaque détecteur analyse une liste de flux et retourne des alertes.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logger = get_logger(f"detectors.{self.detector_name}")

    @property
    @abstractmethod
    def detector_name(self) -> str:
        """Identifiant du détecteur."""

    @abstractmethod
    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        """
        Analyse les flux et retourne les alertes.

        Args:
            flows: Liste des flux reconstruits depuis le PCAP.

        Returns:
            Liste de C2Alert (peut être vide si rien de suspect).
        """

    def _build_alert(
        self,
        flow: NetworkFlow,
        alert_type: AlertType,
        score: int,
        description: str,
        evidence: list[str],
        metadata: dict[str, object] | None = None,
    ) -> C2Alert:
        """Helper : construit une C2Alert depuis un flux."""
        severity = self._score_to_severity(score)
        return C2Alert(
            alert_type=alert_type,
            severity=severity,
            confidence_score=max(0, min(100, score)),
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol.value,
            first_seen=flow.first_seen,
            last_seen=flow.last_seen,
            packet_count=flow.packet_count,
            byte_count=flow.byte_count_src_to_dst + flow.byte_count_dst_to_src,
            description=description,
            evidence=evidence,
            metadata=metadata or {},
        )

    @staticmethod
    def _score_to_severity(score: int) -> AlertSeverity:
        if score >= 80: return AlertSeverity.CRITICAL
        if score >= 60: return AlertSeverity.HIGH
        if score >= 40: return AlertSeverity.MEDIUM
        if score >= 20: return AlertSeverity.LOW
        return AlertSeverity.INFO
