"""
Module   : admap_m2.analyzers.flow_analyzer
Version  : 1.0.0
Dépend   : [admap_m2.models.flow, admap_m2.models.alert]
"""
from __future__ import annotations

from admap_m2.core.config import Settings
from admap_m2.core.logging import get_logger
from admap_m2.models.alert import C2Alert
from admap_m2.models.flow import NetworkFlow


class FlowAnalyzer:
    """
    Orchestrateur de l'analyse flux par flux.
    Passe chaque flux aux détecteurs et corrélateurs configurés.
    """

    def __init__(self, settings: Settings, detectors: list, correlators: list):
        self._settings = settings
        self._logger = get_logger("analyzers.flow_analyzer")
        self._detectors = detectors
        self._correlators = correlators

    def analyze(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        alerts = []
        
        # 1. Détecteurs
        for detector in self._detectors:
            try:
                new_alerts = detector.detect(flows)
                alerts.extend(new_alerts)
                self._logger.debug(
                    "detector_run_success",
                    detector=detector.detector_name,
                    alerts_found=len(new_alerts)
                )
            except Exception as e:
                self._logger.error(
                    "detector_failed",
                    detector=detector.detector_name,
                    error=str(e)
                )

        # 2. Corrélateurs
        for correlator in self._correlators:
            try:
                correlated_alerts = correlator.correlate(flows, alerts)
                alerts.extend(correlated_alerts)
                self._logger.debug(
                    "correlator_run_success",
                    correlator=correlator.correlator_name,
                    alerts_found=len(correlated_alerts)
                )
            except Exception as e:
                self._logger.error(
                    "correlator_failed",
                    correlator=correlator.correlator_name,
                    error=str(e)
                )

        # Filtrer par min_confidence_threshold
        threshold = self._settings.min_confidence_threshold if hasattr(self._settings, "min_confidence_threshold") else 20
        filtered_alerts = [a for a in alerts if a.confidence_score >= threshold]

        return filtered_alerts
