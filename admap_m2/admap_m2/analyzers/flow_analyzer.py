"""
Module   : admap_m2.analyzers.flow_analyzer
Version  : 1.0.0
Dépend   : [admap_m2.core.config, admap_m2.core.logging,
            admap_m2.models.alert, admap_m2.models.flow]
"""
from __future__ import annotations

from admap_m2.core.config import Settings
from admap_m2.core.logging import get_logger
from admap_m2.models.alert import C2Alert
from admap_m2.models.flow import NetworkFlow


class FlowAnalyzer:
    """
    Orchestrateur de l'analyse flux par flux.
    Exécute séquentiellement les détecteurs puis les corrélateurs.
    Le filtrage par seuil de confiance est délégué à l'appelant.
    """

    def __init__(
        self,
        settings: Settings,
        detectors: list,
        correlators: list,
    ) -> None:
        self._settings = settings
        self._logger = get_logger("analyzers.flow_analyzer")
        self._detectors = detectors
        self._correlators = correlators

    def analyze(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        """
        Exécute tous les détecteurs et corrélateurs sur les flux.

        Retourne toutes les alertes sans filtrage par seuil —
        le filtrage est à la charge de l'appelant (orchestrateur).

        Args:
            flows: Liste des flux réseau reconstruits.

        Returns:
            Liste brute de toutes les alertes générées.
        """
        alerts: list[C2Alert] = []

        for detector in self._detectors:
            try:
                new_alerts = detector.detect(flows)
                alerts.extend(new_alerts)
                self._logger.debug(
                    "detector_run_success",
                    detector=detector.detector_name,
                    alerts_found=len(new_alerts),
                )
            except Exception as e:
                self._logger.error(
                    "detector_failed",
                    detector=detector.detector_name,
                    error=str(e),
                )

        for correlator in self._correlators:
            try:
                correlated_alerts = correlator.correlate(flows, alerts)
                alerts.extend(correlated_alerts)
                self._logger.debug(
                    "correlator_run_success",
                    correlator=correlator.correlator_name,
                    alerts_found=len(correlated_alerts),
                )
            except Exception as e:
                self._logger.error(
                    "correlator_failed",
                    correlator=correlator.correlator_name,
                    error=str(e),
                )

        return alerts
