"""
Module   : admap_m2.correlators.base
Version  : 1.0.0
Dépend   : [abc, admap_m2.core.config, admap_m2.core.logging,
            admap_m2.models.alert, admap_m2.models.flow]
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from admap_m2.core.config import Settings
from admap_m2.core.logging import get_logger
from admap_m2.models.alert import C2Alert
from admap_m2.models.flow import NetworkFlow


class BaseCorrelator(ABC):
    """
    Interface pour les corrélateurs.
    Un corrélateur génère de nouvelles alertes par corrélation
    à partir des flux et/ou alertes existantes.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logger = get_logger(f"correlators.{self.correlator_name}")

    @property
    @abstractmethod
    def correlator_name(self) -> str:
        """Identifiant unique du corrélateur."""

    @abstractmethod
    def correlate(
        self, flows: list[NetworkFlow], alerts: list[C2Alert]
    ) -> list[C2Alert]:
        """
        Effectue la corrélation et retourne de nouvelles alertes.

        Args:
            flows: Liste des flux reconstruits.
            alerts: Alertes déjà générées par les détecteurs.

        Returns:
            Liste de nouvelles C2Alert (peut être vide).
        """
