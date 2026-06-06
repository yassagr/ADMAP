"""
Module   : admap_m2.correlators.base
Version  : 1.0.0
Dépend   : [abc, admap_m2.models.flow, admap_m2.models.alert]
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
    Un corrélateur prend les flux (et/ou les alertes existantes)
    et les enrichit, ou génère de nouvelles alertes par corrélation.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logger = get_logger(f"correlators.{self.correlator_name}")

    @property
    @abstractmethod
    def correlator_name(self) -> str:
        """Identifiant du corrélateur."""

    @abstractmethod
    def correlate(self, flows: list[NetworkFlow], alerts: list[C2Alert]) -> list[C2Alert]:
        """
        Effectue la corrélation et retourne une liste de NOUVELLES alertes,
        ou modifie la liste des alertes existantes.
        """
