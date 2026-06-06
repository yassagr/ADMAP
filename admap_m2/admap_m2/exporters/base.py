"""
Module   : admap_m2.exporters.base
Version  : 1.0.0
Dépend   : [abc, admap_m2.models.alert]
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from admap_m2.models.alert import AlertBundle


class BaseExporter(ABC):
    """Interface pour les exportateurs."""

    @abstractmethod
    def export(self, bundle: AlertBundle) -> str:
        """
        Exporte un AlertBundle vers une chaîne de caractères (JSON, CSV, STIX).
        """
