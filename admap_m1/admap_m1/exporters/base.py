"""
Module   : admap_m1.exporters.base
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.core.logging]

Classe de base pour les exportateurs de formats (STIX, OpenIOC, MISP, Cytomic).
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from admap_m1.core.logging import get_logger
from admap_m1.models.ioc import IOCBundle


class BaseExporter(ABC):
    """Classe de base pour l'exportation des résultats.

    Transforme le modèle interne IOCBundle vers un format standard.
    """

    def __init__(self) -> None:
        self._logger = get_logger(f"exporters.{self.format_name}")

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Nom du format d'export (ex: 'stix21', 'misp')."""
        pass

    @abstractmethod
    def export(self, bundle: IOCBundle) -> str:
        """Sérialise le bundle dans le format cible.

        Args:
            bundle: Le résultat complet de l'analyse.

        Returns:
            La chaîne de caractères du format généré (JSON, XML, etc.).
        """
        pass
