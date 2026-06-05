"""
Module   : admap_m1.enrichers.base
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.core.logging]

Classe de base asynchrone pour les enrichisseurs d'IOC (ex: VirusTotal).
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from admap_m1.core.logging import get_logger
from admap_m1.models.ioc import IOC


class BaseEnricher(ABC):
    """Classe de base pour les services d'enrichissement d'IOCs.

    Tous les enrichisseurs doivent être asynchrones pour ne pas bloquer
    l'orchestrateur.
    """

    def __init__(self) -> None:
        self._logger = get_logger(f"enrichers.{self.enricher_name}")

    @property
    @abstractmethod
    def enricher_name(self) -> str:
        """Nom de la source d'enrichissement (ex: 'virustotal')."""
        pass

    @abstractmethod
    async def enrich_bulk(self, iocs: list[IOC]) -> None:
        """Enrichit une liste d'IOCs en place.

        Met à jour les attributs de l'IOC (ex: ioc.vt_result).
        Gère ses propres timeouts, retries et caches.

        Args:
            iocs: Liste d'IOCs à enrichir (mutée en place pour VTResult).
                  Même si IOC est frozen, on peut utiliser object.__setattr__
                  pendant cette phase de construction ou on recrée l'IOC.
        """
        pass
