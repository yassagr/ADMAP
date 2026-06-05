"""
Module   : admap_m1.extractors.base
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.core.logging]

Classe de base abstraite pour tous les extracteurs d'IOCs.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from admap_m1.core.logging import get_logger
from admap_m1.models.ioc import FileMetadata, RawIOC


class BaseExtractor(ABC):
    """Classe de base pour tous les extracteurs d'IOCs.

    Un extracteur prend un contenu brut (ou semi-structuré) et retourne
    une liste de `RawIOC`.
    """

    def __init__(self) -> None:
        self._logger = get_logger(f"extractors.{self.extraction_method}")

    @property
    @abstractmethod
    def extraction_method(self) -> str:
        """Nom de la méthode d'extraction (ex: 'regex_text', 'pe_imports')."""
        pass

    @abstractmethod
    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """Détermine si cet extracteur est applicable à ces données."""
        pass

    @abstractmethod
    def extract(
        self,
        file_bytes: bytes,
        file_path: Path,
        metadata: FileMetadata,
    ) -> list[RawIOC]:
        """Extrait les IOCs bruts des données.

        Args:
            file_bytes: Contenu brut à analyser.
            file_path: Chemin original.
            metadata: Métadonnées produites par le parser (ex: PEInfo).

        Returns:
            Liste d'IOCs bruts (`RawIOC`).
        """
        pass

    def _get_context_snippet(
        self,
        text: str,
        match_start: int,
        match_end: int,
        context_size: int = 32
    ) -> str:
        """Extrait un contexte autour d'un match (gauche et droite).

        Args:
            text: Le texte complet.
            match_start: Index de début du match.
            match_end: Index de fin du match.
            context_size: Nombre de caractères à inclure avant et après.

        Returns:
            Snippet contextuel, tronqué et nettoyé des retours chariot.
        """
        start = max(0, match_start - context_size)
        end = min(len(text), match_end + context_size)
        
        # Extraire et remplacer les retours chariot par des espaces
        snippet = text[start:end].replace('\r', ' ').replace('\n', ' ')
        
        # Réduire les espaces multiples
        import re
        snippet = re.sub(r'\s+', ' ', snippet).strip()
        
        return snippet
