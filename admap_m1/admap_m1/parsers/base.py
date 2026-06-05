"""
Module   : admap_m1.parsers.base
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.core.logging, admap_m1.heuristics.entropy]

Classe de base abstraite pour tous les parsers de format de fichier.
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from pathlib import Path

from admap_m1.core.logging import get_logger
from admap_m1.heuristics.entropy import EntropyCalculator
from admap_m1.models.ioc import FileHashes, FileMetadata

try:
    import ppdeep
    PPDEEP_AVAILABLE = True
except ImportError:
    PPDEEP_AVAILABLE = False


class BaseParser(ABC):
    """Classe de base pour les analyseurs de format de fichier.

    Chaque parser spécifique (PE, ELF, Office, etc.) doit implémenter
    ``can_handle`` et ``parse_metadata``.
    """

    def __init__(self) -> None:
        self._logger = get_logger(f"parsers.{self.parser_name}")

    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Nom identifiant le parser."""
        pass

    @abstractmethod
    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """Détermine si ce parser peut analyser le fichier.

        Généralement basé sur les magic bytes ou l'extension.

        Args:
            file_bytes: Contenu brut du fichier.
            file_path: Chemin du fichier.

        Returns:
            True si le format est supporté.
        """
        pass

    @abstractmethod
    def parse_metadata(self, file_bytes: bytes, file_path: Path) -> FileMetadata:
        """Analyse le fichier et extrait ses métadonnées.

        Args:
            file_bytes: Contenu brut du fichier.
            file_path: Chemin du fichier.

        Returns:
            FileMetadata structurées.

        Raises:
            ExtractionError: En cas d'échec critique du parsing.
        """
        pass

    def _compute_basic_metadata(
        self,
        file_bytes: bytes,
        file_path: Path,
        filetype: str = "unknown"
    ) -> FileMetadata:
        """Calcule les métadonnées de base communes (hashes, taille, entropie).

        Args:
            file_bytes: Contenu brut.
            file_path: Chemin du fichier.
            filetype: Type MIME ou description du format.

        Returns:
            FileMetadata partiellement rempli (à compléter par le parser).
        """
        md5 = hashlib.md5(file_bytes).hexdigest()
        sha1 = hashlib.sha1(file_bytes).hexdigest()
        sha256 = hashlib.sha256(file_bytes).hexdigest()

        ssdeep_hash = None
        if PPDEEP_AVAILABLE:
            ssdeep_hash = ppdeep.hash(file_bytes)

        hashes = FileHashes(
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            ssdeep=ssdeep_hash,
        )

        magic_bytes = file_bytes[:16].hex()
        entropy = EntropyCalculator.calculate(file_bytes)

        return FileMetadata(
            filename=file_path.name,
            filesize=len(file_bytes),
            filetype=filetype,
            magic_bytes=magic_bytes,
            hashes=hashes,
            entropy=entropy,
            is_packed=entropy > 7.5,  # Heuristique très basique, à affiner par le packer detector
        )
