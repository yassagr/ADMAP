"""
Module   : admap_m1.parsers.elf_parser
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.parsers.base]

Parser pour les fichiers ELF (Exécutables Linux/Unix).
Utilise pyelftools si disponible, sinon mode dégradé (métadonnées basiques).
"""
from __future__ import annotations

import io
from pathlib import Path

from admap_m1.models.ioc import FileMetadata
from admap_m1.parsers.base import BaseParser

try:
    from elftools.elf.elffile import ELFFile
    from elftools.common.exceptions import ELFError
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False


class ELFParser(BaseParser):
    """Parser pour les exécutables ELF (Linux/Unix).

    Dépendance optionnelle : pyelftools. Si absent, renvoie les métadonnées de base.
    """

    @property
    def parser_name(self) -> str:
        return "elf_parser"

    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """Vérifie si le fichier commence par le magic bytes ELF (0x7f 'E' 'L' 'F')."""
        return file_bytes.startswith(b"\x7fELF")

    def parse_metadata(self, file_bytes: bytes, file_path: Path) -> FileMetadata:
        """Analyse le fichier ELF et construit les métadonnées.

        En cas d'absence de pyelftools ou d'ELF corrompu, retourne les
        métadonnées de base avec fallback vers string_extractor plus tard.
        """
        metadata = self._compute_basic_metadata(file_bytes, file_path, "ELF/unknown")

        if not PYELFTOOLS_AVAILABLE:
            self._logger.info("pyelftools_unavailable_using_fallback", filename=file_path.name)
            return metadata

        try:
            stream = io.BytesIO(file_bytes)
            elf = ELFFile(stream)
            
            # Déterminer 32 ou 64 bits
            arch = elf.elfclass  # 32 ou 64
            metadata.filetype = f"ELF{arch}"
            
            # TODO: Extraction plus poussée (sections, symboles dynamiques) 
            # si on décide d'ajouter un ELFInfo au modèle.
            
        except ELFError as e:
            self._logger.warning(
                "elf_parsing_error",
                filename=file_path.name,
                error=str(e)
            )
            metadata.filetype = "ELF/corrupted"

        return metadata
