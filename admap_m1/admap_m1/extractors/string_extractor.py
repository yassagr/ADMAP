"""
Module   : admap_m1.extractors.string_extractor
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.extractors.base, admap_m1.extractors.regex_extractor]

Extracteur de chaînes de caractères (ASCII/UTF-16LE) depuis les binaires purs.
Sert de fallback ou est utilisé par les extracteurs PE/ELF.
"""
from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from admap_m1.extractors.base import BaseExtractor
from admap_m1.extractors.regex_extractor import RegexExtractor
from admap_m1.models.ioc import FileMetadata, RawIOC


class StringExtractor(BaseExtractor):
    """Extrait les chaînes de caractères ASCII et Unicode (UTF-16LE)
    depuis des données binaires brutes.

    Utilisé comme extracteur de fallback pour les binaires non reconnus,
    et comme sous-composant de PEExtractor et ELFExtractor.
    """

    MIN_STRING_LENGTH: ClassVar[int] = 6
    MAX_STRING_LENGTH: ClassVar[int] = 4096  # Éviter les très longues chaînes

    # Bytes ASCII imprimables (0x20-0x7E + tab + newline + carriage return)
    PRINTABLE_ASCII: ClassVar[frozenset[int]] = frozenset(
        range(0x20, 0x7F)
    ) | frozenset([0x09, 0x0A, 0x0D])

    def __init__(self) -> None:
        super().__init__()
        self._regex_extractor = RegexExtractor()

    @property
    def extraction_method(self) -> str:
        return "binary_strings"

    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """
        True pour tout fichier binaire qui n'est pas du texte pur.
        Laisse regex_extractor gérer les fichiers texte décodables.
        """
        try:
            file_bytes[:512].decode("utf-8")
            return False  # Texte pur → regex_extractor s'en charge
        except (UnicodeDecodeError, ValueError):
            return True  # Binaire → string_extractor applicable

    def extract(
        self,
        file_bytes: bytes,
        file_path: Path,
        metadata: FileMetadata,
    ) -> list[RawIOC]:
        """Extrait les strings ASCII et Unicode puis applique regex_extractor.

        Returns:
            RawIOC produits par regex_extractor sur les strings extraites.
        """
        ascii_strings = self._extract_ascii(file_bytes)
        unicode_strings = self._extract_unicode(file_bytes)

        # Agréger toutes les strings dans un pseudo-texte avec offsets
        combined_text = "\n".join(s for s, _ in ascii_strings + unicode_strings)

        # Déléguer à regex_extractor pour l'extraction des IOCs
        raw_iocs = self._regex_extractor.extract(
            combined_text.encode("utf-8", errors="replace"),
            file_path,
            metadata,
        )

        # Mettre à jour extraction_method pour indiquer que ça vient de strings extraites
        for ioc in raw_iocs:
            object.__setattr__(ioc, "extraction_method", "binary_strings")

        return raw_iocs

    def extract_from_section(
        self,
        section_data: bytes,
        section_name: str,
        base_offset: int = 0,
    ) -> list[tuple[str, int]]:
        """Extrait les strings d'une section PE/ELF spécifique.

        Args:
            section_data: Contenu brut de la section.
            section_name: Nom de la section (ex: ".rdata").
            base_offset: Offset de base de la section dans le fichier.

        Returns:
            Liste de (string_value, offset_absolu).
        """
        ascii_strings = [
            (s, base_offset + off)
            for s, off in self._extract_ascii(section_data)
        ]
        unicode_strings = [
            (s, base_offset + off)
            for s, off in self._extract_unicode(section_data)
        ]
        return ascii_strings + unicode_strings

    def _extract_ascii(self, data: bytes) -> list[tuple[str, int]]:
        """Extrait les séquences ASCII imprimables de longueur >= MIN_STRING_LENGTH.

        Returns:
            Liste de (string, offset_dans_data).
        """
        results: list[tuple[str, int]] = []
        current: list[int] = []
        start_offset: int = 0

        for i, byte in enumerate(data):
            if byte in self.PRINTABLE_ASCII:
                if not current:
                    start_offset = i
                current.append(byte)
            else:
                if self.MIN_STRING_LENGTH <= len(current) <= self.MAX_STRING_LENGTH:
                    results.append((bytes(current).decode("ascii"), start_offset))
                current = []

        # Flush final
        if self.MIN_STRING_LENGTH <= len(current) <= self.MAX_STRING_LENGTH:
            results.append((bytes(current).decode("ascii"), start_offset))

        return results

    def _extract_unicode(self, data: bytes) -> list[tuple[str, int]]:
        """Extrait les séquences UTF-16LE imprimables (Windows Unicode).

        Algorithme : chercher des séquences de paires (byte_imprimable, 0x00).

        Returns:
            Liste de (string, offset_dans_data).
        """
        results: list[tuple[str, int]] = []
        i = 0
        n = len(data)

        while i < n - 1:
            # Vérifier début d'une séquence UTF-16LE
            if data[i] in self.PRINTABLE_ASCII and data[i + 1] == 0x00:
                start = i
                chars: list[str] = []

                while i < n - 1:
                    lo = data[i]
                    hi = data[i + 1]
                    if lo in self.PRINTABLE_ASCII and hi == 0x00:
                        chars.append(chr(lo))
                        i += 2
                    else:
                        break

                if self.MIN_STRING_LENGTH <= len(chars) <= self.MAX_STRING_LENGTH:
                    results.append(("".join(chars), start))
            else:
                i += 1

        return results
