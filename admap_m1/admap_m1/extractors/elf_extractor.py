"""
Module   : admap_m1.extractors.elf_extractor
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.extractors.base, admap_m1.extractors.string_extractor]

Extracteur spécifique aux fichiers ELF.
Extrait des IOCs depuis les sections via pyelftools si disponible.
"""
from __future__ import annotations

import io
from pathlib import Path

from admap_m1.extractors.base import BaseExtractor
from admap_m1.extractors.regex_extractor import RegexExtractor
from admap_m1.extractors.string_extractor import StringExtractor
from admap_m1.models.ioc import FileMetadata, RawIOC

try:
    from elftools.elf.elffile import ELFFile
    from elftools.common.exceptions import ELFError
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False


class ELFExtractor(BaseExtractor):
    """Extracteur d'IOCs spécifique aux fichiers ELF."""

    def __init__(self) -> None:
        super().__init__()
        self._regex_extractor = RegexExtractor()
        self._string_extractor = StringExtractor()

    @property
    def extraction_method(self) -> str:
        return "elf_extractor"

    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """Applicable si le magic bytes est ELF."""
        return file_bytes.startswith(b"\x7fELF")

    def extract(
        self,
        file_bytes: bytes,
        file_path: Path,
        metadata: FileMetadata,
    ) -> list[RawIOC]:
        """Extrait les IOCs depuis l'ELF.

        Si pyelftools n'est pas disponible, délègue simplement à string_extractor.
        """
        if not PYELFTOOLS_AVAILABLE:
            return self._string_extractor.extract(file_bytes, file_path, metadata)

        iocs: list[RawIOC] = []

        try:
            stream = io.BytesIO(file_bytes)
            elf = ELFFile(stream)
            
            for section in elf.iter_sections():
                sec_name = section.name
                sec_data = section.data()
                if not sec_data:
                    continue

                # On extrait les strings de cette section spécifique
                strings = self._string_extractor.extract_from_section(
                    sec_data, sec_name, section['sh_offset']
                )

                if not strings:
                    continue

                # On join les strings pour le regex extractor
                combined_text = "\n".join(s for s, _ in strings)
                
                # Extraction par regex
                sec_iocs = self._regex_extractor.extract_from_text(combined_text)

                # Mettre à jour l'origine des IOCs trouvés
                for ioc in sec_iocs:
                    object.__setattr__(ioc, "section_name", sec_name)
                    object.__setattr__(ioc, "extraction_method", "elf_section")
                    iocs.append(ioc)

        except ELFError as e:
            self._logger.warning("elf_format_error_fallback_to_strings", error=str(e))
            return self._string_extractor.extract(file_bytes, file_path, metadata)

        return iocs
