"""
Module   : admap_m1.extractors.pe_extractor
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.extractors.base, admap_m1.extractors.string_extractor]

Extracteur spécifique aux fichiers PE (Portable Executable).
Extrait des IOCs depuis les imports, les sections, et l'overlay.
"""
from __future__ import annotations

from pathlib import Path

from admap_m1.extractors.base import BaseExtractor
from admap_m1.extractors.regex_extractor import RegexExtractor
from admap_m1.extractors.string_extractor import StringExtractor
from admap_m1.models.ioc import FileMetadata, RawIOC


class PEExtractor(BaseExtractor):
    """Extracteur d'IOCs spécifique aux fichiers PE.

    Analyse les sections individuelles via string_extractor,
    taggue les IOCs trouvés avec le nom de leur section d'origine,
    et passe le résultat à regex_extractor.
    """

    def __init__(self) -> None:
        super().__init__()
        self._regex_extractor = RegexExtractor()
        self._string_extractor = StringExtractor()

    @property
    def extraction_method(self) -> str:
        return "pe_extractor"

    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """Applicable si le magic bytes est MZ."""
        return file_bytes.startswith(b"MZ")

    def extract(
        self,
        file_bytes: bytes,
        file_path: Path,
        metadata: FileMetadata,
    ) -> list[RawIOC]:
        """Extrait les IOCs depuis le PE.

        S'appuie fortement sur pefile pour extraire section par section.
        """
        import pefile
        
        iocs: list[RawIOC] = []

        try:
            pe = pefile.PE(data=file_bytes, fast_load=False)
        except pefile.PEFormatError as e:
            self._logger.warning("pe_format_error_fallback_to_strings", error=str(e))
            # Fallback vers string extractor classique
            return self._string_extractor.extract(file_bytes, file_path, metadata)

        # Extraction depuis les sections
        for section in pe.sections:
            sec_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            sec_data = section.get_data()
            if not sec_data:
                continue

            # On extrait les strings de cette section spécifique
            strings = self._string_extractor.extract_from_section(
                sec_data, sec_name, section.PointerToRawData
            )

            if not strings:
                continue

            # On join les strings pour le regex extractor
            combined_text = "\n".join(s for s, _ in strings)
            
            # Extraction par regex
            sec_iocs = self._regex_extractor.extract_from_text(combined_text)

            # Mettre à jour l'origine des IOCs trouvés
            for ioc in sec_iocs:
                # Approximation: l'offset retourné par regex_extractor est relatif
                # au combined_text, pas à l'offset réel dans le binaire.
                # Pour être parfait il faudrait re-mapper, mais on se contente du nom de section.
                object.__setattr__(ioc, "section_name", sec_name)
                object.__setattr__(ioc, "extraction_method", "pe_section")
                iocs.append(ioc)

        # Extraction de l'overlay (données ajoutées à la fin du PE)
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            overlay_data = file_bytes[overlay_offset:]
            if overlay_data:
                strings = self._string_extractor.extract_from_section(
                    overlay_data, "overlay", overlay_offset
                )
                if strings:
                    combined_text = "\n".join(s for s, _ in strings)
                    overlay_iocs = self._regex_extractor.extract_from_text(combined_text)
                    for ioc in overlay_iocs:
                        object.__setattr__(ioc, "section_name", "overlay")
                        object.__setattr__(ioc, "extraction_method", "pe_overlay")
                        iocs.append(ioc)

        return iocs
