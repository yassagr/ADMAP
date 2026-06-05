"""
Module   : admap_m1.extractors.vba_extractor
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.extractors.base, admap_m1.extractors.regex_extractor]

Extracteur de macros VBA depuis les documents Office.
Utilise oletools.olevba si disponible.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from admap_m1.extractors.base import BaseExtractor
from admap_m1.extractors.regex_extractor import RegexExtractor
from admap_m1.models.ioc import FileMetadata, RawIOC

try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False


class VBAExtractor(BaseExtractor):
    """Extracteur d'IOCs depuis les macros VBA des documents Office.

    Si oletools est disponible, extrait le code VBA, détecte les autoexecs
    et shells, puis extrait les IOCs via regex.
    """

    def __init__(self) -> None:
        super().__init__()
        self._regex_extractor = RegexExtractor()

    @property
    def extraction_method(self) -> str:
        return "vba_macro"

    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """S'applique aux documents Office si oletools est disponible."""
        if not OLETOOLS_AVAILABLE:
            return False
            
        is_ole = file_bytes.startswith(b"\xd0\xcf\x11\xe0")
        is_zip = file_bytes.startswith(b"PK\x03\x04")
        
        ext = file_path.suffix.lower()
        office_exts = {
            ".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm",
            ".docx", ".xlsx", ".pptx", ".rtf", ".dotm", ".xltm",
        }
        
        return is_ole or (is_zip and ext in office_exts)

    def extract(
        self,
        file_bytes: bytes,
        file_path: Path,
        metadata: FileMetadata,
    ) -> list[RawIOC]:
        """Extrait le code VBA et y cherche des IOCs."""
        if not OLETOOLS_AVAILABLE:
            return []

        iocs: list[RawIOC] = []
        
        try:
            vba_parser = VBA_Parser(filename=file_path.name, data=file_bytes)
            if not vba_parser.detect_vba_macros():
                vba_parser.close()
                return []

            autoexec_detected = False
            shell_detected = False
            obfuscation_techniques: list[str] = []

            # Analyser les macros
            results = vba_parser.analyze_macros()
            for kw_type, keyword, description in results:
                kw_type_lower = kw_type.lower()
                if kw_type_lower == "autoexec":
                    autoexec_detected = True
                elif kw_type_lower == "executable file" or keyword.lower() in ("shell", "wscript.shell"):
                    shell_detected = True
                elif kw_type_lower == "suspicious" and "obfusc" in description.lower():
                    obfuscation_techniques.append(keyword)

            # Extraire tout le code VBA
            all_vba_code = ""
            for (_, _, _, vba_code) in vba_parser.extract_macros():
                all_vba_code += vba_code + "\n"

            vba_parser.close()

            if all_vba_code:
                # Appliquer le regex extractor sur le code VBA
                raw_iocs = self._regex_extractor.extract_from_text(all_vba_code)
                for ioc in raw_iocs:
                    object.__setattr__(ioc, "extraction_method", "vba_macro")
                    # On marque le contexte avec un attribut temporaire pour le scorer
                    # qui va récupérer l'autoexec/shell status via le context builder
                    iocs.append(ioc)
            
            # NOTE: L'état autoexec/shell doit remonter au pipeline pour le contexte global.
            # L'extraction_method "vba_macro" + le ContexAnalyzer suffiront dans le pipeline
            # si le pipeline extrait ces infos de FileMetadata.
            # Pour l'instant, on se contente de tagguer les IOCs.

        except Exception as e:
            self._logger.warning("vba_extraction_failed", error=str(e))

        return iocs
