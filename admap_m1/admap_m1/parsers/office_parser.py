"""
Module   : admap_m1.parsers.office_parser
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.parsers.base]

Parser pour les documents Microsoft Office (OLE et OpenXML).
Utilise oletools (oleid, olevba) si disponible.
"""
from __future__ import annotations

import io
from pathlib import Path

from admap_m1.models.ioc import FileMetadata
from admap_m1.parsers.base import BaseParser

try:
    from oletools.oleid import OleID
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False


class OfficeParser(BaseParser):
    """Parser pour les documents Microsoft Office (doc, docx, xls, etc.).

    Dépendance optionnelle : oletools. Si absent, ce parser se désactive
    et l'extraction texte/strings prendra le relais.
    """

    @property
    def parser_name(self) -> str:
        return "office_parser"

    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """Vérifie si oletools est dispo et si le fichier est un doc Office."""
        if not OLETOOLS_AVAILABLE:
            return False
            
        # Vérification par magic bytes OLE (D0 CF 11 E0) ou OpenXML (PK) avec extension Office
        is_ole = file_bytes.startswith(b"\xd0\xcf\x11\xe0")
        is_zip = file_bytes.startswith(b"PK\x03\x04")
        
        ext = file_path.suffix.lower()
        office_exts = {
            ".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm",
            ".docx", ".xlsx", ".pptx", ".rtf", ".dotm", ".xltm",
        }
        
        return is_ole or (is_zip and ext in office_exts)

    def parse_metadata(self, file_bytes: bytes, file_path: Path) -> FileMetadata:
        """Analyse le document Office et construit les métadonnées.
        
        Détecte la présence de macros VBA.
        """
        metadata = self._compute_basic_metadata(file_bytes, file_path, "Office/unknown")
        
        if not OLETOOLS_AVAILABLE:
            return metadata
            
        try:
            oid = OleID(data=file_bytes)
            indicators = oid.check()
            
            # Déterminer le type plus précisément
            is_word = False
            is_excel = False
            has_macros = False
            
            for i in indicators:
                if i.id == "Word" and i.value:
                    is_word = True
                elif i.id == "Excel" and i.value:
                    is_excel = True
                elif i.id == "vba" and i.value == "Yes":
                    has_macros = True
                    
            if is_word:
                metadata.filetype = "Office/Word"
            elif is_excel:
                metadata.filetype = "Office/Excel"
            else:
                metadata.filetype = "Office/OLE"
                
            if has_macros:
                metadata.filetype += " (VBA)"
                
        except Exception as e:
            self._logger.warning(
                "office_parsing_error",
                filename=file_path.name,
                error=str(e)
            )
            metadata.filetype = "Office/corrupted"

        return metadata
