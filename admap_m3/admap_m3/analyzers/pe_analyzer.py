"""
Module   : admap_m3.analyzers.pe_analyzer
Version  : 1.0.0
Dépend   : [pefile, structlog]

Analyseur de fichiers PE (Portable Executable) pour l'extraction de
features : strings imprimables, imports/exports, n-grams d'opcodes,
imphash.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pefile
import structlog

from admap_m3.analyzers.base import BaseAnalyzer

if TYPE_CHECKING:
    pass

logger: structlog.stdlib.BoundLogger = structlog.get_logger()

# Regex pour les séquences de caractères ASCII imprimables
_PRINTABLE_RE: re.Pattern[bytes] = re.compile(rb"[\x20-\x7e]{6,}")


class PEAnalyzer(BaseAnalyzer):
    """Analyse statique de fichiers PE via ``pefile``.

    Extrait :
    1. Strings imprimables depuis les sections ``.data`` et ``.rdata``.
    2. Noms des imports (DLL + fonctions importées).
    3. Noms des exports (si présents).
    4. N-grams de bytes depuis les sections exécutables (``.text``, ``.code``).
    5. Import hash (``imphash``).
    """

    def __init__(self, min_token_length: int = 6, ngram_size: int = 4) -> None:
        self._min_token_length: int = min_token_length
        self._ngram_size: int = ngram_size

    @property
    def analyzer_name(self) -> str:
        return "PEAnalyzer"

    def extract_tokens(self, data: bytes, file_path: str) -> list[str]:
        """Extrait les features d'un binaire PE.

        En cas de ``pefile.PEFormatError`` le warning est loggé et une
        liste vide est retournée (jamais d'exception propagée).
        """
        try:
            pe: pefile.PE = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as exc:
            logger.warning(
                "pe_parse_error",
                file_path=file_path,
                error=str(exc),
                analyzer=self.analyzer_name,
            )
            return []

        tokens: list[str] = []

        # 1. Strings imprimables depuis .data / .rdata
        tokens.extend(self._extract_section_strings(pe))

        # 2. Imports
        tokens.extend(self._extract_imports(pe))

        # 3. Exports
        tokens.extend(self._extract_exports(pe))

        # 4. N-grams de bytes depuis sections exécutables
        tokens.extend(self._extract_opcode_ngrams(pe))

        # 5. Imphash
        imphash: str | None = self._extract_imphash(pe)
        if imphash:
            tokens.append(imphash)

        pe.close()
        return tokens

    # ── Méthodes privées ─────────────────────────────────────────────────

    def _extract_section_strings(self, pe: pefile.PE) -> list[str]:
        """Extrait les strings imprimables des sections .data et .rdata."""
        result: list[str] = []
        target_names: set[str] = {".data", ".rdata"}

        for section in pe.sections:
            section_name: str = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
            if section_name in target_names:
                section_data: bytes = section.get_data()
                for match in _PRINTABLE_RE.finditer(section_data):
                    token: str = match.group().decode("ascii", errors="ignore")
                    if len(token) >= self._min_token_length:
                        result.append(token)

        return result

    def _extract_imports(self, pe: pefile.PE) -> list[str]:
        """Extrait les noms de DLLs et fonctions importées."""
        result: list[str] = []

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return result

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name: str = entry.dll.decode("ascii", errors="ignore")
            if len(dll_name) >= self._min_token_length:
                result.append(dll_name)

            for imp in entry.imports:
                if imp.name is not None:
                    func_name: str = imp.name.decode("ascii", errors="ignore")
                    if len(func_name) >= self._min_token_length:
                        result.append(func_name)

        return result

    def _extract_exports(self, pe: pefile.PE) -> list[str]:
        """Extrait les noms des fonctions exportées."""
        result: list[str] = []

        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return result

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name is not None:
                export_name: str = exp.name.decode("ascii", errors="ignore")
                if len(export_name) >= self._min_token_length:
                    result.append(export_name)

        return result

    def _extract_opcode_ngrams(self, pe: pefile.PE) -> list[str]:
        """Extrait les n-grams de bytes depuis les sections exécutables."""
        result: list[str] = []
        executable_names: set[str] = {".text", ".code"}

        for section in pe.sections:
            section_name: str = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore")
            if section_name in executable_names:
                section_data: bytes = section.get_data()
                ngram_count: int = len(section_data) - self._ngram_size + 1
                for i in range(min(ngram_count, 500)):
                    ngram: bytes = section_data[i : i + self._ngram_size]
                    hex_ngram: str = ngram.hex().upper()
                    result.append(hex_ngram)

        return result

    def _extract_imphash(self, pe: pefile.PE) -> str | None:
        """Calcule l'import hash du binaire."""
        try:
            imphash: str = pe.get_imphash()
            if imphash:
                return imphash
        except Exception:
            pass
        return None
