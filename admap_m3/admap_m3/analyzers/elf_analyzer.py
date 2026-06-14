"""
Module   : admap_m3.analyzers.elf_analyzer
Version  : 1.0.0
Dépend   : [structlog]

Analyseur de fichiers ELF pour l'extraction de features : strings
imprimables, n-grams de bytes depuis les segments exécutables,
noms de sections et symboles.

Le parser ELF est implémenté manuellement.  Si ``pyelftools`` est
disponible, il est utilisé comme implémentation alternative.
"""
from __future__ import annotations

import re
import struct

import structlog

from admap_m3.analyzers.base import BaseAnalyzer

logger: structlog.stdlib.BoundLogger = structlog.get_logger()

# Regex pour les séquences de caractères ASCII imprimables
_PRINTABLE_RE: re.Pattern[bytes] = re.compile(rb"[\x20-\x7e]{6,}")

# Constantes ELF
_ELF_MAGIC: bytes = b"\x7fELF"
_ELFCLASS32: int = 1
_ELFCLASS64: int = 2
_PT_LOAD: int = 1
_PF_X: int = 0x1

# pyelftools disponible ?
try:
    from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]

    _PYELFTOOLS_AVAILABLE: bool = True
except ImportError:
    _PYELFTOOLS_AVAILABLE = False


class ELFAnalyzer(BaseAnalyzer):
    """Analyse statique de fichiers ELF.

    Extrait :
    1. Strings imprimables (scan linéaire).
    2. N-grams de bytes depuis les segments PT_LOAD exécutables.
    3. Noms de sections et symboles (si disponibles).
    """

    def __init__(self, min_token_length: int = 6, ngram_size: int = 4) -> None:
        self._min_token_length: int = min_token_length
        self._ngram_size: int = ngram_size

    @property
    def analyzer_name(self) -> str:
        return "ELFAnalyzer"

    def extract_tokens(self, data: bytes, file_path: str) -> list[str]:
        """Extrait les features d'un binaire ELF."""
        if len(data) < 16 or data[:4] != _ELF_MAGIC:
            logger.warning(
                "elf_invalid_magic",
                file_path=file_path,
                analyzer=self.analyzer_name,
            )
            return []

        try:
            if _PYELFTOOLS_AVAILABLE:
                return self._extract_with_pyelftools(data, file_path)
            return self._extract_manual(data, file_path)
        except Exception as exc:
            logger.warning(
                "elf_parse_error",
                file_path=file_path,
                error=str(exc),
                analyzer=self.analyzer_name,
            )
            return []

    # ── pyelftools path ──────────────────────────────────────────────────

    def _extract_with_pyelftools(self, data: bytes, file_path: str) -> list[str]:
        """Extraction via pyelftools si disponible."""
        import io

        from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]

        tokens: list[str] = []
        elf: ELFFile = ELFFile(io.BytesIO(data))

        # 1. Strings imprimables (scan global)
        tokens.extend(self._scan_printable_strings(data))

        # 2. N-grams depuis segments exécutables
        for segment in elf.iter_segments():
            if segment.header["p_type"] == "PT_LOAD" and (segment.header["p_flags"] & _PF_X):
                seg_data: bytes = segment.data()
                tokens.extend(self._extract_ngrams(seg_data))

        # 3. Noms de sections
        for section in elf.iter_sections():
            section_name: str = section.name
            if section_name and len(section_name) >= self._min_token_length:
                tokens.append(section_name)

        # 4. Symboles
        try:
            symtab = elf.get_section_by_name(".symtab")
            if symtab is not None:
                for symbol in symtab.iter_symbols():
                    sym_name: str = symbol.name
                    if sym_name and len(sym_name) >= self._min_token_length:
                        tokens.append(sym_name)
        except Exception:
            pass

        return tokens

    # ── Manual ELF parsing ───────────────────────────────────────────────

    def _extract_manual(self, data: bytes, file_path: str) -> list[str]:
        """Extraction manuelle via parsing direct des headers ELF."""
        tokens: list[str] = []

        # 1. Strings imprimables (scan global)
        tokens.extend(self._scan_printable_strings(data))

        # Déterminer la classe (32 ou 64 bits)
        ei_class: int = data[4]

        if ei_class == _ELFCLASS64:
            tokens.extend(self._parse_elf64_segments(data))
        elif ei_class == _ELFCLASS32:
            tokens.extend(self._parse_elf32_segments(data))

        return tokens

    def _parse_elf64_segments(self, data: bytes) -> list[str]:
        """Parse les program headers ELF64 pour extraire les n-grams."""
        tokens: list[str] = []

        if len(data) < 64:
            return tokens

        # ELF64 header : e_phoff(8B) à offset 32, e_phentsize(2B) à 54, e_phnum(2B) à 56
        e_phoff: int = struct.unpack_from("<Q", data, 32)[0]
        e_phentsize: int = struct.unpack_from("<H", data, 54)[0]
        e_phnum: int = struct.unpack_from("<H", data, 56)[0]

        for i in range(e_phnum):
            offset: int = e_phoff + i * e_phentsize
            if offset + 56 > len(data):
                break

            # ELF64 Phdr: p_type(4B), p_flags(4B), p_offset(8B), ..., p_filesz(8B)
            p_type: int = struct.unpack_from("<I", data, offset)[0]
            p_flags: int = struct.unpack_from("<I", data, offset + 4)[0]
            p_offset: int = struct.unpack_from("<Q", data, offset + 8)[0]
            p_filesz: int = struct.unpack_from("<Q", data, offset + 32)[0]

            if p_type == _PT_LOAD and (p_flags & _PF_X):
                end: int = min(p_offset + p_filesz, len(data))
                seg_data: bytes = data[p_offset:end]
                tokens.extend(self._extract_ngrams(seg_data))

        return tokens

    def _parse_elf32_segments(self, data: bytes) -> list[str]:
        """Parse les program headers ELF32 pour extraire les n-grams."""
        tokens: list[str] = []

        if len(data) < 52:
            return tokens

        # ELF32 header : e_phoff(4B) à offset 28, e_phentsize(2B) à 42, e_phnum(2B) à 44
        e_phoff: int = struct.unpack_from("<I", data, 28)[0]
        e_phentsize: int = struct.unpack_from("<H", data, 42)[0]
        e_phnum: int = struct.unpack_from("<H", data, 44)[0]

        for i in range(e_phnum):
            offset: int = e_phoff + i * e_phentsize
            if offset + 32 > len(data):
                break

            # ELF32 Phdr: p_type(4B), p_offset(4B), ..., p_filesz(4B) à +16, p_flags(4B) à +24
            p_type: int = struct.unpack_from("<I", data, offset)[0]
            p_offset: int = struct.unpack_from("<I", data, offset + 4)[0]
            p_filesz: int = struct.unpack_from("<I", data, offset + 16)[0]
            p_flags: int = struct.unpack_from("<I", data, offset + 24)[0]

            if p_type == _PT_LOAD and (p_flags & _PF_X):
                end: int = min(p_offset + p_filesz, len(data))
                seg_data: bytes = data[p_offset:end]
                tokens.extend(self._extract_ngrams(seg_data))

        return tokens

    # ── Helpers ──────────────────────────────────────────────────────────

    def _scan_printable_strings(self, data: bytes) -> list[str]:
        """Extrait toutes les séquences de caractères imprimables."""
        result: list[str] = []
        for match in _PRINTABLE_RE.finditer(data):
            token: str = match.group().decode("ascii", errors="ignore")
            if len(token) >= self._min_token_length:
                result.append(token)
        return result

    def _extract_ngrams(self, segment_data: bytes) -> list[str]:
        """Extrait les n-grams de bytes depuis un segment, hex-encodés."""
        result: list[str] = []
        ngram_count: int = len(segment_data) - self._ngram_size + 1
        for i in range(min(ngram_count, 500)):
            ngram: bytes = segment_data[i : i + self._ngram_size]
            result.append(ngram.hex().upper())
        return result
