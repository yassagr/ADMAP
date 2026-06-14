"""
Tests unitaires pour le ELFAnalyzer (admap_m3.analyzers.elf_analyzer).
"""
from __future__ import annotations

from admap_m3.analyzers.elf_analyzer import ELFAnalyzer


class TestELFAnalyzer:
    """Tests du ELFAnalyzer."""

    def test_analyzer_name(self) -> None:
        """analyzer_name == 'ELFAnalyzer'."""
        analyzer: ELFAnalyzer = ELFAnalyzer()
        assert analyzer.analyzer_name == "ELFAnalyzer"

    def test_invalid_elf_returns_empty(self) -> None:
        """Données ELF invalides → retourne [] sans exception."""
        analyzer: ELFAnalyzer = ELFAnalyzer()
        tokens: list[str] = analyzer.extract_tokens(b"NOT AN ELF", "test.elf")
        assert tokens == []

    def test_minimal_elf_no_crash(self, minimal_elf_bytes: bytes) -> None:
        """Un ELF minimal ne provoque pas de crash."""
        analyzer: ELFAnalyzer = ELFAnalyzer()
        tokens: list[str] = analyzer.extract_tokens(minimal_elf_bytes, "test.elf")
        assert isinstance(tokens, list)
