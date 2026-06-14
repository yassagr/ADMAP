"""
Tests unitaires pour le PEAnalyzer (admap_m3.analyzers.pe_analyzer).
"""
from __future__ import annotations

from admap_m3.analyzers.pe_analyzer import PEAnalyzer


class TestPEAnalyzer:
    """Tests du PEAnalyzer."""

    def test_analyzer_name(self) -> None:
        """analyzer_name == 'PEAnalyzer'."""
        analyzer: PEAnalyzer = PEAnalyzer()
        assert analyzer.analyzer_name == "PEAnalyzer"

    def test_invalid_pe_returns_empty(self) -> None:
        """Données PE invalides → retourne [] sans exception."""
        analyzer: PEAnalyzer = PEAnalyzer()
        tokens: list[str] = analyzer.extract_tokens(b"NOT A PE FILE", "test.exe")
        assert tokens == []

    def test_minimal_pe_no_crash(self, minimal_pe_bytes: bytes) -> None:
        """Un PE minimal ne provoque pas de crash."""
        analyzer: PEAnalyzer = PEAnalyzer()
        # Le PE minimal peut échouer au parsing (pas de sections valides)
        # mais ne doit jamais lever d'exception
        tokens: list[str] = analyzer.extract_tokens(minimal_pe_bytes, "test.exe")
        assert isinstance(tokens, list)
