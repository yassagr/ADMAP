"""
Tests unitaires pour le TextAnalyzer (admap_m3.analyzers.text_analyzer).
"""
from __future__ import annotations

from admap_m3.analyzers.text_analyzer import TextAnalyzer


class TestTextAnalyzer:
    """Tests du TextAnalyzer."""

    def test_analyzer_name(self) -> None:
        """analyzer_name == 'TextAnalyzer'."""
        analyzer: TextAnalyzer = TextAnalyzer()
        assert analyzer.analyzer_name == "TextAnalyzer"

    def test_extract_words(self) -> None:
        """Extrait les mots de longueur ≥ min_token_length."""
        analyzer: TextAnalyzer = TextAnalyzer(min_token_length=6)
        data: bytes = b"CreateRemoteThread hello world VirtualAlloc"
        tokens: list[str] = analyzer.extract_tokens(data, "test.txt")

        assert "CreateRemoteThread" in tokens
        assert "VirtualAlloc" in tokens
        # "hello" et "world" ont 5 chars → exclus
        assert "hello" not in tokens

    def test_extract_urls(self) -> None:
        """Extrait les URLs."""
        analyzer: TextAnalyzer = TextAnalyzer(min_token_length=4)
        data: bytes = b"C2 server at http://evil.example.com/payload.bin"
        tokens: list[str] = analyzer.extract_tokens(data, "test.txt")

        url_found: bool = any("http://evil.example.com" in t for t in tokens)
        assert url_found

    def test_extract_hex_hashes(self) -> None:
        """Extrait les hashes hex ≥ 32 caractères."""
        analyzer: TextAnalyzer = TextAnalyzer(min_token_length=6)
        md5: str = "d41d8cd98f00b204e9800998ecf8427e"
        data: bytes = f"Hash: {md5}".encode("utf-8")
        tokens: list[str] = analyzer.extract_tokens(data, "test.txt")

        assert md5 in tokens

    def test_empty_data_returns_empty(self) -> None:
        """Données vides → liste vide."""
        analyzer: TextAnalyzer = TextAnalyzer()
        tokens: list[str] = analyzer.extract_tokens(b"", "empty.txt")
        assert tokens == []
