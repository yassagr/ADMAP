"""
Tests unitaires additionnels pour la couverture : extractor, generic analyzer,
M1 client, jobs routes.
"""
from __future__ import annotations

import os
import tempfile
from typing import Any

import pytest

from admap_m3.analyzers.generic_analyzer import GenericBinaryAnalyzer
from admap_m3.config import Settings
from admap_m3.core.extractor import BinaryFeatureExtractor
from admap_m3.models.corpus import CorpusFile, FileLabel, FileType


class TestBinaryFeatureExtractor:
    """Tests du BinaryFeatureExtractor."""

    def test_detect_pe(self, settings: Settings) -> None:
        """b'MZ...' → FileType.PE."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor(settings)
        ft: FileType = extractor._detect_type(b"MZ" + b"\x00" * 100)
        assert ft == FileType.PE

    def test_detect_elf(self, settings: Settings) -> None:
        """b'\\x7fELF...' → FileType.ELF."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor(settings)
        ft: FileType = extractor._detect_type(b"\x7fELF" + b"\x00" * 100)
        assert ft == FileType.ELF

    def test_detect_text(self, settings: Settings) -> None:
        """UTF-8 text → FileType.TEXT."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor(settings)
        ft: FileType = extractor._detect_type(b"Hello world, this is plain text")
        assert ft == FileType.TEXT

    def test_detect_generic(self, settings: Settings) -> None:
        """Random binary data → FileType.GENERIC."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor(settings)
        ft: FileType = extractor._detect_type(bytes(range(256)))
        assert ft == FileType.GENERIC

    def test_extract_text_file(self, settings: Settings) -> None:
        """Extraction from a real text file."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor(settings)
        tmp: str = os.path.join(tempfile.mkdtemp(), "test.txt")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("CreateRemoteThread VirtualAllocEx evil_payload_marker")

        corpus_file, tokens = extractor.extract(tmp, FileLabel.MALWARE)
        assert isinstance(corpus_file, CorpusFile)
        assert corpus_file.file_type == FileType.TEXT
        assert corpus_file.label == FileLabel.MALWARE
        assert len(tokens) > 0

    def test_extract_file_not_found(self, settings: Settings) -> None:
        """FileNotFoundError for missing files."""
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor(settings)
        with pytest.raises(FileNotFoundError):
            extractor.extract("/nonexistent/path/file.bin", FileLabel.MALWARE)

    def test_extract_file_too_large(self, settings: Settings) -> None:
        """ValueError for files exceeding max_file_size_bytes."""
        settings_small = Settings(max_file_size_bytes=10, corpus_dir=tempfile.mkdtemp(), output_dir=tempfile.mkdtemp())
        extractor: BinaryFeatureExtractor = BinaryFeatureExtractor(settings_small)
        tmp: str = os.path.join(tempfile.mkdtemp(), "big.bin")
        with open(tmp, "wb") as fh:
            fh.write(b"\x00" * 100)

        with pytest.raises(ValueError, match="trop volumineux"):
            extractor.extract(tmp, FileLabel.MALWARE)


class TestGenericBinaryAnalyzer:
    """Tests du GenericBinaryAnalyzer."""

    def test_analyzer_name(self) -> None:
        analyzer: GenericBinaryAnalyzer = GenericBinaryAnalyzer()
        assert analyzer.analyzer_name == "GenericBinaryAnalyzer"

    def test_extract_includes_entropy(self) -> None:
        """L'entropie est incluse comme feature symbolique."""
        analyzer: GenericBinaryAnalyzer = GenericBinaryAnalyzer(min_token_length=6)
        data: bytes = b"\x00" * 100 + b"AAAAAA" * 10  # low entropy with repeated strings
        tokens: list[str] = analyzer.extract_tokens(data, "test.bin")
        entropy_tokens: list[str] = [t for t in tokens if t.startswith("entropy:")]
        assert len(entropy_tokens) == 1

    def test_extract_ngrams(self) -> None:
        """N-grams are hex-encoded."""
        analyzer: GenericBinaryAnalyzer = GenericBinaryAnalyzer(min_token_length=6, ngram_size=4)
        data: bytes = b"\x41\x42\x43\x44\x45"  # ABCDE
        tokens: list[str] = analyzer.extract_tokens(data, "test.bin")
        # Should have hex ngrams like "41424344", "42434445"
        hex_tokens: list[str] = [t for t in tokens if all(c in "0123456789ABCDEF" for c in t)]
        assert len(hex_tokens) >= 1

    def test_empty_data(self) -> None:
        """Empty data produces entropy:0.00."""
        analyzer: GenericBinaryAnalyzer = GenericBinaryAnalyzer()
        tokens: list[str] = analyzer.extract_tokens(b"", "empty.bin")
        assert "entropy:0.00" in tokens
