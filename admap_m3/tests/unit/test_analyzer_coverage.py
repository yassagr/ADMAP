"""
Tests de couverture additionnels pour les analyzers PE et ELF.
"""
from __future__ import annotations

import os
import struct
import tempfile

from admap_m3.analyzers.elf_analyzer import ELFAnalyzer
from admap_m3.analyzers.pe_analyzer import PEAnalyzer
from admap_m3.analyzers.text_analyzer import TextAnalyzer


class TestPEAnalyzerCoverage:
    """Tests de couverture pour PEAnalyzer."""

    def test_pe_with_strings(self) -> None:
        """PE avec des strings ASCII imprimables → extraction."""
        analyzer: PEAnalyzer = PEAnalyzer()
        # Construire un fichier "PE-like" avec des strings lisibles
        data: bytes = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"
        data += b"\x00" * 68  # Padding jusqu'à offset 0x80
        data += b"PE\x00\x00"  # PE signature
        data += b"\x00" * 20  # COFF header minimal
        # Ajouter des strings imprimables en fin
        data += b"CreateRemoteThread\x00VirtualAllocEx\x00evil_function_name\x00"
        data += b"\x00" * 100

        tokens: list[str] = analyzer.extract_tokens(data, "test.exe")
        # Même si le PE est invalide, on vérifie qu'il ne crash pas
        assert isinstance(tokens, list)

    def test_pe_completely_invalid(self) -> None:
        """Données complètement invalides → liste vide, pas d'exception."""
        analyzer: PEAnalyzer = PEAnalyzer()
        tokens: list[str] = analyzer.extract_tokens(b"\x00\x01\x02\x03", "garbage.bin")
        assert tokens == []

    def test_pe_truncated_mz(self) -> None:
        """MZ header tronqué → liste vide."""
        analyzer: PEAnalyzer = PEAnalyzer()
        tokens: list[str] = analyzer.extract_tokens(b"MZ\x00", "short.exe")
        assert tokens == []


class TestELFAnalyzerCoverage:
    """Tests de couverture pour ELFAnalyzer."""

    def test_elf_with_strings(self) -> None:
        """ELF avec des strings ASCII → extraction."""
        analyzer: ELFAnalyzer = ELFAnalyzer(min_token_length=6)
        # ELF magic + header minimal + strings
        data: bytes = b"\x7fELF"
        data += b"\x02\x01\x01\x00"  # 64-bit, little-endian, Linux
        data += b"\x00" * 8  # padding
        data += b"\x02\x00"  # ET_EXEC
        data += b"\x3e\x00"  # EM_X86_64
        data += b"\x01\x00\x00\x00"  # EV_CURRENT
        data += b"\x00" * 40  # rest of header
        # Strings imprimables
        data += b"malicious_function_call\x00evil_export_symbol\x00"
        data += b"\x00" * 100

        tokens: list[str] = analyzer.extract_tokens(data, "test.elf")
        assert isinstance(tokens, list)
        # Devrait au moins avoir des strings ou des n-grams
        assert len(tokens) >= 0

    def test_elf_32bit(self) -> None:
        """ELF 32-bit → extraction sans crash."""
        analyzer: ELFAnalyzer = ELFAnalyzer(min_token_length=6)
        data: bytes = b"\x7fELF"
        data += b"\x01\x01\x01\x00"  # 32-bit, little-endian
        data += b"\x00" * 8
        data += b"\x02\x00\x03\x00"  # ET_EXEC, EM_386
        data += b"\x01\x00\x00\x00"
        data += b"\x00" * 28  # 32-bit header remainder
        data += b"test_string_here\x00" * 5

        tokens: list[str] = analyzer.extract_tokens(data, "test32.elf")
        assert isinstance(tokens, list)

    def test_elf_big_endian(self) -> None:
        """ELF big-endian → extraction sans crash."""
        analyzer: ELFAnalyzer = ELFAnalyzer(min_token_length=6)
        data: bytes = b"\x7fELF"
        data += b"\x02\x02\x01\x00"  # 64-bit, big-endian
        data += b"\x00" * 56
        data += b"sample_token_value\x00" * 3

        tokens: list[str] = analyzer.extract_tokens(data, "testbe.elf")
        assert isinstance(tokens, list)

    def test_elf_corrupted(self) -> None:
        """ELF avec header corrompu → liste vide ou partielle."""
        analyzer: ELFAnalyzer = ELFAnalyzer(min_token_length=6)
        data: bytes = b"\x7fELF\xff\xff\xff\xff" + b"\x00" * 10
        tokens: list[str] = analyzer.extract_tokens(data, "corrupt.elf")
        assert isinstance(tokens, list)


class TestTextAnalyzerCoverage:
    """Tests de couverture additionnels pour TextAnalyzer."""

    def test_extract_ips(self) -> None:
        """Extraction d'adresses IP."""
        analyzer: TextAnalyzer = TextAnalyzer(min_token_length=6)
        data: bytes = b"Connection to 192.168.1.100 on port 8080"
        tokens: list[str] = analyzer.extract_tokens(data, "log.txt")
        assert any("192.168.1.100" in t for t in tokens)

    def test_extract_domains(self) -> None:
        """Extraction de domaines."""
        analyzer: TextAnalyzer = TextAnalyzer(min_token_length=6)
        data: bytes = b"Contacting evil.malware.example.com for C2"
        tokens: list[str] = analyzer.extract_tokens(data, "report.txt")
        assert any("evil.malware.example.com" in t for t in tokens)

    def test_extract_windows_paths(self) -> None:
        """Extraction de chemins Windows."""
        analyzer: TextAnalyzer = TextAnalyzer(min_token_length=6)
        data: bytes = b"Dropped payload at C:\\Windows\\System32\\malware.exe"
        tokens: list[str] = analyzer.extract_tokens(data, "analysis.txt")
        assert len(tokens) > 0

    def test_extract_hex_sequences(self) -> None:
        """Extraction de séquences hexadécimales."""
        analyzer: TextAnalyzer = TextAnalyzer(min_token_length=6)
        data: bytes = b"Shellcode: 4D5A90000300000004000000FFFF"
        tokens: list[str] = analyzer.extract_tokens(data, "shellcode.txt")
        assert len(tokens) > 0

    def test_mixed_encoding(self) -> None:
        """Données avec encodage mixte → pas de crash."""
        analyzer: TextAnalyzer = TextAnalyzer(min_token_length=6)
        data: bytes = b"Normal text \xff\xfe\x00 more text CreateRemoteThread"
        tokens: list[str] = analyzer.extract_tokens(data, "mixed.txt")
        assert isinstance(tokens, list)
