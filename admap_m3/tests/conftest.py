"""
Fixtures partagées pour les tests ADMAP M3.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from admap_m3.config import Settings
from admap_m3.core.pipeline import GenerationPipeline


@pytest.fixture
def settings() -> Settings:
    """Settings de test avec seuils permissifs pour un petit corpus."""
    return Settings(
        delta_threshold=0.30,
        min_token_length=6,
        max_tokens_per_rule=20,
        min_tokens_per_rule=1,
        min_df_malware=1,
        max_df_benign=0,
        ngram_size=4,
        corpus_dir=tempfile.mkdtemp(),
        output_dir=tempfile.mkdtemp(),
        m1_integration_enabled=False,
    )


@pytest.fixture
def pipeline(settings: Settings) -> GenerationPipeline:
    """Instance de pipeline configurée pour les tests."""
    return GenerationPipeline(settings=settings)


@pytest.fixture
def minimal_pe_bytes() -> bytes:
    """Bytes minimaux d'un PE valide (MZ header) pour les tests."""
    return b"MZ" + b"\x00" * 58 + b"\x3c\x00\x00\x00" + b"\x00" * 60 + b"PE\x00\x00"


@pytest.fixture
def minimal_elf_bytes() -> bytes:
    """Bytes minimaux d'un ELF valide pour les tests."""
    return b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 56


@pytest.fixture
def sample_malware_token_lists() -> list[list[str]]:
    """Listes de tokens malware de test."""
    return [
        ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "cmd.exe", "INJECT001"],
        ["CreateRemoteThread", "OpenProcess", "VirtualAllocEx", "shellcode", "INJECT001"],
        ["C2SERVER", "beacon", "interval", "jitter", "CreateRemoteThread"],
    ]


@pytest.fixture
def sample_benign_token_lists() -> list[list[str]]:
    """Listes de tokens bénins de test."""
    return [
        ["CreateFile", "ReadFile", "WriteFile", "CloseHandle", "RegOpenKey"],
        ["MessageBox", "DialogBox", "CreateWindow", "DefWindowProc"],
    ]


@pytest.fixture
def malware_text_files(tmp_path: object) -> list[str]:
    """Crée des fichiers texte malware temporaires pour les tests d'intégration."""
    import pathlib

    tmp: pathlib.Path = tmp_path  # type: ignore[assignment]
    malware_dir: pathlib.Path = tmp / "malware"
    malware_dir.mkdir()

    contents: list[str] = [
        "CreateRemoteThread VirtualAllocEx WriteProcessMemory evil_payload INJECT001 shellcode_dropper",
        "CreateRemoteThread OpenProcess VirtualAllocEx shellcode_dropper INJECT001 beacon_callback",
    ]

    paths: list[str] = []
    for i, content in enumerate(contents):
        file_path: pathlib.Path = malware_dir / f"malware_{i}.txt"
        file_path.write_text(content, encoding="utf-8")
        paths.append(str(file_path))

    return paths


@pytest.fixture
def benign_text_files(tmp_path: object) -> list[str]:
    """Crée des fichiers texte bénins temporaires pour les tests d'intégration."""
    import pathlib

    tmp: pathlib.Path = tmp_path  # type: ignore[assignment]
    benign_dir: pathlib.Path = tmp / "benign"
    benign_dir.mkdir()

    contents: list[str] = [
        "CreateFile ReadFile WriteFile CloseHandle RegOpenKey normal_operation",
        "MessageBox DialogBox CreateWindow DefWindowProc standard_window",
    ]

    paths: list[str] = []
    for i, content in enumerate(contents):
        file_path: pathlib.Path = benign_dir / f"benign_{i}.txt"
        file_path.write_text(content, encoding="utf-8")
        paths.append(str(file_path))

    return paths
