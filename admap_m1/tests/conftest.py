"""
Module   : admap_m1.tests.conftest
Version  : 3.0.0
Dépend   : [pytest, admap_m1.models.ioc]

Fixtures Pytest partagées pour tous les tests M1.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from admap_m1.models.ioc import FileHashes, FileMetadata, PEInfo


@pytest.fixture
def sample_metadata() -> FileMetadata:
    """FileMetadata avec PEInfo pour les tests nécessitant un contexte PE."""
    from admap_m1.models.ioc import (
        FileMetadata, FileHashes, PEInfo, PESection
    )
    return FileMetadata(
        filename="test_sample.exe",
        filesize=2048,
        filetype="PE32",
        magic_bytes="4d5a90000300000004000000",
        hashes=FileHashes(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb924"
                  "27ae41e4649b934ca495991b7852b855",
        ),
        entropy=5.4,
        pe_info=PEInfo(
            entry_point="0x1000",
            imports={
                "kernel32.dll": ["VirtualAlloc", "GetProcAddress",
                                 "LoadLibraryA", "ExitProcess"],
                "ws2_32.dll":   ["WSAStartup", "connect", "send", "recv"],
            },
            sections=[
                PESection(
                    name=".text",
                    virtual_address="0x1000",
                    raw_size=4096,
                    entropy=6.1,
                    characteristics=["EXECUTE", "READ"],
                    is_suspicious=False,
                ),
                PESection(
                    name=".data",
                    virtual_address="0x2000",
                    raw_size=512,
                    entropy=3.2,
                    characteristics=["READ", "WRITE"],
                    is_suspicious=False,
                ),
            ],
            is_64bit=False,
            suspicious_imports=["VirtualAlloc", "WSAStartup"],
            import_suspicion_score=25,
        ),
    )


@pytest.fixture
def mock_vt_client():
    """Mock le client HTTPX asynchrone pour VirusTotal."""
    with patch("httpx.AsyncClient") as mock_client:
        mock_instance = mock_client.return_value.__aenter__.return_value
        
        # Configuration par défaut du mock response
        from unittest.mock import MagicMock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 1,
                        "undetected": 50,
                        "harmless": 10
                    }
                }
            }
        }
        mock_instance.get.return_value = mock_response
        
        yield mock_instance


@pytest.fixture
def test_data_dir() -> Path:
    """Chemin vers un répertoire (virtuel) de données de test."""
    return Path("/tmp/admap_m1_test_data")
