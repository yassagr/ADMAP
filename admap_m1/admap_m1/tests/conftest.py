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
    """Fournit des métadonnées de base pour les tests d'extracteurs."""
    return FileMetadata(
        filename="test.exe",
        filesize=1024,
        filetype="PE32",
        magic_bytes="4d5a9000",
        hashes=FileHashes(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        entropy=4.5,
        pe_info=PEInfo(
            entry_point="0x1000",
            imports={"kernel32.dll": ["VirtualAlloc", "GetProcAddress"]},
            is_64bit=False,
        )
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
