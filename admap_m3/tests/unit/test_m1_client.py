"""
Tests unitaires pour le client M1 (admap_m3.integrations.m1_client).
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any

import pytest

from admap_m3.config import Settings
from admap_m3.integrations.m1_client import M1IOCClient


@pytest.fixture
def m1_client(settings: Settings) -> M1IOCClient:
    return M1IOCClient(settings)


@pytest.fixture
def sample_bundle(tmp_path: Any) -> str:
    """Crée un fichier IOCBundle JSON de test."""
    import pathlib

    tmp: pathlib.Path = tmp_path
    bundle: dict[str, Any] = {
        "iocs": {
            "domains": ["evil.example.com", "c2.malware.org"],
            "urls": ["http://evil.example.com/payload.bin"],
            "ips": ["192.168.1.1", "10.0.0.1"],
            "strings": ["cmd.exe /c whoami", "CreateRemoteThread"],
        }
    }
    path: pathlib.Path = tmp / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return str(path)


class TestM1IOCClient:
    """Tests du client M1."""

    @pytest.mark.asyncio
    async def test_load_bundle(self, m1_client: M1IOCClient, sample_bundle: str) -> None:
        """Charge un bundle JSON depuis le disque."""
        bundle: dict[str, Any] = await m1_client.load_bundle(sample_bundle)
        assert "iocs" in bundle
        assert "domains" in bundle["iocs"]

    def test_extract_tokens_domains(self, m1_client: M1IOCClient) -> None:
        """Les domaines sont extraits avec le préfixe m1_ioc:."""
        bundle: dict[str, Any] = {
            "iocs": {
                "domains": ["evil.example.com"],
                "urls": [],
            }
        }
        tokens: list[str] = m1_client.extract_tokens(bundle)
        assert "m1_ioc:evil.example.com" in tokens

    def test_extract_tokens_urls(self, m1_client: M1IOCClient) -> None:
        """Les URLs sont extraites."""
        bundle: dict[str, Any] = {
            "iocs": {
                "domains": [],
                "urls": ["http://evil.com/payload"],
            }
        }
        tokens: list[str] = m1_client.extract_tokens(bundle)
        url_tokens: list[str] = [t for t in tokens if "http" in t]
        assert len(url_tokens) >= 1

    def test_extract_tokens_excludes_ips(self, m1_client: M1IOCClient) -> None:
        """Les IPs sont volontairement exclues."""
        bundle: dict[str, Any] = {
            "iocs": {
                "domains": [],
                "urls": [],
                "ips": ["192.168.1.1", "10.0.0.1"],
            }
        }
        tokens: list[str] = m1_client.extract_tokens(bundle)
        ip_tokens: list[str] = [t for t in tokens if "192.168" in t or "10.0.0" in t]
        assert len(ip_tokens) == 0

    def test_extract_tokens_suspicious_strings(self, m1_client: M1IOCClient) -> None:
        """Les strings suspectes sont extraites."""
        bundle: dict[str, Any] = {
            "iocs": {
                "domains": [],
                "urls": [],
                "strings": ["cmd.exe /c whoami"],
            }
        }
        tokens: list[str] = m1_client.extract_tokens(bundle)
        assert any("cmd.exe" in t for t in tokens)

    def test_extract_tokens_empty_bundle(self, m1_client: M1IOCClient) -> None:
        """Un bundle vide retourne une liste vide."""
        bundle: dict[str, Any] = {}
        tokens: list[str] = m1_client.extract_tokens(bundle)
        assert tokens == []
