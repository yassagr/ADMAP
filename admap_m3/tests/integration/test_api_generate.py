"""
Tests d'intégration pour l'endpoint POST /api/v1/generate.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from admap_m3.api.app import app


@pytest.mark.asyncio
class TestGenerateEndpoint:
    """Tests de l'endpoint de génération."""

    @pytest.fixture(autouse=True)
    async def _lifespan(self):
        async with app.router.lifespan_context(app):
            yield

    async def test_generate_capabilities(self) -> None:
        """GET /api/v1/generate/capabilities → 200 avec les formats."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/generate/capabilities")

        assert response.status_code == 200
        body = response.json()
        assert "supported_formats" in body
        assert "pe" in body["supported_formats"]
        assert "export_formats" in body
        assert "yar" in body["export_formats"]
        assert body["algorithm"] == "tfidf_discriminant"

    async def test_generate_returns_202(self) -> None:
        """POST /api/v1/generate avec des fichiers → 202 + job_id."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            malware_content: bytes = (
                b"CreateRemoteThread VirtualAllocEx evil_payload shellcode_dropper"
            )
            benign_content: bytes = (
                b"CreateFile ReadFile WriteFile CloseHandle normal_operation"
            )

            response = await client.post(
                "/api/v1/generate",
                files=[
                    (
                        "malware_files",
                        ("malware.txt", malware_content, "application/octet-stream"),
                    ),
                    (
                        "benign_files",
                        ("benign.txt", benign_content, "application/octet-stream"),
                    ),
                ],
            )

        assert response.status_code == 202
        body = response.json()
        assert "job_id" in body
        assert body["status"] == "pending"
        assert "status_url" in body

    async def test_generate_too_many_files_returns_400(self) -> None:
        """POST /api/v1/generate avec trop de fichiers → 400."""
        from admap_m3.config import get_settings

        settings = get_settings()
        max_per_side: int = settings.max_corpus_files // 2

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Dépasser la limite malware
            files = []
            for i in range(max_per_side + 1):
                files.append(
                    (
                        "malware_files",
                        (f"malware_{i}.txt", b"evil content here xxx", "application/octet-stream"),
                    )
                )
            files.append(
                ("benign_files", ("benign.txt", b"safe content here xxx", "application/octet-stream"))
            )

            response = await client.post("/api/v1/generate", files=files)

        assert response.status_code == 400
