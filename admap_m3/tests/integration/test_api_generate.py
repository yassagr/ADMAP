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

    async def test_generate_capabilities(self) -> None:
        """GET /api/v1/generate/capabilities → 200 avec les formats."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
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
        import asyncio

        from admap_m3.models.job import GenerationJob

        # Manually set up app state to simulate the lifespan
        app.state.job_queue = asyncio.Queue()
        app.state.jobs = {}
        app.state.results = {}

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            malware_content: bytes = b"CreateRemoteThread VirtualAllocEx evil_payload shellcode_dropper"
            benign_content: bytes = b"CreateFile ReadFile WriteFile CloseHandle normal_operation"

            response = await client.post(
                "/api/v1/generate",
                files=[
                    ("malware_files", ("malware.txt", malware_content, "application/octet-stream")),
                    ("benign_files", ("benign.txt", benign_content, "application/octet-stream")),
                ],
            )

        assert response.status_code == 202
        body = response.json()
        assert "job_id" in body
        assert body["status"] == "pending"
        assert "status_url" in body

        # Clean up
        del app.state.job_queue
        del app.state.jobs
        del app.state.results
