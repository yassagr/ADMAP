"""
Tests d'intégration pour les endpoints de santé (health, ready).
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from admap_m3.api.app import app


@pytest.mark.asyncio
class TestHealthEndpoints:
    """Tests des endpoints /health et /ready."""

    async def test_health_returns_ok(self) -> None:
        """GET /health → 200, body['status'] == 'ok'."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["version"] == "1.0.0"
        assert body["module"] == "admap_m3"

    async def test_ready_returns_status(self) -> None:
        """GET /ready → 200, 'status' dans body."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/ready")

        assert response.status_code == 200
        body = response.json()
        assert "status" in body
        assert body["status"] in ("ready", "not_ready")
