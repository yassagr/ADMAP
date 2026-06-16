from __future__ import annotations
import pytest
from httpx import AsyncClient, ASGITransport
from admap_m5.api.app import create_app


@pytest.fixture
async def app():
    from admap_m5.api.app import lifespan
    app_instance = create_app()
    async with lifespan(app_instance):
        yield app_instance


@pytest.mark.asyncio
async def test_health(app):
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.json()["module"] == "M5-Attribution"


@pytest.mark.asyncio
async def test_ready(app):
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/ready")
    assert resp.status_code == 200
    assert "queue_size" in resp.json()


@pytest.mark.asyncio
async def test_analyze_submit(app, sample_apt_map_report_json):
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/analyze",
                files={
                    "apt_map_report": (
                        "report.json",
                        sample_apt_map_report_json.encode(),
                        "application/json",
                    )
                },
            )
    assert resp.status_code == 202
    data = resp.json()
    assert "job_id" in data
    assert data["status"] == "pending"


@pytest.mark.asyncio
async def test_get_job_not_found(app):
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/jobs/nonexistent-job-id")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_capabilities(app):
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/capabilities")
    assert resp.status_code == 200
    data = resp.json()
    assert "module" in data
    assert data["module"] == "M5-Attribution"
