from __future__ import annotations
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_health(async_client: AsyncClient):
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

@pytest.mark.asyncio
async def test_ready(async_client: AsyncClient):
    response = await async_client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"

@pytest.mark.asyncio
async def test_analyze_valid(async_client: AsyncClient, sample_alert_bundle_json):
    files = {"alert_bundle": ("alert.json", sample_alert_bundle_json, "application/json")}
    response = await async_client.post("/api/v1/analyze", files=files)
    assert response.status_code == 202
    assert "job_id" in response.json()

@pytest.mark.asyncio
async def test_get_job(async_client: AsyncClient, sample_alert_bundle_json):
    files = {"alert_bundle": ("alert.json", sample_alert_bundle_json, "application/json")}
    response = await async_client.post("/api/v1/analyze", files=files)
    job_id = response.json()["job_id"]

    response_job = await async_client.get(f"/api/v1/jobs/{job_id}")
    assert response_job.status_code == 200
    assert response_job.json()["status"] in ["pending", "running", "completed"]

@pytest.mark.asyncio
async def test_capabilities(async_client: AsyncClient):
    response = await async_client.get("/api/v1/capabilities")
    assert response.status_code == 200
    assert response.json()["module"] == "M4"
