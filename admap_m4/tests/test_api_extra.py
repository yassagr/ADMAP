from __future__ import annotations
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_analyze_invalid(async_client: AsyncClient):
    files = {"alert_bundle": ("alert.json", "invalid json", "application/json")}
    response = await async_client.post("/api/v1/analyze", files=files)
    assert response.status_code == 202
    job_id = response.json()["job_id"]
    
    response_job = await async_client.get(f"/api/v1/jobs/{job_id}/result")
    assert response_job.status_code == 409

@pytest.mark.asyncio
async def test_cancel_job(async_client: AsyncClient, sample_alert_bundle_json):
    files = {"alert_bundle": ("alert.json", sample_alert_bundle_json, "application/json")}
    response = await async_client.post("/api/v1/analyze", files=files)
    job_id = response.json()["job_id"]
    
    response_cancel = await async_client.delete(f"/api/v1/jobs/{job_id}")
    assert response_cancel.status_code == 200

@pytest.mark.asyncio
async def test_export_endpoints(async_client: AsyncClient, sample_alert_bundle_json):
    # Just check non-existing or not ready
    response = await async_client.get("/api/v1/export/invalid_id/json")
    assert response.status_code == 404
