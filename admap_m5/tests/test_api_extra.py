from __future__ import annotations
import pytest
import json
from httpx import AsyncClient, ASGITransport
from admap_m5.api.app import create_app


@pytest.fixture
async def app():
    from admap_m5.api.app import lifespan
    app_instance = create_app()
    async with lifespan(app_instance):
        yield app_instance


@pytest.mark.asyncio
async def test_analyze_with_ioc_bundle(app, sample_apt_map_report_json, sample_ioc_bundle_json):
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/analyze",
                files={
                    "apt_map_report": (
                        "report.json",
                        sample_apt_map_report_json.encode(),
                        "application/json",
                    ),
                    "ioc_bundle": (
                        "ioc.json",
                        sample_ioc_bundle_json.encode(),
                        "application/json",
                    ),
                },
            )
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_analyze_with_alert_bundle(app, sample_apt_map_report_json):
    alert_bundle = json.dumps({"alerts": []})
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/analyze",
                files={
                    "apt_map_report": (
                        "report.json",
                        sample_apt_map_report_json.encode(),
                        "application/json",
                    ),
                    "alert_bundle": (
                        "alert.json",
                        alert_bundle.encode(),
                        "application/json",
                    ),
                },
            )
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_cancel_job(app, sample_apt_map_report_json):
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
            job_id = resp.json()["job_id"]
            resp_delete = await client.delete(f"/api/v1/jobs/{job_id}")
    assert resp_delete.status_code == 200
    assert resp_delete.json()["status"] == "cancelled"


@pytest.mark.asyncio
async def test_cancel_nonexistent_job(app):
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.delete("/api/v1/jobs/nonexistent-job")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_export_invalid_format(app, sample_apt_map_report_json):
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
            job_id = resp.json()["job_id"]
            # Job est PENDING (pas COMPLETED) — la route retourne 409 avant d'evaluer le format
            resp_export = await client.get(f"/api/v1/export/{job_id}/invalid_format")
    assert resp_export.status_code == 409


@pytest.mark.asyncio
async def test_export_nonexistent_job(app):
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/v1/export/nonexistent-job/json")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_analyze_options_json(app, sample_apt_map_report_json):
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/analyze",
                data={"options": '{"top_k": 1}'},
                files={
                    "apt_map_report": (
                        "report.json",
                        sample_apt_map_report_json.encode(),
                        "application/json",
                    )
                },
            )
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_result_not_ready(app, sample_apt_map_report_json):
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
            job_id = resp.json()["job_id"]
            resp_result = await client.get(f"/api/v1/jobs/{job_id}/result")
    assert resp_result.status_code == 409
