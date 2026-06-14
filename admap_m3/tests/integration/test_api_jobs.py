"""
Tests additionnels pour les routes jobs et l'API.
"""
from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from admap_m3.api.app import app
from admap_m3.models.job import GenerationJob, GenerationStatus
from admap_m3.models.rule import RuleMetadata, YaraRule, YaraRuleSet


def _setup_app_state() -> None:
    """Simule le lifespan en initialisant app.state."""
    app.state.job_queue = asyncio.Queue()
    app.state.jobs = {}
    app.state.results = {}


def _teardown_app_state() -> None:
    """Nettoie app.state."""
    for attr in ("job_queue", "jobs", "results"):
        if hasattr(app.state, attr):
            delattr(app.state, attr)


@pytest.mark.asyncio
class TestJobsRoutes:
    """Tests des endpoints /jobs."""

    async def test_get_job_not_found(self) -> None:
        _setup_app_state()
        try:
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get("/api/v1/jobs/nonexistent")
            assert response.status_code == 404
        finally:
            _teardown_app_state()

    async def test_get_job_found(self) -> None:
        _setup_app_state()
        try:
            job = GenerationJob(
                job_id="test123",
                status=GenerationStatus.PENDING,
                status_url="/api/v1/jobs/test123",
            )
            app.state.jobs["test123"] = job

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get("/api/v1/jobs/test123")
            assert response.status_code == 200
            body = response.json()
            assert body["job_id"] == "test123"
            assert body["status"] == "pending"
        finally:
            _teardown_app_state()

    async def test_cancel_pending_job(self) -> None:
        _setup_app_state()
        try:
            job = GenerationJob(
                job_id="cancel_me",
                status=GenerationStatus.PENDING,
                status_url="/api/v1/jobs/cancel_me",
            )
            app.state.jobs["cancel_me"] = job

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.delete("/api/v1/jobs/cancel_me")
            assert response.status_code == 200
            assert response.json()["status"] == "cancelled"
        finally:
            _teardown_app_state()

    async def test_cancel_running_job_returns_409(self) -> None:
        _setup_app_state()
        try:
            job = GenerationJob(
                job_id="running_job",
                status=GenerationStatus.RUNNING,
                status_url="/api/v1/jobs/running_job",
            )
            app.state.jobs["running_job"] = job

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.delete("/api/v1/jobs/running_job")
            assert response.status_code == 409
        finally:
            _teardown_app_state()

    async def test_get_result_not_completed(self) -> None:
        _setup_app_state()
        try:
            job = GenerationJob(
                job_id="pending_result",
                status=GenerationStatus.PENDING,
                status_url="/api/v1/jobs/pending_result",
            )
            app.state.jobs["pending_result"] = job

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.get("/api/v1/jobs/pending_result/result")
            assert response.status_code == 409
        finally:
            _teardown_app_state()
