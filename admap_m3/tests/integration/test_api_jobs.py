"""
Tests additionnels pour les routes jobs et l'API.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from admap_m3.api.app import app
from admap_m3.models.job import GenerationJob, GenerationStatus


@pytest.mark.asyncio
class TestJobsRoutes:
    """Tests des endpoints /jobs."""

    @pytest.fixture(autouse=True)
    async def _lifespan(self):
        async with app.router.lifespan_context(app):
            yield

    async def test_get_job_not_found(self) -> None:
        """GET /api/v1/jobs/nonexistent → 404."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/jobs/nonexistent")
        assert response.status_code == 404

    async def test_get_job_found(self) -> None:
        """GET /api/v1/jobs/{id} pour un job existant → 200."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Injecter un job directement dans app.state (via lifespan déjà déclenché)
            job = GenerationJob(
                job_id="test123",
                status=GenerationStatus.PENDING,
                status_url="/api/v1/jobs/test123",
            )
            app.state.jobs["test123"] = job

            response = await client.get("/api/v1/jobs/test123")

            # Cleanup
            del app.state.jobs["test123"]

        assert response.status_code == 200
        body = response.json()
        assert body["job_id"] == "test123"
        assert body["status"] == "pending"

    async def test_cancel_pending_job(self) -> None:
        """DELETE /api/v1/jobs/{id} pour un job PENDING → 200."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            job = GenerationJob(
                job_id="cancel_me",
                status=GenerationStatus.PENDING,
                status_url="/api/v1/jobs/cancel_me",
            )
            app.state.jobs["cancel_me"] = job

            response = await client.delete("/api/v1/jobs/cancel_me")

            # Cleanup
            if "cancel_me" in app.state.jobs:
                del app.state.jobs["cancel_me"]

        assert response.status_code == 200
        assert response.json()["status"] == "cancelled"

    async def test_cancel_running_job_returns_409(self) -> None:
        """DELETE /api/v1/jobs/{id} pour un job RUNNING → 409."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            job = GenerationJob(
                job_id="running_job",
                status=GenerationStatus.RUNNING,
                status_url="/api/v1/jobs/running_job",
            )
            app.state.jobs["running_job"] = job

            response = await client.delete("/api/v1/jobs/running_job")

            # Cleanup
            del app.state.jobs["running_job"]

        assert response.status_code == 409

    async def test_get_result_not_completed(self) -> None:
        """GET /api/v1/jobs/{id}/result pour un job PENDING → 409."""
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            job = GenerationJob(
                job_id="pending_result",
                status=GenerationStatus.PENDING,
                status_url="/api/v1/jobs/pending_result",
            )
            app.state.jobs["pending_result"] = job

            response = await client.get("/api/v1/jobs/pending_result/result")

            # Cleanup
            del app.state.jobs["pending_result"]

        assert response.status_code == 409
