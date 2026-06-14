"""
Tests unitaires pour le worker asynchrone (admap_m3.api.worker).
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from admap_m3.api.worker import _process_job, job_worker
from admap_m3.models.job import GenerationJob, GenerationStatus


@pytest.mark.asyncio
class TestProcessJob:
    """Tests de _process_job."""

    async def test_process_job_not_found(self) -> None:
        """Un job_id absent du store → log error, retour silencieux."""
        app = MagicMock()
        app.state.jobs = {}

        await _process_job(
            app,
            {"job_id": "nonexistent"},
            asyncio.Semaphore(1),
        )
        # Pas d'exception levée

    async def test_process_job_already_cancelled(self) -> None:
        """Un job CANCELLED → retour silencieux sans exécuter le pipeline."""
        app = MagicMock()
        job = GenerationJob(
            job_id="cancelled_job",
            status=GenerationStatus.CANCELLED,
            status_url="/api/v1/jobs/cancelled_job",
        )
        app.state.jobs = {"cancelled_job": job}
        app.state.results = {}

        await _process_job(
            app,
            {"job_id": "cancelled_job"},
            asyncio.Semaphore(1),
        )

        assert job.status == GenerationStatus.CANCELLED

    async def test_process_job_pipeline_failure(self) -> None:
        """Une exception dans le pipeline → job.status = FAILED."""
        app = MagicMock()
        job = GenerationJob(
            job_id="fail_job",
            status=GenerationStatus.PENDING,
            status_url="/api/v1/jobs/fail_job",
        )
        app.state.jobs = {"fail_job": job}
        app.state.results = {}

        with patch("admap_m3.api.worker.GenerationPipeline") as mock_pipeline_cls:
            mock_pipeline = MagicMock()
            mock_pipeline.run = AsyncMock(side_effect=ValueError("Test error"))
            mock_pipeline_cls.return_value = mock_pipeline

            await _process_job(
                app,
                {
                    "job_id": "fail_job",
                    "malware_paths": [],
                    "benign_paths": [],
                    "corpus_id": "test",
                },
                asyncio.Semaphore(1),
            )

        assert job.status == GenerationStatus.FAILED
        assert job.error == "Test error"

    async def test_process_job_success(self) -> None:
        """Pipeline réussi → job.status = COMPLETED, résultat stocké."""
        app = MagicMock()
        job = GenerationJob(
            job_id="success_job",
            status=GenerationStatus.PENDING,
            status_url="/api/v1/jobs/success_job",
        )
        app.state.jobs = {"success_job": job}
        app.state.results = {}

        mock_ruleset = MagicMock()
        mock_ruleset.ruleset_id = "RS_test123"
        mock_ruleset.total_rules = 1
        mock_ruleset.compiled_rules = 1
        mock_ruleset.generation_duration_ms = 42.0

        with patch("admap_m3.api.worker.GenerationPipeline") as mock_pipeline_cls:
            mock_pipeline = MagicMock()
            mock_pipeline.run = AsyncMock(return_value=mock_ruleset)
            mock_pipeline_cls.return_value = mock_pipeline

            await _process_job(
                app,
                {
                    "job_id": "success_job",
                    "malware_paths": ["/tmp/m.txt"],
                    "benign_paths": ["/tmp/b.txt"],
                    "corpus_id": "test",
                },
                asyncio.Semaphore(1),
            )

        assert job.status == GenerationStatus.COMPLETED
        assert job.ruleset_id == "RS_test123"
        assert "success_job" in app.state.results
