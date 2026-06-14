"""
Tests d'intégration pour les endpoints d'export.
"""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from admap_m3.api.app import app
from admap_m3.models.job import GenerationJob, GenerationStatus
from admap_m3.models.rule import YaraRuleSet, YaraRule, RuleMetadata


@pytest.mark.asyncio
class TestExportRoutes:
    """Tests des endpoints /export."""

    @pytest.fixture(autouse=True)
    async def _lifespan(self):
        async with app.router.lifespan_context(app):
            yield

    def _setup_completed_job(self, job_id: str) -> None:
        """Prépare un job COMPLETED avec un YaraRuleSet dans le state."""
        job = GenerationJob(
            job_id=job_id,
            status=GenerationStatus.COMPLETED,
            status_url=f"/api/v1/jobs/{job_id}",
            ruleset_id=f"RS_{job_id}",
        )
        app.state.jobs[job_id] = job

        # Mock RuleSet
        rule = YaraRule(
            rule_id=f"R_{job_id}",
            rule_name="TestRule",
            metadata=RuleMetadata(description="Test", corpus_id="test", date="2026-06-14", hash_corpus="abc"),
            strings=[],
            condition="any_of_them",
            raw_yara='rule TestRule { strings: $a = "test" condition: $a }',
            compiled=True,
            token_count=1,
            confidence_score=90
        )
        ruleset = YaraRuleSet(
            ruleset_id=f"RS_{job_id}",
            corpus_id="test_corpus",
            rules=[rule],
            total_rules=1,
            compiled_rules=1,
            failed_rules=0,
            generation_duration_ms=42.0
        )
        app.state.results[job_id] = ruleset

    async def test_export_yar(self) -> None:
        """GET /api/v1/export/{id}/yar → 200 FileResponse."""
        self._setup_completed_job("export_yar_job")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/export/export_yar_job/yar")
            
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")

    async def test_export_json(self) -> None:
        """GET /api/v1/export/{id}/json → 200 FileResponse."""
        self._setup_completed_job("export_json_job")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/export/export_json_job/json")
            
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")

    async def test_export_stix(self) -> None:
        """GET /api/v1/export/{id}/stix → 200 FileResponse."""
        self._setup_completed_job("export_stix_job")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/export/export_stix_job/stix")
            
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")

    async def test_export_csv(self) -> None:
        """GET /api/v1/export/{id}/csv → 200 FileResponse."""
        self._setup_completed_job("export_csv_job")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/export/export_csv_job/csv")
            
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")

    async def test_export_all(self) -> None:
        """GET /api/v1/export/{id}/all → 200 ZIP File."""
        self._setup_completed_job("export_all_job")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/export/export_all_job/all")
            
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"

    async def test_export_not_found(self) -> None:
        """GET /api/v1/export/{id}/yar avec job inexistant → 404."""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/export/nonexistent/yar")
        assert response.status_code == 404

    async def test_export_not_completed(self) -> None:
        """GET /api/v1/export/{id}/yar avec job PENDING → 409."""
        job = GenerationJob(job_id="pending_job", status=GenerationStatus.PENDING, status_url="")
        app.state.jobs["pending_job"] = job
        
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/export/pending_job/yar")
            
        assert response.status_code == 409
