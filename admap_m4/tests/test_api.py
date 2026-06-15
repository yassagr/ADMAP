from __future__ import annotations
import asyncio
import pytest
from datetime import datetime, timezone
from httpx import AsyncClient
from admap_m4.models.report import AnalysisJob, AnalysisOptions, JobStatus, APTMapReport
from admap_m4.models.cluster import ClusterBundle, CampaignCluster


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_completed_job(job_id: str) -> AnalysisJob:
    """Crée un AnalysisJob avec status=completed et un APTMapReport minimal."""
    cluster = CampaignCluster(
        cluster_id="c1c1c1c1-0000-0000-0000-000000000001",
        cluster_label=0,
        member_profile_ids=["p1"],
        dominant_techniques=["T1071"],
        dominant_tactics=["command-and-control"],
        confidence_score=75.0,
        involved_ips=["10.0.0.1"],
        yara_tags=[],
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 2, tzinfo=timezone.utc),
    )
    report = APTMapReport(
        report_id=job_id,
        source_bundle_id="bundle-001",
        mitre_coverage={"command-and-control": ["T1071"]},
        top_techniques=[("T1071", 1)],
        top_tactics=[("command-and-control", 1)],
        campaign_count=1,
        noise_count=0,
        analysis_duration_seconds=0.1,
        options_used=AnalysisOptions(),
        created_at=datetime.now(timezone.utc),
        cluster_bundle=ClusterBundle(
            bundle_id="b1",
            source_bundle_id="bundle-001",
            total_profiles=1,
            total_clusters=1,
            noise_count=0,
            noise_profile_ids=[],
            clusters=[cluster],
            created_at=datetime.now(timezone.utc),
        ),
    )
    job = AnalysisJob(job_id=job_id, options=AnalysisOptions())
    job.status = JobStatus.completed
    job.result = report
    return job


# ── Tests de base ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health(async_client: AsyncClient):
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["module"] == "M4-APTMapper"


@pytest.mark.asyncio
async def test_ready(async_client: AsyncClient):
    response = await async_client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert "queue_size" in response.json()


@pytest.mark.asyncio
async def test_ready_503_when_no_queue(app):
    """Couvre la branche 503 de /ready quand la queue n'est pas initialisée."""
    from httpx import AsyncClient, ASGITransport
    # Supprimer la queue du state pour simuler un état non prêt
    del app.state.job_queue
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/ready")
    assert response.status_code == 503
    # Remettre la queue pour ne pas polluer les autres tests
    app.state.job_queue = asyncio.Queue()


@pytest.mark.asyncio
async def test_capabilities(async_client: AsyncClient):
    response = await async_client.get("/api/v1/capabilities")
    assert response.status_code == 200
    assert response.json()["module"] == "M4"
    assert "TF-IDF-manual" in response.json()["algorithms"]


# ── /analyze ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_valid(async_client: AsyncClient, sample_alert_bundle_json):
    files = {"alert_bundle": ("alert.json", sample_alert_bundle_json, "application/json")}
    response = await async_client.post("/api/v1/analyze", files=files)
    assert response.status_code == 202
    assert "job_id" in response.json()
    assert "status_url" in response.json()


@pytest.mark.asyncio
async def test_analyze_queue_full(app, sample_alert_bundle_json):
    """Couvre la branche QueueFull de /analyze."""
    from httpx import AsyncClient, ASGITransport
    # Remplir la queue jusqu'au maximum
    app.state.job_queue = asyncio.Queue(maxsize=1)
    app.state.job_queue.put_nowait("fake_job")  # queue pleine
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        files = {"alert_bundle": ("alert.json", sample_alert_bundle_json, "application/json")}
        response = await client.post("/api/v1/analyze", files=files)
    assert response.status_code == 503
    # Remettre une queue normale
    app.state.job_queue = asyncio.Queue()


# ── /jobs/{job_id} ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_job_existing(async_client: AsyncClient, sample_alert_bundle_json):
    files = {"alert_bundle": ("alert.json", sample_alert_bundle_json, "application/json")}
    response = await async_client.post("/api/v1/analyze", files=files)
    job_id = response.json()["job_id"]
    response_job = await async_client.get(f"/api/v1/jobs/{job_id}")
    assert response_job.status_code == 200
    assert response_job.json()["status"] in ["pending", "running", "completed"]


@pytest.mark.asyncio
async def test_get_job_not_found(async_client: AsyncClient):
    """Couvre la branche 404 de GET /jobs/{job_id}."""
    response = await async_client.get("/api/v1/jobs/nonexistent-id")
    assert response.status_code == 404


# ── /jobs/{job_id}/result ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_job_result_not_found(async_client: AsyncClient):
    """Couvre la branche 404 de GET /jobs/{job_id}/result."""
    response = await async_client.get("/api/v1/jobs/nonexistent-id/result")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_job_result_not_completed(async_client: AsyncClient, sample_alert_bundle_json):
    """Couvre la branche 409 de GET /jobs/{job_id}/result (job encore pending)."""
    files = {"alert_bundle": ("alert.json", sample_alert_bundle_json, "application/json")}
    response = await async_client.post("/api/v1/analyze", files=files)
    job_id = response.json()["job_id"]
    # Le job est pending immédiatement après le POST (worker async)
    response_result = await async_client.get(f"/api/v1/jobs/{job_id}/result")
    # Peut être 409 (pending) ou 200 (complété très vite) — les deux sont valides
    assert response_result.status_code in [200, 409]


@pytest.mark.asyncio
async def test_get_job_result_completed(app):
    """Couvre la branche return job.result (job complété) de GET /jobs/{job_id}/result."""
    from httpx import AsyncClient, ASGITransport
    job_id = "completed-job-001"
    app.state.jobs[job_id] = _make_completed_job(job_id)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/jobs/{job_id}/result")
    assert response.status_code == 200
    assert response.json()["report_id"] == job_id


# ── DELETE /jobs/{job_id} ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cancel_job_pending(async_client: AsyncClient, sample_alert_bundle_json):
    files = {"alert_bundle": ("alert.json", sample_alert_bundle_json, "application/json")}
    response = await async_client.post("/api/v1/analyze", files=files)
    job_id = response.json()["job_id"]
    response_cancel = await async_client.delete(f"/api/v1/jobs/{job_id}")
    assert response_cancel.status_code == 200


@pytest.mark.asyncio
async def test_cancel_job_not_found(async_client: AsyncClient):
    """Couvre la branche 404 de DELETE /jobs/{job_id}."""
    response = await async_client.delete("/api/v1/jobs/nonexistent-id")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_cancel_job_already_completed(app):
    """Couvre la branche 'job déjà terminal' de DELETE /jobs/{job_id}."""
    from httpx import AsyncClient, ASGITransport
    job_id = "completed-job-002"
    app.state.jobs[job_id] = _make_completed_job(job_id)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.delete(f"/api/v1/jobs/{job_id}")
    assert response.status_code == 200
    assert response.json()["cancelled"] is False


# ── GET /export/{job_id}/{format} ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_not_found(async_client: AsyncClient):
    response = await async_client.get("/api/v1/export/nonexistent-id/json")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_export_job_not_completed(async_client: AsyncClient, sample_alert_bundle_json):
    """Couvre la branche 409 de /export (job non complété)."""
    files = {"alert_bundle": ("alert.json", sample_alert_bundle_json, "application/json")}
    response = await async_client.post("/api/v1/analyze", files=files)
    job_id = response.json()["job_id"]
    response_export = await async_client.get(f"/api/v1/export/{job_id}/json")
    assert response_export.status_code in [200, 409]


@pytest.mark.asyncio
async def test_export_json(app):
    """Couvre le format 'json' de /export."""
    from httpx import AsyncClient, ASGITransport
    job_id = "export-job-json"
    app.state.jobs[job_id] = _make_completed_job(job_id)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/export/{job_id}/json")
    assert response.status_code == 200
    assert response.json()["report_id"] == job_id


@pytest.mark.asyncio
async def test_export_csv(app):
    """Couvre le format 'csv' de /export."""
    from httpx import AsyncClient, ASGITransport
    job_id = "export-job-csv"
    app.state.jobs[job_id] = _make_completed_job(job_id)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/export/{job_id}/csv")
    assert response.status_code == 200
    assert "cluster_id" in response.text


@pytest.mark.asyncio
async def test_export_stix(app):
    """Couvre le format 'stix' de /export."""
    from httpx import AsyncClient, ASGITransport
    job_id = "export-job-stix"
    app.state.jobs[job_id] = _make_completed_job(job_id)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/export/{job_id}/stix")
    assert response.status_code == 200
    assert "objects" in response.json()


@pytest.mark.asyncio
async def test_export_all(app):
    """Couvre le format 'all' de /export."""
    from httpx import AsyncClient, ASGITransport
    job_id = "export-job-all"
    app.state.jobs[job_id] = _make_completed_job(job_id)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/export/{job_id}/all")
    assert response.status_code == 200
    data = response.json()
    assert "json" in data
    assert "csv" in data
    assert "stix" in data


@pytest.mark.asyncio
async def test_export_invalid_format(app):
    """Couvre la branche 400 'Invalid format' de /export."""
    from httpx import AsyncClient, ASGITransport
    job_id = "export-job-bad"
    app.state.jobs[job_id] = _make_completed_job(job_id)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(f"/api/v1/export/{job_id}/xml")
    assert response.status_code == 400
