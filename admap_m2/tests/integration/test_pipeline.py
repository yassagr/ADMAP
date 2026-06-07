"""
Module   : tests.integration.test_pipeline
Version  : 1.0.0
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from admap_m2.models.alert import AlertType
from admap_m2.models.job import AnalysisOptions
from admap_m2.pipeline.orchestrator import AnalysisPipeline


@pytest.fixture
def pipeline_options() -> AnalysisOptions:
    return AnalysisOptions(
        enable_beaconing=True,
        enable_dga=True,
        enable_dns_tunnel=True,
        enable_http_c2=True,
        enable_tls=True,
        enable_irc=True,
        enable_port_scan=True,
        min_confidence_threshold=10,
    )


@pytest.mark.asyncio
async def test_full_pipeline_minimal_pcap(minimal_pcap_bytes, pipeline_options):
    """Pipeline complet sur PCAP minimal avec DNS."""
    pipeline = AnalysisPipeline(options=pipeline_options)
    bundle = await pipeline.run(minimal_pcap_bytes, "test.pcap")

    assert bundle.pcap_filename == "test.pcap"
    assert bundle.total_packets >= 3
    assert bundle.total_flows >= 1
    assert isinstance(bundle.alerts, list)
    assert bundle.analysis_duration_ms > 0
    assert len(bundle.pcap_sha256) == 64


@pytest.mark.asyncio
async def test_pipeline_detects_beaconing(beaconing_pcap_bytes):
    """Pipeline détecte le beaconing dans le PCAP fixture."""
    options = AnalysisOptions(enable_beaconing=True, min_confidence_threshold=20)
    pipeline = AnalysisPipeline(options=options)
    bundle = await pipeline.run(beaconing_pcap_bytes, "beaconing.pcap")
    beaconing = [a for a in bundle.alerts if a.alert_type == AlertType.BEACONING]
    assert len(beaconing) >= 1


@pytest.mark.asyncio
async def test_pipeline_empty_pcap_raises():
    """Pipeline lève PCAPEmptyError sur fichier vide."""
    from admap_m2.core.exceptions import PCAPEmptyError
    pipeline = AnalysisPipeline()
    with pytest.raises(PCAPEmptyError):
        await pipeline.run(b"", "empty.pcap")


@pytest.mark.asyncio
async def test_pipeline_invalid_magic_raises():
    """Pipeline lève PCAPParsingError sur magic invalide."""
    from admap_m2.core.exceptions import PCAPParsingError
    pipeline = AnalysisPipeline()
    with pytest.raises(PCAPParsingError):
        await pipeline.run(b"\x00\x01\x02\x03" + b"\x00" * 100, "invalid.pcap")


@pytest.mark.asyncio
async def test_api_health():
    """GET /health → 200 avec version 1.0.0."""
    from admap_m2.api.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"


@pytest.mark.asyncio
async def test_api_ready():
    """GET /ready → 200 avec capacités."""
    from admap_m2.api.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "scapy_available" in data
    assert "m1_integration" in data
    assert "queue_size" in data


@pytest.mark.asyncio
async def test_api_submit_pcap(minimal_pcap_bytes):
    """POST /api/v1/analyze → 202 avec job_id."""
    import io
    from admap_m2.api.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post(
            "/api/v1/analyze",
            files={"file": ("test.pcap", io.BytesIO(minimal_pcap_bytes), "application/octet-stream")},
        )
    assert response.status_code in (200, 202)
    data = response.json()
    assert "job_id" in data


@pytest.mark.asyncio
async def test_api_capabilities():
    """GET /api/v1/analyze/capabilities → liste détecteurs."""
    from admap_m2.api.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/api/v1/analyze/capabilities")
    assert response.status_code == 200
    data = response.json()
    assert "detectors" in data
    assert "beaconing" in data["detectors"]
