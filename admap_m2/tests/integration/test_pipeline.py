"""
Module   : tests.integration.test_pipeline
Version  : 1.0.0
Dépend   : [pytest, pytest_asyncio, httpx, admap_m2.pipeline.orchestrator,
            admap_m2.models.alert, admap_m2.models.job, admap_m2.core.config]
"""
from __future__ import annotations

import pytest

from admap_m2.core.config import Settings
from admap_m2.models.alert import AlertBundle, AlertType
from admap_m2.models.job import AnalysisOptions
from admap_m2.pipeline.orchestrator import AnalysisPipeline


@pytest.mark.asyncio
async def test_full_pipeline_minimal_pcap(
    minimal_pcap_bytes: bytes,
    test_settings: Settings,
) -> None:
    """Pipeline complet sur PCAP minimal retourne un AlertBundle valide."""
    options = AnalysisOptions(
        enable_beaconing=True,
        enable_dga=True,
        enable_dns_tunnel=True,
        min_confidence_threshold=0,
    )
    # AnalysisPipeline accepte settings comme premier argument optionnel
    pipeline = AnalysisPipeline(settings=test_settings, options=options)
    bundle = await pipeline.run(minimal_pcap_bytes, "test.pcap")

    assert isinstance(bundle, AlertBundle)
    assert bundle.pcap_filename == "test.pcap"
    assert bundle.total_packets >= 3
    assert bundle.total_flows >= 1
    assert isinstance(bundle.alerts, list)
    assert bundle.analysis_duration_ms > 0
    assert len(bundle.pcap_sha256) == 64


@pytest.mark.asyncio
async def test_pipeline_detects_beaconing(
    beaconing_pcap_bytes: bytes,
    test_settings: Settings,
) -> None:
    """Pipeline détecte le beaconing dans le PCAP dédié."""
    options = AnalysisOptions(
        enable_beaconing=True,
        enable_dga=False,
        enable_dns_tunnel=False,
        enable_http_c2=False,
        enable_tls=False,
        enable_irc=False,
        enable_port_scan=False,
        min_confidence_threshold=20,
    )
    pipeline = AnalysisPipeline(settings=test_settings, options=options)
    bundle = await pipeline.run(beaconing_pcap_bytes, "beaconing.pcap")

    beaconing = [a for a in bundle.alerts if a.alert_type == AlertType.BEACONING]
    assert len(beaconing) >= 1


@pytest.mark.asyncio
async def test_pipeline_empty_pcap_raises(test_settings: Settings) -> None:
    """PCAP vide (0 octets) lève PCAPEmptyError."""
    from admap_m2.core.exceptions import PCAPEmptyError
    pipeline = AnalysisPipeline(settings=test_settings)
    with pytest.raises(PCAPEmptyError):
        await pipeline.run(b"", "empty.pcap")


@pytest.mark.asyncio
async def test_pipeline_invalid_pcap_raises(test_settings: Settings) -> None:
    """PCAP avec magic bytes invalides lève PCAPParsingError."""
    from admap_m2.core.exceptions import PCAPParsingError
    pipeline = AnalysisPipeline(settings=test_settings)
    with pytest.raises(PCAPParsingError):
        await pipeline.run(b"\x00\x01\x02\x03\x04\x05\x06\x07", "bad.pcap")


@pytest.mark.asyncio
async def test_api_health() -> None:
    """GET /health retourne {'status': 'ok', 'version': '1.0.0'}."""
    from fastapi.testclient import TestClient
    from admap_m2.api.main import app

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"


@pytest.mark.asyncio
async def test_api_ready() -> None:
    """GET /ready retourne les capacités du module."""
    from fastapi.testclient import TestClient
    from admap_m2.api.main import app

    with TestClient(app) as client:
        response = client.get("/ready")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "queue_size" in data
    assert "scapy_available" in data
    assert "m1_integration" in data


@pytest.mark.asyncio
async def test_api_submit_pcap(minimal_pcap_bytes: bytes) -> None:
    """POST /api/v1/analyze avec PCAP valide retourne 202 + job_id."""
    from fastapi.testclient import TestClient
    from admap_m2.api.main import app

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/analyze",
            files={"file": ("test.pcap", minimal_pcap_bytes, "application/octet-stream")},
            data={"min_confidence": "0"},
        )

    assert response.status_code in (200, 202)
    data = response.json()
    assert "job_id" in data
