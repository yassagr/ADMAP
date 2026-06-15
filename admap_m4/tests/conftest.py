from __future__ import annotations
import json
import pytest
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from admap_m4.main import create_app
from admap_m4.config import Settings
from admap_m4.models.report import AnalysisOptions
from admap_m4.core.pipeline import AnalysisPipeline

@pytest.fixture
def settings() -> Settings:
    return Settings(
        dbscan_epsilon=0.3,
        dbscan_min_samples=2,
        min_confidence_score=0,
    )

@pytest.fixture
def analysis_options() -> AnalysisOptions:
    return AnalysisOptions(dbscan_epsilon=0.3, dbscan_min_samples=2)

@pytest.fixture
def pipeline(settings, analysis_options) -> AnalysisPipeline:
    # CRITIQUE : signature doit rester (settings=None, options=None)
    return AnalysisPipeline(settings=settings, options=analysis_options)

@pytest.fixture
def sample_alert_bundle() -> dict:
    return {
        "bundle_id": "test-bundle-001",
        "pcap_filename": "test.pcap",
        "pcap_sha256": "abc123",
        "alerts": [
            {
                "alert_type": "beaconing",
                "severity": "high",
                "confidence_score": 75,
                "src_ip": "10.0.0.1",
                "dst_ip": "192.168.1.100",
                "src_port": 54321,
                "dst_port": 443,
                "protocol": "TCP",
                "first_seen": datetime(2024, 1, 1, tzinfo=timezone.utc).isoformat(),
                "last_seen": datetime(2024, 1, 2, tzinfo=timezone.utc).isoformat(),
                "evidence": ["periodic_interval"],
                "ioc_matches": [],
                "metadata": {},
            },
            {
                "alert_type": "dns_tunnel",
                "severity": "critical",
                "confidence_score": 90,
                "src_ip": "10.0.0.2",
                "dst_ip": "8.8.8.8",
                "src_port": 1234,
                "dst_port": 53,
                "protocol": "UDP",
                "first_seen": datetime(2024, 1, 1, tzinfo=timezone.utc).isoformat(),
                "last_seen": datetime(2024, 1, 3, tzinfo=timezone.utc).isoformat(),
                "evidence": ["high_entropy_subdomain"],
                "ioc_matches": [],
                "metadata": {},
            },
            {
                "alert_type": "beaconing",
                "severity": "high",
                "confidence_score": 80,
                "src_ip": "10.0.0.3",
                "dst_ip": "192.168.1.101",
                "src_port": 54322,
                "dst_port": 443,
                "protocol": "TCP",
                "first_seen": datetime(2024, 1, 1, tzinfo=timezone.utc).isoformat(),
                "last_seen": datetime(2024, 1, 2, tzinfo=timezone.utc).isoformat(),
                "evidence": ["periodic_interval"],
                "ioc_matches": [],
                "metadata": {},
            },
        ],
        "alerts_by_type": {"beaconing": 2, "dns_tunnel": 1},
        "alerts_by_severity": {"high": 2, "critical": 1},
        "top_suspicious_ips": ["192.168.1.100"],
        "m1_bundle_id": None,
        "ioc_hits": 0,
    }

@pytest.fixture
def sample_alert_bundle_json(sample_alert_bundle) -> str:
    return json.dumps(sample_alert_bundle)

@pytest.fixture
def sample_profiles():
    from admap_m4.models.ttp import TTPProfile
    return [
        TTPProfile(
            alert_id="1", alert_type="beaconing", techniques=["T1071", "T1573"],
            tactics=["c2"], confidence_score=80, src_ip="1", dst_ip="2", timestamp=datetime.utcnow()
        ),
        TTPProfile(
            alert_id="2", alert_type="beaconing", techniques=["T1071", "T1573"],
            tactics=["c2"], confidence_score=80, src_ip="1", dst_ip="2", timestamp=datetime.utcnow()
        ),
        TTPProfile(
            alert_id="3", alert_type="dns_tunnel", techniques=["T1048"],
            tactics=["exfil"], confidence_score=90, src_ip="1", dst_ip="2", timestamp=datetime.utcnow()
        ),
    ]

@pytest.fixture
def app():
    from fastapi.testclient import TestClient
    from admap_m4.main import create_app
    import asyncio
    
    application = create_app()
    # Mock lifespan initialization
    application.state.job_queue = asyncio.Queue()
    application.state.jobs = {}
    from admap_m4.config import get_settings
    application.state.settings = get_settings()
    return application

@pytest.fixture
async def async_client(app):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client
