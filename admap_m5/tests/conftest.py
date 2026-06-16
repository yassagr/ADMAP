from __future__ import annotations
import json
import pytest
from datetime import datetime, timezone
from pathlib import Path

from admap_m5.config import M5Settings
from admap_m5.models.input import AttributionOptions
from admap_m5.models.output import AttributionReport, AttributionResult, APTCandidate


@pytest.fixture
def settings(tmp_path: Path) -> M5Settings:
    """Settings de test avec chemins temporaires."""
    kb_path = tmp_path / "apt_kb.json"
    # Copier le contenu minimal de la KB
    kb_path.write_text(json.dumps({
        "version": "1.0.0",
        "last_updated": "2025-01-01",
        "apt_groups": [
            {
                "apt_id": "G0007",
                "apt_name": "APT28",
                "aliases": ["Fancy Bear"],
                "origin": "Russia",
                "mitre_url": "https://attack.mitre.org/groups/G0007/",
                "signature_techniques": ["T1071", "T1059", "T1078"],
                "signature_tactics": ["command-and-control", "execution"],
                "signature_ips": ["185.220.101.0/24"],
                "signature_domains_patterns": [".ru"],
                "signature_yara_tags": ["apt28", "fancy_bear"],
                "signature_imphash_patterns": ["c2d3d"],
                "malware_families": ["X-Agent"],
                "description": "Russian state-sponsored group."
            },
            {
                "apt_id": "G0032",
                "apt_name": "Lazarus Group",
                "aliases": ["Hidden Cobra"],
                "origin": "North Korea",
                "mitre_url": "https://attack.mitre.org/groups/G0032/",
                "signature_techniques": ["T1059", "T1027", "T1105"],
                "signature_tactics": ["execution", "defense-evasion"],
                "signature_ips": ["175.45.176.0/24"],
                "signature_domains_patterns": ["update"],
                "signature_yara_tags": ["lazarus", "wannacry"],
                "signature_imphash_patterns": ["a1b2c"],
                "malware_families": ["WannaCry"],
                "description": "North Korean group."
            }
        ]
    }), encoding="utf-8")

    model_store = tmp_path / "models_store"
    model_store.mkdir()

    return M5Settings(
        apt_kb_path=kb_path,
        model_store_path=model_store,
        top_k_candidates=3,
    )


@pytest.fixture
def sample_apt_map_report_json() -> str:
    """APTMapReport minimal valide pour les tests."""
    return json.dumps({
        "report_id": "test-report-001",
        "source_bundle_id": "bundle-001",
        "cluster_bundle": {
            "bundle_id": "cluster-bundle-001",
            "source_bundle_id": "bundle-001",
            "clusters": [
                {
                    "cluster_id": "cluster-001",
                    "cluster_label": 0,
                    "member_profile_ids": ["p1", "p2"],
                    "dominant_techniques": ["T1071", "T1059"],
                    "dominant_tactics": ["command-and-control", "execution"],
                    "confidence_score": 75.0,
                    "involved_ips": ["192.168.1.100", "10.0.0.5"],
                    "yara_tags": ["apt28"],
                    "first_seen": "2024-01-01T00:00:00",
                    "last_seen": "2024-01-02T00:00:00",
                    "metadata": {}
                }
            ],
            "noise_profile_ids": [],
            "total_profiles": 2,
            "total_clusters": 1,
            "noise_count": 0,
            "created_at": "2024-01-02T00:00:00"
        },
        "mitre_coverage": {"command-and-control": ["T1071"], "execution": ["T1059"]},
        "top_techniques": [["T1071", 2], ["T1059", 1]],
        "top_tactics": [["command-and-control", 2]],
        "campaign_count": 1,
        "noise_count": 0,
        "analysis_duration_seconds": 0.5,
        "options_used": {},
        "created_at": "2024-01-02T00:00:00",
        "version": "1.0.0"
    })


@pytest.fixture
def sample_ioc_bundle_json() -> str:
    return json.dumps({
        "bundle_id": "ioc-bundle-001",
        "hashes": [
            {"md5": "d41d8cd98f00b204e9800998ecf8427e",
             "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             "ssdeep": "3:abc:xyz",
             "imphash": "c2d3d"}
        ],
        "ips": ["185.220.101.10"],
        "domains": ["evil.ru"],
        "strings": ["cmd.exe", "powershell"]
    })


@pytest.fixture
def sample_attribution_report(settings: M5Settings) -> AttributionReport:
    candidate = APTCandidate(
        rank=1,
        apt_name="APT28",
        apt_id="G0007",
        confidence_score=72.5,
        xgb_probability=0.6,
        cosine_similarity=0.8,
        matched_techniques=["T1071"],
        matched_tactics=["command-and-control"],
        matched_yara_tags=["apt28"],
        matched_ips=[],
        evidence_summary="Techniques: T1071; YARA: apt28",
        mitre_group_url="https://attack.mitre.org/groups/G0007/",
    )
    result = AttributionResult(
        cluster_id="cluster-001",
        cluster_label=0,
        candidates=[candidate],
        feature_vector_size=50,
        analysis_method="xgboost+cosine",
    )
    return AttributionReport(
        report_id="report-001",
        source_report_id="m4-report-001",
        results=[result],
        top_global_candidate=candidate,
        total_clusters_analyzed=1,
        noise_clusters_skipped=0,
        analysis_duration_seconds=0.3,
        options_used={"top_k": 3},
        created_at=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
