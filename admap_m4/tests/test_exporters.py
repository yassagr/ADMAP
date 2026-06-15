from __future__ import annotations
import pytest
from datetime import datetime, timezone
from admap_m4.exporters.json_exporter import JSONExporter
from admap_m4.exporters.csv_exporter import CSVExporter
from admap_m4.exporters.stix_exporter import STIXExporter
from admap_m4.models.report import APTMapReport, AnalysisOptions
from admap_m4.models.cluster import ClusterBundle, CampaignCluster


@pytest.fixture
def empty_report():
    return APTMapReport(
        report_id="1",
        source_bundle_id="1",
        mitre_coverage={},
        top_techniques=[],
        top_tactics=[],
        campaign_count=0,
        noise_count=0,
        analysis_duration_seconds=0.0,
        options_used=AnalysisOptions(),
        created_at=datetime.now(timezone.utc),
        cluster_bundle=ClusterBundle(
            bundle_id="1",
            source_bundle_id="1",
            total_profiles=0,
            total_clusters=0,
            noise_count=0,
            noise_profile_ids=[],
            clusters=[],
            created_at=datetime.now(timezone.utc),
        ),
    )


@pytest.fixture
def report_with_clusters():
    """Rapport avec un cluster à confidence_score >= 40 pour couvrir le corps STIX."""
    cluster = CampaignCluster(
        cluster_id="c1c1c1c1-0000-0000-0000-000000000001",
        cluster_label=0,
        member_profile_ids=["p1", "p2"],
        dominant_techniques=["T1071", "T1048", "T1071"],  # T1071 apparaît 2x pour couvrir le branch "already in attack_patterns"
        dominant_tactics=["command-and-control", "exfiltration"],
        confidence_score=75.0,
        involved_ips=["10.0.0.1", "192.168.1.1"],
        yara_tags=["ransomware"],
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 2, tzinfo=timezone.utc),
    )
    return APTMapReport(
        report_id="2",
        source_bundle_id="bundle-001",
        mitre_coverage={"command-and-control": ["T1071"], "exfiltration": ["T1048"]},
        top_techniques=[("T1071", 2), ("T1048", 1)],
        top_tactics=[("command-and-control", 1)],
        campaign_count=1,
        noise_count=0,
        analysis_duration_seconds=0.5,
        options_used=AnalysisOptions(),
        created_at=datetime.now(timezone.utc),
        cluster_bundle=ClusterBundle(
            bundle_id="2",
            source_bundle_id="bundle-001",
            total_profiles=2,
            total_clusters=1,
            noise_count=0,
            noise_profile_ids=[],
            clusters=[cluster],
            created_at=datetime.now(timezone.utc),
        ),
    )


def test_json_exporter(empty_report):
    res = JSONExporter().export(empty_report)
    assert isinstance(res, dict)


def test_json_exporter_error():
    res = JSONExporter().export(None)
    assert "error" in res


def test_csv_exporter(empty_report):
    res = CSVExporter().export(empty_report)
    assert isinstance(res, str)
    assert "cluster_id" in res


def test_csv_exporter_with_clusters(report_with_clusters):
    res = CSVExporter().export(report_with_clusters)
    assert isinstance(res, str)
    assert "c1c1c1c1" in res


def test_csv_exporter_error():
    res = CSVExporter().export(None)
    assert "error,code" in res


def test_stix_exporter_empty(empty_report):
    """Rapport sans cluster : bundle STIX valide avec seulement l'Identity."""
    res = STIXExporter().export(empty_report)
    assert isinstance(res, dict)
    assert "objects" in res


def test_stix_exporter_with_clusters(report_with_clusters):
    """Rapport avec cluster >= 40 : couvre IntrusionSet, AttackPattern, Relationship."""
    res = STIXExporter().export(report_with_clusters)
    assert isinstance(res, dict)
    assert "objects" in res
    # Au moins : Identity + IntrusionSet + 2 AttackPattern + 3 Relationship = 7 objets
    assert len(res["objects"]) >= 6
    types = {obj["type"] for obj in res["objects"]}
    assert "identity" in types
    assert "intrusion-set" in types
    assert "attack-pattern" in types
    assert "relationship" in types


def test_stix_exporter_duplicate_technique(report_with_clusters):
    """Couvre le branch 'technique déjà dans attack_patterns' (ligne 23)."""
    # dominant_techniques contient "T1071" deux fois dans la fixture report_with_clusters
    res = STIXExporter().export(report_with_clusters)
    assert isinstance(res, dict)
    ap_names = [obj["name"] for obj in res["objects"] if obj["type"] == "attack-pattern"]
    # T1071 ne doit apparaître qu'une fois malgré deux occurrences dans dominant_techniques
    assert ap_names.count("MITRE T1071") == 1


def test_stix_exporter_error():
    res = STIXExporter().export(None)
    assert "error" in res
    assert res["code"] == "STIX_EXPORT_FAILED"
