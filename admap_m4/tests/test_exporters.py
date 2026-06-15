from __future__ import annotations
import pytest
from datetime import datetime
from admap_m4.exporters.json_exporter import JSONExporter
from admap_m4.exporters.csv_exporter import CSVExporter
from admap_m4.exporters.stix_exporter import STIXExporter
from admap_m4.models.report import APTMapReport, AnalysisOptions
from admap_m4.models.cluster import ClusterBundle

@pytest.fixture
def empty_report():
    return APTMapReport(
        report_id="1", source_bundle_id="1", mitre_coverage={}, top_techniques=[], top_tactics=[],
        campaign_count=0, noise_count=0, analysis_duration_seconds=0.0, options_used=AnalysisOptions(),
        created_at=datetime.utcnow(), cluster_bundle=ClusterBundle(
            bundle_id="1", source_bundle_id="1", total_profiles=0, total_clusters=0, noise_count=0,
            noise_profile_ids=[], clusters=[], created_at=datetime.utcnow()
        )
    )

def test_json_exporter(empty_report):
    exporter = JSONExporter()
    res = exporter.export(empty_report)
    assert isinstance(res, dict)

def test_json_exporter_error():
    exporter = JSONExporter()
    res = exporter.export(None)
    assert "error" in res

def test_csv_exporter(empty_report):
    exporter = CSVExporter()
    res = exporter.export(empty_report)
    assert isinstance(res, str)
    assert "cluster_id" in res

def test_csv_exporter_error():
    exporter = CSVExporter()
    res = exporter.export(None)
    assert "error,code" in res

def test_stix_exporter(empty_report):
    exporter = STIXExporter()
    res = exporter.export(empty_report)
    assert isinstance(res, dict)
    assert "objects" in res

def test_stix_exporter_error():
    exporter = STIXExporter()
    res = exporter.export(None)
    assert "error" in res
