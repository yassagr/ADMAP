from __future__ import annotations
import pytest
from admap_m5.exporters.json_exporter import JSONExporter
from admap_m5.exporters.csv_exporter import CSVExporter
from admap_m5.exporters.stix_exporter import STIXExporter


def test_json_exporter_basic(sample_attribution_report):
    exporter = JSONExporter()
    out = exporter.export(sample_attribution_report)
    assert "report_id" in out
    assert out["report_id"] == "report-001"


def test_json_exporter_no_runtime_error():
    exporter = JSONExporter()
    out = exporter.export(None) # type: ignore
    assert "error" in out


def test_csv_exporter_basic(sample_attribution_report):
    exporter = CSVExporter()
    out = exporter.export(sample_attribution_report)
    assert "csv" in out
    assert isinstance(out["csv"], str)


def test_csv_has_header(sample_attribution_report):
    exporter = CSVExporter()
    out = exporter.export(sample_attribution_report)
    assert "cluster_id" in out["csv"]


def test_csv_exporter_no_runtime_error():
    exporter = CSVExporter()
    out = exporter.export(None) # type: ignore
    assert "error" in out


def test_stix_exporter_basic(sample_attribution_report):
    exporter = STIXExporter()
    out = exporter.export(sample_attribution_report)
    assert "type" in out
    assert out["type"] == "bundle"


def test_stix_has_type_bundle(sample_attribution_report):
    exporter = STIXExporter()
    out = exporter.export(sample_attribution_report)
    assert out["type"] == "bundle"


def test_stix_has_threat_actor(sample_attribution_report):
    exporter = STIXExporter()
    out = exporter.export(sample_attribution_report)
    objects = out.get("objects", [])
    assert any(obj["type"] == "threat-actor" for obj in objects)


def test_stix_confidence_threshold(sample_attribution_report):
    from admap_m5.models.output import APTCandidate, AttributionResult, AttributionReport
    
    # Modifier le rapport pour avoir une confiance faible
    candidate = sample_attribution_report.results[0].candidates[0].model_copy(update={"confidence_score": 10.0})
    result = sample_attribution_report.results[0].model_copy(update={"candidates": [candidate]})
    low_conf_report = sample_attribution_report.model_copy(update={"results": [result]})
    
    exporter = STIXExporter()
    out = exporter.export(low_conf_report)
    objects = out.get("objects", [])
    assert not any(obj["type"] == "threat-actor" for obj in objects)


def test_stix_exporter_no_runtime_error():
    exporter = STIXExporter()
    out = exporter.export(None) # type: ignore
    assert "error" in out
