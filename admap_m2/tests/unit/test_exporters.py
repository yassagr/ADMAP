"""
Module   : tests.unit.test_exporters
Version  : 1.0.0
"""
from __future__ import annotations

import csv
import io
import json

import pytest

from admap_m2.exporters.csv_exporter import CSVExporter
from admap_m2.exporters.json_exporter import JSONExporter


def test_json_exporter_valid_json(sample_bundle):
    """L'export JSON est du JSON valide."""
    exporter = JSONExporter()
    output = exporter.export(sample_bundle)
    data = json.loads(output)
    assert "bundle_id" in data
    assert "alerts" in data
    assert len(data["alerts"]) == 1


def test_json_exporter_roundtrip(sample_bundle):
    """L'export JSON peut être re-parsé en AlertBundle."""
    from admap_m2.models.alert import AlertBundle
    exporter = JSONExporter()
    output = exporter.export(sample_bundle)
    bundle2 = AlertBundle.model_validate_json(output)
    assert str(bundle2.bundle_id) == str(sample_bundle.bundle_id)
    assert len(bundle2.alerts) == 1


def test_csv_exporter_has_header(sample_bundle):
    """L'export CSV contient une ligne header."""
    exporter = CSVExporter()
    output = exporter.export(sample_bundle)
    reader = csv.DictReader(io.StringIO(output))
    assert "alert_type" in reader.fieldnames
    assert "score" in reader.fieldnames


def test_csv_exporter_correct_rows(sample_bundle):
    """L'export CSV contient autant de lignes que d'alertes."""
    exporter = CSVExporter()
    output = exporter.export(sample_bundle)
    reader = csv.DictReader(io.StringIO(output))
    rows = list(reader)
    assert len(rows) == len(sample_bundle.alerts)


def test_csv_exporter_empty_bundle():
    """Export CSV sur bundle sans alertes → header uniquement."""
    from admap_m2.models.alert import AlertBundle
    bundle = AlertBundle(pcap_filename="empty.pcap", pcap_sha256="a" * 64, pcap_size_bytes=0)
    exporter = CSVExporter()
    output = exporter.export(bundle)
    assert "alert_type" in output
    lines = [l for l in output.strip().split("\n") if l]
    assert len(lines) == 1  # Header seul


def test_stix_exporter_skipped_if_no_stix2():
    """STIXExporter lève RuntimeError si stix2 absent."""
    try:
        import stix2  # noqa: F401
        pytest.skip("stix2 is installed, skip absence test")
    except ImportError:
        from admap_m2.exporters.stix_exporter import STIXExporter
        from admap_m2.models.alert import AlertBundle
        bundle = AlertBundle(pcap_filename="t.pcap", pcap_sha256="a" * 64, pcap_size_bytes=0)
        exporter = STIXExporter()
        with pytest.raises(RuntimeError):
            exporter.export(bundle)
