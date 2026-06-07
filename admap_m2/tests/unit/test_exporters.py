"""
Module   : tests.unit.test_exporters
Version  : 1.0.0
Dépend   : [pytest, json, csv, io, admap_m2.exporters.*, admap_m2.models.alert]
"""
from __future__ import annotations

import csv
import io
import json

import pytest

from admap_m2.exporters.csv_exporter import CSVExporter
from admap_m2.exporters.json_exporter import JSONExporter
from admap_m2.exporters.stix_exporter import STIX2_AVAILABLE, STIXExporter
from admap_m2.models.alert import AlertBundle


def test_json_exporter_valid(sample_bundle: AlertBundle) -> None:
    """JSONExporter produit un JSON valide avec bundle_id et alerts."""
    output = JSONExporter().export(sample_bundle)
    data = json.loads(output)
    assert "bundle_id" in data
    assert "alerts" in data
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["alert_type"] == "beaconing"


def test_json_exporter_roundtrip(sample_bundle: AlertBundle) -> None:
    """L'export JSON peut être relu par AlertBundle.model_validate_json."""
    output = JSONExporter().export(sample_bundle)
    restored = AlertBundle.model_validate_json(output)
    assert restored.bundle_id == sample_bundle.bundle_id
    assert len(restored.alerts) == len(sample_bundle.alerts)


def test_csv_exporter_header(sample_bundle: AlertBundle) -> None:
    """CSVExporter produit un CSV avec les colonnes attendues."""
    output = CSVExporter().export(sample_bundle)
    reader = csv.DictReader(io.StringIO(output))
    rows = list(reader)
    assert len(rows) == 1
    assert "alert_type" in rows[0]
    assert "score" in rows[0]
    assert "src_ip" in rows[0]
    assert "dst_ip" in rows[0]


def test_csv_exporter_empty_bundle() -> None:
    """CSVExporter sur bundle vide retourne juste le header CSV."""
    bundle = AlertBundle(
        pcap_filename="empty.pcap",
        pcap_sha256="b" * 64,
        pcap_size_bytes=0,
    )
    output = CSVExporter().export(bundle)
    assert "alert_type" in output
    rows = list(csv.DictReader(io.StringIO(output)))
    assert len(rows) == 0


def test_stix_exporter_no_stix2(sample_bundle: AlertBundle) -> None:
    """Sans stix2, export() retourne un JSON d'erreur (pas d'exception)."""
    if STIX2_AVAILABLE:
        pytest.skip("stix2 is available")
    output = STIXExporter().export(sample_bundle)
    data = json.loads(output)
    assert "error" in data


def test_stix_exporter_with_stix2(sample_bundle: AlertBundle) -> None:
    """Avec stix2, l'export produit un STIX Bundle valide."""
    if not STIX2_AVAILABLE:
        pytest.skip("stix2 not installed")
    output = STIXExporter().export(sample_bundle)
    data = json.loads(output)
    assert data.get("type") == "bundle"
    assert "objects" in data


def test_stix_exporter_filters_low_severity() -> None:
    """STIXExporter ne génère des Indicators que pour CRITICAL et HIGH."""
    if not STIX2_AVAILABLE:
        pytest.skip("stix2 not installed")
    from datetime import datetime, timezone
    from admap_m2.models.alert import AlertSeverity, AlertType, C2Alert
    dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
    low_alert = C2Alert(
        alert_type=AlertType.PORT_SCAN,
        severity=AlertSeverity.LOW,
        confidence_score=25,
        src_ip="192.168.1.1", dst_ip="10.0.0.1",
        src_port=12345, dst_port=80,
        protocol="tcp",
        first_seen=dt, last_seen=dt,
        packet_count=1, byte_count=100,
        description="Low severity", evidence=["ev"],
    )
    bundle = AlertBundle(
        pcap_filename="test.pcap",
        pcap_sha256="a" * 64,
        pcap_size_bytes=100,
        alerts=[low_alert],
    )
    output = STIXExporter().export(bundle)
    data = json.loads(output)
    # Seul l'Identity object doit être présent, pas d'Indicator
    indicators = [o for o in data.get("objects", []) if o.get("type") == "indicator"]
    assert len(indicators) == 0
