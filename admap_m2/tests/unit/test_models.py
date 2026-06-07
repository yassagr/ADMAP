"""
Module   : tests.unit.test_models
Version  : 1.0.0
Dépend   : [pytest, pydantic, datetime, admap_m2.models.*]
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from admap_m2.models.alert import AlertBundle, AlertSeverity, AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow, Protocol
from admap_m2.models.job import AnalysisOptions


def _make_alert(**overrides) -> C2Alert:
    defaults = dict(
        alert_type=AlertType.BEACONING,
        severity=AlertSeverity.HIGH,
        confidence_score=75,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=4444,
        protocol="tcp",
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 1, 0, 1, tzinfo=timezone.utc),
        packet_count=10,
        byte_count=1000,
        description="Test alert",
        evidence=["Evidence 1"],
    )
    defaults.update(overrides)
    return C2Alert(**defaults)


def test_flow_creation() -> None:
    flow = NetworkFlow(
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        protocol=Protocol.DNS,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    assert flow.protocol == Protocol.DNS
    assert flow.packet_count == 0
    assert flow.inter_packet_intervals == []


def test_alert_creation() -> None:
    alert = _make_alert()
    assert alert.confidence_score == 75
    assert alert.alert_type == AlertType.BEACONING


def test_c2_alert_score_validation_upper() -> None:
    with pytest.raises(ValidationError):
        _make_alert(confidence_score=101)


def test_c2_alert_score_validation_lower() -> None:
    with pytest.raises(ValidationError):
        _make_alert(confidence_score=-1)


def test_c2_alert_score_boundary_valid() -> None:
    a0 = _make_alert(confidence_score=0)
    a100 = _make_alert(confidence_score=100)
    assert a0.confidence_score == 0
    assert a100.confidence_score == 100


def test_c2_alert_is_frozen() -> None:
    alert = _make_alert()
    with pytest.raises(Exception):
        alert.confidence_score = 90  # type: ignore[misc]


def test_alert_bundle_empty() -> None:
    bundle = AlertBundle(
        pcap_filename="test.pcap",
        pcap_sha256="a" * 64,
        pcap_size_bytes=0,
    )
    assert len(bundle.alerts) == 0
    assert bundle.total_packets == 0


def test_alert_bundle_json_roundtrip(sample_bundle: AlertBundle) -> None:
    json_str = sample_bundle.model_dump_json()
    restored = AlertBundle.model_validate_json(json_str)
    assert restored.bundle_id == sample_bundle.bundle_id
    assert len(restored.alerts) == len(sample_bundle.alerts)


def test_analysis_options_defaults() -> None:
    opts = AnalysisOptions()
    assert opts.enable_beaconing is True
    assert opts.enable_dga is True
    assert opts.min_confidence_threshold == 20


def test_analysis_options_validation() -> None:
    with pytest.raises(ValidationError):
        AnalysisOptions(min_confidence_threshold=101)
    with pytest.raises(ValidationError):
        AnalysisOptions(min_confidence_threshold=-1)
