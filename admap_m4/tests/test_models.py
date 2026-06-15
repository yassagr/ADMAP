from __future__ import annotations
import pytest
from datetime import datetime, timezone
from admap_m4.models.alert import AlertType, AlertSeverity, C2Alert, AlertBundle


def test_alert_type_values():
    assert AlertType.beaconing == "beaconing"
    assert AlertType.dns_tunnel == "dns_tunnel"
    assert AlertType.dga == "dga"
    assert AlertType.http_c2 == "http_c2"
    assert AlertType.tls_suspect == "tls_suspect"
    assert AlertType.irc_c2 == "irc_c2"
    assert AlertType.port_scan == "port_scan"
    assert AlertType.ioc_match == "ioc_match"
    assert AlertType.large_upload == "large_upload"
    assert AlertType.custom_protocol == "custom_protocol"


def test_alert_severity_values():
    assert AlertSeverity.critical == "critical"
    assert AlertSeverity.high == "high"
    assert AlertSeverity.medium == "medium"
    assert AlertSeverity.low == "low"
    assert AlertSeverity.info == "info"


def test_c2alert_instantiation():
    alert = C2Alert(
        alert_type=AlertType.beaconing,
        severity=AlertSeverity.high,
        confidence_score=80,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 2, tzinfo=timezone.utc),
        evidence=["periodic_interval"],
        ioc_matches=[],
        metadata={},
    )
    assert alert.alert_type == AlertType.beaconing
    assert alert.confidence_score == 80


def test_alert_bundle_instantiation():
    alert = C2Alert(
        alert_type=AlertType.dns_tunnel,
        severity=AlertSeverity.critical,
        confidence_score=90,
        src_ip="10.0.0.2",
        dst_ip="8.8.8.8",
        src_port=1234,
        dst_port=53,
        protocol="UDP",
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 3, tzinfo=timezone.utc),
        evidence=["high_entropy"],
        ioc_matches=[],
        metadata={},
    )
    bundle = AlertBundle(
        bundle_id="test-bundle",
        pcap_filename="test.pcap",
        pcap_sha256="abc123",
        alerts=[alert],
        alerts_by_type={"dns_tunnel": 1},
        alerts_by_severity={"critical": 1},
        top_suspicious_ips=["8.8.8.8"],
        m1_bundle_id=None,
        ioc_hits=0,
    )
    assert bundle.bundle_id == "test-bundle"
    assert len(bundle.alerts) == 1
    assert bundle.alerts[0].alert_type == AlertType.dns_tunnel
