"""
Module   : admap_m2.tests.unit.test_models
Version  : 1.0.0
"""
from datetime import datetime, timezone
from admap_m2.models.flow import NetworkFlow, Protocol
from admap_m2.models.alert import C2Alert, AlertType, AlertSeverity

def test_flow_creation():
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

def test_alert_creation():
    alert = C2Alert(
        alert_type=AlertType.DNS_TUNNEL,
        severity=AlertSeverity.HIGH,
        confidence_score=75,
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        protocol="udp",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        packet_count=100,
        byte_count=5000,
        description="Test",
        evidence=["test"]
    )
    assert alert.confidence_score == 75
