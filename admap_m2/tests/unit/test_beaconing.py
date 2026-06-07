"""
Module   : tests.unit.test_beaconing
Version  : 1.0.0
Dépend   : [pytest, datetime, admap_m2.detectors.beaconing_detector,
            admap_m2.parsers.flow_builder, admap_m2.parsers.pcap_parser]
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from admap_m2.detectors.beaconing_detector import BeaconingDetector
from admap_m2.models.alert import AlertType
from admap_m2.models.flow import NetworkFlow, Protocol
from admap_m2.parsers.flow_builder import FlowBuilder
from admap_m2.parsers.pcap_parser import PCAPParser


def test_beaconing_detector_name(test_settings) -> None:
    """detector_name doit retourner 'beaconing'."""
    assert BeaconingDetector(test_settings).detector_name == "beaconing"


def test_beaconing_detection(beaconing_pcap_bytes: bytes, test_settings) -> None:
    """BeaconingDetector détecte le beaconing dans le PCAP dédié."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, link_type in parser.stream_packets(beaconing_pcap_bytes):
        builder.process_packet(ts, buf, link_type)
    flows = builder.finalize()

    detector = BeaconingDetector(test_settings)
    alerts = detector.detect(flows)

    beaconing_alerts = [a for a in alerts if a.alert_type == AlertType.BEACONING]
    assert len(beaconing_alerts) >= 1
    top = max(beaconing_alerts, key=lambda a: a.confidence_score)
    assert top.confidence_score >= 30
    assert top.dst_ip == "185.234.100.123"


def test_beaconing_not_triggered_single_flow(
    sample_flow: NetworkFlow, test_settings
) -> None:
    """Un seul flux ne déclenche pas d'alerte beaconing."""
    detector = BeaconingDetector(test_settings)
    alerts = detector.detect([sample_flow])
    assert len(alerts) == 0


def test_beaconing_score_calculation(test_settings) -> None:
    """Score élevé pour beaconing très précis avec beaucoup d'occurrences."""
    detector = BeaconingDetector(test_settings)
    score = detector._calculate_score(50, 0.005, 60.0)
    assert score >= 80


def test_beaconing_cv_above_tolerance(test_settings) -> None:
    """CV > BEACONING_JITTER_TOLERANCE ne génère pas d'alerte."""
    # 10 flux avec intervalles alternés très variables
    base_ts = 1700000000.0
    flows = []
    cumulative = 0.0
    for i in range(10):
        interval = 10.0 if i % 2 == 0 else 600.0
        cumulative += interval
        dt = datetime.fromtimestamp(base_ts + cumulative, tz=timezone.utc)
        flows.append(NetworkFlow(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=10000 + i,
            dst_port=4444,
            protocol=Protocol.TCP,
            first_seen=dt,
            last_seen=dt,
        ))

    detector = BeaconingDetector(test_settings)
    alerts = detector.detect(flows)
    assert len(alerts) == 0
