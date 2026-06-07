"""
Module   : tests.unit.test_beaconing
Version  : 1.0.0
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from admap_m2.detectors.beaconing_detector import BeaconingDetector
from admap_m2.models.alert import AlertType
from admap_m2.models.flow import NetworkFlow, Protocol
from admap_m2.parsers.flow_builder import FlowBuilder
from admap_m2.parsers.pcap_parser import PCAPParser


def _make_flow(dst_ip: str, dst_port: int, ts_offset_s: float, src_port: int = 12345) -> NetworkFlow:
    """Crée un flux avec un timestamp précis."""
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    first = base + timedelta(seconds=ts_offset_s)
    return NetworkFlow(
        src_ip="192.168.1.1",
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=Protocol.TCP,
        first_seen=first,
        last_seen=first + timedelta(seconds=1),
        packet_count=1,
    )


def test_beaconing_detected_regular_intervals(test_settings):
    """Beaconing détecté sur 10 flux espacés de 60s exactement."""
    flows = [_make_flow("185.234.100.123", 4444, i * 60.0, src_port=50000 + i) for i in range(10)]
    detector = BeaconingDetector(test_settings)
    alerts = detector.detect(flows)
    beaconing = [a for a in alerts if a.alert_type == AlertType.BEACONING]
    assert len(beaconing) >= 1
    assert beaconing[0].confidence_score >= 50
    assert beaconing[0].dst_ip == "185.234.100.123"
    assert beaconing[0].dst_port == 4444


def test_beaconing_from_pcap_fixture(test_settings, beaconing_pcap_bytes):
    """Beaconing détecté sur le PCAP fixture (20 SYN toutes les 60s)."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, ltype in parser.stream_packets(beaconing_pcap_bytes):
        builder.process_packet(ts, buf, ltype)
    flows = builder.finalize()

    detector = BeaconingDetector(test_settings)
    alerts = detector.detect(flows)
    beaconing = [a for a in alerts if a.alert_type == AlertType.BEACONING]
    assert len(beaconing) >= 1
    top = max(beaconing, key=lambda a: a.confidence_score)
    assert top.confidence_score >= 50
    assert top.dst_ip == "185.234.100.123"


def test_beaconing_not_triggered_single_flow(test_settings, sample_flow):
    """Aucun beaconing sur un seul flux."""
    detector = BeaconingDetector(test_settings)
    alerts = detector.detect([sample_flow])
    assert all(a.alert_type != AlertType.BEACONING for a in alerts)


def test_beaconing_not_triggered_high_jitter(test_settings):
    """Pas de beaconing si intervalles très irréguliers (CV > 0.15)."""
    import random
    random.seed(42)
    flows = [
        _make_flow("10.0.0.1", 8080, random.uniform(0, 3600), src_port=50000 + i)
        for i in range(10)
    ]
    detector = BeaconingDetector(test_settings)
    alerts = detector.detect(flows)
    beaconing = [a for a in alerts if a.alert_type == AlertType.BEACONING]
    assert len(beaconing) == 0


def test_beaconing_score_high_precision_many_occurrences(test_settings):
    """Score élevé pour beaconing précis avec beaucoup de répétitions."""
    detector = BeaconingDetector(test_settings)
    score = detector._calculate_score(occurrences=50, cv=0.005, mean_interval=60.0)
    assert score >= 80


def test_beaconing_score_low_occurrences(test_settings):
    """Score modéré pour peu de répétitions."""
    detector = BeaconingDetector(test_settings)
    score = detector._calculate_score(occurrences=3, cv=0.10, mean_interval=300.0)
    assert score < 80
