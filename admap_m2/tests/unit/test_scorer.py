"""
Module   : tests.unit.test_scorer
Version  : 1.0.0
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from admap_m2.models.alert import AlertSeverity, AlertType, C2Alert
from admap_m2.scorers.c2_scorer import C2Scorer


def _make_alert(alert_type: AlertType, score: int, dst_ip: str = "10.0.0.1", dst_port: int = 4444) -> C2Alert:
    now = datetime.now(timezone.utc)
    return C2Alert(
        alert_type=alert_type,
        severity=C2Scorer._score_to_severity(score),
        confidence_score=score,
        src_ip="192.168.1.1",
        dst_ip=dst_ip,
        src_port=12345,
        dst_port=dst_port,
        protocol="tcp",
        first_seen=now,
        last_seen=now,
        packet_count=10,
        byte_count=1000,
        description="Test alert",
        evidence=["test"],
    )


def test_aggregate_single_alert():
    """Un seul alert → retourné tel quel."""
    alert = _make_alert(AlertType.BEACONING, 75)
    result = C2Scorer.aggregate_alerts([alert])
    assert len(result) == 1
    assert result[0].confidence_score == 75


def test_aggregate_merges_same_endpoint():
    """Deux alertes sur même endpoint (src→dst:port) → fusionnées."""
    a1 = _make_alert(AlertType.BEACONING, 75)
    a2 = _make_alert(AlertType.DGA, 50)
    result = C2Scorer.aggregate_alerts([a1, a2])
    assert len(result) == 1
    assert result[0].confidence_score > 75  # Score agrégé > score individuel max


def test_aggregate_no_merge_different_ports():
    """Alertes sur ports différents → pas fusionnées."""
    a1 = _make_alert(AlertType.BEACONING, 75, dst_port=4444)
    a2 = _make_alert(AlertType.DGA, 50, dst_port=8080)
    result = C2Scorer.aggregate_alerts([a1, a2])
    assert len(result) == 2


def test_aggregate_no_merge_different_dst_ips():
    """Alertes sur IPs destination différentes → pas fusionnées."""
    a1 = _make_alert(AlertType.BEACONING, 75, dst_ip="10.0.0.1")
    a2 = _make_alert(AlertType.BEACONING, 75, dst_ip="10.0.0.2")
    result = C2Scorer.aggregate_alerts([a1, a2])
    assert len(result) == 2


def test_aggregate_score_capped_at_100():
    """Score agrégé ne dépasse pas 100."""
    a1 = _make_alert(AlertType.BEACONING, 90)
    a2 = _make_alert(AlertType.DGA, 90)
    a3 = _make_alert(AlertType.IRC_C2, 90)
    result = C2Scorer.aggregate_alerts([a1, a2, a3])
    assert result[0].confidence_score <= 100


def test_score_to_severity_mapping():
    """Mapping score → severity."""
    assert C2Scorer._score_to_severity(90) == AlertSeverity.CRITICAL
    assert C2Scorer._score_to_severity(70) == AlertSeverity.HIGH
    assert C2Scorer._score_to_severity(50) == AlertSeverity.MEDIUM
    assert C2Scorer._score_to_severity(30) == AlertSeverity.LOW
    assert C2Scorer._score_to_severity(10) == AlertSeverity.INFO


def test_aggregate_empty_list():
    """Liste vide → liste vide."""
    assert C2Scorer.aggregate_alerts([]) == []


def test_aggregate_sorted_by_score_desc():
    """Résultat trié par score décroissant."""
    a1 = _make_alert(AlertType.BEACONING, 30, dst_port=1111)
    a2 = _make_alert(AlertType.DGA, 80, dst_port=2222)
    a3 = _make_alert(AlertType.IRC_C2, 55, dst_port=3333)
    result = C2Scorer.aggregate_alerts([a1, a2, a3])
    scores = [r.confidence_score for r in result]
    assert scores == sorted(scores, reverse=True)
