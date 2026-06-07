"""
Module   : tests.unit.test_scorer
Version  : 1.0.0
Dépend   : [pytest, datetime, admap_m2.scorers.c2_scorer, admap_m2.models.alert]
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from admap_m2.models.alert import AlertSeverity, AlertType, C2Alert
from admap_m2.scorers.c2_scorer import C2Scorer


def _dt() -> datetime:
    return datetime(2024, 1, 1, tzinfo=timezone.utc)


def _make_alert(
    alert_type: AlertType = AlertType.BEACONING,
    score: int = 75,
    dst_ip: str = "10.0.0.1",
    dst_port: int = 4444,
    src_port: int = 12345,
) -> C2Alert:
    return C2Alert(
        alert_type=alert_type,
        severity=AlertSeverity.HIGH,
        confidence_score=score,
        src_ip="192.168.1.1",
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="tcp",
        first_seen=_dt(),
        last_seen=_dt(),
        packet_count=10,
        byte_count=1000,
        description="Test",
        evidence=["ev1"],
    )


def test_aggregate_two_same_endpoint() -> None:
    """Deux alertes sur le même endpoint sont fusionnées en une."""
    a1 = _make_alert(AlertType.BEACONING, score=75)
    a2 = _make_alert(AlertType.DGA, score=50)
    result = C2Scorer.aggregate_alerts([a1, a2])
    assert len(result) == 1
    # 75 + 50*0.7 = 110 → cap 100
    assert result[0].confidence_score == 100


def test_no_merge_different_endpoints() -> None:
    """Alertes sur des endpoints différents restent séparées."""
    a1 = _make_alert(dst_ip="10.0.0.1", dst_port=4444)
    a2 = _make_alert(dst_ip="10.0.0.2", dst_port=4444)
    result = C2Scorer.aggregate_alerts([a1, a2])
    assert len(result) == 2


def test_empty_input() -> None:
    """Liste vide retourne liste vide."""
    assert C2Scorer.aggregate_alerts([]) == []


def test_single_alert_unchanged() -> None:
    """Une seule alerte n'est pas modifiée."""
    alert = _make_alert(score=60)
    result = C2Scorer.aggregate_alerts([alert])
    assert len(result) == 1
    assert result[0].confidence_score == 60


def test_severity_mapping() -> None:
    """_score_to_severity mappe les scores correctement."""
    assert C2Scorer._score_to_severity(90) == AlertSeverity.CRITICAL
    assert C2Scorer._score_to_severity(80) == AlertSeverity.CRITICAL
    assert C2Scorer._score_to_severity(79) == AlertSeverity.HIGH
    assert C2Scorer._score_to_severity(60) == AlertSeverity.HIGH
    assert C2Scorer._score_to_severity(59) == AlertSeverity.MEDIUM
    assert C2Scorer._score_to_severity(40) == AlertSeverity.MEDIUM
    assert C2Scorer._score_to_severity(39) == AlertSeverity.LOW
    assert C2Scorer._score_to_severity(20) == AlertSeverity.LOW
    assert C2Scorer._score_to_severity(19) == AlertSeverity.INFO
    assert C2Scorer._score_to_severity(0) == AlertSeverity.INFO


def test_sorted_by_score_descending() -> None:
    """aggregate_alerts retourne les alertes triées par score décroissant."""
    alerts = [
        _make_alert(score=30, dst_ip="10.0.0.1", dst_port=1001),
        _make_alert(score=90, dst_ip="10.0.0.2", dst_port=1002),
        _make_alert(score=60, dst_ip="10.0.0.3", dst_port=1003),
    ]
    result = C2Scorer.aggregate_alerts(alerts)
    scores = [a.confidence_score for a in result]
    assert scores == sorted(scores, reverse=True)


def test_aggregated_evidence_merged() -> None:
    """Les preuves sont fusionnées sans doublons dans l'alerte agrégée."""
    a1 = _make_alert(AlertType.BEACONING, score=70)
    a2 = _make_alert(AlertType.DGA, score=50)
    result = C2Scorer.aggregate_alerts([a1, a2])
    assert len(result) == 1
    # Les types agrégés sont dans les metadata
    assert "aggregated_types" in result[0].metadata
