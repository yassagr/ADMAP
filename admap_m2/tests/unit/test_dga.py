"""
Module   : tests.unit.test_dga
Version  : 1.0.0
"""
from __future__ import annotations

import pytest

from admap_m2.detectors.dga_detector import DGADetector
from admap_m2.models.alert import AlertType
from admap_m2.models.flow import DNSQuery, NetworkFlow, Protocol
from datetime import datetime, timezone


def _make_dns_flow(domain: str) -> NetworkFlow:
    """Crée un flux DNS minimal avec une requête vers domain."""
    now = datetime.now(timezone.utc)
    flow = NetworkFlow(
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        src_port=12345,
        dst_port=53,
        protocol=Protocol.DNS,
        first_seen=now,
        last_seen=now,
        packet_count=1,
    )
    flow.dns_queries.append(DNSQuery(
        timestamp=now,
        query_name=domain,
        query_type="A",
    ))
    return flow


def test_dga_high_entropy_detected(test_settings):
    """Domaine haute entropie (DGA typique) doit être détecté."""
    flow = _make_dns_flow("xk3j9mzqpl7wvnbf2r.ru")
    detector = DGADetector(test_settings)
    alerts = detector.detect([flow])
    dga_alerts = [a for a in alerts if a.alert_type == AlertType.DGA]
    assert len(dga_alerts) >= 1
    assert dga_alerts[0].confidence_score >= 20


def test_dga_normal_domain_not_flagged(test_settings):
    """google.com ne doit pas être détecté comme DGA."""
    flow = _make_dns_flow("google.com")
    detector = DGADetector(test_settings)
    alerts = detector.detect([flow])
    dga_alerts = [a for a in alerts if a.alert_type == AlertType.DGA]
    assert len(dga_alerts) == 0


def test_dga_shannon_entropy_constant():
    """Entropie Shannon = 0 pour chaîne constante."""
    detector = DGADetector(None)
    entropy = detector._shannon_entropy("aaaa")
    assert entropy == 0.0


def test_dga_shannon_entropy_uniform():
    """Entropie Shannon > 2 pour chaîne aléatoire."""
    detector = DGADetector(None)
    entropy = detector._shannon_entropy("abcdefghij")
    assert entropy > 2.5


def test_dga_short_domain_not_flagged(test_settings):
    """Domaine trop court ignoré même si haute entropie."""
    flow = _make_dns_flow("xy.com")
    detector = DGADetector(test_settings)
    alerts = detector.detect([flow])
    assert all(a.alert_type != AlertType.DGA for a in alerts)


def test_dga_no_dns_queries(test_settings, sample_flow):
    """Aucune alerte si le flux n'a pas de requêtes DNS."""
    detector = DGADetector(test_settings)
    alerts = detector.detect([sample_flow])
    assert all(a.alert_type != AlertType.DGA for a in alerts)
