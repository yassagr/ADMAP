"""
Module   : tests.unit.test_detectors
Version  : 1.0.0
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from admap_m2.detectors.dns_tunnel_detector import DNSTunnelDetector
from admap_m2.detectors.http_c2_detector import HTTPC2Detector
from admap_m2.detectors.irc_detector import IRCDetector
from admap_m2.detectors.port_scan_detector import PortScanDetector
from admap_m2.detectors.tls_detector import TLSDetector
from admap_m2.models.alert import AlertType
from admap_m2.models.flow import (
    DNSQuery, HTTPRequest, NetworkFlow, Protocol, TLSInfo,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _base_flow(**kwargs) -> NetworkFlow:
    defaults = dict(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=Protocol.TCP,
        first_seen=_now(),
        last_seen=_now(),
        packet_count=10,
    )
    defaults.update(kwargs)
    return NetworkFlow(**defaults)


def test_dns_tunnel_detected_long_queries(test_settings):
    """DNS tunnel détecté sur requêtes longues."""
    now = _now()
    flow = _base_flow(dst_port=53, protocol=Protocol.DNS)
    for i in range(5):
        flow.dns_queries.append(DNSQuery(
            timestamp=now,
            query_name="a" * 35 + f".evil.com",
            query_type="TXT",
        ))
    detector = DNSTunnelDetector(test_settings)
    alerts = detector.detect([flow])
    # Avec min_queries=3 et avg_len >= threshold, doit détecter
    dns_alerts = [a for a in alerts if a.alert_type == AlertType.DNS_TUNNEL]
    assert len(dns_alerts) >= 1


def test_dns_tunnel_no_alert_short_queries(test_settings):
    """Pas de tunnel DNS si requêtes courtes."""
    now = _now()
    flow = _base_flow(dst_port=53, protocol=Protocol.DNS)
    for i in range(5):
        flow.dns_queries.append(DNSQuery(
            timestamp=now, query_name=f"google.com", query_type="A"
        ))
    detector = DNSTunnelDetector(test_settings)
    alerts = detector.detect([flow])
    assert all(a.alert_type != AlertType.DNS_TUNNEL for a in alerts)


def test_http_c2_suspicious_ua(test_settings):
    """User-Agent python-requests doit déclencher une alerte."""
    now = _now()
    flow = _base_flow(dst_port=80, protocol=Protocol.HTTP)
    flow.http_requests.append(HTTPRequest(
        timestamp=now, method="POST", host="10.0.0.1", uri="/cmd",
        user_agent="python-requests/2.28.0",
    ))
    detector = HTTPC2Detector(test_settings)
    alerts = detector.detect([flow])
    assert len(alerts) >= 1


def test_http_c2_empty_ua(test_settings):
    """User-Agent vide doit déclencher une alerte."""
    now = _now()
    flow = _base_flow(dst_port=80, protocol=Protocol.HTTP)
    flow.http_requests.append(HTTPRequest(
        timestamp=now, method="GET", host="10.0.0.1", uri="/", user_agent="",
    ))
    detector = HTTPC2Detector(test_settings)
    alerts = detector.detect([flow])
    assert len(alerts) >= 1


def test_irc_port_detection(test_settings):
    """Port IRC 6667 doit déclencher une alerte."""
    flow = _base_flow(dst_port=6667, protocol=Protocol.IRC)
    flow.payload_sample = b"NICK bot123\r\nUSER bot 0 * :Bot\r\nJOIN #botnet\r\n"
    detector = IRCDetector(test_settings)
    alerts = detector.detect([flow])
    irc_alerts = [a for a in alerts if a.alert_type == AlertType.IRC_C2]
    assert len(irc_alerts) >= 1


def test_port_scan_detection(test_settings):
    """Scan détecté si une IP touche >= PORT_SCAN_THRESHOLD ports."""
    flows = []
    for port in range(1, 10):  # test_settings.PORT_SCAN_THRESHOLD = 5
        flows.append(_base_flow(src_port=54321, dst_port=port, dst_ip="10.10.10.1"))
    detector = PortScanDetector(test_settings)
    alerts = detector.detect(flows)
    scan_alerts = [a for a in alerts if a.alert_type == AlertType.PORT_SCAN]
    assert len(scan_alerts) >= 1


def test_tls_missing_sni(test_settings):
    """TLS sans SNI doit déclencher une alerte."""
    flow = _base_flow(dst_port=443, protocol=Protocol.TLS)
    object.__setattr__(flow, 'tls_info', TLSInfo(sni=""))
    detector = TLSDetector(test_settings)
    alerts = detector.detect([flow])
    tls_alerts = [a for a in alerts if a.alert_type == AlertType.TLS_SUSPECT]
    assert len(tls_alerts) >= 1


def test_no_alerts_clean_traffic(test_settings):
    """Aucune alerte sur un flux normal (HTTP vers google.com)."""
    now = _now()
    flow = _base_flow(dst_port=80, protocol=Protocol.HTTP)
    flow.http_requests.append(HTTPRequest(
        timestamp=now, method="GET", host="www.google.com", uri="/",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    ))
    detector = HTTPC2Detector(test_settings)
    alerts = detector.detect([flow])
    assert len(alerts) == 0
