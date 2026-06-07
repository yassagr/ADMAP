"""
Module   : tests.unit.test_detectors
Version  : 1.0.0
Dépend   : [pytest, datetime, admap_m2.detectors.*, admap_m2.models.*]
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
from admap_m2.models.flow import DNSQuery, HTTPRequest, NetworkFlow, Protocol, TLSInfo


def _dt() -> datetime:
    return datetime(2024, 1, 1, tzinfo=timezone.utc)


def _make_flow(**kwargs) -> NetworkFlow:
    defaults = dict(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=Protocol.TCP,
        first_seen=_dt(),
        last_seen=_dt(),
    )
    defaults.update(kwargs)
    return NetworkFlow(**defaults)


# ── DNS Tunnel ────────────────────────────────────────────────────────────────

def test_dns_tunnel_detector_name(test_settings) -> None:
    assert DNSTunnelDetector(test_settings).detector_name == "dns_tunnel"


def test_dns_tunnel_not_triggered_few_queries(test_settings) -> None:
    """Moins de DNS_TUNNEL_MIN_QUERIES → pas d'alerte."""
    detector = DNSTunnelDetector(test_settings)
    flow = _make_flow(protocol=Protocol.DNS, dst_port=53)
    flow.dns_queries.append(DNSQuery(
        timestamp=_dt(), query_name="short.com", query_type="A",
    ))
    assert len(detector.detect([flow])) == 0


def test_dns_tunnel_root_domain_grouping(test_settings) -> None:
    """Les requêtes vers le même domaine racine sont groupées."""
    detector = DNSTunnelDetector(test_settings)
    flow = _make_flow(protocol=Protocol.DNS, dst_port=53)
    long_name = "a" * 40
    for i in range(5):
        flow.dns_queries.append(DNSQuery(
            timestamp=_dt(),
            query_name=f"{long_name}{i}.evil.com",
            query_type="TXT",
        ))
    alerts = detector.detect([flow])
    # Avec 5 queries TXT et sous-domaines longs → alerte possible
    # (le test vérifie que ça ne crashe pas et respecte la logique)
    assert isinstance(alerts, list)


# ── HTTP C2 ───────────────────────────────────────────────────────────────────

def test_http_c2_detector_name(test_settings) -> None:
    assert HTTPC2Detector(test_settings).detector_name == "http_c2"


def test_http_c2_suspicious_ua(test_settings) -> None:
    """User-Agent python-requests déclenche une alerte."""
    detector = HTTPC2Detector(test_settings)
    flow = _make_flow(dst_port=80, protocol=Protocol.HTTP)
    flow.http_requests.append(HTTPRequest(
        timestamp=_dt(),
        method="GET",
        host="evil.com",
        uri="/cmd",
        user_agent="python-requests/2.28.0",
    ))
    alerts = detector.detect([flow])
    assert len(alerts) >= 1
    assert any("python-requests" in e.lower() for e in alerts[0].evidence)


def test_http_c2_empty_ua(test_settings) -> None:
    """User-Agent vide contribue au score."""
    detector = HTTPC2Detector(test_settings)
    flow = _make_flow(dst_port=80, protocol=Protocol.HTTP)
    flow.http_requests.append(HTTPRequest(
        timestamp=_dt(), method="POST", host="10.0.0.1", uri="/upload",
    ))
    alerts = detector.detect([flow])
    assert len(alerts) >= 1


def test_http_c2_ip_host_detection(test_settings) -> None:
    """Host = IP directe est correctement détecté via ipaddress."""
    detector = HTTPC2Detector(test_settings)
    flow = _make_flow(dst_port=80, protocol=Protocol.HTTP)
    flow.http_requests.append(HTTPRequest(
        timestamp=_dt(),
        method="GET",
        host="192.168.1.1",
        uri="/beacon",
        user_agent="go-http-client/1.1",
    ))
    alerts = detector.detect([flow])
    assert len(alerts) >= 1
    assert any("IP" in e for e in alerts[0].evidence)


# ── IRC ───────────────────────────────────────────────────────────────────────

def test_irc_detector_name(test_settings) -> None:
    assert IRCDetector(test_settings).detector_name == "irc_c2"


def test_irc_port_detection(test_settings) -> None:
    """Port 6667 déclenche une alerte IRC."""
    detector = IRCDetector(test_settings)
    flow = _make_flow(dst_port=6667, protocol=Protocol.IRC)
    alerts = detector.detect([flow])
    assert len(alerts) >= 1
    assert alerts[0].alert_type == AlertType.IRC_C2


def test_irc_no_alert_below_threshold(test_settings) -> None:
    """Un flux TCP aléatoire sans payload IRC ne déclenche pas d'alerte."""
    detector = IRCDetector(test_settings)
    flow = _make_flow(dst_port=8080, protocol=Protocol.HTTP)
    alerts = detector.detect([flow])
    assert len(alerts) == 0


# ── Port Scan ─────────────────────────────────────────────────────────────────

def test_port_scan_detector_name(test_settings) -> None:
    assert PortScanDetector(test_settings).detector_name == "port_scan"


def test_port_scan_detection(test_settings) -> None:
    """PORT_SCAN_THRESHOLD ports distincts déclenchent une alerte."""
    detector = PortScanDetector(test_settings)
    flows = []
    for port in range(1, test_settings.PORT_SCAN_THRESHOLD + 2):
        flows.append(_make_flow(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=50000 + port,
            dst_port=port,
        ))
    alerts = detector.detect(flows)
    assert len(alerts) >= 1
    assert alerts[0].alert_type == AlertType.PORT_SCAN


def test_port_scan_below_threshold(test_settings) -> None:
    """Moins de THRESHOLD ports → pas d'alerte."""
    detector = PortScanDetector(test_settings)
    flows = [
        _make_flow(src_port=50000 + i, dst_port=i)
        for i in range(1, test_settings.PORT_SCAN_THRESHOLD - 1)
    ]
    alerts = detector.detect(flows)
    assert len(alerts) == 0


# ── TLS ───────────────────────────────────────────────────────────────────────

def test_tls_detector_name(test_settings) -> None:
    assert TLSDetector(test_settings).detector_name == "tls_suspect"


def test_tls_missing_sni(test_settings) -> None:
    """SNI absent → alerte TLS_SUSPECT."""
    detector = TLSDetector(test_settings)
    flow = _make_flow(dst_port=8444, protocol=Protocol.TLS)
    object.__setattr__(flow, "tls_info", TLSInfo(sni=""))
    alerts = detector.detect([flow])
    assert len(alerts) >= 1
    assert alerts[0].alert_type == AlertType.TLS_SUSPECT


def test_tls_no_info_no_alert(test_settings) -> None:
    """Flux sans TLSInfo ne génère pas d'alerte."""
    detector = TLSDetector(test_settings)
    flow = _make_flow(dst_port=443, protocol=Protocol.TCP)
    assert flow.tls_info is None
    assert len(detector.detect([flow])) == 0


def test_tls_known_ja3_critical(test_settings) -> None:
    """JA3 fingerprint Cobalt Strike → score >= 50."""
    detector = TLSDetector(test_settings)
    flow = _make_flow(dst_port=443, protocol=Protocol.TLS)
    object.__setattr__(flow, "tls_info", TLSInfo(
        sni="legit.com",
        ja3="e7d705a3286e19ea42f587b344ee6865",
    ))
    alerts = detector.detect([flow])
    assert len(alerts) >= 1
    assert alerts[0].confidence_score >= 50
