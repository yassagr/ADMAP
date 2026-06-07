"""
Module   : tests.conftest
Version  : 1.0.0
Dépend   : [pytest, dpkt, struct, socket, datetime,
            admap_m2.core.config, admap_m2.models.alert, admap_m2.models.flow]
"""
from __future__ import annotations

import socket
import struct
from datetime import datetime, timezone

import dpkt
import pytest

from admap_m2.core.config import Settings
from admap_m2.models.alert import AlertBundle, AlertSeverity, AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow, Protocol


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Settings de test avec seuils bas pour faciliter la détection."""
    return Settings(
        MAX_PCAP_SIZE_MB=10,
        ANALYSIS_TIMEOUT_SECONDS=30,
        BEACONING_MIN_OCCURRENCES=3,
        DGA_ENTROPY_THRESHOLD=3.0,
        DGA_MIN_DOMAIN_LENGTH=8,
        DNS_TUNNEL_QUERY_LENGTH=30,
        DNS_TUNNEL_MIN_QUERIES=3,
        PORT_SCAN_THRESHOLD=5,
        MIN_CONFIDENCE_THRESHOLD=10,
        M1_BUNDLE_DEFAULT_PATH="",
    )


def _make_pcap_global_header() -> bytes:
    """Construit un header PCAP global valide (little-endian, Ethernet)."""
    return struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic little-endian
        2, 4,         # version
        0,            # thiszone
        0,            # sigfigs
        65535,        # snaplen
        1,            # network = Ethernet
    )


def _make_pcap_record(raw_bytes: bytes, ts: float) -> bytes:
    """Enveloppe un paquet brut dans un record PCAP."""
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return (
        struct.pack("<IIII", ts_sec, ts_usec, len(raw_bytes), len(raw_bytes))
        + raw_bytes
    )


def _build_dns_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    query_name: str,
) -> bytes:
    """Construit un paquet Ethernet/IP/UDP/DNS complet."""
    dns = dpkt.dns.DNS(
        id=1234,
        op=dpkt.dns.DNS_RD,
        qd=[dpkt.dns.DNS.Q(name=query_name, type=dpkt.dns.DNS_A)],
    )
    dns_bytes = bytes(dns)
    udp = dpkt.udp.UDP(
        sport=src_port,
        dport=dst_port,
        data=dns_bytes,
        ulen=8 + len(dns_bytes),
    )
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=dpkt.ip.IP_PROTO_UDP,
        data=bytes(udp),
        len=20 + 8 + len(dns_bytes),
    )
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xff\xff\xff\xff\xff\xff",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=bytes(ip),
    )
    return bytes(eth)


def _build_tcp_syn(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
) -> bytes:
    """Construit un paquet Ethernet/IP/TCP SYN."""
    tcp = dpkt.tcp.TCP(
        sport=src_port,
        dport=dst_port,
        flags=dpkt.tcp.TH_SYN,
        seq=12345,
    )
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,
        data=bytes(tcp),
        len=20 + 20,
    )
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55",
        dst=b"\xaa\xbb\xcc\xdd\xee\xff",
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=bytes(ip),
    )
    return bytes(eth)


@pytest.fixture(scope="session")
def minimal_pcap_bytes() -> bytes:
    """
    PCAP valide avec 3 paquets UDP/DNS vers 8.8.8.8:53.
    Contient des domaines suspects et normaux.
    """
    header = _make_pcap_global_header()
    base_ts = 1700000000.0
    packets = b""
    for i, domain in enumerate(["evil-c2.ru", "payload-host.xyz", "google.com"]):
        raw = _build_dns_packet(
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            src_port=12345 + i,
            dst_port=53,
            query_name=domain,
        )
        packets += _make_pcap_record(raw, base_ts + i * 300.0)
    return header + packets


@pytest.fixture(scope="session")
def beaconing_pcap_bytes() -> bytes:
    """
    PCAP avec pattern de beaconing : 20 connexions TCP toutes les 60s
    vers 185.234.100.123:4444 — intervalle régulier = CV très bas.
    """
    header = _make_pcap_global_header()
    base_ts = 1700000000.0
    packets = b""
    for i in range(20):
        raw = _build_tcp_syn(
            src_ip="192.168.1.50",
            dst_ip="185.234.100.123",
            src_port=50000 + i,
            dst_port=4444,
        )
        packets += _make_pcap_record(raw, base_ts + i * 60.0)
    return header + packets


@pytest.fixture
def sample_flow() -> NetworkFlow:
    """Flux réseau TCP de test minimal."""
    return NetworkFlow(
        src_ip="192.168.1.100",
        dst_ip="185.234.100.123",
        src_port=12345,
        dst_port=4444,
        protocol=Protocol.TCP,
        first_seen=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 1, 0, 1, 0, tzinfo=timezone.utc),
        duration_ms=60000,
        packet_count=100,
        byte_count_src_to_dst=5000,
    )


@pytest.fixture
def sample_alert(sample_flow: NetworkFlow) -> C2Alert:
    """Alerte C2 de type BEACONING HIGH pour les tests."""
    return C2Alert(
        alert_type=AlertType.BEACONING,
        severity=AlertSeverity.HIGH,
        confidence_score=75,
        src_ip=sample_flow.src_ip,
        dst_ip=sample_flow.dst_ip,
        src_port=sample_flow.src_port,
        dst_port=sample_flow.dst_port,
        protocol="tcp",
        first_seen=sample_flow.first_seen,
        last_seen=sample_flow.last_seen,
        packet_count=sample_flow.packet_count,
        byte_count=5000,
        description="Test beaconing alert",
        evidence=["Test evidence 1", "Test evidence 2"],
    )


@pytest.fixture
def sample_bundle(sample_alert: C2Alert) -> AlertBundle:
    """AlertBundle de test avec une seule alerte BEACONING HIGH."""
    return AlertBundle(
        pcap_filename="test.pcap",
        pcap_sha256="a" * 64,
        pcap_size_bytes=1024,
        analysis_duration_ms=500,
        total_packets=100,
        total_flows=10,
        alerts=[sample_alert],
        alerts_by_type={"beaconing": 1},
        alerts_by_severity={"high": 1},
    )
