"""
Module   : tests.unit.test_flow_builder
Version  : 1.0.0
"""
from __future__ import annotations

import pytest

from admap_m2.parsers.flow_builder import FlowBuilder
from admap_m2.parsers.pcap_parser import PCAPParser


def test_flow_builder_from_minimal_pcap(minimal_pcap_bytes):
    """Construction de flux depuis un PCAP minimal avec DNS."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, ltype in parser.stream_packets(minimal_pcap_bytes):
        builder.process_packet(ts, buf, ltype)
    flows = builder.finalize()
    assert len(flows) >= 1


def test_flow_builder_dns_flows_present(minimal_pcap_bytes):
    """Les flux DNS vers port 53 sont bien reconstruits."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, ltype in parser.stream_packets(minimal_pcap_bytes):
        builder.process_packet(ts, buf, ltype)
    flows = builder.finalize()
    dns_flows = [f for f in flows if f.dst_port == 53]
    assert len(dns_flows) >= 1


def test_flow_builder_dns_extraction(minimal_pcap_bytes):
    """Les noms de domaine DNS sont extraits des flux."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, ltype in parser.stream_packets(minimal_pcap_bytes):
        builder.process_packet(ts, buf, ltype)
    flows = builder.finalize()
    all_queries = [q for f in flows for q in f.dns_queries]
    query_names = [q.query_name for q in all_queries]
    assert any("evil-c2" in name or "payload" in name or "google" in name for name in query_names)


def test_flow_builder_finalize_clears_state(minimal_pcap_bytes):
    """finalize() vide les structures internes."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, ltype in parser.stream_packets(minimal_pcap_bytes):
        builder.process_packet(ts, buf, ltype)
    builder.finalize()
    assert len(builder._flows) == 0
    assert len(builder._completed_flows) == 0


def test_flow_builder_empty_pcap():
    """FlowBuilder sur PCAP sans paquets retourne liste vide."""
    builder = FlowBuilder()
    flows = builder.finalize()
    assert flows == []


def test_flow_builder_beaconing_pcap(beaconing_pcap_bytes):
    """Flux TCP vers port 4444 présents dans PCAP beaconing."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, ltype in parser.stream_packets(beaconing_pcap_bytes):
        builder.process_packet(ts, buf, ltype)
    flows = builder.finalize()
    c2_flows = [f for f in flows if f.dst_port == 4444]
    assert len(c2_flows) >= 1
