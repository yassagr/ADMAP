"""
Module   : tests.unit.test_flow_builder
Version  : 1.0.0
Dépend   : [pytest, struct, admap_m2.parsers.flow_builder, admap_m2.parsers.pcap_parser]
"""
from __future__ import annotations

import struct

import pytest

from admap_m2.models.flow import Protocol
from admap_m2.parsers.flow_builder import FlowBuilder
from admap_m2.parsers.pcap_parser import PCAPParser


def test_flow_builder_from_minimal_pcap(minimal_pcap_bytes: bytes) -> None:
    """FlowBuilder reconstruit au moins un flux depuis le PCAP minimal."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, link_type in parser.stream_packets(minimal_pcap_bytes):
        builder.process_packet(ts, buf, link_type)
    flows = builder.finalize()
    assert len(flows) >= 1


def test_flow_builder_dns_extraction(minimal_pcap_bytes: bytes) -> None:
    """Les requêtes DNS sont correctement extraites des paquets UDP/53."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, link_type in parser.stream_packets(minimal_pcap_bytes):
        builder.process_packet(ts, buf, link_type)
    flows = builder.finalize()
    dns_flows = [f for f in flows if f.dst_port == 53]
    assert len(dns_flows) >= 1
    all_queries = [q for f in dns_flows for q in f.dns_queries]
    assert len(all_queries) > 0


def test_flow_builder_protocol_detection(minimal_pcap_bytes: bytes) -> None:
    """Le protocole DNS est correctement assigné aux flux sur port 53."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, link_type in parser.stream_packets(minimal_pcap_bytes):
        builder.process_packet(ts, buf, link_type)
    flows = builder.finalize()
    dns_flows = [f for f in flows if f.dst_port == 53]
    for f in dns_flows:
        assert f.protocol == Protocol.DNS


def test_flow_builder_finalize_clears_state(minimal_pcap_bytes: bytes) -> None:
    """Un deuxième appel à finalize() retourne une liste vide."""
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, link_type in parser.stream_packets(minimal_pcap_bytes):
        builder.process_packet(ts, buf, link_type)
    _ = builder.finalize()
    second = builder.finalize()
    assert second == []


def test_flow_builder_empty_pcap() -> None:
    """Un PCAP sans paquets (header seul) retourne 0 flux."""
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    parser = PCAPParser()
    builder = FlowBuilder()
    for ts, buf, link_type in parser.stream_packets(header):
        builder.process_packet(ts, buf, link_type)
    flows = builder.finalize()
    assert flows == []
