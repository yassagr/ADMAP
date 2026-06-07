"""
Module   : tests.unit.test_models
Version  : 1.0.0
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from admap_m2.models.alert import AlertBundle, AlertSeverity, AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow, Protocol
from admap_m2.models.job import AnalysisJob, AnalysisOptions, JobStatus


def test_flow_creation():
    now = datetime.now(timezone.utc)
    flow = NetworkFlow(
        src_ip="192.168.1.1", dst_ip="8.8.8.8",
        src_port=12345, dst_port=53,
        protocol=Protocol.DNS, first_seen=now, last_seen=now,
    )
    assert flow.protocol == Protocol.DNS
    assert flow.packet_count == 0


def test_alert_creation():
    now = datetime.now(timezone.utc)
    alert = C2Alert(
        alert_type=AlertType.DNS_TUNNEL, severity=AlertSeverity.HIGH,
        confidence_score=75, src_ip="192.168.1.1", dst_ip="8.8.8.8",
        src_port=12345, dst_port=53, protocol="udp",
        first_seen=now, last_seen=now, packet_count=100, byte_count=5000,
        description="Test", evidence=["test"],
    )
    assert alert.confidence_score == 75


def test_c2_alert_score_validation_too_high():
    """confidence_score > 100 doit lever ValidationError."""
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        C2Alert(
            alert_type=AlertType.BEACONING, severity=AlertSeverity.HIGH,
            confidence_score=101, src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1234, dst_port=4444, protocol="tcp",
            first_seen=now, last_seen=now, packet_count=1, byte_count=100,
            description="test", evidence=["x"],
        )


def test_c2_alert_is_frozen():
    """C2Alert est frozen — toute mutation doit lever une exception."""
    now = datetime.now(timezone.utc)
    alert = C2Alert(
        alert_type=AlertType.BEACONING, severity=AlertSeverity.HIGH,
        confidence_score=75, src_ip="1.1.1.1", dst_ip="2.2.2.2",
        src_port=1234, dst_port=4444, protocol="tcp",
        first_seen=now, last_seen=now, packet_count=1, byte_count=100,
        description="test", evidence=["x"],
    )
    with pytest.raises(Exception):
        alert.confidence_score = 90  # type: ignore


def test_alert_bundle_empty():
    """AlertBundle sans alertes est valide."""
    bundle = AlertBundle(pcap_filename="test.pcap", pcap_sha256="a" * 64, pcap_size_bytes=0)
    assert len(bundle.alerts) == 0


def test_analysis_options_defaults():
    """Vérification des valeurs par défaut des AnalysisOptions."""
    opts = AnalysisOptions()
    assert opts.enable_beaconing is True
    assert opts.enable_dga is True
    assert opts.min_confidence_threshold == 20
    assert opts.max_pcap_size_mb == 500


def test_analysis_job_default_status():
    """Un nouveau job est en statut QUEUED."""
    job = AnalysisJob(filename="test.pcap", pcap_sha256="a" * 64)
    assert job.status == JobStatus.QUEUED
    assert job.progress == 0


def test_pcap_parser_validates_empty():
    """PCAPParser lève PCAPEmptyError sur fichier vide."""
    from admap_m2.core.exceptions import PCAPEmptyError
    from admap_m2.parsers.pcap_parser import PCAPParser
    parser = PCAPParser()
    with pytest.raises(PCAPEmptyError):
        parser.validate(b"", "test.pcap")


def test_pcap_parser_validates_invalid_magic():
    """PCAPParser lève PCAPParsingError sur magic invalide."""
    from admap_m2.core.exceptions import PCAPParsingError
    from admap_m2.parsers.pcap_parser import PCAPParser
    parser = PCAPParser()
    with pytest.raises(PCAPParsingError):
        parser.validate(b"\x00\x01\x02\x03" + b"\x00" * 20, "test.pcap")
