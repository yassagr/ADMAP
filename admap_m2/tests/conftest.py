"""
Module   : tests.conftest
Version  : 1.0.0
"""
import pytest
from admap_m2.core.config import Settings

@pytest.fixture
def test_settings():
    return Settings(
        MAX_PCAP_SIZE_MB=5,
        ANALYSIS_TIMEOUT_SECONDS=10,
        BEACONING_MIN_OCCURRENCES=3,
        DGA_ENTROPY_THRESHOLD=3.0,
        DNS_TUNNEL_QUERY_LENGTH=30,
        PORT_SCAN_THRESHOLD=5,
        M1_BUNDLE_DEFAULT_PATH="",
    )

@pytest.fixture
def minimal_pcap_bytes():
    # PCAP header (24 bytes) + 1 empty packet
    # magic(4), version_major(2), version_minor(2), thiszone(4), sigfigs(4), snaplen(4), network(4)
    header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00"
    return header
