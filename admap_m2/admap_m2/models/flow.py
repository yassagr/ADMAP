"""
Module   : admap_m2.models.flow
Version  : 1.0.0
Dépend   : [pydantic]
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Protocol(str, Enum):
    TCP  = "tcp"
    UDP  = "udp"
    ICMP = "icmp"
    DNS  = "dns"    # UDP/53 ou TCP/53
    HTTP = "http"   # TCP/80
    TLS  = "tls"    # TCP/443
    IRC  = "irc"    # TCP/6667, 6668, 6669, 7000
    FTP  = "ftp"
    SMTP = "smtp"
    OTHER = "other"


class DNSQuery(BaseModel):
    """Requête DNS extraite d'un flux."""
    timestamp: datetime
    query_name: str
    query_type: str      # A, AAAA, MX, TXT, CNAME...
    response_ips: list[str] = Field(default_factory=list)
    ttl: int = 0
    is_nxdomain: bool = False


class HTTPRequest(BaseModel):
    """Requête HTTP extraite d'un flux."""
    timestamp: datetime
    method: str          # GET, POST, PUT...
    host: str
    uri: str
    user_agent: str = ""
    content_length: int = 0
    headers: dict[str, str] = Field(default_factory=dict)


class TLSInfo(BaseModel):
    """Informations TLS extraites d'une session."""
    sni: str = ""                    # Server Name Indication
    ja3: str = ""                    # JA3 fingerprint client
    ja3s: str = ""                   # JA3S fingerprint serveur
    cert_issuer: str = ""
    cert_subject: str = ""
    cert_san: list[str] = Field(default_factory=list)
    cert_validity_days: int = 0
    cipher_suite: str = ""


class NetworkFlow(BaseModel):
    """Flux réseau reconstruit depuis un PCAP."""

    flow_id: UUID = Field(default_factory=uuid4)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    first_seen: datetime
    last_seen: datetime
    duration_ms: int = 0
    packet_count: int = 0
    byte_count_src_to_dst: int = 0
    byte_count_dst_to_src: int = 0

    # Données temporelles pour beaconing
    inter_packet_intervals: list[float] = Field(default_factory=list)

    # Données applicatives
    dns_queries: list[DNSQuery] = Field(default_factory=list)
    http_requests: list[HTTPRequest] = Field(default_factory=list)
    tls_info: TLSInfo | None = None

    # Flags TCP
    has_syn: bool = False
    has_fin: bool = False
    has_rst: bool = False

    # Données brutes pour analyse avancée
    payload_sample: bytes | None = None   # Premiers 256 bytes du payload
    payload_entropy: float = 0.0


class FlowStats(BaseModel):
    """Statistiques globales sur l'ensemble des flux."""
    total_flows: int = 0
    tcp_flows: int = 0
    udp_flows: int = 0
    dns_queries_total: int = 0
    http_requests_total: int = 0
    tls_sessions_total: int = 0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_dst_ports: int = 0
    top_dst_ips: list[tuple[str, int]] = Field(default_factory=list)  # (ip, count)
    top_dst_ports: list[tuple[int, int]] = Field(default_factory=list)  # (port, count)
