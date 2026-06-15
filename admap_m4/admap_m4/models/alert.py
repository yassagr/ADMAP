from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, ConfigDict
from datetime import datetime
from typing import Any

class AlertType(str, Enum):
    beaconing = "beaconing"
    dns_tunnel = "dns_tunnel"
    dga = "dga"
    http_c2 = "http_c2"
    tls_suspect = "tls_suspect"
    irc_c2 = "irc_c2"
    port_scan = "port_scan"
    ioc_match = "ioc_match"
    large_upload = "large_upload"
    custom_protocol = "custom_protocol"

class AlertSeverity(str, Enum):
    critical = "critical"  # score >= 80
    high = "high"          # score >= 60
    medium = "medium"      # score >= 40
    low = "low"            # score >= 20
    info = "info"          # score < 20

class C2Alert(BaseModel):
    model_config = ConfigDict(frozen=True)
    alert_type: AlertType
    severity: AlertSeverity
    confidence_score: int  # 0-100
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_seen: datetime
    last_seen: datetime
    evidence: list[str]
    ioc_matches: list[str]
    metadata: dict[str, Any]

class AlertBundle(BaseModel):
    bundle_id: str
    pcap_filename: str
    pcap_sha256: str
    alerts: list[C2Alert]
    alerts_by_type: dict[str, int]
    alerts_by_severity: dict[str, int]
    top_suspicious_ips: list[str]
    m1_bundle_id: str | None
    ioc_hits: int
