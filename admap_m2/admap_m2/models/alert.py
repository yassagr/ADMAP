"""
Module   : admap_m2.models.alert
Version  : 1.0.0
Dépend   : [pydantic]
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AlertSeverity(str, Enum):
    CRITICAL = "critical"   # score 80-100 : C2 actif confirmé
    HIGH     = "high"       # score 60-79  : très probable C2
    MEDIUM   = "medium"     # score 40-59  : suspect
    LOW      = "low"        # score 20-39  : anomalie faible
    INFO     = "info"       # score 0-19   : informatif seulement


class AlertType(str, Enum):
    BEACONING       = "beaconing"       # Intervalles réguliers suspects
    DNS_TUNNEL      = "dns_tunnel"      # Tunneling DNS
    DGA             = "dga"             # Domain Generation Algorithm
    HTTP_C2         = "http_c2"         # C2 via HTTP/HTTPS
    TLS_SUSPECT     = "tls_suspect"     # TLS avec certificat/JA3 suspect
    IRC_C2          = "irc_c2"          # C2 via IRC
    PORT_SCAN       = "port_scan"       # Reconnaissance réseau
    IOC_MATCH       = "ioc_match"       # Correspondance avec IOC M1
    LARGE_UPLOAD    = "large_upload"    # Exfiltration données
    CUSTOM_PROTOCOL = "custom_protocol" # Protocole binaire suspect


class C2Alert(BaseModel):
    """Alerte C2 détectée — résultat principal de M2."""

    model_config = ConfigDict(frozen=True)

    id: UUID = Field(default_factory=uuid4)
    alert_type: AlertType
    severity: AlertSeverity
    confidence_score: int           # 0-100
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str                   # "TCP" | "UDP" | "DNS" | "HTTP" | ...
    first_seen: datetime
    last_seen: datetime
    packet_count: int
    byte_count: int
    description: str                # Description humaine de l'alerte
    evidence: list[str]             # Preuves techniques (audit trail)
    ioc_matches: list[str] = Field(default_factory=list)  # IOC M1 correspondants
    metadata: dict[str, object] = Field(default_factory=dict)  # Données spécifiques

    @field_validator("confidence_score")
    @classmethod
    def validate_score(cls, v: int) -> int:
        if not 0 <= v <= 100:
            raise ValueError("confidence_score must be between 0 and 100")
        return v


class AlertBundle(BaseModel):
    """Résultat complet d'une analyse M2 — contrat d'interface principal."""

    bundle_id: UUID = Field(default_factory=uuid4)
    pcap_filename: str
    pcap_sha256: str
    pcap_size_bytes: int
    analysis_duration_ms: int = 0
    total_packets: int = 0
    total_flows: int = 0
    alerts: list[C2Alert] = Field(default_factory=list)
    # Statistiques globales
    alerts_by_type: dict[str, int] = Field(default_factory=dict)
    alerts_by_severity: dict[str, int] = Field(default_factory=dict)
    top_suspicious_ips: list[str] = Field(default_factory=list)
    # Corrélation M1
    m1_bundle_id: str | None = None   # UUID de l'IOCBundle M1 utilisé
    ioc_hits: int = 0                  # Nombre de flux matchant des IOCs M1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    pipeline_version: str = "1.0.0"
