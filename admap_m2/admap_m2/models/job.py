"""
Module   : admap_m2.models.job
Version  : 1.0.0
Dépend   : [pydantic]
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    QUEUED    = "queued"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class AnalysisOptions(BaseModel):
    # Détecteurs à activer (tous actifs par défaut)
    enable_beaconing: bool = True
    enable_dga: bool = True
    enable_dns_tunnel: bool = True
    enable_http_c2: bool = True
    enable_tls: bool = True
    enable_irc: bool = True
    enable_port_scan: bool = True
    # Corrélation M1
    m1_bundle_path: str | None = None   # Chemin vers IOCBundle JSON M1
    # Seuils
    min_confidence_threshold: int = Field(default=20, ge=0, le=100)
    beaconing_min_occurrences: int = Field(default=5, ge=3)
    dga_entropy_threshold: float = Field(default=3.5, ge=0.0, le=8.0)
    dns_tunnel_query_length_threshold: int = Field(default=50, ge=20)
    # Limites de sécurité
    max_pcap_size_mb: int = Field(default=500, ge=1, le=2000)
    max_flows: int = Field(default=100000, ge=100)
    analysis_timeout_seconds: int = Field(default=300, ge=10)


class AnalysisJob(BaseModel):
    job_id: UUID = Field(default_factory=uuid4)
    filename: str
    pcap_sha256: str
    status: JobStatus = JobStatus.QUEUED
    progress: int = Field(default=0, ge=0, le=100)
    current_stage: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    result_bundle_id: UUID | None = None
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)
