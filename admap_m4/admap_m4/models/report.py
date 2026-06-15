from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime, timezone
from typing import Any
from admap_m4.models.cluster import ClusterBundle

class JobStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"

class AnalysisOptions(BaseModel):
    model_config = ConfigDict(frozen=False)

    # Seuils DBSCAN
    dbscan_epsilon: float = Field(default=0.3, ge=0.0, le=1.0)
    dbscan_min_samples: int = Field(default=2, ge=1)

    # Seuils de filtrage TTP
    min_confidence_score: int = Field(default=20, ge=0, le=100)
    min_techniques_per_profile: int = Field(default=1, ge=1)

    # Enrichissements optionnels
    include_yara_tags: bool = True
    include_ioc_enrichment: bool = True

    # Export
    export_format: list[str] = Field(default_factory=lambda: ["json"])

class APTMapReport(BaseModel):
    """Rapport final M4."""
    model_config = ConfigDict(frozen=True)

    report_id: str
    source_bundle_id: str
    cluster_bundle: ClusterBundle
    mitre_coverage: dict[str, list[str]] = Field(
        description="Tactique -> liste de techniques couvertes"
    )
    top_techniques: list[tuple[str, int]] = Field(
        description="Technique -> fréquence, triées desc"
    )
    top_tactics: list[tuple[str, int]]
    campaign_count: int
    noise_count: int
    analysis_duration_seconds: float
    options_used: AnalysisOptions
    created_at: datetime
    version: str = "1.0.0"

class AnalysisJob(BaseModel):
    """Suivi d'un job asynchrone M4."""
    model_config = ConfigDict(frozen=False)

    job_id: str
    status: JobStatus = JobStatus.pending
    alert_bundle_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    result: APTMapReport | None = None
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)
    metadata: dict[str, Any] = Field(default_factory=dict) # Needed to pass json data in worker.py
