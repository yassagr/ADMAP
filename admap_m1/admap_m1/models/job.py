"""
Module   : admap_m1.models.job
Version  : 3.0.0
Dépend   : [pydantic, admap_m1.models.ioc]

Modèles pour le système de jobs d'analyse asynchrone.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    """Statut d'un job d'analyse dans la queue."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AnalysisOptions(BaseModel):
    """Options de configuration pour une analyse M1.

    Transmises via l'API ou le CLI pour paramétrer le pipeline.
    """

    enable_vt_enrichment: bool = False
    vt_api_key: str | None = None
    vt_max_per_type: int = Field(default=5, ge=1, le=50)
    enable_deobfuscation: bool = True
    max_recursion_depth: int = Field(default=3, ge=1, le=10)
    export_formats: list[str] = Field(default_factory=list)
    min_confidence_threshold: int = Field(default=20, ge=0, le=100)


class AnalysisJob(BaseModel):
    """Job d'analyse dans la queue asynchrone.

    Suivi du cycle de vie complet : QUEUED → RUNNING → COMPLETED/FAILED/CANCELLED.
    """

    job_id: UUID = Field(default_factory=uuid4)
    filename: str
    file_hash_sha256: str
    status: JobStatus = JobStatus.QUEUED
    progress: int = Field(default=0, ge=0, le=100)
    current_stage: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    result_bundle_id: UUID | None = None
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)
