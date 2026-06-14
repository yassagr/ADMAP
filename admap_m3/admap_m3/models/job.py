"""
Module   : admap_m3.models.job
Version  : 1.0.0
Dépend   : [pydantic]

Modèle de job asynchrone pour la génération de règles YARA.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class GenerationStatus(str, Enum):
    """Statuts possibles d'un job de génération."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class GenerationJob(BaseModel):
    """Job de génération de règles YARA.

    Ce modèle est *mutable* (pas frozen) car le statut, les horodatages
    et l'erreur sont mis à jour au fil du cycle de vie du job.

    Attributes:
        job_id: Identifiant unique du job.
        status: Statut courant du job.
        corpus_id: Identifiant du corpus (assigné au lancement).
        ruleset_id: Identifiant du ruleset produit (assigné à la fin).
        created_at: Horodatage de création.
        started_at: Horodatage de démarrage effectif.
        completed_at: Horodatage de fin (succès ou échec).
        error: Message d'erreur en cas d'échec.
        progress_pct: Pourcentage de progression (0-100).
        status_url: URL de consultation du statut.
        result_url: URL du résultat (assignée à la fin).
    """

    job_id: str
    status: GenerationStatus = GenerationStatus.PENDING
    corpus_id: str | None = None
    ruleset_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    progress_pct: int = 0
    status_url: str
    result_url: str | None = None
