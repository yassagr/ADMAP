"""
Module   : admap_m3.api.worker
Version  : 1.0.0
Dépend   : [asyncio, structlog, fastapi]

Worker asynchrone consommant la job queue pour exécuter le
``GenerationPipeline`` en arrière-plan.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import FastAPI

from admap_m3.config import get_settings
from admap_m3.core.pipeline import GenerationPipeline
from admap_m3.models.job import GenerationJob, GenerationStatus
from admap_m3.models.rule import YaraRuleSet

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


async def job_worker(app: FastAPI) -> None:
    """Boucle infinie consommant ``app.state.job_queue``.

    Pour chaque job :
    1. Mettre ``status = RUNNING``, ``started_at = now``.
    2. Appeler ``await GenerationPipeline().run(...)``.
    3. Mettre ``status = COMPLETED``, stocker le ``YaraRuleSet``.
    4. En cas d'exception : ``status = FAILED``, ``error = str(e)``.

    Respecte ``settings.max_concurrent_jobs`` via un ``asyncio.Semaphore``.
    """
    settings = get_settings()
    semaphore: asyncio.Semaphore = asyncio.Semaphore(settings.max_concurrent_jobs)

    logger.info(
        "job_worker_started",
        max_concurrent_jobs=settings.max_concurrent_jobs,
    )

    while True:
        try:
            job_data: dict[str, Any] = await app.state.job_queue.get()
        except asyncio.CancelledError:
            logger.info("job_worker_cancelled")
            return

        # Lancer le traitement avec le sémaphore
        asyncio.create_task(_process_job(app, job_data, semaphore))


async def _process_job(
    app: FastAPI,
    job_data: dict[str, Any],
    semaphore: asyncio.Semaphore,
) -> None:
    """Traite un job individuel sous le contrôle du sémaphore."""
    job_id: str = job_data["job_id"]
    jobs: dict[str, GenerationJob] = app.state.jobs

    if job_id not in jobs:
        logger.error("job_not_found_in_store", job_id=job_id)
        return

    job: GenerationJob = jobs[job_id]

    # Vérifier si le job a été annulé avant le démarrage
    if job.status == GenerationStatus.CANCELLED:
        logger.info("job_already_cancelled", job_id=job_id)
        return

    async with semaphore:
        # 1. RUNNING
        job.status = GenerationStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        job.progress_pct = 10

        logger.info("job_started", job_id=job_id)

        try:
            # 2. Exécuter le pipeline
            settings = get_settings()
            pipeline: GenerationPipeline = GenerationPipeline(settings=settings)

            ruleset: YaraRuleSet = await pipeline.run(
                malware_paths=job_data["malware_paths"],
                benign_paths=job_data["benign_paths"],
                corpus_id=job_data["corpus_id"],
                m1_bundle_path=job_data.get("m1_bundle_path"),
                malware_family=job_data.get("malware_family"),
                mitre_attack=job_data.get("mitre_attack"),
            )

            # 3. COMPLETED
            job.status = GenerationStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            job.progress_pct = 100
            job.ruleset_id = ruleset.ruleset_id
            job.result_url = f"/api/v1/jobs/{job_id}/result"

            # Stocker le résultat
            app.state.results[job_id] = ruleset

            logger.info(
                "job_completed",
                job_id=job_id,
                ruleset_id=ruleset.ruleset_id,
                total_rules=ruleset.total_rules,
                compiled_rules=ruleset.compiled_rules,
                duration_ms=ruleset.generation_duration_ms,
            )

        except Exception as exc:
            # 4. FAILED
            job.status = GenerationStatus.FAILED
            job.completed_at = datetime.now(timezone.utc)
            job.error = str(exc)

            logger.error(
                "job_failed",
                job_id=job_id,
                error=str(exc),
                exc_info=True,
            )
