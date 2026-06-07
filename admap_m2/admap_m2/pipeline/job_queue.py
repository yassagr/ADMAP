"""
Module   : admap_m2.pipeline.job_queue
Version  : 1.0.0
Dépend   : [asyncio, admap_m2.models.job, admap_m2.models.alert,
            admap_m2.pipeline.orchestrator, admap_m2.core.exceptions]
"""
from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from uuid import UUID

from admap_m2.core.config import get_settings
from admap_m2.core.exceptions import JobNotFoundError
from admap_m2.core.logging import get_logger
from admap_m2.models.alert import AlertBundle
from admap_m2.models.job import AnalysisJob, AnalysisOptions, JobStatus
from admap_m2.pipeline.orchestrator import AnalysisPipeline


class JobQueue:
    """
    File d'attente asynchrone pour les analyses PCAP.
    Utilise asyncio.Queue avec sentinel None pour arrêt propre des workers.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._logger = get_logger("pipeline.job_queue")
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=self._settings.MAX_QUEUE_SIZE)
        self._jobs: dict[UUID, AnalysisJob] = {}
        self._results: dict[UUID, AlertBundle] = {}
        self._file_data_store: dict[UUID, bytes] = {}
        self._workers: list[asyncio.Task] = []

    def start_workers(self, num_workers: int = 1) -> None:
        """
        Démarre les workers asynchrones (synchrone, appelle asyncio.create_task).

        Args:
            num_workers: Nombre de workers à démarrer.
        """
        for i in range(num_workers):
            task = asyncio.create_task(self._worker_loop(i))
            self._workers.append(task)
        self._logger.info("job_workers_started", count=num_workers)

    async def stop_workers(self) -> None:
        """Arrête les workers via le sentinel None (poison pill)."""
        for _ in self._workers:
            await self._queue.put(None)
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        self._logger.info("job_workers_stopped")

    def submit_job(
        self, filename: str, file_bytes: bytes, options: AnalysisOptions
    ) -> AnalysisJob:
        """
        Soumet un job d'analyse à la file d'attente.

        Args:
            filename: Nom du fichier PCAP.
            file_bytes: Contenu brut du PCAP.
            options: Options d'analyse.

        Returns:
            L'AnalysisJob créé (status=QUEUED).
        """
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        job = AnalysisJob(filename=filename, pcap_sha256=sha256, options=options)
        self._jobs[job.job_id] = job
        self._file_data_store[job.job_id] = file_bytes
        self._queue.put_nowait(job)
        self._logger.info("job_submitted", job_id=str(job.job_id), filename=filename)
        return job

    def get_job_status(self, job_id: UUID) -> AnalysisJob:
        """
        Retourne le statut d'un job.

        Args:
            job_id: UUID du job.

        Returns:
            L'AnalysisJob correspondant.

        Raises:
            JobNotFoundError: Si le job n'existe pas.
        """
        if job_id not in self._jobs:
            raise JobNotFoundError(f"Job {job_id} not found", "JOB_NOT_FOUND")
        return self._jobs[job_id]

    def get_job_result(self, job_id: UUID) -> AlertBundle | None:
        """
        Retourne l'AlertBundle résultat d'un job complété.

        Args:
            job_id: UUID du job.

        Returns:
            AlertBundle ou None si pas encore disponible.
        """
        job = self.get_job_status(job_id)
        if job.status == JobStatus.COMPLETED and job.result_bundle_id:
            return self._results.get(job.result_bundle_id)
        return None

    def cancel_job(self, job_id: UUID) -> bool:
        """
        Annule un job en attente ou en cours.

        Args:
            job_id: UUID du job.

        Returns:
            True si annulé, False si déjà terminé/introuvable.
        """
        if job_id in self._jobs:
            job = self._jobs[job_id]
            if job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
                object.__setattr__(job, 'status', JobStatus.CANCELLED)
                return True
        return False

    async def _worker_loop(self, worker_id: int) -> None:
        """Boucle principale d'un worker."""
        while True:
            item = await self._queue.get()
            if item is None:  # Sentinel poison pill
                self._queue.task_done()
                break
            job: AnalysisJob = item
            if job.status == JobStatus.CANCELLED:
                self._cleanup(job.job_id)
                self._queue.task_done()
                continue

            object.__setattr__(job, 'status', JobStatus.RUNNING)
            object.__setattr__(job, 'started_at', datetime.now(timezone.utc))

            def progress_cb(pct: int, stage: str) -> None:
                object.__setattr__(job, 'progress', pct)
                object.__setattr__(job, 'current_stage', stage)

            try:
                pipeline = AnalysisPipeline(options=job.options)
                file_bytes = self._file_data_store.get(job.job_id, b"")
                bundle = await pipeline.run(file_bytes, job.filename, progress_cb)
                self._results[bundle.bundle_id] = bundle
                object.__setattr__(job, 'result_bundle_id', bundle.bundle_id)
                object.__setattr__(job, 'status', JobStatus.COMPLETED)
                object.__setattr__(job, 'progress', 100)
                self._logger.info(
                    "job_completed",
                    job_id=str(job.job_id),
                    alerts=len(bundle.alerts),
                )
            except Exception as e:
                object.__setattr__(job, 'status', JobStatus.FAILED)
                object.__setattr__(job, 'error', str(e))
                self._logger.error("job_failed", job_id=str(job.job_id), error=str(e))
            finally:
                object.__setattr__(job, 'completed_at', datetime.now(timezone.utc))
                self._cleanup(job.job_id)
                self._queue.task_done()

    def _cleanup(self, job_id: UUID) -> None:
        """Libère les données binaires du PCAP après traitement."""
        self._file_data_store.pop(job_id, None)

    @property
    def queue_size(self) -> int:
        """Taille actuelle de la file d'attente."""
        return self._queue.qsize()
