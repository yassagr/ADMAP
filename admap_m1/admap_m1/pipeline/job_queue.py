"""
Module   : admap_m1.pipeline.job_queue
Version  : 3.0.0
Dépend   : [asyncio, admap_m1.models.job, admap_m1.pipeline.orchestrator]

File d'attente asynchrone des jobs d'analyse pour le Worker M1.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from admap_m1.core.config import get_settings
from admap_m1.core.exceptions import JobNotFoundError
from admap_m1.core.logging import get_logger
from admap_m1.models.ioc import IOCBundle
from admap_m1.models.job import AnalysisJob, AnalysisOptions, JobStatus
from admap_m1.pipeline.orchestrator import AnalysisPipeline


class JobQueue:
    """Gestionnaire asynchrone des jobs d'analyse.

    Implémente un pattern Producer-Consumer via asyncio.Queue.
    Permet à l'API de rester non-bloquante pendant les analyses longues.
    """

    def __init__(self) -> None:
        self.settings = get_settings()
        self._logger = get_logger("pipeline.job_queue")
        
        self._queue: asyncio.Queue[AnalysisJob] = asyncio.Queue(maxsize=self.settings.MAX_QUEUE_SIZE)
        self._jobs: dict[UUID, AnalysisJob] = {}
        self._results: dict[UUID, IOCBundle] = {}
        self._workers: list[asyncio.Task] = []
        
        # Structure pour stocker temporairement le fichier binaire (en RAM pour l'instant)
        self._file_data_store: dict[UUID, bytes] = {}

    def start_workers(self, num_workers: int = 1) -> None:
        """Démarre les workers en arrière-plan."""
        if not self._workers:
            for i in range(num_workers):
                task = asyncio.create_task(self._worker_loop(i))
                self._workers.append(task)
            self._logger.info("job_workers_started", count=num_workers)

    async def stop_workers(self) -> None:
        """Arrête proprement tous les workers."""
        for _ in self._workers:
            await self._queue.put(None)  # Type: ignore (Poison pill)
        
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        self._logger.info("job_workers_stopped")

    def submit_job(
        self,
        filename: str,
        file_bytes: bytes,
        options: AnalysisOptions
    ) -> AnalysisJob:
        """Soumet un nouveau job dans la file d'attente.

        Args:
            filename: Nom original du fichier.
            file_bytes: Contenu binaire.
            options: Options de l'analyse (VT, deobf, etc.).

        Returns:
            Le job créé.

        Raises:
            asyncio.QueueFull: Si la file est pleine.
        """
        import hashlib
        file_hash = hashlib.sha256(file_bytes).hexdigest()

        job = AnalysisJob(
            filename=filename,
            file_hash_sha256=file_hash,
            options=options,
        )

        self._jobs[job.job_id] = job
        self._file_data_store[job.job_id] = file_bytes
        
        # put_nowait lève QueueFull si maxsize est atteint
        self._queue.put_nowait(job)
        self._logger.info("job_submitted", job_id=str(job.job_id), filename=filename)
        
        return job

    def get_job_status(self, job_id: UUID) -> AnalysisJob:
        """Récupère l'état d'un job."""
        if job_id not in self._jobs:
            raise JobNotFoundError(f"Job {job_id} introuvable")
        return self._jobs[job_id]

    def get_job_result(self, job_id: UUID) -> IOCBundle | None:
        """Récupère le bundle résultat si le job est terminé."""
        job = self.get_job_status(job_id)
        if job.status == JobStatus.COMPLETED and job.result_bundle_id:
            return self._results.get(job.result_bundle_id)
        return None

    def cancel_job(self, job_id: UUID) -> bool:
        """Marque un job comme annulé.
        Le worker vérifiera ce statut pour s'interrompre si possible.
        """
        if job_id in self._jobs:
            job = self._jobs[job_id]
            if job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
                job.status = JobStatus.CANCELLED
                self._logger.info("job_cancelled", job_id=str(job_id))
                return True
        return False

    async def _worker_loop(self, worker_id: int) -> None:
        """Boucle de consommation des jobs."""
        self._logger.debug("worker_loop_started", worker_id=worker_id)
        
        while True:
            job = await self._queue.get()
            
            if job is None:  # Poison pill
                self._queue.task_done()
                break

            # Si annulé entre-temps
            if job.status == JobStatus.CANCELLED:
                self._cleanup_job_data(job.job_id)
                self._queue.task_done()
                continue

            # Démarrer le job
            job.status = JobStatus.RUNNING
            job.started_at = datetime.now(timezone.utc)
            self._logger.info("job_started", job_id=str(job.job_id), worker_id=worker_id)

            def progress_cb(progress: int, stage: str):
                job.progress = progress
                job.current_stage = stage
                if job.status == JobStatus.CANCELLED:
                    raise asyncio.CancelledError("Job cancelled by user")

            try:
                pipeline = AnalysisPipeline(options=job.options)
                file_bytes = self._file_data_store.get(job.job_id, b"")
                
                bundle = await pipeline.run(
                    file_bytes=file_bytes,
                    file_path=Path(job.filename),
                    progress_callback=progress_cb
                )

                # Succès
                self._results[bundle.bundle_id] = bundle
                job.result_bundle_id = bundle.bundle_id
                job.status = JobStatus.COMPLETED
                job.progress = 100
                job.current_stage = "Analyse terminée"

            except asyncio.CancelledError:
                self._logger.info("job_aborted", job_id=str(job.job_id))
                # Le statut est déjà CANCELLED

            except Exception as e:
                self._logger.exception("job_failed", job_id=str(job.job_id), error=str(e))
                job.status = JobStatus.FAILED
                job.error = str(e)
                job.current_stage = "Erreur critique"

            finally:
                job.completed_at = datetime.now(timezone.utc)
                self._cleanup_job_data(job.job_id)
                self._queue.task_done()

    def _cleanup_job_data(self, job_id: UUID) -> None:
        """Libère la mémoire binaire du job."""
        if job_id in self._file_data_store:
            del self._file_data_store[job_id]

# Instance globale (Singleton pattern pour FastAPI)
_job_queue_instance: JobQueue | None = None

def get_job_queue() -> JobQueue:
    global _job_queue_instance
    if _job_queue_instance is None:
        _job_queue_instance = JobQueue()
    return _job_queue_instance
