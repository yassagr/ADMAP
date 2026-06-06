"""
Module   : admap_m2.pipeline.job_queue
Version  : 1.0.0
Dépend   : [asyncio, admap_m2.models.job]
"""
from __future__ import annotations

import asyncio
from typing import Any

from admap_m2.core.config import Settings
from admap_m2.core.logging import get_logger
from admap_m2.models.alert import AlertBundle
from admap_m2.models.job import AnalysisJob, JobStatus
from admap_m2.pipeline.orchestrator import AnalysisPipeline


class JobQueue:
    """
    Gère la file d'attente asynchrone pour les analyses PCAP.
    Stocke l'état des jobs et les résultats (AlertBundle).
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        self._logger = get_logger("pipeline.job_queue")
        self.queue: asyncio.Queue[tuple[AnalysisJob, bytes]] = asyncio.Queue(maxsize=settings.MAX_QUEUE_SIZE)
        self.jobs: dict[str, AnalysisJob] = {}
        self.results: dict[str, AlertBundle] = {}
        self.workers: list[asyncio.Task] = []
        self._pipeline = AnalysisPipeline(settings)

    async def start_workers(self, num_workers: int = 1) -> None:
        """Démarre les workers asynchrones."""
        for i in range(num_workers):
            task = asyncio.create_task(self._worker_loop(i))
            self.workers.append(task)
        self._logger.info("job_workers_started", count=num_workers)

    async def stop_workers(self) -> None:
        """Arrête les workers."""
        for task in self.workers:
            task.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        self._logger.info("job_workers_stopped")

    async def enqueue_job(self, job: AnalysisJob, file_bytes: bytes) -> None:
        """Ajoute un job à la file d'attente."""
        self.jobs[str(job.job_id)] = job
        await self.queue.put((job, file_bytes))
        self._logger.info("job_enqueued", job_id=str(job.job_id))

    def get_job(self, job_id: str) -> AnalysisJob | None:
        return self.jobs.get(job_id)

    def get_result(self, bundle_id: str) -> AlertBundle | None:
        return self.results.get(bundle_id)

    async def _worker_loop(self, worker_id: int) -> None:
        while True:
            try:
                job, file_bytes = await self.queue.get()
                await self._process_job(job, file_bytes)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._logger.error("worker_error", worker_id=worker_id, error=str(e))

    async def _process_job(self, job: AnalysisJob, file_bytes: bytes) -> None:
        job.status = JobStatus.RUNNING
        job.started_at = asyncio.get_event_loop().time() # placeholder for datetime
        self._logger.info("job_started", job_id=str(job.job_id))
        
        try:
            # Exécution dans un thread séparé pour ne pas bloquer l'event loop
            bundle = await asyncio.to_thread(self._pipeline.run, job, file_bytes)
            
            job.status = JobStatus.COMPLETED
            job.progress = 100
            job.result_bundle_id = bundle.bundle_id
            
            self.results[str(bundle.bundle_id)] = bundle
            self._logger.info("job_completed", job_id=str(job.job_id), alerts=len(bundle.alerts))
            
        except Exception as e:
            job.status = JobStatus.FAILED
            job.error = str(e)
            self._logger.error("job_failed", job_id=str(job.job_id), error=str(e))
