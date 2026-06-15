from __future__ import annotations
import asyncio
import structlog
from datetime import datetime
from admap_m4.config import Settings
from admap_m4.models.report import AnalysisJob, JobStatus
from admap_m4.core.pipeline import AnalysisPipeline

class AsyncWorker:
    """Consomme la job queue et exécute le pipeline M4."""

    def __init__(
        self,
        queue: asyncio.Queue,
        jobs: dict[str, AnalysisJob],
        settings: Settings,
    ) -> None:
        self._queue = queue
        self._jobs = jobs
        self._settings = settings
        self._log = structlog.get_logger(self.__class__.__name__)

    async def run(self) -> None:
        """Boucle principale du worker."""
        self._log.info("worker_started")
        while True:
            try:
                job_id: str = await self._queue.get()
                await self._process_job(job_id)
            except asyncio.CancelledError:
                self._log.info("worker_cancelled")
                break
            except Exception as e:
                self._log.error("worker_unhandled_error", error=str(e))
            finally:
                try:
                    self._queue.task_done()
                except Exception:
                    pass

    async def _process_job(self, job_id: str) -> None:
        """Traite un job individuel."""
        job = self._jobs.get(job_id)
        if job is None:
            self._log.warning("job_not_found", job_id=job_id)
            return

        job.status = JobStatus.running
        job.started_at = datetime.utcnow()
        self._log.info("job_started", job_id=job_id)

        try:
            pipeline = AnalysisPipeline(settings=self._settings, options=job.options)
            result = await pipeline.run(
                alert_bundle_json=job.metadata.get("alert_bundle_json", "{}"),
                ioc_bundle_json=job.metadata.get("ioc_bundle_json"),
                yara_ruleset_json=job.metadata.get("yara_ruleset_json"),
            )
            job.result = result
            job.status = JobStatus.completed
            job.completed_at = datetime.utcnow()
            self._log.info("job_completed", job_id=job_id)
        except Exception as e:
            job.status = JobStatus.failed
            job.error_message = str(e)
            job.completed_at = datetime.utcnow()
            self._log.error("job_failed", job_id=job_id, error=str(e))
