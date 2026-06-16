from __future__ import annotations
from datetime import datetime, timezone
import structlog

from admap_m5.config import M5Settings
from admap_m5.core.pipeline import AttributionPipeline
from admap_m5.models.input import AttributionOptions
from admap_m5.models.job import AttributionJob, JobStatus

logger = structlog.get_logger(__name__)


async def run_attribution_job(
    job_id: str,
    jobs: dict,
    apt_map_report_json: str,
    ioc_bundle_json: str | None,
    alert_bundle_json: str | None,
    options: AttributionOptions,
    settings: M5Settings,
) -> None:
    """Worker asynchrone — exécute un job d'attribution et met à jour jobs[job_id]."""
    job: AttributionJob = jobs[job_id]
    jobs[job_id] = job.model_copy(
        update={
            "status": JobStatus.RUNNING,
            "started_at": datetime.now(timezone.utc),
            "progress": 10,
        }
    )

    try:
        pipeline = AttributionPipeline(settings=settings, options=options)
        report = await pipeline.run(
            apt_map_report_json=apt_map_report_json,
            ioc_bundle_json=ioc_bundle_json,
            alert_bundle_json=alert_bundle_json,
            options=options,
        )

        jobs[job_id] = jobs[job_id].model_copy(
            update={
                "status": JobStatus.COMPLETED,
                "completed_at": datetime.now(timezone.utc),
                "result": report,
                "progress": 100,
            }
        )
        logger.info("worker.job_completed", job_id=job_id)

    except Exception as exc:
        logger.error("worker.job_failed", job_id=job_id, error=str(exc))
        jobs[job_id] = jobs[job_id].model_copy(
            update={
                "status": JobStatus.FAILED,
                "completed_at": datetime.now(timezone.utc),
                "error_message": str(exc),
                "progress": 0,
            }
        )
