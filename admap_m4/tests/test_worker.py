from __future__ import annotations
import pytest
import asyncio
from admap_m4.worker import AsyncWorker
from admap_m4.models.report import AnalysisJob, JobStatus, AnalysisOptions

@pytest.mark.asyncio
async def test_worker_process_job(settings, sample_alert_bundle_json):
    queue = asyncio.Queue()
    job_id = "test_job_1"
    jobs = {
        job_id: AnalysisJob(
            job_id=job_id,
            options=AnalysisOptions(),
            metadata={"alert_bundle_json": sample_alert_bundle_json}
        )
    }
    worker = AsyncWorker(queue, jobs, settings)
    
    await worker._process_job(job_id)
    assert jobs[job_id].status == JobStatus.completed
    assert jobs[job_id].result is not None

@pytest.mark.asyncio
async def test_worker_process_invalid_job(settings):
    queue = asyncio.Queue()
    job_id = "test_job_2"
    jobs = {
        job_id: AnalysisJob(
            job_id=job_id,
            options=AnalysisOptions(),
            metadata={"alert_bundle_json": "invalid json"}
        )
    }
    worker = AsyncWorker(queue, jobs, settings)
    
    await worker._process_job(job_id)
    assert jobs[job_id].status == JobStatus.failed
    assert jobs[job_id].error_message is not None
