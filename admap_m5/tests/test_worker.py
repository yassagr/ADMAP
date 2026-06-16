from __future__ import annotations
import pytest
from admap_m5.worker.attribution_worker import run_attribution_job
from admap_m5.models.input import AttributionOptions
from admap_m5.models.job import AttributionJob, JobStatus


@pytest.mark.asyncio
async def test_worker_completes_successfully(sample_apt_map_report_json, settings):
    job_id = "job123"
    jobs = {job_id: AttributionJob(job_id=job_id)}
    options = AttributionOptions()
    
    await run_attribution_job(
        job_id, jobs, sample_apt_map_report_json, None, None, options, settings
    )
    
    job = jobs[job_id]
    assert job.status == JobStatus.COMPLETED
    assert job.result is not None


@pytest.mark.asyncio
async def test_worker_handles_invalid_json(settings):
    job_id = "job123"
    jobs = {job_id: AttributionJob(job_id=job_id)}
    options = AttributionOptions()
    
    await run_attribution_job(
        job_id, jobs, "invalid json", None, None, options, settings
    )
    
    job = jobs[job_id]
    assert job.status == JobStatus.FAILED
    assert job.error_message is not None


@pytest.mark.asyncio
async def test_worker_updates_progress(sample_apt_map_report_json, settings):
    job_id = "job123"
    jobs = {job_id: AttributionJob(job_id=job_id)}
    options = AttributionOptions()
    
    await run_attribution_job(
        job_id, jobs, sample_apt_map_report_json, None, None, options, settings
    )
    
    job = jobs[job_id]
    assert job.progress == 100


@pytest.mark.asyncio
async def test_worker_sets_started_at(sample_apt_map_report_json, settings):
    job_id = "job123"
    jobs = {job_id: AttributionJob(job_id=job_id)}
    options = AttributionOptions()
    
    assert jobs[job_id].started_at is None
    
    await run_attribution_job(
        job_id, jobs, sample_apt_map_report_json, None, None, options, settings
    )
    
    job = jobs[job_id]
    # We can't easily capture the middle state directly without mocking, but we know it should be completed.
    # The requirement is that started_at is not None after execution (we can assume it was set).
    # Since it's mutated in place by worker, the final job object won't have started_at set to None 
    # if it updated it properly (the mock update might preserve it if we passed it correctly).
    # Wait, the worker does: jobs[job_id] = jobs[job_id].model_copy(update={"status": RUNNING, "started_at": ...})
    # Then later it does: jobs[job_id] = jobs[job_id].model_copy(update={"status": COMPLETED, "completed_at": ...})
    # model_copy keeps existing values if not updated, so started_at should remain.
    assert job.started_at is not None
