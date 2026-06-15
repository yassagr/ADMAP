from __future__ import annotations
import pytest
from admap_m4.models.report import APTMapReport

@pytest.mark.asyncio
async def test_pipeline_run(pipeline, sample_alert_bundle_json):
    report = await pipeline.run(sample_alert_bundle_json)
    assert isinstance(report, APTMapReport)
    assert report.campaign_count >= 0
    assert report.source_bundle_id == "test-bundle-001"

@pytest.mark.asyncio
async def test_pipeline_invalid_json(pipeline):
    with pytest.raises(ValueError):
        await pipeline.run("invalid json")
