from __future__ import annotations
import pytest
from admap_m5.core.pipeline import AttributionPipeline
from admap_m5.models.input import AttributionOptions


def test_pipeline_init_default():
    pipeline = AttributionPipeline()
    assert pipeline._settings is not None
    assert pipeline._options is not None


@pytest.mark.asyncio
async def test_pipeline_run_basic(sample_apt_map_report_json, settings):
    pipeline = AttributionPipeline(settings=settings)
    report = await pipeline.run(sample_apt_map_report_json)
    assert report is not None
    assert report.total_clusters_analyzed >= 1


@pytest.mark.asyncio
async def test_pipeline_report_has_results(sample_apt_map_report_json, settings):
    pipeline = AttributionPipeline(settings=settings)
    report = await pipeline.run(sample_apt_map_report_json)
    assert len(report.results) >= 1


@pytest.mark.asyncio
async def test_pipeline_candidates_ranked(sample_apt_map_report_json, settings):
    pipeline = AttributionPipeline(settings=settings)
    report = await pipeline.run(sample_apt_map_report_json)
    assert len(report.results[0].candidates) > 0
    assert report.results[0].candidates[0].rank == 1


@pytest.mark.asyncio
async def test_pipeline_top_k_respected(sample_apt_map_report_json, settings):
    options = AttributionOptions(top_k=1)
    pipeline = AttributionPipeline(settings=settings, options=options)
    report = await pipeline.run(sample_apt_map_report_json)
    for result in report.results:
        assert len(result.candidates) <= 1


@pytest.mark.asyncio
async def test_pipeline_with_ioc_bundle(sample_apt_map_report_json, sample_ioc_bundle_json, settings):
    pipeline = AttributionPipeline(settings=settings)
    report = await pipeline.run(sample_apt_map_report_json, ioc_bundle_json=sample_ioc_bundle_json)
    assert report is not None
    assert len(report.results) >= 1


@pytest.mark.asyncio
async def test_pipeline_confidence_score_range(sample_apt_map_report_json, settings):
    pipeline = AttributionPipeline(settings=settings)
    report = await pipeline.run(sample_apt_map_report_json)
    for result in report.results:
        for candidate in result.candidates:
            assert 0 <= candidate.confidence_score <= 100


@pytest.mark.asyncio
async def test_pipeline_cosine_only_mode(sample_apt_map_report_json, settings):
    options = AttributionOptions(use_xgboost=False, use_cosine_similarity=True)
    pipeline = AttributionPipeline(settings=settings, options=options)
    report = await pipeline.run(sample_apt_map_report_json)
    for result in report.results:
        assert result.analysis_method == "cosine_only"


@pytest.mark.asyncio
async def test_pipeline_source_report_id_preserved(sample_apt_map_report_json, settings):
    pipeline = AttributionPipeline(settings=settings)
    report = await pipeline.run(sample_apt_map_report_json)
    assert report.source_report_id == "test-report-001"
