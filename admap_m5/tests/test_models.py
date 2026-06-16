from __future__ import annotations
import pytest
from datetime import datetime, timezone
from pydantic import ValidationError
from admap_m5.models.input import AttributionOptions, AttributionRequest
from admap_m5.models.output import APTCandidate, AttributionResult, AttributionReport
from admap_m5.models.job import AttributionJob, JobStatus


# ── AttributionOptions ────────────────────────────────────────────────────────

def test_attribution_options_defaults():
    opts = AttributionOptions()
    assert opts.top_k == 3
    assert opts.min_confidence == 10.0
    assert opts.use_cosine_similarity is True
    assert opts.use_xgboost is True
    assert opts.include_noise_clusters is False


def test_attribution_options_top_k_bounds():
    with pytest.raises(ValidationError):
        AttributionOptions(top_k=0)
    with pytest.raises(ValidationError):
        AttributionOptions(top_k=11)


def test_attribution_options_min_confidence_bounds():
    with pytest.raises(ValidationError):
        AttributionOptions(min_confidence=-1.0)
    with pytest.raises(ValidationError):
        AttributionOptions(min_confidence=101.0)


def test_attribution_options_frozen():
    opts = AttributionOptions()
    with pytest.raises(Exception):
        opts.top_k = 5  # type: ignore[misc]


# ── AttributionRequest ────────────────────────────────────────────────────────

def test_attribution_request_valid(sample_apt_map_report_json):
    req = AttributionRequest(apt_map_report_json=sample_apt_map_report_json)
    assert req.ioc_bundle_json is None
    assert req.alert_bundle_json is None


def test_attribution_request_invalid_json():
    with pytest.raises(ValidationError):
        AttributionRequest(apt_map_report_json="{invalid}")


def test_attribution_request_missing_cluster_bundle():
    import json
    with pytest.raises(ValidationError):
        AttributionRequest(apt_map_report_json=json.dumps({"report_id": "x"}))


# ── APTCandidate ──────────────────────────────────────────────────────────────

def test_apt_candidate_frozen():
    candidate = APTCandidate(
        rank=1,
        apt_name="APT28",
        apt_id="G0007",
        confidence_score=72.5,
        xgb_probability=0.6,
        cosine_similarity=0.8,
        matched_techniques=["T1071"],
        matched_tactics=["command-and-control"],
        matched_yara_tags=["apt28"],
        matched_ips=[],
        evidence_summary="Techniques: T1071",
        mitre_group_url="https://attack.mitre.org/groups/G0007/",
    )
    with pytest.raises(Exception):
        candidate.rank = 2  # type: ignore[misc]


def test_apt_candidate_fields():
    candidate = APTCandidate(
        rank=1,
        apt_name="APT28",
        apt_id="G0007",
        confidence_score=72.5,
        xgb_probability=0.6,
        cosine_similarity=0.8,
        matched_techniques=["T1071"],
        matched_tactics=["command-and-control"],
        matched_yara_tags=[],
        matched_ips=[],
        evidence_summary="test",
        mitre_group_url="https://attack.mitre.org/groups/G0007/",
    )
    assert candidate.apt_id == "G0007"
    assert candidate.apt_name == "APT28"
    assert candidate.confidence_score == 72.5


# ── AttributionResult ─────────────────────────────────────────────────────────

def test_attribution_result_frozen():
    result = AttributionResult(
        cluster_id="c1",
        cluster_label=0,
        candidates=[],
        feature_vector_size=50,
        analysis_method="cosine_only",
    )
    with pytest.raises(Exception):
        result.cluster_id = "c2"  # type: ignore[misc]


def test_attribution_result_fields():
    result = AttributionResult(
        cluster_id="cluster-001",
        cluster_label=0,
        candidates=[],
        feature_vector_size=100,
        analysis_method="xgboost+cosine",
    )
    assert result.cluster_id == "cluster-001"
    assert result.analysis_method == "xgboost+cosine"
    assert result.feature_vector_size == 100


# ── AttributionReport ─────────────────────────────────────────────────────────

def test_attribution_report_version_default():
    report = AttributionReport(
        report_id="r1",
        source_report_id="m4-r1",
        results=[],
        top_global_candidate=None,
        total_clusters_analyzed=0,
        noise_clusters_skipped=0,
        analysis_duration_seconds=0.1,
        options_used={},
    )
    assert report.version == "1.0.0"
    assert report.module == "M5-Attribution"


def test_attribution_report_frozen(sample_attribution_report):
    with pytest.raises(Exception):
        sample_attribution_report.report_id = "other"  # type: ignore[misc]


# ── AttributionJob ────────────────────────────────────────────────────────────

def test_attribution_job_default_status():
    job = AttributionJob(job_id="j1")
    assert job.status == JobStatus.PENDING
    assert job.progress == 0
    assert job.result is None
    assert job.error_message is None


def test_attribution_job_frozen():
    job = AttributionJob(job_id="j1")
    with pytest.raises(Exception):
        job.status = JobStatus.RUNNING  # type: ignore[misc]


def test_job_status_enum_values():
    assert JobStatus.PENDING == "pending"
    assert JobStatus.RUNNING == "running"
    assert JobStatus.COMPLETED == "completed"
    assert JobStatus.FAILED == "failed"
    assert JobStatus.CANCELLED == "cancelled"


def test_attribution_job_progress_bounds():
    with pytest.raises(ValidationError):
        AttributionJob(job_id="j1", progress=-1)
    with pytest.raises(ValidationError):
        AttributionJob(job_id="j1", progress=101)
