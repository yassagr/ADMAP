"""
Module   : admap_m2.tests.integration.test_pipeline
Version  : 1.0.0
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from admap_m2.pipeline.orchestrator import AnalysisPipeline
from admap_m2.models.job import AnalysisJob

def test_pipeline_initialization(test_settings):
    pipeline = AnalysisPipeline(test_settings)
    assert len(pipeline.detectors) == 7
    assert len(pipeline.correlators) == 2

def test_pipeline_run_empty(test_settings, minimal_pcap_bytes):
    pipeline = AnalysisPipeline(test_settings)
    job = AnalysisJob(filename="test.pcap", pcap_sha256="1234")
    bundle = pipeline.run(job, minimal_pcap_bytes)
    assert bundle.total_packets == 0
    assert bundle.total_flows == 0
    assert len(bundle.alerts) == 0
