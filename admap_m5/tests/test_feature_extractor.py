from __future__ import annotations
import json
import pytest
from admap_m5.core.feature_extractor import FeatureExtractor


def test_extract_basic(sample_apt_map_report_json):
    extractor = FeatureExtractor()
    features = extractor.extract(sample_apt_map_report_json)
    assert len(features) == 1


def test_extract_techniques(sample_apt_map_report_json):
    extractor = FeatureExtractor()
    features = extractor.extract(sample_apt_map_report_json)
    assert features[0].techniques == ["T1071", "T1059"]


def test_extract_excludes_noise_by_default(sample_apt_map_report_json):
    data = json.loads(sample_apt_map_report_json)
    data["cluster_bundle"]["clusters"][0]["cluster_label"] = -1
    extractor = FeatureExtractor()
    features = extractor.extract(json.dumps(data))
    assert len(features) == 0


def test_extract_includes_noise_when_flag(sample_apt_map_report_json):
    data = json.loads(sample_apt_map_report_json)
    data["cluster_bundle"]["clusters"][0]["cluster_label"] = -1
    extractor = FeatureExtractor()
    features = extractor.extract(json.dumps(data), include_noise=True)
    assert len(features) == 1


def test_extract_with_ioc_bundle(sample_apt_map_report_json, sample_ioc_bundle_json):
    extractor = FeatureExtractor()
    features = extractor.extract(sample_apt_map_report_json, ioc_bundle_json=sample_ioc_bundle_json)
    assert len(features[0].sha256_hashes) > 0
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in features[0].sha256_hashes


def test_extract_with_alert_bundle(sample_apt_map_report_json):
    alert_bundle = json.dumps({
        "alerts": [{"alert_type": "c2_beacon"}],
        "top_suspicious_ips": ["1.1.1.1"]
    })
    extractor = FeatureExtractor()
    features = extractor.extract(sample_apt_map_report_json, alert_bundle_json=alert_bundle)
    assert len(features[0].alert_types) > 0
    assert "c2_beacon" in features[0].alert_types


def test_extract_invalid_json():
    extractor = FeatureExtractor()
    with pytest.raises(ValueError):
        extractor.extract("{invalid json")


def test_to_token_list(sample_apt_map_report_json):
    extractor = FeatureExtractor()
    features = extractor.extract(sample_apt_map_report_json)
    tokens = features[0].to_token_list()
    assert len(tokens) > 0
    assert "T1071" in tokens
    assert "apt28" in tokens
