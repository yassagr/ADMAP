from __future__ import annotations
import pytest
from admap_m4.core.ttp_extractor import TTPExtractor
from admap_m4.config import Settings

def test_extract_valid_bundle(sample_alert_bundle, settings):
    extractor = TTPExtractor(settings)
    profiles = extractor.extract(sample_alert_bundle)
    assert len(profiles) == 3
    assert profiles[0].alert_type == "beaconing"
    assert "T1071" in profiles[0].techniques

def test_extract_empty_bundle(settings):
    extractor = TTPExtractor(settings)
    profiles = extractor.extract({})
    assert len(profiles) == 0

def test_extract_below_confidence_score():
    s = Settings(min_confidence_score=85)
    extractor = TTPExtractor(s)
    bundle = {
        "alerts": [
            {"alert_type": "beaconing", "confidence_score": 80, "first_seen": "2024-01-01T00:00:00Z"},
            {"alert_type": "dns_tunnel", "confidence_score": 90, "first_seen": "2024-01-01T00:00:00Z"}
        ]
    }
    profiles = extractor.extract(bundle)
    assert len(profiles) == 1
    assert profiles[0].alert_type == "dns_tunnel"

def test_extract_unknown_alert_type(settings):
    extractor = TTPExtractor(settings)
    bundle = {
        "alerts": [
            {"alert_type": "unknown_type", "confidence_score": 100, "first_seen": "2024-01-01T00:00:00Z"}
        ]
    }
    profiles = extractor.extract(bundle)
    assert len(profiles) == 0

def test_extract_yara_tags(sample_alert_bundle, settings):
    extractor = TTPExtractor(settings)
    yara_ruleset = {
        "rules": [
            {"tags": ["ransomware", "apt29"]},
            {"tags": ["apt29", "windows"]}
        ]
    }
    profiles = extractor.extract(sample_alert_bundle, yara_ruleset)
    assert len(profiles) == 3
    assert "ransomware" in profiles[0].yara_tags
    assert "apt29" in profiles[0].yara_tags
    assert "windows" in profiles[0].yara_tags

def test_extractor_name(settings):
    extractor = TTPExtractor(settings)
    assert extractor.extractor_name == "TTPExtractor"
