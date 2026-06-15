from __future__ import annotations
import pytest
from datetime import datetime, timezone
from admap_m4.core.mitre_mapper import MITREMapper
from admap_m4.models.cluster import ClusterBundle, CampaignCluster

def test_map_coverage(settings):
    cluster_bundle = ClusterBundle(
        bundle_id="1", source_bundle_id="1", total_profiles=1, total_clusters=1, noise_count=0,
        noise_profile_ids=[], created_at=datetime.now(timezone.utc),
        clusters=[
            CampaignCluster(
                cluster_id="c1", cluster_label=0, member_profile_ids=[], dominant_techniques=["T1071", "T1048"],
                dominant_tactics=[], confidence_score=50, involved_ips=[], yara_tags=[],
                first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc)
            )
        ]
    )
    mapper = MITREMapper(settings)
    coverage = mapper.map_coverage(cluster_bundle)
    assert "command-and-control" in coverage
    assert "T1071" in coverage["command-and-control"]
    assert "exfiltration" in coverage
    assert "T1048" in coverage["exfiltration"]

def test_mapper_name(settings):
    mapper = MITREMapper(settings)
    assert mapper.mapper_name == "MITREMapper"
