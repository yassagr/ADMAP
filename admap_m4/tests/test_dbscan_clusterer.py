from __future__ import annotations
import pytest
from admap_m4.core.dbscan_clusterer import ManualDBSCANClusterer
from admap_m4.core.tfidf_vectorizer import ManualTFIDFVectorizer

def test_cluster_normal(settings, sample_profiles):
    vectorizer = ManualTFIDFVectorizer(settings)
    vectors = vectorizer.fit_transform(sample_profiles)
    clusterer = ManualDBSCANClusterer(settings)
    bundle = clusterer.cluster(vectors, sample_profiles, epsilon=0.1, min_samples=2)
    assert bundle.total_clusters == 1
    assert bundle.noise_count == 1
    assert len(bundle.clusters[0].member_profile_ids) == 2

def test_cluster_empty(settings):
    clusterer = ManualDBSCANClusterer(settings)
    bundle = clusterer.cluster([], [])
    assert bundle.total_clusters == 0

def test_cluster_epsilon_zero(settings, sample_profiles):
    vectorizer = ManualTFIDFVectorizer(settings)
    vectors = vectorizer.fit_transform(sample_profiles)
    clusterer = ManualDBSCANClusterer(settings)
    bundle = clusterer.cluster(vectors, sample_profiles, epsilon=0.0, min_samples=2)
    # Epsilon = 0 means sim >= 1.0. Profiles 1 and 2 are identical, but maybe not 100.00%
    # If they are exactly 1.0, they cluster. Otherwise noise.
    # Actually they are exactly identical, so sim = 1.0, they should form 1 cluster.
    assert bundle.total_clusters == 1

def test_cluster_epsilon_one(settings, sample_profiles):
    vectorizer = ManualTFIDFVectorizer(settings)
    vectors = vectorizer.fit_transform(sample_profiles)
    clusterer = ManualDBSCANClusterer(settings)
    bundle = clusterer.cluster(vectors, sample_profiles, epsilon=1.0, min_samples=2)
    # Epsilon = 1.0 means sim >= 0.0. All similarities are >= 0.
    # Therefore, all 3 items form 1 cluster.
    assert bundle.total_clusters == 1
    assert bundle.noise_count == 0

def test_clusterer_name(settings):
    clusterer = ManualDBSCANClusterer(settings)
    assert clusterer.clusterer_name == "ManualDBSCANClusterer"
