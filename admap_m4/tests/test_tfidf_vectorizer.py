from __future__ import annotations
import pytest
from datetime import datetime
from admap_m4.core.tfidf_vectorizer import ManualTFIDFVectorizer
from admap_m4.models.ttp import TTPProfile, TTPVector

def test_fit_transform(settings, sample_profiles):
    vectorizer = ManualTFIDFVectorizer(settings)
    vectors = vectorizer.fit_transform(sample_profiles)
    assert len(vectors) == 3
    assert vectors[0].profile_id == "1"
    assert vectors[2].profile_id == "3"

def test_transform_before_fit(settings, sample_profiles):
    vectorizer = ManualTFIDFVectorizer(settings)
    with pytest.raises(RuntimeError):
        vectorizer.transform(sample_profiles)

def test_cosine_similarity():
    v1 = TTPVector(profile_id="1", vector={"T1": 0.5, "T2": 0.5}, norm=0.707)
    v2 = TTPVector(profile_id="2", vector={"T1": 0.5, "T2": 0.5}, norm=0.707)
    sim = ManualTFIDFVectorizer.cosine_similarity(v1, v2)
    assert pytest.approx(sim, 0.1) == 1.0

def test_cosine_similarity_orthogonal():
    v1 = TTPVector(profile_id="1", vector={"T1": 1.0}, norm=1.0)
    v2 = TTPVector(profile_id="2", vector={"T2": 1.0}, norm=1.0)
    sim = ManualTFIDFVectorizer.cosine_similarity(v1, v2)
    assert sim == 0.0

def test_empty_corpus(settings):
    vectorizer = ManualTFIDFVectorizer(settings)
    vectorizer.fit([])
    vectors = vectorizer.transform([])
    assert len(vectors) == 0

def test_vectorizer_name(settings):
    vectorizer = ManualTFIDFVectorizer(settings)
    assert vectorizer.vectorizer_name == "ManualTFIDFVectorizer"
