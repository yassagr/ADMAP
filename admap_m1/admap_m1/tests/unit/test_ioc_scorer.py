"""
Module   : admap_m1.tests.unit.test_ioc_scorer
"""
from __future__ import annotations

from admap_m1.heuristics.context_analyzer import ContextAnalyzer
from admap_m1.heuristics.ioc_scorer import IOCScorer
from admap_m1.models.ioc import IOCConfidenceLevel, IOCType, RawIOC


def test_context_analyzer(sample_metadata):
    """Test de l'extraction des tags contextuels."""
    # 1. Près d'un verbe d'exécution
    raw1 = RawIOC(
        type=IOCType.URL,
        value="http://evil.com",
        context_snippet="download from http://evil.com and execute it",
        extraction_method="regex"
    )
    flags1 = ContextAnalyzer.analyze(raw1, sample_metadata)
    assert "near_execution_verb" in flags1

    # 2. Dans un layer décodé
    raw2 = RawIOC(
        type=IOCType.DOMAIN,
        value="bad.com",
        in_decoded_layer=True,
        extraction_method="regex"
    )
    flags2 = ContextAnalyzer.analyze(raw2, sample_metadata)
    assert "in_decoded_layer" in flags2

    # 3. Import PE bénin
    raw3 = RawIOC(
        type=IOCType.DOMAIN, # on feinte un peu, disons STRING
        value="VirtualAlloc",
        extraction_method="regex"
    )
    flags3 = ContextAnalyzer.analyze(raw3, sample_metadata)
    assert "is_pe_import" in flags3


def test_ioc_scorer():
    """Test du calcul de confiance."""
    # Base URL = 60
    raw_url = RawIOC(type=IOCType.URL, value="http://evil.com", extraction_method="regex")
    
    # 1. URL sans contexte -> 60 (HIGH)
    score, level, _ = IOCScorer.score(raw_url, [])
    assert score == 60
    assert level == IOCConfidenceLevel.HIGH
    
    # 2. URL + in_decoded_layer (+25) -> 85 (CONFIRMED)
    score, level, _ = IOCScorer.score(raw_url, ["in_decoded_layer"])
    assert score == 85
    assert level == IOCConfidenceLevel.CONFIRMED
    
    # 3. Base IP = 40
    raw_ip = RawIOC(type=IOCType.IPV4, value="8.8.8.8", extraction_method="regex")
    score, level, _ = IOCScorer.score(raw_ip, ["is_pe_import"]) # -30 -> 10 (NOISE)
    assert score == 10
    assert level == IOCConfidenceLevel.NOISE

    # 4. RFC1918 -> 0
    raw_priv = RawIOC(type=IOCType.IPV4, value="10.0.0.1", extraction_method="regex")
    score, level, _ = IOCScorer.score(raw_priv, ["near_execution_verb"]) # Modificateurs ignorés
    assert score == 0
