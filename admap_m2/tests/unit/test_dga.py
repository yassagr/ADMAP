"""
Module   : tests.unit.test_dga
Version  : 1.0.0
Dépend   : [pytest, admap_m2.detectors.dga_detector]
"""
from __future__ import annotations

import pytest

from admap_m2.detectors.dga_detector import DGADetector


def test_dga_detector_name(test_settings) -> None:
    """detector_name doit retourner 'dga'."""
    assert DGADetector(test_settings).detector_name == "dga"


def test_dga_high_entropy_domain(test_settings) -> None:
    """Domaine à haute entropie est scoré comme DGA."""
    detector = DGADetector(test_settings)
    score, evidence = detector._score_domain("xk3j9mzqpl7wvnbf2r.ru")
    assert score >= 20
    assert len(evidence) > 0


def test_dga_normal_domain_not_flagged(test_settings) -> None:
    """Un domaine normal (court) retourne score 0."""
    detector = DGADetector(test_settings)
    score, _ = detector._score_domain("google.com")
    assert score == 0


def test_dga_vowel_ratio_evidence(test_settings) -> None:
    """Un label sans voyelles génère une evidence 'vowel'."""
    detector = DGADetector(test_settings)
    score, evidence = detector._score_domain("bcdfghjklmnpqrstvwxyzbc.xyz")
    vowel_evidence = [e for e in evidence if "vowel" in e.lower()]
    assert len(vowel_evidence) > 0


def test_dga_shannon_entropy_uniform(test_settings) -> None:
    """Entropie d'une chaîne uniforme est 0."""
    assert DGADetector._shannon_entropy("aaaa") == 0.0


def test_dga_shannon_entropy_diverse(test_settings) -> None:
    """Entropie d'une chaîne diversifiée est > 2."""
    assert DGADetector._shannon_entropy("abcdefghijklmnop") > 2.5


def test_dga_suspect_tld(test_settings) -> None:
    """Un TLD suspect (.xyz) génère une evidence 'TLD'."""
    detector = DGADetector(test_settings)
    score, evidence = detector._score_domain("xk3j9mzqpl7wvnbf2r.xyz")
    tld_evidence = [e for e in evidence if "TLD" in e]
    assert len(tld_evidence) > 0


def test_dga_short_domain_ignored(test_settings) -> None:
    """Domaine trop court (< DGA_MIN_DOMAIN_LENGTH) n'est pas analysé."""
    detector = DGADetector(test_settings)
    score, evidence = detector._score_domain("abc.ru")
    assert score == 0
    assert evidence == []


def test_dga_analyzes_tld_plus_one(test_settings) -> None:
    """DGA doit analyser le label TLD+1 (parts[-2]), pas parts[0]."""
    detector = DGADetector(test_settings)
    # Sous-domaine court 'sub' + domaine long suspect en TLD+1
    score_sub, _ = detector._score_domain("sub.xk3j9mzqpl7wvnbf2r.com")
    # Le label analysé est 'xk3j9mzqpl7wvnbf2r' (TLD+1), pas 'sub'
    assert score_sub >= 10
