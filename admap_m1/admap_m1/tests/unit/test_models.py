"""
Module   : admap_m1.tests.unit.test_models
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from admap_m1.models.ioc import IOC, IOCConfidenceLevel, IOCType, RawIOC


def test_raw_ioc_creation():
    """Test de la création d'un RawIOC."""
    raw = RawIOC(
        type=IOCType.IPV4,
        value="192.168.1.1",
        context_snippet="connect to 192.168.1.1:80",
        extraction_method="regex_text",
        source_offset=11
    )
    assert raw.type == IOCType.IPV4
    assert raw.value == "192.168.1.1"
    assert raw.in_decoded_layer is False


def test_ioc_validation():
    """Test de la validation stricte d'un IOC finalisé."""
    ioc = IOC(
        type=IOCType.DOMAIN,
        value="evil.com",
        value_defanged="evil[.]com",
        confidence_score=85,
        confidence_level=IOCConfidenceLevel.CONFIRMED,
        context_snippet="download from evil.com",
        extraction_method="pe_section"
    )
    assert ioc.confidence_score == 85
    
    # Test validator: score hors limites
    with pytest.raises(ValidationError):
        IOC(
            type=IOCType.DOMAIN,
            value="evil.com",
            value_defanged="evil[.]com",
            confidence_score=150,  # Invalide
            confidence_level=IOCConfidenceLevel.CONFIRMED,
            context_snippet="download from evil.com",
            extraction_method="pe_section"
        )

def test_ioc_immutability():
    """Test que l'IOC est gelé (frozen) par défaut via ConfigDict."""
    ioc = IOC(
        type=IOCType.DOMAIN,
        value="evil.com",
        value_defanged="evil[.]com",
        confidence_score=85,
        confidence_level=IOCConfidenceLevel.CONFIRMED,
        context_snippet="download from evil.com",
        extraction_method="pe_section"
    )
    
    with pytest.raises(ValidationError):
        ioc.confidence_score = 90
