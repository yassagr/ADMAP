"""
Module   : admap_m1.tests.unit.test_exporters
"""
from __future__ import annotations

import json
from unittest.mock import patch

from admap_m1.exporters.cytomic_exporter import CytomicExporter
from admap_m1.exporters.misp_exporter import MISPExporter
from admap_m1.exporters.openioc_exporter import OpenIOCExporter
from admap_m1.exporters.stix_exporter import STIXExporter, STIX2_AVAILABLE
from admap_m1.models.ioc import AnalysisStats, IOC, IOCBundle, IOCConfidenceLevel, IOCType


def _get_dummy_bundle(sample_metadata) -> IOCBundle:
    ioc1 = IOC(
        type=IOCType.URL,
        value="http://evil.com",
        value_defanged="hxxp[://]evil[.]com",
        confidence_score=85,
        confidence_level=IOCConfidenceLevel.CONFIRMED,
        context_snippet="",
        extraction_method="regex"
    )
    return IOCBundle(
        metadata=sample_metadata,
        iocs=[ioc1],
        analysis_stats=AnalysisStats()
    )


def test_misp_exporter(sample_metadata):
    """Test du format MISP Event JSON."""
    bundle = _get_dummy_bundle(sample_metadata)
    exporter = MISPExporter()
    
    output = exporter.export(bundle)
    data = json.loads(output)
    
    assert "Event" in data
    assert "Attribute" in data["Event"]
    
    # 1 attribut pour le hash du fichier (si dispo) + 1 pour l'IOC
    attributes = data["Event"]["Attribute"]
    assert len(attributes) >= 1
    
    url_attrs = [a for a in attributes if a["type"] == "url"]
    assert len(url_attrs) == 1
    assert url_attrs[0]["value"] == "http://evil.com"
    assert url_attrs[0]["to_ids"] is True  # Score 85 >= 60


def test_cytomic_exporter(sample_metadata):
    """Test du format Cytomic Orion."""
    bundle = _get_dummy_bundle(sample_metadata)
    exporter = CytomicExporter()
    
    output = exporter.export(bundle)
    data = json.loads(output)
    
    assert "Indicators" in data
    assert len(data["Indicators"]) == 1
    
    ind = data["Indicators"][0]
    assert ind["Type"] == "Url"
    assert ind["Action"] == "Block" # Confirmed = Block


def test_openioc_exporter(sample_metadata):
    """Test du format OpenIOC."""
    bundle = _get_dummy_bundle(sample_metadata)
    exporter = OpenIOCExporter()
    
    output = exporter.export(bundle)
    
    # Simple vérification textuelle pour l'XML
    assert "http://openioc.org/schemas/OpenIOC_1.1" in output
    assert "IndicatorItem" in output
    assert "http://evil.com" in output


def test_stix_exporter(sample_metadata):
    """Test du format STIX 2.1."""
    if not STIX2_AVAILABLE:
        return # Skip test
        
    bundle = _get_dummy_bundle(sample_metadata)
    exporter = STIXExporter()
    
    output = exporter.export(bundle)
    data = json.loads(output)
    
    assert data["type"] == "bundle"
    assert "objects" in data
    
    # On devrait avoir Identity, Malware, File, Indicator, Relationship
    types = [obj["type"] for obj in data["objects"]]
    assert "indicator" in types
    
    indicators = [obj for obj in data["objects"] if obj["type"] == "indicator"]
    assert len(indicators) == 1
    assert "pattern" in indicators[0]
    assert "http://evil.com" in indicators[0]["pattern"]
