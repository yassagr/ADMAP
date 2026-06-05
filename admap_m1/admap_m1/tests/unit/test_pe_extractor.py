"""
Module   : admap_m1.tests.unit.test_pe_extractor
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from admap_m1.extractors.pe_extractor import PEExtractor


def test_pe_extractor_invalid_pe(sample_metadata):
    """Test fallback vers string extractor si le PE est malformé."""
    extractor = PEExtractor()
    # "MZ" mais structure corrompue
    bad_pe_bytes = b"MZ\x90\x00" + b"\x00" * 100 + b"http://bad.com/payload.exe"
    
    iocs = extractor.extract(bad_pe_bytes, "test.exe", sample_metadata)
    
    # Doit avoir fallback sur string_extractor + regex_extractor
    urls = [ioc.value for ioc in iocs if ioc.type.value == "url"]
    assert "http://bad.com/payload.exe" in urls


@patch("pefile.PE")
def test_pe_extractor_sections(mock_pe_class, sample_metadata):
    """Test l'extraction section par section."""
    extractor = PEExtractor()
    
    # Mocking pefile
    mock_pe = MagicMock()
    mock_section = MagicMock()
    mock_section.Name = b".data\x00"
    mock_section.get_data.return_value = b"some binary data http://evil.com/123 some other data"
    mock_section.PointerToRawData = 1024
    
    mock_pe.sections = [mock_section]
    mock_pe.get_overlay_data_start_offset.return_value = None
    mock_pe_class.return_value = mock_pe
    
    iocs = extractor.extract(b"MZ...", "test.exe", sample_metadata)
    
    assert len(iocs) == 1
    assert iocs[0].value == "http://evil.com/123"
    assert iocs[0].section_name == ".data"
    assert iocs[0].extraction_method == "pe_section"
