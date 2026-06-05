"""
Module   : admap_m1.tests.unit.test_regex_extractor
"""
from __future__ import annotations

from admap_m1.extractors.regex_extractor import RegexExtractor
from admap_m1.models.ioc import IOCType


def test_regex_ip_domain_url():
    """Test des expressions régulières réseau."""
    extractor = RegexExtractor()
    
    text = "Connect to http://malicious.com/payload.exe or 192.168.50.5"
    iocs = extractor.extract_from_text(text)
    
    types = [ioc.type for ioc in iocs]
    values = [ioc.value for ioc in iocs]
    
    assert IOCType.URL in types
    assert "http://malicious.com/payload.exe" in values
    
    assert IOCType.IPV4 in types
    assert "192.168.50.5" in values
    
    # malicious.com doit être ignoré s'il est extrait via URL, mais
    # RegexExtractor gère cela (le domaine de l'URL n'est pas extrait à part).
    
def test_regex_hashes():
    """Test d'extraction des empreintes."""
    extractor = RegexExtractor()
    text = "File hash is 44d88612fea8a8f36de82e1278abb02f and sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    iocs = extractor.extract_from_text(text)
    
    values = [ioc.value for ioc in iocs]
    assert "44d88612fea8a8f36de82e1278abb02f" in values
    assert "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" in values

def test_regex_powershell():
    """Test d'extraction de commandes suspectes."""
    extractor = RegexExtractor()
    text = "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdA"
    iocs = extractor.extract_from_text(text)
    
    commands = [ioc for ioc in iocs if ioc.type == IOCType.COMMAND]
    assert len(commands) == 1
    assert "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdA" in commands[0].value
