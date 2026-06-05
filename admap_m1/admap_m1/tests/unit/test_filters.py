"""
Module   : admap_m1.tests.unit.test_filters
"""
from __future__ import annotations

from admap_m1.filters.deduplicator import IOCDeduplicator
from admap_m1.filters.defanger import IOCDefanger
from admap_m1.filters.whitelist import WhitelistFilter
from admap_m1.models.ioc import IOCType, RawIOC


def test_defanger():
    """Test des règles de defanging / refanging."""
    defanger = IOCDefanger()
    
    # URL
    assert defanger.defang("https://evil.com/path", IOCType.URL) == "hxxps[://]evil[.]com/path"
    assert defanger.refang("hxxps[://]evil[.]com/path") == "https://evil.com/path"
    
    # IP
    assert defanger.defang("192.168.1.1", IOCType.IPV4) == "192[.]168[.]1[.]1"
    assert defanger.refang("192[.]168[.]1[.]1") == "192.168.1.1"
    
    # Email
    assert defanger.defang("admin@evil.com", IOCType.EMAIL) == "admin[@]evil[.]com"
    assert defanger.refang("admin[@]evil[.]com") == "admin@evil.com"


def test_whitelist():
    """Test du filtrage statique (domaines bénins, TLDs)."""
    assert WhitelistFilter.is_benign_domain_static("microsoft.com") is True
    assert WhitelistFilter.is_benign_domain_static("update.microsoft.com") is True
    assert WhitelistFilter.is_benign_domain_static("evil.com") is False
    
    assert WhitelistFilter.is_valid_tld("com") is True
    assert WhitelistFilter.is_valid_tld("invalidtldxyz") is False
    
    assert WhitelistFilter.is_rfc1918("192.168.1.100") is True
    assert WhitelistFilter.is_rfc1918("8.8.8.8") is False


def test_deduplicator():
    """Test de la logique de dédoublonnage et priorisation."""
    raw1 = RawIOC(type=IOCType.DOMAIN, value="EVIL.COM", extraction_method="regex")
    raw2 = RawIOC(type=IOCType.DOMAIN, value="evil.com", extraction_method="pe_section", in_decoded_layer=True)
    raw3 = RawIOC(type=IOCType.IPV4, value="8.8.8.8", extraction_method="regex")
    
    unique = IOCDeduplicator.deduplicate_raw([raw1, raw2, raw3])
    
    assert len(unique) == 2
    # Doit avoir gardé raw2 (in_decoded_layer prioritaire et casse normalisée)
    domain_ioc = next(i for i in unique if i.type == IOCType.DOMAIN)
    assert domain_ioc.in_decoded_layer is True
