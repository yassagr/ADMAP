"""
Module   : admap_m1.deobfuscators.base64_decoder
Version  : 3.0.0
Dépend   : [base64, re, admap_m1.deobfuscators.base]

Désobfuscateur Base64. Gère le Base64 standard, URL-safe, et
recherche de blocs Base64 dans du texte mixte (ex: commandes PowerShell).
"""
from __future__ import annotations

import base64
import re

from admap_m1.deobfuscators.base import BaseDeobfuscator, DeobfuscationResult


class Base64Decoder(BaseDeobfuscator):
    """Désobfuscateur pour le Base64.

    Recherche des blocs Base64 valides d'une taille minimale et tente de
    les décoder. Gère également le cas de l'UTF-16LE caché (typique de PowerShell).
    """

    # Pattern pour trouver des blocs qui ressemblent à du Base64 long
    B64_PATTERN = re.compile(rb'[A-Za-z0-9+/=]{40,}')

    @property
    def technique_name(self) -> str:
        return "base64"

    def decode(self, data: bytes) -> list[DeobfuscationResult]:
        results: list[DeobfuscationResult] = []

        # Cas 1: Le fichier entier EST du Base64 pur
        try:
            # On tente de décoder la totalité (en ignorant les retours chariot)
            clean_data = data.replace(b'\n', b'').replace(b'\r', b'')
            # S'assurer que c'est un multiple de 4
            padding_needed = len(clean_data) % 4
            if padding_needed > 0:
                clean_data += b'=' * (4 - padding_needed)

            decoded = base64.b64decode(clean_data, validate=True)
            if self._is_valid_plaintext(decoded):
                results.append(
                    DeobfuscationResult(
                        success=True,
                        technique_name=self.technique_name,
                        decoded_data=decoded,
                        confidence=90,
                        metadata={"scope": "full_file"}
                    )
                )
        except Exception:
            pass

        # Cas 2: Il y a des blocs de Base64 cachés dans le fichier
        # Particulièrement pertinent pour PowerShell -EncodedCommand
        blocks_found = False
        combined_decoded = bytearray()
        
        for match in self.B64_PATTERN.finditer(data):
            block = match.group(0)
            try:
                # Ajouter padding si nécessaire
                padding_needed = len(block) % 4
                if padding_needed > 0:
                    block += b'=' * (4 - padding_needed)
                    
                decoded = base64.b64decode(block, validate=True)
                
                # Vérifier si le résultat est de l'UTF-16LE (PowerShell)
                # UTF-16LE en anglais ressemble à: char \x00 char \x00
                is_utf16le = False
                if len(decoded) > 4 and decoded[1] == 0 and decoded[3] == 0:
                    try:
                        decoded_str = decoded.decode('utf-16-le')
                        decoded = decoded_str.encode('utf-8')
                        is_utf16le = True
                    except UnicodeDecodeError:
                        pass
                
                if self._is_valid_plaintext(decoded) or is_utf16le:
                    blocks_found = True
                    combined_decoded.extend(decoded)
                    combined_decoded.extend(b"\n")
            except Exception:
                continue
                
        if blocks_found and combined_decoded:
            results.append(
                DeobfuscationResult(
                    success=True,
                    technique_name=self.technique_name,
                    decoded_data=bytes(combined_decoded),
                    confidence=80,
                    metadata={"scope": "extracted_blocks"}
                )
            )

        return results
