"""
Module   : admap_m1.deobfuscators.rot_decoder
Version  : 3.0.0
Dépend   : [admap_m1.deobfuscators.base]

Désobfuscateur ROT (Caesar cipher). Teste les décalages de 1 à 25.
"""
from __future__ import annotations

import string

from admap_m1.deobfuscators.base import BaseDeobfuscator, DeobfuscationResult


class ROTDecoder(BaseDeobfuscator):
    """Désobfuscateur pour le chiffrement de César (ROT).

    Essaye tous les décalages de 1 à 25 sur les lettres de l'alphabet
    et évalue le résultat avec une heuristique très basique de texte.
    Principalement utile pour ROT13 très commun dans les malwares.
    """

    @property
    def technique_name(self) -> str:
        return "rot"

    def decode(self, data: bytes) -> list[DeobfuscationResult]:
        results: list[DeobfuscationResult] = []
        
        try:
            # ROT ne s'applique qu'au texte, on essaie de décoder
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return results

        # Pour limiter les faux positifs, on cherche des mots-clés typiques
        # du CTI ou des malwares (http, powershell, etc.)
        keywords = {"http", "https", "powershell", "cmd", "exe", "dll", "wget", "curl"}
        
        for shift in range(1, 26):
            decoded_chars = []
            for char in text:
                if char.islower():
                    decoded_chars.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                elif char.isupper():
                    decoded_chars.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                else:
                    decoded_chars.append(char)
                    
            decoded_text = "".join(decoded_chars)
            decoded_lower = decoded_text.lower()
            
            # Vérifier s'il y a des mots clés
            if any(kw in decoded_lower for kw in keywords):
                results.append(
                    DeobfuscationResult(
                        success=True,
                        technique_name=self.technique_name,
                        decoded_data=decoded_text.encode("utf-8"),
                        confidence=70,
                        metadata={"shift": str(shift)}
                    )
                )
                
        return results
