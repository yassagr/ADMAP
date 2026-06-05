"""
Module   : admap_m1.deobfuscators.xor_decoder
Version  : 3.0.0
Dépend   : [admap_m1.deobfuscators.base]

Désobfuscateur XOR 1-byte. Tente de brute-forcer la clé sur 255 possibilités.
"""
from __future__ import annotations

from admap_m1.deobfuscators.base import BaseDeobfuscator, DeobfuscationResult


class XOR1ByteDecoder(BaseDeobfuscator):
    """Désobfuscateur par brute-force XOR sur 1 octet.

    Essaye les clés de 0x01 à 0xFF et retient celles qui produisent
    un pourcentage élevé de texte imprimable.
    """

    @property
    def technique_name(self) -> str:
        return "xor_1byte"

    def decode(self, data: bytes) -> list[DeobfuscationResult]:
        results: list[DeobfuscationResult] = []
        
        # Inutile de brute-forcer des données très courtes
        if len(data) < 10:
            return results

        # Parcourir toutes les clés possibles sauf 0x00
        for key in range(1, 256):
            # Optimisation: vérifier d'abord un échantillon si le fichier est gros
            if len(data) > 1024:
                sample = data[:1024]
                decoded_sample = bytes(b ^ key for b in sample)
                if not self._is_valid_plaintext(decoded_sample):
                    continue

            # Décodage complet
            decoded = bytes(b ^ key for b in data)
            
            if self._is_valid_plaintext(decoded):
                results.append(
                    DeobfuscationResult(
                        success=True,
                        technique_name=self.technique_name,
                        decoded_data=decoded,
                        confidence=60,  # Confiance moyenne, beaucoup de faux positifs possibles
                        metadata={"key": hex(key)}
                    )
                )

        # Trier par nombre de caractères imprimables (approx via heuristique)
        # pour remonter les meilleurs résultats en premier
        def score_printable(res: DeobfuscationResult) -> int:
            if not res.decoded_data: return 0
            return sum(1 for b in res.decoded_data if 32 <= b <= 126)
            
        results.sort(key=score_printable, reverse=True)
        return results[:10]  # Ne garder que les 10 meilleurs candidats pour éviter l'explosion
