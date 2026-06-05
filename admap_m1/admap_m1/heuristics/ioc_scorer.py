"""
Module   : admap_m1.heuristics.ioc_scorer
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc]

Calcule le score de confiance (0-100) pour chaque IOC en fonction
de son type et des flags contextuels. Implémente la section 30 du plan.
"""
from __future__ import annotations

from typing import ClassVar

from admap_m1.models.ioc import IOCConfidenceLevel, IOCType, RawIOC


class IOCScorer:
    """Moteur de scoring attribuant une note de confiance (0-100) aux IOCs."""

    # Section 30.1 - Scores de base par type
    BASE_SCORES: ClassVar[dict[IOCType, int]] = {
        IOCType.IPV4: 40,
        IOCType.IPV6: 40,
        IOCType.DOMAIN: 50,
        IOCType.URL: 60,
        IOCType.EMAIL: 45,
        IOCType.HASH_MD5: 80,
        IOCType.HASH_SHA1: 80,
        IOCType.HASH_SHA256: 80,
        IOCType.HASH_SSDEEP: 70,
        IOCType.HASH_IMPHASH: 60,
        IOCType.FILEPATH: 30,
        IOCType.FILENAME: 20,
        IOCType.REGISTRY_KEY: 50,
        IOCType.MUTEX: 60,
        IOCType.COMMAND: 70,
    }

    # Section 30.2 - Modificateurs contextuels
    CONTEXT_MODIFIERS: ClassVar[dict[str, int]] = {
        "is_pe_import": -30,               # Fortement probable que ce soit bénin si c'est un import (sauf suspicieux)
        "in_high_entropy_section": +20,    # Obfusqué = plus suspect
        "in_autoexec_macro": +30,          # Macro VBA auto exécutable
        "near_suspicious_api": +20,        # Près de VirtualAlloc, etc.
        "is_defanged": +40,                # Déjà defangé dans le texte original = partagé par un analyste
        "near_execution_verb": +15,        # Près de "run", "execute"
        "in_decoded_layer": +25,           # Trouvé après désobfuscation
    }

    @staticmethod
    def score(ioc: RawIOC, context_flags: list[str]) -> tuple[int, IOCConfidenceLevel, list[str]]:
        """Calcule le score final de l'IOC et détermine le niveau de confiance.

        Args:
            ioc: Le RawIOC à évaluer.
            context_flags: Les tags calculés par le ContextAnalyzer.

        Returns:
            Tuple (score_final, niveau_de_confiance, historique_scoring).
        """
        reasons: list[str] = []
        
        # 1. Score de base
        base_score = IOCScorer.BASE_SCORES.get(ioc.type, 30)
        score = base_score
        reasons.append(f"Base score for {ioc.type.value}: {base_score}")

        # Cas spécial: IP RFC1918 (privée) -> score tombe à 0
        from admap_m1.filters.whitelist import WhitelistFilter
        if ioc.type in (IOCType.IPV4, IOCType.IPV6) and WhitelistFilter.is_rfc1918(str(ioc.value)):
            score = 0
            reasons.append("RFC1918 Private IP -> Score set to 0")
            return 0, IOCConfidenceLevel.NOISE, reasons

        # Cas spécial: Faux positifs connus
        if ioc.type == IOCType.DOMAIN and WhitelistFilter.is_benign_domain_static(str(ioc.value)):
            score = 0
            reasons.append("Benign Domain Whitelist -> Score set to 0")
            return 0, IOCConfidenceLevel.NOISE, reasons

        # 2. Application des modificateurs
        for flag in context_flags:
            if flag in IOCScorer.CONTEXT_MODIFIERS:
                mod = IOCScorer.CONTEXT_MODIFIERS[flag]
                score += mod
                sign = "+" if mod > 0 else ""
                reasons.append(f"Context flag '{flag}': {sign}{mod}")

        # Clamp entre 0 et 100
        score = max(0, min(100, score))

        # 3. Détermination du niveau
        if score >= 80:
            level = IOCConfidenceLevel.CONFIRMED
        elif score >= 60:
            level = IOCConfidenceLevel.HIGH
        elif score >= 40:
            level = IOCConfidenceLevel.MEDIUM
        elif score >= 20:
            level = IOCConfidenceLevel.LOW
        else:
            level = IOCConfidenceLevel.NOISE

        return score, level, reasons
