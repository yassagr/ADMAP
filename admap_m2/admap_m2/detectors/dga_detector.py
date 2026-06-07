"""
Module   : admap_m2.detectors.dga_detector
Version  : 1.0.0
Dépend   : [math, collections, admap_m2.detectors.base,
            admap_m2.models.alert, admap_m2.models.flow]
"""
from __future__ import annotations

import math
from collections import Counter
from typing import ClassVar

from admap_m2.detectors.base import BaseDetector
from admap_m2.models.alert import AlertType, C2Alert
from admap_m2.models.flow import NetworkFlow


class DGADetector(BaseDetector):
    """
    Détecte les domaines générés par algorithme (DGA).

    Heuristiques (7) :
    1. Entropie de Shannon du label principal
    2. Ratio consonnes/voyelles (DGA = peu de voyelles)
    3. Longueur du label (DGA = long)
    4. Ratio de chiffres
    5. N-grams : faible proportion de bigrammes anglais courants
    6. TLD suspect (xyz, top, cc...)
    7. Réponse NXDOMAIN (DGA cherche son C2)
    """

    VOWELS: ClassVar[frozenset[str]] = frozenset("aeiou")

    DGA_TLDS: ClassVar[set[str]] = {
        "xyz", "top", "cc", "pw", "bit", "gq", "cf", "ml", "ga",
        "tk", "click", "link", "online", "site", "fun", "icu",
    }

    COMMON_BIGRAMS: ClassVar[set[str]] = {
        "th", "he", "in", "er", "an", "on", "re", "at", "en", "nd",
        "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
        "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    }

    @property
    def detector_name(self) -> str:
        return "dga"

    def detect(self, flows: list[NetworkFlow]) -> list[C2Alert]:
        """
        Analyse les requêtes DNS pour détecter les domaines DGA.

        Args:
            flows: Liste des flux réseau.

        Returns:
            Liste de C2Alert de type DGA.
        """
        alerts: list[C2Alert] = []

        for flow in flows:
            if not flow.dns_queries:
                continue
            for dns_query in flow.dns_queries:
                score, evidence = self._score_domain(dns_query.query_name)
                if dns_query.is_nxdomain and score > 0:
                    score = min(100, score + 10)
                    evidence.append("NXDOMAIN response (DGA seeking C2)")
                if score >= self._settings.MIN_CONFIDENCE_THRESHOLD:
                    alerts.append(self._build_alert(
                        flow,
                        AlertType.DGA,
                        score,
                        f"Potential DGA domain: {dns_query.query_name} (score: {score})",
                        evidence,
                        metadata={
                            "domain": dns_query.query_name,
                            "query_type": dns_query.query_type,
                            "is_nxdomain": dns_query.is_nxdomain,
                        },
                    ))

        return alerts

    def _score_domain(self, domain: str) -> tuple[int, list[str]]:
        """
        Score un domaine pour probabilité DGA via 7 heuristiques.

        Args:
            domain: Nom de domaine FQDN à analyser.

        Returns:
            Tuple (score_0_100, liste_evidence).
        """
        evidence: list[str] = []
        score = 0

        parts = domain.lower().rstrip(".").split(".")
        if len(parts) < 2:
            return 0, []

        tld = parts[-1]
        label_to_analyze = parts[-2]

        if len(label_to_analyze) < self._settings.DGA_MIN_DOMAIN_LENGTH:
            return 0, []

        # 1. Entropie de Shannon
        entropy = self._shannon_entropy(label_to_analyze)
        if entropy >= self._settings.DGA_ENTROPY_THRESHOLD:
            bonus = int((entropy - self._settings.DGA_ENTROPY_THRESHOLD) * 15)
            score += min(25, bonus + 10)
            evidence.append(
                f"High entropy: {entropy:.2f} "
                f"(threshold: {self._settings.DGA_ENTROPY_THRESHOLD})"
            )

        # 2. Ratio voyelles
        total_letters = sum(1 for c in label_to_analyze if c.isalpha())
        if total_letters > 0:
            vowel_ratio = (
                sum(1 for c in label_to_analyze if c in self.VOWELS) / total_letters
            )
            if vowel_ratio < 0.20:
                score += 20
                evidence.append(f"Low vowel ratio: {vowel_ratio:.2f} (normal ~0.38)")

        # 3. Longueur du label
        if len(label_to_analyze) >= 25:
            score += 20
            evidence.append(f"Very long label: {len(label_to_analyze)} chars")
        elif len(label_to_analyze) >= 16:
            score += 10
            evidence.append(f"Long label: {len(label_to_analyze)} chars")

        # 4. Ratio numérique
        if len(label_to_analyze) > 0:
            digit_ratio = (
                sum(1 for c in label_to_analyze if c.isdigit())
                / len(label_to_analyze)
            )
            if digit_ratio > 0.3:
                score += 10
                evidence.append(f"High digit ratio: {digit_ratio:.2f}")

        # 5. Bigrammes anglais courants
        bigrams = [
            label_to_analyze[i: i + 2]
            for i in range(len(label_to_analyze) - 1)
        ]
        if bigrams:
            common_ratio = (
                sum(1 for bg in bigrams if bg in self.COMMON_BIGRAMS)
                / len(bigrams)
            )
            if common_ratio < 0.10:
                score += 15
                evidence.append(f"Low common bigram ratio: {common_ratio:.2f}")

        # 6. TLD suspect
        if tld in self.DGA_TLDS:
            score += 10
            evidence.append(f"Suspect TLD: .{tld}")

        return min(100, score), evidence

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """
        Calcule l'entropie de Shannon d'une chaîne.

        Args:
            text: Chaîne à analyser.

        Returns:
            Entropie en bits.
        """
        if not text:
            return 0.0
        freq = Counter(text)
        n = len(text)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())
