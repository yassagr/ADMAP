"""
Module   : admap_m1.heuristics.entropy
Version  : 3.0.0
Dépend   : []

Calcul d'entropie de Shannon sur des données binaires.
Aucune dépendance externe. Utilisé par parsers, deobfuscators et scorer.
"""
from __future__ import annotations

import math
from collections import Counter


class EntropyCalculator:
    """Calcul d'entropie de Shannon sur des données binaires.

    Fournit entropie globale, par fenêtres, classification et détection
    de régions haute entropie. Aucune dépendance externe.
    """

    @staticmethod
    def calculate(data: bytes) -> float:
        """Calcule l'entropie de Shannon globale.

        Args:
            data: Données binaires à analyser.

        Returns:
            Entropie entre 0.0 (données uniformes) et 8.0 (aléatoire parfait).
            Retourne 0.0 si data est vide.
        """
        if not data:
            return 0.0
        n: int = len(data)
        freq: Counter[int] = Counter(data)
        return -sum(
            (count / n) * math.log2(count / n)
            for count in freq.values()
        )

    @staticmethod
    def calculate_windowed(
        data: bytes,
        window_size: int = 256,
    ) -> list[float]:
        """Calcule l'entropie par fenêtres non-chevauchantes.

        Args:
            data: Données binaires.
            window_size: Taille de chaque fenêtre en bytes.

        Returns:
            Liste d'entropies, une par fenêtre.
            Longueur = len(data) // window_size.
        """
        results: list[float] = []
        for i in range(0, len(data) - window_size + 1, window_size):
            window: bytes = data[i: i + window_size]
            results.append(EntropyCalculator.calculate(window))
        return results

    @staticmethod
    def classify(entropy: float) -> str:
        """Classifie l'entropie en catégorie lisible.

        Args:
            entropy: Valeur d'entropie entre 0.0 et 8.0.

        Returns:
            Catégorie parmi : ``binary_zeros``, ``plaintext``,
            ``compressed_or_encoded``, ``mixed``,
            ``likely_encrypted``, ``encrypted_or_random``.
        """
        if entropy < 1.0:
            return "binary_zeros"
        if entropy < 4.0:
            return "plaintext"
        if entropy < 6.0:
            return "compressed_or_encoded"
        if entropy < 7.0:
            return "mixed"
        if entropy < 7.5:
            return "likely_encrypted"
        return "encrypted_or_random"

    @staticmethod
    def find_high_entropy_regions(
        data: bytes,
        threshold: float = 7.0,
        window_size: int = 256,
    ) -> list[tuple[int, int]]:
        """Identifie les zones à haute entropie dans les données.

        Args:
            data: Données binaires à analyser.
            threshold: Seuil d'entropie (défaut 7.0).
            window_size: Taille de fenêtre pour le calcul.

        Returns:
            Liste de (offset_start, offset_end) des régions
            dont l'entropie dépasse le seuil. Les régions adjacentes
            sont fusionnées.
        """
        raw_regions: list[tuple[int, int]] = []

        for i in range(0, len(data) - window_size + 1, window_size):
            window: bytes = data[i: i + window_size]
            entropy: float = EntropyCalculator.calculate(window)
            if entropy >= threshold:
                raw_regions.append((i, i + window_size))

        # Fusionner les régions adjacentes
        if not raw_regions:
            return []

        merged: list[tuple[int, int]] = [raw_regions[0]]
        for start, end in raw_regions[1:]:
            prev_start, prev_end = merged[-1]
            if start <= prev_end:  # Régions adjacentes ou chevauchantes
                merged[-1] = (prev_start, max(prev_end, end))
            else:
                merged.append((start, end))

        return merged
