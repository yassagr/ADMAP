"""
Module   : admap_m3.analyzers.generic_analyzer
Version  : 1.0.0
Dépend   : [structlog]

Analyseur fallback pour les fichiers de format non reconnu.
Extrait des strings imprimables, des n-grams de bytes, et l'entropie
de Shannon comme feature symbolique.
"""
from __future__ import annotations

import math
import re

import structlog

from admap_m3.analyzers.base import BaseAnalyzer

logger: structlog.stdlib.BoundLogger = structlog.get_logger()

# Regex pour les séquences de caractères ASCII imprimables
_PRINTABLE_RE: re.Pattern[bytes] = re.compile(rb"[\x20-\x7e]{6,}")


class GenericBinaryAnalyzer(BaseAnalyzer):
    """Fallback pour tout format de fichier non reconnu.

    Extrait :
    1. Strings imprimables (scan linéaire, ASCII consécutifs).
    2. N-grams de bytes → hex-encodés.
    3. Entropie de Shannon du fichier (feature symbolique ``entropy:X.XX``).
    """

    def __init__(self, min_token_length: int = 6, ngram_size: int = 4) -> None:
        self._min_token_length: int = min_token_length
        self._ngram_size: int = ngram_size

    @property
    def analyzer_name(self) -> str:
        return "GenericBinaryAnalyzer"

    def extract_tokens(self, data: bytes, file_path: str) -> list[str]:
        """Extrait les features depuis un fichier binaire de format inconnu."""
        tokens: list[str] = []

        # 1. Strings imprimables
        for match in _PRINTABLE_RE.finditer(data):
            token: str = match.group().decode("ascii", errors="ignore")
            if len(token) >= self._min_token_length:
                tokens.append(token)

        # 2. N-grams de bytes
        tokens.extend(self._extract_ngrams(data))

        # 3. Entropie de Shannon
        entropy_value: float = self._shannon_entropy(data)
        tokens.append(f"entropy:{entropy_value:.2f}")

        logger.debug(
            "generic_extraction_complete",
            file_path=file_path,
            token_count=len(tokens),
            entropy=entropy_value,
            analyzer=self.analyzer_name,
        )

        return tokens

    # ── Helpers ──────────────────────────────────────────────────────────

    def _extract_ngrams(self, data: bytes) -> list[str]:
        """Extrait les n-grams de bytes, hex-encodés."""
        result: list[str] = []
        ngram_count: int = len(data) - self._ngram_size + 1
        for i in range(min(ngram_count, 500)):
            ngram: bytes = data[i : i + self._ngram_size]
            result.append(ngram.hex().upper())
        return result

    def _shannon_entropy(self, data: bytes) -> float:
        """Calcule l'entropie de Shannon du fichier en bits par byte.

        Retourne 0.0 pour des données vides.
        """
        if not data:
            return 0.0

        length: int = len(data)
        freq: dict[int, int] = {}
        for byte_val in data:
            freq[byte_val] = freq.get(byte_val, 0) + 1

        entropy: float = 0.0
        for count in freq.values():
            probability: float = count / length
            if probability > 0.0:
                entropy -= probability * math.log2(probability)

        return entropy
