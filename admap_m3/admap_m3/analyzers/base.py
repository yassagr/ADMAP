"""
Module   : admap_m3.analyzers.base
Version  : 1.0.0

Classe abstraite commune à tous les analyseurs de fichiers du module M3.
Chaque analyseur concret doit implémenter ``analyzer_name`` et
``extract_tokens``.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class BaseAnalyzer(ABC):
    """Classe abstraite commune à tous les analyzers de M3.

    Un analyzer extrait une liste de tokens (strings, hex patterns,
    n-grams d'opcodes…) depuis les bytes bruts d'un fichier.
    L'extraction est **purement statique** : aucune exécution du binaire.
    """

    @property
    @abstractmethod
    def analyzer_name(self) -> str:
        """Nom unique de l'analyzer.  Doit être une string non vide."""
        ...

    @abstractmethod
    def extract_tokens(self, data: bytes, file_path: str) -> list[str]:
        """Extrait une liste de tokens depuis les bytes du fichier.

        Args:
            data: Contenu binaire brut du fichier.
            file_path: Chemin d'origine (pour le logging).

        Returns:
            Liste de tokens (strings, hex, opcodes…).
        """
        ...
