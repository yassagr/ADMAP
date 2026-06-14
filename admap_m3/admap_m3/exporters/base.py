"""
Module   : admap_m3.exporters.base
Version  : 1.0.0

Classe abstraite pour les exporteurs de ``YaraRuleSet``.
Les exporteurs ne lèvent JAMAIS de ``RuntimeError`` : en cas d'échec,
ils retournent un dict structuré ``{"status": "error", ...}``.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from admap_m3.models.rule import YaraRuleSet


class BaseExporter(ABC):
    """Classe abstraite pour l'export de ``YaraRuleSet``."""

    @property
    @abstractmethod
    def exporter_name(self) -> str:
        """Nom unique de l'exporteur."""
        ...

    @abstractmethod
    def export(
        self,
        ruleset: YaraRuleSet,
        output_path: str,
    ) -> dict[str, Any]:
        """Exporte le ruleset vers ``output_path``.

        Retourne TOUJOURS un dict :
        - succès → ``{"status": "ok", "output_path": ..., "exported_rules": N}``
        - échec  → ``{"status": "error", "error": str(e), "output_path": ...}``

        **NE LÈVE JAMAIS de RuntimeError.**
        """
        ...
