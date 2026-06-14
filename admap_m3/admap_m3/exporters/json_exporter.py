"""
Module   : admap_m3.exporters.json_exporter
Version  : 1.0.0
Dépend   : [structlog]

Export d'un ``YaraRuleSet`` au format JSON (sérialisation Pydantic).
"""
from __future__ import annotations

from typing import Any

import structlog

from admap_m3.exporters.base import BaseExporter
from admap_m3.models.rule import YaraRuleSet

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


class JSONExporter(BaseExporter):
    """Exporte un ``YaraRuleSet`` en JSON via ``model_dump_json``."""

    @property
    def exporter_name(self) -> str:
        return "JSONExporter"

    def export(self, ruleset: YaraRuleSet, output_path: str) -> dict[str, Any]:
        """Écrit ``ruleset.model_dump_json(indent=2)`` dans le fichier."""
        try:
            json_content: str = ruleset.model_dump_json(indent=2)

            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(json_content)

            logger.info(
                "json_export_complete",
                output_path=output_path,
                exported_rules=ruleset.total_rules,
                exporter=self.exporter_name,
            )

            return {
                "status": "ok",
                "output_path": output_path,
                "exported_rules": ruleset.total_rules,
            }
        except Exception as exc:
            logger.error(
                "json_export_failed",
                output_path=output_path,
                error=str(exc),
                exporter=self.exporter_name,
            )
            return {
                "status": "error",
                "error": str(exc),
                "output_path": output_path,
            }
