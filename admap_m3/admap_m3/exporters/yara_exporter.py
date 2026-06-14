"""
Module   : admap_m3.exporters.yara_exporter
Version  : 1.0.0
Dépend   : [structlog]

Export d'un ``YaraRuleSet`` au format ``.yar`` (texte YARA).
"""
from __future__ import annotations

from typing import Any

import structlog

from admap_m3.exporters.base import BaseExporter
from admap_m3.models.rule import YaraRuleSet

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


class YaraFileExporter(BaseExporter):
    """Exporte les règles compilées dans un fichier ``.yar``."""

    @property
    def exporter_name(self) -> str:
        return "YaraFileExporter"

    def export(self, ruleset: YaraRuleSet, output_path: str) -> dict[str, Any]:
        """Écrit un fichier ``.yar`` avec en-tête et règles compilées."""
        try:
            compiled_rules = [r for r in ruleset.rules if r.compiled]

            header: str = (
                f"// ADMAP M3 — YARA Signature Generator\n"
                f"// Ruleset ID: {ruleset.ruleset_id}\n"
                f"// Generated: {ruleset.created_at.isoformat()}\n"
                f"// Total rules: {ruleset.compiled_rules} compiled / "
                f"{ruleset.total_rules} total\n"
            )

            content: str = header + "\n"
            for rule in compiled_rules:
                content += rule.raw_yara + "\n\n"

            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(content)

            logger.info(
                "yara_export_complete",
                output_path=output_path,
                exported_rules=len(compiled_rules),
                exporter=self.exporter_name,
            )

            return {
                "status": "ok",
                "output_path": output_path,
                "exported_rules": len(compiled_rules),
            }
        except Exception as exc:
            logger.error(
                "yara_export_failed",
                output_path=output_path,
                error=str(exc),
                exporter=self.exporter_name,
            )
            return {
                "status": "error",
                "error": str(exc),
                "output_path": output_path,
            }
