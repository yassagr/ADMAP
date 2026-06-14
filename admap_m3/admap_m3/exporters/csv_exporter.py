"""
Module   : admap_m3.exporters.csv_exporter
Version  : 1.0.0
Dépend   : [csv, structlog]

Export d'un ``YaraRuleSet`` au format CSV.
"""
from __future__ import annotations

import csv
from typing import Any

import structlog

from admap_m3.exporters.base import BaseExporter
from admap_m3.models.rule import YaraRuleSet

logger: structlog.stdlib.BoundLogger = structlog.get_logger()

# Colonnes dans l'ordre exact spécifié
_CSV_COLUMNS: list[str] = [
    "rule_id",
    "rule_name",
    "compiled",
    "confidence_score",
    "token_count",
    "tlp",
    "corpus_id",
    "malware_family",
    "mitre_attack",
    "created_at",
]


class CSVExporter(BaseExporter):
    """Exporte un ``YaraRuleSet`` en CSV."""

    @property
    def exporter_name(self) -> str:
        return "CSVExporter"

    def export(self, ruleset: YaraRuleSet, output_path: str) -> dict[str, Any]:
        """Écrit un CSV avec les colonnes dans l'ordre exact du spec."""
        try:
            with open(output_path, "w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=_CSV_COLUMNS)
                writer.writeheader()

                for rule in ruleset.rules:
                    mitre_str: str = "|".join(rule.metadata.mitre_attack)
                    row: dict[str, Any] = {
                        "rule_id": rule.rule_id,
                        "rule_name": rule.rule_name,
                        "compiled": rule.compiled,
                        "confidence_score": rule.confidence_score,
                        "token_count": rule.token_count,
                        "tlp": rule.metadata.tlp.value,
                        "corpus_id": rule.metadata.corpus_id,
                        "malware_family": rule.metadata.malware_family or "",
                        "mitre_attack": mitre_str,
                        "created_at": ruleset.created_at.isoformat(),
                    }
                    writer.writerow(row)

            logger.info(
                "csv_export_complete",
                output_path=output_path,
                exported_rules=len(ruleset.rules),
                exporter=self.exporter_name,
            )

            return {
                "status": "ok",
                "output_path": output_path,
                "exported_rules": len(ruleset.rules),
            }
        except Exception as exc:
            logger.error(
                "csv_export_failed",
                output_path=output_path,
                error=str(exc),
                exporter=self.exporter_name,
            )
            return {
                "status": "error",
                "error": str(exc),
                "output_path": output_path,
            }
