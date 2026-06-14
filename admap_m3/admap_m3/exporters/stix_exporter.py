"""
Module   : admap_m3.exporters.stix_exporter
Version  : 1.0.0
Dépend   : [structlog, json, uuid]

Export d'un ``YaraRuleSet`` au format STIX 2.1 (bundle JSON).
Chaque règle compilée avec ``confidence_score ≥ 60`` produit un objet
Indicator STIX avec ``pattern_type = "yara"``.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from admap_m3.exporters.base import BaseExporter
from admap_m3.models.rule import YaraRuleSet

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


class STIXExporter(BaseExporter):
    """Exporte un ``YaraRuleSet`` en bundle STIX 2.1."""

    @property
    def exporter_name(self) -> str:
        return "STIXExporter"

    def export(self, ruleset: YaraRuleSet, output_path: str) -> dict[str, Any]:
        """Produit un bundle STIX 2.1 JSON avec indicateurs YARA."""
        try:
            now_iso: str = datetime.now(timezone.utc).isoformat(timespec="seconds")

            # Identity object
            identity_id: str = f"identity--{uuid.uuid4()}"
            identity_obj: dict[str, Any] = {
                "type": "identity",
                "id": identity_id,
                "created": now_iso,
                "modified": now_iso,
                "name": "ADMAP Platform M3",
                "identity_class": "system",
            }

            # Indicators
            indicators: list[dict[str, Any]] = []
            for rule in ruleset.rules:
                if not rule.compiled or rule.confidence_score < 60:
                    continue

                indicator_id: str = f"indicator--{uuid.uuid4()}"
                indicator: dict[str, Any] = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": rule.rule_name,
                    "description": rule.metadata.description,
                    "pattern": "[file:hashes.'SHA-256' = 'PLACEHOLDER_YARA_RULE']",
                    "pattern_type": "yara",
                    "pattern_version": "4.0",
                    "valid_from": now_iso,
                    "confidence": rule.confidence_score,
                    "labels": ["malicious-activity"],
                    "extensions": {
                        "extension-definition--yara": {
                            "extension_type": "new-sco",
                            "rule_source": rule.raw_yara,
                        }
                    },
                }
                indicators.append(indicator)

            # Bundle
            bundle: dict[str, Any] = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": "2.1",
                "created": now_iso,
                "objects": [identity_obj, *indicators],
            }

            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(bundle, fh, indent=2, ensure_ascii=False)

            logger.info(
                "stix_export_complete",
                output_path=output_path,
                exported_indicators=len(indicators),
                exporter=self.exporter_name,
            )

            return {
                "status": "ok",
                "output_path": output_path,
                "exported_rules": len(indicators),
            }
        except Exception as exc:
            logger.error(
                "stix_export_failed",
                output_path=output_path,
                error=str(exc),
                exporter=self.exporter_name,
            )
            return {
                "status": "error",
                "error": str(exc),
                "output_path": output_path,
            }
