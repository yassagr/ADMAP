"""
Module   : admap_m2.exporters.json_exporter
Version  : 1.0.0
Dépend   : [admap_m2.exporters.base]
"""
from __future__ import annotations

from admap_m2.exporters.base import BaseExporter
from admap_m2.models.alert import AlertBundle


class JSONExporter(BaseExporter):
    """Exporte au format JSON natif ADMAP."""

    def export(self, bundle: AlertBundle) -> str:
        return bundle.model_dump_json(indent=2)
