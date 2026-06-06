"""
Module   : admap_m2.exporters.stix_exporter
Version  : 1.0.0
Dépend   : [stix2, admap_m2.exporters.base]
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from admap_m2.exporters.base import BaseExporter
from admap_m2.models.alert import AlertBundle

try:
    import stix2
    STIX2_AVAILABLE = True
except ImportError:
    STIX2_AVAILABLE = False


class STIXExporter(BaseExporter):
    """Exporte au format STIX 2.1."""

    def export(self, bundle: AlertBundle) -> str:
        if not STIX2_AVAILABLE:
            raise RuntimeError("stix2 package is not installed")

        stix_objects = []

        # Pour simplifier, on crée un Incident / Indicator pour chaque alerte
        for alert in bundle.alerts:
            # Créer l'indicateur
            pattern = ""
            if alert.protocol == "tcp":
                pattern = f"[network-traffic:src_ref.value = '{alert.src_ip}' AND network-traffic:dst_ref.value = '{alert.dst_ip}' AND network-traffic:dst_port = {alert.dst_port}]"
            elif alert.protocol == "udp":
                pattern = f"[network-traffic:src_ref.value = '{alert.src_ip}' AND network-traffic:dst_ref.value = '{alert.dst_ip}' AND network-traffic:dst_port = {alert.dst_port}]"
            else:
                pattern = f"[network-traffic:src_ref.value = '{alert.src_ip}' AND network-traffic:dst_ref.value = '{alert.dst_ip}']"

            indicator = stix2.Indicator(
                name=f"C2 Alert: {alert.alert_type.value}",
                description=alert.description,
                pattern=pattern,
                pattern_type="stix",
                valid_from=alert.first_seen,
            )
            stix_objects.append(indicator)

        stix_bundle = stix2.Bundle(objects=stix_objects)
        return stix_bundle.serialize()
