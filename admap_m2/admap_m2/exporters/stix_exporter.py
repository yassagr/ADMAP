"""
Module   : admap_m2.exporters.stix_exporter
Version  : 1.0.0
Dépend   : [json, ipaddress, datetime, stix2 (optionnel),
            admap_m2.exporters.base, admap_m2.models.alert]
"""
from __future__ import annotations

import ipaddress
import json
from datetime import timezone

from admap_m2.exporters.base import BaseExporter
from admap_m2.models.alert import AlertBundle, AlertSeverity, C2Alert

try:
    import stix2
    STIX2_AVAILABLE = True
except ImportError:
    STIX2_AVAILABLE = False


class STIXExporter(BaseExporter):
    """Exporte les alertes C2 au format STIX 2.1."""

    def export(self, bundle: AlertBundle) -> str:
        """
        Exporte un AlertBundle au format STIX 2.1.

        Seules les alertes CRITICAL et HIGH génèrent des Indicators.
        Si stix2 n'est pas installé, retourne un JSON d'erreur.

        Args:
            bundle: AlertBundle à exporter.

        Returns:
            JSON STIX 2.1 sérialisé, ou JSON d'erreur si stix2 absent.
        """
        if not STIX2_AVAILABLE:
            return json.dumps({"error": "stix2 library not installed"})

        stix_objects = []

        identity = stix2.Identity(
            name="ADMAP Platform M2",
            identity_class="system",
            description="C2 Detector — Module M2",
        )
        stix_objects.append(identity)

        for alert in bundle.alerts:
            if alert.severity not in (AlertSeverity.CRITICAL, AlertSeverity.HIGH):
                continue

            indicator = stix2.Indicator(
                name=f"C2 Alert: {alert.alert_type.value} from {alert.src_ip}",
                description=alert.description,
                pattern=self._build_pattern(alert),
                pattern_type="stix",
                valid_from=alert.first_seen.replace(tzinfo=timezone.utc),
                created_by_ref=identity.id,
                confidence=alert.confidence_score,
            )
            stix_objects.append(indicator)

        stix_bundle = stix2.Bundle(objects=stix_objects)
        return stix_bundle.serialize(indent=4)

    def _build_pattern(self, alert: C2Alert) -> str:
        """
        Construit un pattern STIX valide pour une alerte.

        Distingue ipv4-addr, ipv6-addr et domain-name selon la nature de
        dst_ip, pour produire un SCO (STIX Cyber-observable Object) du
        type sémantiquement correct.

        IMPORTANT : ipaddress.ip_address() accepte aussi bien les adresses
        IPv4 que IPv6 — il faut explicitement tester isinstance(...,
        ipaddress.IPv6Address) pour ne pas taguer une IPv6 comme ipv4-addr.

        Args:
            alert: C2Alert à convertir en pattern STIX.

        Returns:
            Pattern STIX string (toujours non vide).
        """
        try:
            ip_obj = ipaddress.ip_address(alert.dst_ip)
        except ValueError:
            return f"[domain-name:value = '{alert.dst_ip}']"

        if isinstance(ip_obj, ipaddress.IPv6Address):
            return f"[ipv6-addr:value = '{alert.dst_ip}']"
        return f"[ipv4-addr:value = '{alert.dst_ip}']"
