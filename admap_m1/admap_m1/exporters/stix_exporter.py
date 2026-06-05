"""
Module   : admap_m1.exporters.stix_exporter
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.exporters.base]

Exportateur STIX 2.1 pour la standardisation CTI.
"""
from __future__ import annotations

import json
from datetime import timezone
from typing import Any

from admap_m1.exporters.base import BaseExporter
from admap_m1.models.ioc import IOCBundle, IOCType

try:
    import stix2
    STIX2_AVAILABLE = True
except ImportError:
    STIX2_AVAILABLE = False


class STIXExporter(BaseExporter):
    """Exportateur au format STIX 2.1.

    Génère un Bundle STIX contenant des Indicator et Observable pour chaque IOC.
    Dépendance optionnelle : stix2.
    """

    @property
    def format_name(self) -> str:
        return "stix21"

    def export(self, bundle: IOCBundle) -> str:
        if not STIX2_AVAILABLE:
            self._logger.error("stix2_library_missing")
            return json.dumps({"error": "stix2 library not installed"})

        stix_objects: list[Any] = []

        # Identité du créateur
        identity = stix2.Identity(
            name="ADMAP Platform M1",
            identity_class="system",
            description="Advanced Detection & Malware Analysis Platform - Static Extractor",
        )
        stix_objects.append(identity)

        # Fichier analysé comme Malware/File observable
        hashes = {}
        if bundle.metadata.hashes.md5:
            hashes["MD5"] = bundle.metadata.hashes.md5
        if bundle.metadata.hashes.sha1:
            hashes["SHA-1"] = bundle.metadata.hashes.sha1
        if bundle.metadata.hashes.sha256:
            hashes["SHA-256"] = bundle.metadata.hashes.sha256

        file_obj = stix2.File(
            name=bundle.metadata.filename,
            size=bundle.metadata.filesize,
            hashes=hashes,
        )
        stix_objects.append(file_obj)

        malware = stix2.Malware(
            name=f"Malware sample {bundle.metadata.filename}",
            is_family=False,
            created_by_ref=identity.id,
        )
        stix_objects.append(malware)

        # Relation Fichier -> Malware
        # stix2 handles refs directly or via relationships
        # Pour faire simple, on crée juste les Indicators.

        for ioc in bundle.iocs:
            pattern = self._create_stix_pattern(ioc)
            if not pattern:
                continue

            # Mappage de la confiance
            confidence = ioc.confidence_score

            indicator = stix2.Indicator(
                name=f"Extracted {ioc.type.value} from {bundle.metadata.filename}",
                description=f"Context: {ioc.context_snippet}",
                pattern=pattern,
                pattern_type="stix",
                valid_from=ioc.first_seen.replace(tzinfo=timezone.utc),
                created_by_ref=identity.id,
                confidence=confidence,
                kill_chain_phases=[
                    stix2.KillChainPhase(kill_chain_name="lockheed-martin-cyber-kill-chain", phase_name="delivery")
                ],
            )
            stix_objects.append(indicator)

            # Lier l'indicateur au malware
            rel = stix2.Relationship(
                source_ref=indicator.id,
                target_ref=malware.id,
                relationship_type="indicates",
                created_by_ref=identity.id,
            )
            stix_objects.append(rel)

        stix_bundle = stix2.Bundle(objects=stix_objects)
        return stix_bundle.serialize(indent=4)

    def _create_stix_pattern(self, ioc) -> str | None:
        """Traduit un type M1 en pattern STIX 2.1."""
        val = str(ioc.value).replace("'", "\\'")

        if ioc.type == IOCType.IPV4:
            return f"[ipv4-addr:value = '{val}']"
        elif ioc.type == IOCType.IPV6:
            return f"[ipv6-addr:value = '{val}']"
        elif ioc.type == IOCType.DOMAIN:
            return f"[domain-name:value = '{val}']"
        elif ioc.type == IOCType.URL:
            return f"[url:value = '{val}']"
        elif ioc.type == IOCType.EMAIL:
            return f"[email-addr:value = '{val}']"
        elif ioc.type == IOCType.HASH_MD5:
            return f"[file:hashes.'MD5' = '{val}']"
        elif ioc.type == IOCType.HASH_SHA1:
            return f"[file:hashes.'SHA-1' = '{val}']"
        elif ioc.type == IOCType.HASH_SHA256:
            return f"[file:hashes.'SHA-256' = '{val}']"
        elif ioc.type == IOCType.FILEPATH:
            return f"[file:name = '{val}']"
        elif ioc.type == IOCType.REGISTRY_KEY:
            return f"[windows-registry-key:key = '{val}']"
        elif ioc.type == IOCType.MUTEX:
            return f"[mutex:name = '{val}']"
        elif ioc.type == IOCType.COMMAND:
            return f"[process:command_line = '{val}']"
        
        return None
