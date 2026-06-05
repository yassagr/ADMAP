"""
Module   : admap_m1.exporters.misp_exporter
Version  : 3.0.0
Dépend   : [json, admap_m1.exporters.base]

Exportateur MISP Event JSON. Permet l'import direct dans un serveur MISP.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from admap_m1.exporters.base import BaseExporter
from admap_m1.models.ioc import IOCBundle, IOCType


class MISPExporter(BaseExporter):
    """Exportateur au format MISP Event JSON.

    Construit un événement MISP complet avec les attributs correspondants
    pour chaque IOC trouvé, incluant le score et le contexte en commentaire.
    """

    # Mapping IOCType vers types d'attributs MISP
    MISP_TYPES = {
        IOCType.IPV4: "ip-dst",
        IOCType.IPV6: "ip-dst",
        IOCType.DOMAIN: "domain",
        IOCType.URL: "url",
        IOCType.EMAIL: "email-src",
        IOCType.HASH_MD5: "md5",
        IOCType.HASH_SHA1: "sha1",
        IOCType.HASH_SHA256: "sha256",
        IOCType.HASH_SSDEEP: "ssdeep",
        IOCType.HASH_IMPHASH: "imphash",
        IOCType.FILEPATH: "filename",
        IOCType.FILENAME: "filename",
        IOCType.REGISTRY_KEY: "regkey",
        IOCType.MUTEX: "mutex",
        IOCType.COMMAND: "pattern-in-memory",  # Approximation pour process command line
    }

    @property
    def format_name(self) -> str:
        return "misp"

    def export(self, bundle: IOCBundle) -> str:
        now_ts = int(datetime.now(timezone.utc).timestamp())
        
        event_id = str(uuid.uuid4())
        
        misp_event = {
            "Event": {
                "info": f"ADMAP M1 Extraction: {bundle.metadata.filename}",
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "timestamp": str(now_ts),
                "distribution": "0",  # Your organization only
                "threat_level_id": "2",  # Medium by default
                "analysis": "2",  # Completed
                "uuid": event_id,
                "Attribute": [],
                "Tag": [
                    {"name": "admap:m1", "colour": "#0088cc"},
                    {"name": "tlp:amber", "colour": "#ffc000"}
                ]
            }
        }

        # Ajouter le fichier analysé en lui-même (s'il a un sha256)
        if bundle.metadata.hashes.sha256:
            misp_event["Event"]["Attribute"].append({
                "type": "sha256",
                "category": "Payload delivery",
                "to_ids": False,
                "value": bundle.metadata.hashes.sha256,
                "comment": "Analyzed file hash",
                "timestamp": str(now_ts)
            })

        for ioc in bundle.iocs:
            misp_type = self.MISP_TYPES.get(ioc.type)
            if not misp_type:
                continue

            # N'exporter que si la confiance est >= LOW (on ignore les NOISE par défaut)
            to_ids = ioc.confidence_score >= 60

            attr: dict[str, Any] = {
                "type": misp_type,
                "category": self._get_misp_category(ioc.type),
                "to_ids": to_ids,
                "value": ioc.value,
                "comment": f"Confidence: {ioc.confidence_score} | Context: {ioc.context_snippet}",
                "timestamp": str(now_ts),
                "disable_correlation": not to_ids,
            }
            
            # Ajouter les tags d'audit
            if ioc.scoring_reasons:
                tags = [{"name": f"admap:reason=\"{r}\""} for r in ioc.scoring_reasons]
                attr["Tag"] = tags

            misp_event["Event"]["Attribute"].append(attr)

        return json.dumps(misp_event, indent=4)

    def _get_misp_category(self, ioc_type: IOCType) -> str:
        if ioc_type in (IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL):
            return "Network activity"
        elif ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256, 
                          IOCType.HASH_SSDEEP, IOCType.HASH_IMPHASH, IOCType.FILEPATH, IOCType.FILENAME):
            return "Payload delivery"
        elif ioc_type in (IOCType.REGISTRY_KEY, IOCType.MUTEX):
            return "Artifacts dropped"
        elif ioc_type == IOCType.EMAIL:
            return "Payload delivery"
        elif ioc_type == IOCType.COMMAND:
            return "Artifacts dropped"
        return "Other"
