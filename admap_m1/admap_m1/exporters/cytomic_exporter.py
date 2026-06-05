"""
Module   : admap_m1.exporters.cytomic_exporter
Version  : 3.0.0
Dépend   : [json, admap_m1.exporters.base]

Exportateur pour WatchGuard Cytomic Orion (Custom JSON).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from admap_m1.exporters.base import BaseExporter
from admap_m1.models.ioc import IOCBundle, IOCType


class CytomicExporter(BaseExporter):
    """Exportateur au format JSON pour intégration Cytomic Orion (WatchGuard).

    Génère une liste d'indicateurs avec leurs actions (Block, Audit)
    selon la confiance de l'IOC.
    """

    CYTOMIC_TYPES = {
        IOCType.IPV4: "IpAddress",
        IOCType.DOMAIN: "Domain",
        IOCType.URL: "Url",
        IOCType.HASH_MD5: "Md5",
        IOCType.HASH_SHA256: "Sha256",
        # Cytomic ne gère généralement pas nativement les regex ou process cmdline 
        # dans les listes d'IOCs basiques, on filtre les plus standards
    }

    @property
    def format_name(self) -> str:
        return "cytomic"

    def export(self, bundle: IOCBundle) -> str:
        indicators = []

        for ioc in bundle.iocs:
            c_type = self.CYTOMIC_TYPES.get(ioc.type)
            if not c_type:
                continue

            # Déterminer l'action selon la confiance
            if ioc.confidence_score >= 80:
                action = "Block"
            elif ioc.confidence_score >= 60:
                action = "Audit"
            else:
                # On n'exporte pas les IOCs faibles vers un EDR
                continue

            indicator = {
                "Type": c_type,
                "Value": str(ioc.value),
                "Action": action,
                "Description": f"Auto-extracted from {bundle.metadata.filename} by ADMAP M1",
                "CreationDate": ioc.first_seen.replace(tzinfo=timezone.utc).isoformat(),
                "ExpirationDate": None,  # Permanent by default
                "Tags": ["ADMAP", "Auto-Generated", f"Score:{ioc.confidence_score}"]
            }
            indicators.append(indicator)

        payload = {
            "Indicators": indicators,
            "Metadata": {
                "Source": "ADMAP M1",
                "FileAnalyzed": bundle.metadata.filename,
                "FileHash": bundle.metadata.hashes.sha256,
                "TotalIndicators": len(indicators)
            }
        }

        return json.dumps(payload, indent=4)
