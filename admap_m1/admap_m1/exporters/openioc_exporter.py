"""
Module   : admap_m1.exporters.openioc_exporter
Version  : 3.0.0
Dépend   : [xml.etree.ElementTree, admap_m1.exporters.base]

Exportateur OpenIOC (XML) pour rétro-compatibilité.
"""
from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from xml.dom import minidom

from admap_m1.exporters.base import BaseExporter
from admap_m1.models.ioc import IOCBundle, IOCType


class OpenIOCExporter(BaseExporter):
    """Exportateur au format OpenIOC 1.1.

    Génère un document XML conforme au schéma OpenIOC, utile pour
    l'intégration avec des outils legacy de type Mandiant/FireEye.
    """

    # Mapping IOCType vers Termes OpenIOC
    IOC_TERMS = {
        IOCType.IPV4: "PortItem/remote_IP",
        IOCType.IPV6: "PortItem/remote_IP",
        IOCType.DOMAIN: "Network/DNS",
        IOCType.URL: "UrlHistoryItem/URL",
        IOCType.HASH_MD5: "FileItem/Md5sum",
        IOCType.HASH_SHA1: "FileItem/Sha1sum",
        IOCType.HASH_SHA256: "FileItem/Sha256sum",
        IOCType.FILEPATH: "FileItem/FullPath",
        IOCType.FILENAME: "FileItem/FileName",
        IOCType.REGISTRY_KEY: "RegistryItem/Path",
        IOCType.MUTEX: "ProcessItem/HandleList/Handle/Name",
        IOCType.COMMAND: "ProcessItem/CommandLine",
    }

    @property
    def format_name(self) -> str:
        return "openioc"

    def export(self, bundle: IOCBundle) -> str:
        # Espaces de noms OpenIOC standard
        ns = {
            "xmlns": "http://openioc.org/schemas/OpenIOC_1.1",
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "id": str(uuid.uuid4()),
            "last-modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            "published-date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        }

        root = ET.Element("ioc", attrib=ns)

        # Metadata
        metadata = ET.SubElement(root, "metadata")
        short_desc = ET.SubElement(metadata, "short_description")
        short_desc.text = f"ADMAP M1 Auto-Generated IOCs for {bundle.metadata.filename}"
        
        desc = ET.SubElement(metadata, "description")
        desc.text = f"Automated extraction from M1 Pipeline v{bundle.pipeline_version}. Hashes: {bundle.metadata.hashes.sha256}"
        
        authored = ET.SubElement(metadata, "authored_by")
        authored.text = "ADMAP M1"
        
        links = ET.SubElement(metadata, "links")

        # Criteria (le conteneur des indicateurs)
        criteria = ET.SubElement(root, "criteria")
        indicator = ET.SubElement(criteria, "Indicator", attrib={
            "operator": "OR",
            "id": str(uuid.uuid4())
        })

        for ioc in bundle.iocs:
            search = self.IOC_TERMS.get(ioc.type)
            if not search:
                continue

            # Créer l'item OpenIOC
            item = ET.SubElement(indicator, "IndicatorItem", attrib={
                "id": str(ioc.id),
                "condition": "contains"
            })
            
            ctx = ET.SubElement(item, "Context", attrib={
                "document": search.split('/')[0],
                "search": search
            })
            
            content = ET.SubElement(item, "Content", attrib={"type": "string"})
            content.text = str(ioc.value)

        # Pretty print XML
        raw_xml = ET.tostring(root, encoding="utf-8")
        parsed = minidom.parseString(raw_xml)
        return parsed.toprettyxml(indent="  ")
