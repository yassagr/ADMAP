"""
Module   : admap_m2.exporters.csv_exporter
Version  : 1.0.0
Dépend   : [csv, io, admap_m2.exporters.base]
"""
from __future__ import annotations

import csv
import io

from admap_m2.exporters.base import BaseExporter
from admap_m2.models.alert import AlertBundle


class CSVExporter(BaseExporter):
    """Exporte les alertes au format CSV pour l'ingestion SIEM."""

    def export(self, bundle: AlertBundle) -> str:
        if not bundle.alerts:
            return "id,alert_type,severity,score,src_ip,dst_ip,src_port,dst_port,protocol,first_seen,description\n"

        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "id", "alert_type", "severity", "score",
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "first_seen", "description"
        ])
        
        for alert in bundle.alerts:
            writer.writerow([
                str(alert.id),
                alert.alert_type.value,
                alert.severity.value,
                alert.confidence_score,
                alert.src_ip,
                alert.dst_ip,
                alert.src_port,
                alert.dst_port,
                alert.protocol,
                alert.first_seen.isoformat(),
                alert.description
            ])
            
        return output.getvalue()
