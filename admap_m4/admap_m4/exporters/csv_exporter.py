from __future__ import annotations
from admap_m4.models.report import APTMapReport

class CSVExporter:
    """Exporteur CSV pour M4."""

    def export(self, report: APTMapReport) -> str:
        """
        Exporte les clusters du rapport au format CSV.
        Colonnes : cluster_id, cluster_label, confidence_score, dominant_techniques, dominant_tactics, member_count, involved_ips, first_seen, last_seen
        Ne lève jamais RuntimeError.
        """
        try:
            lines = []
            header = "cluster_id,cluster_label,confidence_score,dominant_techniques,dominant_tactics,member_count,involved_ips,first_seen,last_seen"
            lines.append(header)

            for cluster in report.cluster_bundle.clusters:
                # Échapper ou joindre les listes pour éviter de casser le CSV
                techniques = "|".join(cluster.dominant_techniques)
                tactics = "|".join(cluster.dominant_tactics)
                ips = "|".join(cluster.involved_ips)
                member_count = str(len(cluster.member_profile_ids))

                row = [
                    cluster.cluster_id,
                    str(cluster.cluster_label),
                    str(cluster.confidence_score),
                    techniques,
                    tactics,
                    member_count,
                    ips,
                    cluster.first_seen.isoformat(),
                    cluster.last_seen.isoformat()
                ]
                # Envelopper dans des guillemets si besoin (ici, un simple join suffit car on a remplacé les virgules internes par des pipes)
                lines.append(",".join(row))

            return "\n".join(lines)
        except Exception as e:
            return f"error,code\n{str(e)},CSV_EXPORT_FAILED"
