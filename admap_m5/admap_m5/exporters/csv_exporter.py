from __future__ import annotations
import csv
import io
import structlog
from admap_m5.models.output import AttributionReport, AttributionResult, APTCandidate

logger = structlog.get_logger(__name__)


class CSVExporter:
    """Exporte un AttributionReport en CSV SIEM."""

    COLUMNS = [
        "cluster_id", "cluster_label", "rank", "apt_name", "apt_id",
        "confidence_score", "xgb_probability", "cosine_similarity",
        "matched_techniques", "matched_tactics", "matched_yara_tags",
        "evidence_summary", "analysis_method", "mitre_group_url",
    ]

    def export(self, report: AttributionReport) -> dict:
        """Retourne {csv: str}. Ne lève jamais RuntimeError."""
        try:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=self.COLUMNS, extrasaction="ignore")
            writer.writeheader()

            for result in report.results:
                for candidate in result.candidates:
                    writer.writerow({
                        "cluster_id": result.cluster_id,
                        "cluster_label": result.cluster_label,
                        "rank": candidate.rank,
                        "apt_name": candidate.apt_name,
                        "apt_id": candidate.apt_id,
                        "confidence_score": candidate.confidence_score,
                        "xgb_probability": candidate.xgb_probability,
                        "cosine_similarity": candidate.cosine_similarity,
                        "matched_techniques": "|".join(candidate.matched_techniques),
                        "matched_tactics": "|".join(candidate.matched_tactics),
                        "matched_yara_tags": "|".join(candidate.matched_yara_tags),
                        "evidence_summary": candidate.evidence_summary,
                        "analysis_method": result.analysis_method,
                        "mitre_group_url": candidate.mitre_group_url,
                    })

            return {"csv": output.getvalue()}
        except Exception as exc:
            logger.error("csv_exporter.failed", error=str(exc))
            return {"error": str(exc), "report_id": getattr(report, "report_id", "unknown")}
