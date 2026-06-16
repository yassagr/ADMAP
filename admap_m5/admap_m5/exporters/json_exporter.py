from __future__ import annotations
import structlog
from admap_m5.models.output import AttributionReport

logger = structlog.get_logger(__name__)


class JSONExporter:
    """Exporte un AttributionReport en JSON natif ADMAP."""

    def export(self, report: AttributionReport) -> dict:
        """Retourne un dict exportable. Ne lève jamais RuntimeError."""
        try:
            return report.model_dump(mode="json")
        except Exception as exc:
            logger.error("json_exporter.failed", error=str(exc))
            return {"error": str(exc), "report_id": getattr(report, "report_id", "unknown")}
