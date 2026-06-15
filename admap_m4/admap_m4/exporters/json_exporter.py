from __future__ import annotations
from admap_m4.models.report import APTMapReport

class JSONExporter:
    """Exporteur JSON pour M4."""

    def export(self, report: APTMapReport) -> dict[str, object]:
        """
        Exporte le rapport en dict JSON-serializable.
        Ne lève jamais RuntimeError.
        """
        try:
            return report.model_dump(mode="json")
        except Exception as e:
            return {
                "error": str(e),
                "code": "JSON_EXPORT_FAILED",
                "context": {},
            }
