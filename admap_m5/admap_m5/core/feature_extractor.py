from __future__ import annotations
import json
import structlog
from dataclasses import dataclass, field

logger = structlog.get_logger(__name__)


@dataclass
class ClusterFeatures:
    """Vecteur de features extrait pour un cluster donné."""
    cluster_id: str
    cluster_label: int
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    yara_tags: list[str] = field(default_factory=list)
    involved_ips: list[str] = field(default_factory=list)
    confidence_score: float = 0.0
    # Features additionnelles depuis M1
    sha256_hashes: list[str] = field(default_factory=list)
    ssdeep_hashes: list[str] = field(default_factory=list)
    imphash_values: list[str] = field(default_factory=list)
    suspicious_strings: list[str] = field(default_factory=list)
    # Features additionnelles depuis M2
    alert_types: list[str] = field(default_factory=list)
    suspicious_ips_m2: list[str] = field(default_factory=list)

    def to_token_list(self) -> list[str]:
        """Retourne la liste consolidée de tokens pour l'embedding TF-IDF."""
        return (
            self.techniques
            + self.tactics
            + self.yara_tags
            + self.alert_types
        )


class FeatureExtractor:
    """Extrait et normalise les features depuis APTMapReport (M4),
    IOCBundle (M1 optionnel) et AlertBundle (M2 optionnel).
    """

    def __init__(self) -> None:
        pass

    def extract(
        self,
        apt_map_report_json: str,
        ioc_bundle_json: str | None = None,
        alert_bundle_json: str | None = None,
        include_noise: bool = False,
    ) -> list[ClusterFeatures]:
        """Point d'entrée principal — parse les JSON et retourne les features par cluster."""
        try:
            report_data = json.loads(apt_map_report_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid apt_map_report_json: {exc}") from exc

        ioc_data: dict = {}
        if ioc_bundle_json:
            try:
                ioc_data = json.loads(ioc_bundle_json)
            except json.JSONDecodeError:
                logger.warning("feature_extractor.ioc_bundle_invalid_json")

        alert_data: dict = {}
        if alert_bundle_json:
            try:
                alert_data = json.loads(alert_bundle_json)
            except json.JSONDecodeError:
                logger.warning("feature_extractor.alert_bundle_invalid_json")

        cluster_bundle = report_data.get("cluster_bundle", {})
        clusters = cluster_bundle.get("clusters", [])

        features_list: list[ClusterFeatures] = []
        for cluster in clusters:
            label = cluster.get("cluster_label", -1)
            if label == -1 and not include_noise:
                continue

            cf = ClusterFeatures(
                cluster_id=cluster.get("cluster_id", "unknown"),
                cluster_label=label,
                techniques=cluster.get("dominant_techniques", []),
                tactics=cluster.get("dominant_tactics", []),
                yara_tags=cluster.get("yara_tags", []),
                involved_ips=cluster.get("involved_ips", []),
                confidence_score=float(cluster.get("confidence_score", 0.0)),
            )

            # Enrichissement M1
            if ioc_data:
                cf.sha256_hashes = [
                    h.get("sha256", "") for h in ioc_data.get("hashes", []) if h.get("sha256")
                ]
                cf.ssdeep_hashes = [
                    h.get("ssdeep", "") for h in ioc_data.get("hashes", []) if h.get("ssdeep")
                ]
                cf.imphash_values = [
                    h.get("imphash", "") for h in ioc_data.get("hashes", []) if h.get("imphash")
                ]
                cf.suspicious_strings = ioc_data.get("strings", [])[:50]  # Limite à 50

            # Enrichissement M2
            if alert_data:
                cf.alert_types = list({
                    a.get("alert_type", "") for a in alert_data.get("alerts", []) if a.get("alert_type")
                })
                cf.suspicious_ips_m2 = alert_data.get("top_suspicious_ips", [])

            features_list.append(cf)

        logger.info(
            "feature_extractor.done",
            clusters_total=len(clusters),
            clusters_extracted=len(features_list),
            noise_included=include_noise,
        )
        return features_list
