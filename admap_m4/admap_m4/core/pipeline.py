from __future__ import annotations
import json
import time
import uuid
import structlog
from datetime import datetime, timezone
from admap_m4.config import Settings, get_settings
from admap_m4.models.report import AnalysisOptions, APTMapReport
from admap_m4.models.cluster import ClusterBundle
from admap_m4.core.ttp_extractor import TTPExtractor
from admap_m4.core.tfidf_vectorizer import ManualTFIDFVectorizer
from admap_m4.core.dbscan_clusterer import ManualDBSCANClusterer
from admap_m4.core.mitre_mapper import MITREMapper

class AnalysisPipeline:
    """
    Pipeline asynchrone M4 — 6 stages.

    Stage 1 : Ingestion (parse JSON AlertBundle + IOCBundle + YaraRuleSet)
    Stage 2 : TTP Extraction (AlertBundle -> list[TTPProfile])
    Stage 3 : TF-IDF Vectorisation (TTPProfiles -> TTPVectors)
    Stage 4 : DBSCAN Clustering (TTPVectors -> ClusterBundle)
    Stage 5 : MITRE ATT&CK Mapping (ClusterBundle -> coverage dict)
    Stage 6 : Export (APTMapReport finalisé)

    Signature du constructeur :
        AnalysisPipeline(settings: Settings | None = None, options: AnalysisOptions | None = None)
    """

    def __init__(
        self,
        settings: Settings | None = None,
        options: AnalysisOptions | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._options = options or AnalysisOptions()
        self._log = structlog.get_logger(self.__class__.__name__)
        self._extractor = TTPExtractor(self._settings)
        self._vectorizer = ManualTFIDFVectorizer(self._settings)
        self._clusterer = ManualDBSCANClusterer(self._settings)
        self._mapper = MITREMapper(self._settings)

    async def run(
        self,
        alert_bundle_json: str,
        ioc_bundle_json: str | None = None,
        yara_ruleset_json: str | None = None,
    ) -> APTMapReport:
        """
        Point d'entrée principal du pipeline.

        Args:
            alert_bundle_json: JSON string de l'AlertBundle M2.
            ioc_bundle_json: JSON string de l'IOCBundle M1 (optionnel).
            yara_ruleset_json: JSON string du YaraRuleSet M3 (optionnel).

        Returns:
            APTMapReport complet.
        """
        start_time = time.monotonic()
        report_id = str(uuid.uuid4())

        self._log.info("pipeline_start", report_id=report_id)

        # Stage 1 : Ingestion
        alert_bundle = await self._stage1_ingest(
            alert_bundle_json, ioc_bundle_json, yara_ruleset_json
        )

        # Stage 2 : TTP Extraction
        profiles = await self._stage2_extract_ttps(
            alert_bundle["alert_bundle"],
            alert_bundle.get("yara_ruleset"),
        )

        # Stage 3 : Vectorisation TF-IDF
        vectors = await self._stage3_vectorize(profiles)

        # Stage 4 : DBSCAN Clustering
        cluster_bundle = await self._stage4_cluster(
            vectors, profiles, alert_bundle["alert_bundle"].get("bundle_id", "")
        )

        # Stage 5 : MITRE Mapping
        mitre_coverage = await self._stage5_mitre_map(cluster_bundle)

        # Stage 6 : Rapport final
        report = await self._stage6_finalize(
            report_id, alert_bundle["alert_bundle"].get("bundle_id", ""),
            cluster_bundle, mitre_coverage, start_time,
        )

        duration = time.monotonic() - start_time
        self._log.info("pipeline_complete", report_id=report_id, duration=duration)
        return report

    async def _stage1_ingest(
        self,
        alert_bundle_json: str,
        ioc_bundle_json: str | None,
        yara_ruleset_json: str | None,
    ) -> dict[str, object]:
        """Stage 1 : Parse les JSON d'entrée."""
        try:
            alert_bundle = json.loads(alert_bundle_json)
        except json.JSONDecodeError as e:
            self._log.error("stage1_invalid_alert_bundle", error=str(e))
            raise ValueError(f"Invalid AlertBundle JSON: {e}") from e

        ioc_bundle = None
        if ioc_bundle_json:
            try:
                ioc_bundle = json.loads(ioc_bundle_json)
            except json.JSONDecodeError as e:
                self._log.warning("stage1_invalid_ioc_bundle", error=str(e))

        yara_ruleset = None
        if yara_ruleset_json:
            try:
                yara_ruleset = json.loads(yara_ruleset_json)
            except json.JSONDecodeError as e:
                self._log.warning("stage1_invalid_yara_ruleset", error=str(e))

        self._log.info(
            "stage1_ingest_complete",
            has_ioc=ioc_bundle is not None,
            has_yara=yara_ruleset is not None,
            n_alerts=len(alert_bundle.get("alerts", [])),
        )
        return {
            "alert_bundle": alert_bundle,
            "ioc_bundle": ioc_bundle,
            "yara_ruleset": yara_ruleset,
        }

    async def _stage2_extract_ttps(self, alert_bundle: dict, yara_ruleset: dict | None):
        profiles = self._extractor.extract(alert_bundle, yara_ruleset)
        self._log.info("stage2_complete", n_profiles=len(profiles))
        return profiles

    async def _stage3_vectorize(self, profiles):
        vectors = self._vectorizer.fit_transform(profiles)
        self._log.info("stage3_complete", n_vectors=len(vectors))
        return vectors

    async def _stage4_cluster(self, vectors, profiles, source_bundle_id: str) -> ClusterBundle:
        bundle = self._clusterer.cluster(
            vectors, profiles,
            epsilon=self._options.dbscan_epsilon,
            min_samples=self._options.dbscan_min_samples,
        )
        # Patch source_bundle_id (ClusterBundle frozen -> recréer)
        bundle = bundle.model_copy(update={"source_bundle_id": source_bundle_id})
        self._log.info("stage4_complete", n_clusters=bundle.total_clusters)
        return bundle

    async def _stage5_mitre_map(self, cluster_bundle: ClusterBundle) -> dict[str, list[str]]:
        coverage = self._mapper.map_coverage(cluster_bundle)
        self._log.info("stage5_complete", n_tactics=len(coverage))
        return coverage

    async def _stage6_finalize(
        self,
        report_id: str,
        source_bundle_id: str,
        cluster_bundle: ClusterBundle,
        mitre_coverage: dict[str, list[str]],
        start_time: float,
    ) -> APTMapReport:
        # Top techniques et tactiques
        tech_count: dict[str, int] = {}
        tac_count: dict[str, int] = {}
        for cluster in cluster_bundle.clusters:
            for t in cluster.dominant_techniques:
                tech_count[t] = tech_count.get(t, 0) + 1
            for tac in cluster.dominant_tactics:
                tac_count[tac] = tac_count.get(tac, 0) + 1

        top_techniques = sorted(tech_count.items(), key=lambda x: -x[1])[:10]
        top_tactics = sorted(tac_count.items(), key=lambda x: -x[1])

        return APTMapReport(
            report_id=report_id,
            source_bundle_id=source_bundle_id,
            cluster_bundle=cluster_bundle,
            mitre_coverage=mitre_coverage,
            top_techniques=top_techniques,
            top_tactics=top_tactics,
            campaign_count=cluster_bundle.total_clusters,
            noise_count=cluster_bundle.noise_count,
            analysis_duration_seconds=round(time.monotonic() - start_time, 3),
            options_used=self._options,
            created_at=datetime.now(timezone.utc),
        )
