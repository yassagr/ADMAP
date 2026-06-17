from __future__ import annotations
import asyncio
import time
import uuid
from datetime import datetime, timezone

import structlog

from admap_m5.config import M5Settings, get_settings
from admap_m5.core.apt_kb import APTKnowledgeBase, APTGroup
from admap_m5.core.embedder import CosineEmbedder
from admap_m5.core.feature_extractor import FeatureExtractor, ClusterFeatures
from admap_m5.core.xgb_classifier import XGBAttributor
from admap_m5.models.input import AttributionOptions
from admap_m5.models.output import AttributionReport, AttributionResult, APTCandidate

logger = structlog.get_logger(__name__)


class AttributionPipeline:
    """Pipeline d'attribution APT en 5 stages.
    
    Stage 1 : Feature extraction (M4 + M1 opt + M2 opt)
    Stage 2 : Corpus embedding (fit TF-IDF sur KB + transform clusters)
    Stage 3 : Cosine similarity (cluster vs chaque APT group)
    Stage 4 : XGBoost scoring (probabilités par APT group)
    Stage 5 : Score fusion + ranking → AttributionReport
    """

    def __init__(
        self,
        settings: M5Settings | None = None,
        options: AttributionOptions | None = None,
    ) -> None:
        self._settings: M5Settings = settings or get_settings()
        self._options: AttributionOptions = options or AttributionOptions()
        self._kb: APTKnowledgeBase | None = None
        self._embedder: CosineEmbedder | None = None
        self._extractor: FeatureExtractor = FeatureExtractor()
        self._xgb: XGBAttributor | None = None

    def _ensure_initialized(self) -> None:
        """Lazy initialization des composants lourds."""
        if self._kb is None:
            self._kb = APTKnowledgeBase(self._settings.apt_kb_path)
        if self._xgb is None:
            self._xgb = XGBAttributor(self._settings.xgb_model_path)

    async def run(
        self,
        apt_map_report_json: str,
        ioc_bundle_json: str | None = None,
        alert_bundle_json: str | None = None,
        options: AttributionOptions | None = None,
    ) -> AttributionReport:
        """Exécute le pipeline complet et retourne un AttributionReport."""
        options = options or self._options
        start_time = time.monotonic()
        report_id = str(uuid.uuid4())

        logger.info("pipeline.start", report_id=report_id)

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            self._run_sync,
            apt_map_report_json,
            ioc_bundle_json,
            alert_bundle_json,
            options,
            report_id,
            start_time,
        )
        return result

    def _run_sync(
        self,
        apt_map_report_json: str,
        ioc_bundle_json: str | None,
        alert_bundle_json: str | None,
        options: AttributionOptions,
        report_id: str,
        start_time: float,
    ) -> AttributionReport:
        """Exécution synchrone des 5 stages — appelée via run_in_executor."""
        import json as _json
        self._ensure_initialized()
        assert self._kb is not None
        assert self._xgb is not None

        # Extraction du source_report_id
        try:
            source_report_id = _json.loads(apt_map_report_json).get("report_id", "unknown")
        except Exception:
            source_report_id = "unknown"

        # Calcul noise_skipped AVANT filtrage (depuis le JSON brut)
        total_noise_in_report = self._count_noise_clusters(apt_map_report_json)
        noise_skipped = total_noise_in_report if not options.include_noise_clusters else 0

        # -- Stage 1 : Feature extraction ------------------------------------
        logger.info("pipeline.stage1_feature_extraction", report_id=report_id)
        features_list: list[ClusterFeatures] = self._extractor.extract(
            apt_map_report_json=apt_map_report_json,
            ioc_bundle_json=ioc_bundle_json,
            alert_bundle_json=alert_bundle_json,
            include_noise=options.include_noise_clusters,
        )

        # -- Stage 2 : Corpus embedding (TF-IDF) -----------------------------
        logger.info("pipeline.stage2_embedding", report_id=report_id)
        embedder = CosineEmbedder()
        apt_groups = self._kb.groups

        # Corpus = TTPs de tous les groupes APT + features des clusters
        corpus: list[list[str]] = []
        for grp in apt_groups:
            corpus.append(grp.signature_techniques + grp.signature_tactics)
        for cf in features_list:
            corpus.append(cf.to_token_list())

        embedder.fit(corpus)

        # Vecteurs APT
        apt_vectors: dict[str, list[float]] = {}
        for grp in apt_groups:
            tokens = grp.signature_techniques + grp.signature_tactics
            apt_vectors[grp.apt_id] = embedder.transform(tokens)

        # ── Stage 3 + 4 + 5 : Scoring par cluster ────────────────────────────
        results: list[AttributionResult] = []

        for cf in features_list:
            if cf.cluster_label == -1 and not options.include_noise_clusters:
                continue

            cluster_vector = embedder.transform(cf.to_token_list())
            feature_dim = len(cluster_vector)

            # Cosine similarities
            cosine_scores: dict[str, float] = {}
            if options.use_cosine_similarity:
                for apt_id, apt_vec in apt_vectors.items():
                    cosine_scores[apt_id] = CosineEmbedder.cosine_similarity(
                        cluster_vector, apt_vec
                    )

            # XGBoost probabilities
            xgb_scores: dict[str, float] = {}
            if options.use_xgboost:
                xgb_scores = self._xgb.predict_proba(cluster_vector, apt_groups)

            # Détermine la méthode d'analyse
            if options.use_xgboost and options.use_cosine_similarity:
                method = "xgboost+cosine"
            elif options.use_xgboost:
                method = "xgboost_only"
            elif options.use_cosine_similarity:
                method = "cosine_only"
            else:
                method = "fallback"

            # Score fusion
            w_cosine = self._settings.cosine_similarity_weight
            w_xgb = self._settings.xgb_weight
            candidates: list[APTCandidate] = []

            for grp in apt_groups:
                cos = cosine_scores.get(grp.apt_id, 0.0)
                xgb_prob = xgb_scores.get(grp.apt_id, 1.0 / max(len(apt_groups), 1))

                # Score fusionné normalisé sur 100
                if options.use_cosine_similarity and options.use_xgboost:
                    fused_score = (cos * w_cosine + xgb_prob * w_xgb) * 100.0
                elif options.use_cosine_similarity:
                    fused_score = cos * 100.0
                elif options.use_xgboost:
                    fused_score = xgb_prob * 100.0
                else:
                    fused_score = 0.0

                # Calcul des matchs concrets
                matched_techniques = [
                    t for t in cf.techniques if t in grp.signature_techniques
                ]
                matched_tactics = [
                    t for t in cf.tactics if t in grp.signature_tactics
                ]
                matched_yara = [
                    tag for tag in cf.yara_tags if tag.lower() in [y.lower() for y in grp.signature_yara_tags]
                ]
                matched_ips = [
                    ip for ip in cf.involved_ips if any(ip.startswith(pattern.split("/")[0][:8]) for pattern in grp.signature_ips)
                ]

                if fused_score < options.min_confidence:
                    continue

                evidence_parts: list[str] = []
                if matched_techniques:
                    evidence_parts.append(f"Techniques: {', '.join(matched_techniques[:5])}")
                if matched_tactics:
                    evidence_parts.append(f"Tactics: {', '.join(matched_tactics[:3])}")
                if matched_yara:
                    evidence_parts.append(f"YARA: {', '.join(matched_yara[:3])}")
                if matched_ips:
                    evidence_parts.append(f"IPs: {', '.join(matched_ips[:3])}")
                evidence_summary = "; ".join(evidence_parts) if evidence_parts else "Indirect TTP correlation"

                candidates.append(APTCandidate(
                    rank=0,  # Sera réassigné après tri
                    apt_name=grp.apt_name,
                    apt_id=grp.apt_id,
                    confidence_score=round(min(100.0, fused_score), 2),
                    xgb_probability=round(xgb_prob, 4),
                    cosine_similarity=round(cos, 4),
                    matched_techniques=matched_techniques,
                    matched_tactics=matched_tactics,
                    matched_yara_tags=matched_yara,
                    matched_ips=matched_ips,
                    evidence_summary=evidence_summary,
                    mitre_group_url=grp.mitre_url,
                ))

            # Tri et limitation au top-k
            candidates.sort(key=lambda c: c.confidence_score, reverse=True)
            top_k = options.top_k
            top_candidates = candidates[:top_k]

            # Réassigner les rangs
            ranked_candidates = []
            for rank, cand in enumerate(top_candidates, start=1):
                ranked_candidates.append(cand.model_copy(update={"rank": rank}))

            results.append(AttributionResult(
                cluster_id=cf.cluster_id,
                cluster_label=cf.cluster_label,
                candidates=ranked_candidates,
                feature_vector_size=feature_dim,
                analysis_method=method,
            ))

        # Candidat global le plus probable (meilleur score parmi tous les clusters)
        all_candidates = [c for r in results for c in r.candidates if r.candidates]
        top_global: APTCandidate | None = None
        if all_candidates:
            top_global = max(all_candidates, key=lambda c: c.confidence_score)

        duration = time.monotonic() - start_time
        logger.info(
            "pipeline.done",
            report_id=report_id,
            clusters_analyzed=len(results),
            duration_seconds=round(duration, 3),
        )

        return AttributionReport(
            report_id=report_id,
            source_report_id=source_report_id,
            results=results,
            top_global_candidate=top_global,
            total_clusters_analyzed=len(results),
            noise_clusters_skipped=noise_skipped,
            analysis_duration_seconds=round(duration, 3),
            options_used=options.model_dump(),
            created_at=datetime.now(timezone.utc),
        )

    def _count_noise_clusters(self, apt_map_report_json: str) -> int:
        """Compte les clusters noise (label=-1) dans le rapport brut JSON."""
        import json as _json
        try:
            data = _json.loads(apt_map_report_json)
            clusters = data.get("cluster_bundle", {}).get("clusters", [])
            return sum(1 for c in clusters if c.get("cluster_label", 0) == -1)
        except Exception:
            return 0
