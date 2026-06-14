"""
Module   : admap_m3.core.pipeline
Version  : 1.0.0
Dépend   : [admap_m3.config, admap_m3.core.*, admap_m3.models.*, structlog]

Pipeline de génération asynchrone en 6 stages :
  1. Validation des chemins
  2. Extraction features malware
  3. Extraction features bénins
  4. Enrichissement IOC M1 (optionnel)
  5. Calcul TF-IDF + scoring
  6. Construction + validation → YaraRuleSet
"""
from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog

from admap_m3.config import Settings, get_settings
from admap_m3.core.builder import YaraRuleBuilder
from admap_m3.core.extractor import BinaryFeatureExtractor
from admap_m3.core.scorer import TokenScorer
from admap_m3.core.tfidf import TFIDFEngine
from admap_m3.core.validator import YaraValidator
from admap_m3.models.corpus import FileLabel
from admap_m3.models.rule import RuleMetadata, YaraRule, YaraRuleSet
from admap_m3.models.token import TokenFeature, TokenScore

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


class GenerationPipeline:
    """Pipeline asynchrone en 6 stages pour générer un ``YaraRuleSet``.

    Signature OBLIGATOIRE du constructeur :
        ``def __init__(self, settings=None, options=None)``

    Si ``settings`` est ``None`` → appelle ``get_settings()``.
    Si ``options`` est ``None`` → utilise ``{}``.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        self._settings: Settings = settings if settings is not None else get_settings()
        self._options: dict[str, Any] = options if options is not None else {}
        self._extractor: BinaryFeatureExtractor = BinaryFeatureExtractor(self._settings)
        self._tfidf: TFIDFEngine = TFIDFEngine(self._settings)
        self._scorer: TokenScorer = TokenScorer(self._settings)
        self._builder: YaraRuleBuilder = YaraRuleBuilder(self._settings)
        self._validator: YaraValidator = YaraValidator()

    async def run(
        self,
        malware_paths: list[str],
        benign_paths: list[str],
        corpus_id: str,
        m1_bundle_path: str | None = None,
        malware_family: str | None = None,
        mitre_attack: list[str] | None = None,
    ) -> YaraRuleSet:
        """Exécute le pipeline complet de génération YARA.

        Args:
            malware_paths: Chemins des fichiers malware.
            benign_paths: Chemins des fichiers bénins.
            corpus_id: Identifiant unique du corpus.
            m1_bundle_path: Chemin du IOCBundle M1 (optionnel).
            malware_family: Famille de malware ciblée (optionnel).
            mitre_attack: Liste des IDs MITRE ATT&CK (optionnel).

        Returns:
            ``YaraRuleSet`` contenant les règles générées et validées.
        """
        pipeline_start: float = time.monotonic()

        # ── Stage 1 : Validation des chemins ─────────────────────────────
        stage_start: float = time.monotonic()
        self._validate_paths(malware_paths + benign_paths)
        self._log_stage(1, "path_validation", stage_start, len(malware_paths) + len(benign_paths))

        # ── Stage 2 : Extraction features malware ────────────────────────
        stage_start = time.monotonic()
        malware_token_lists: list[list[str]] = []
        for path in malware_paths:
            _, tokens = self._extractor.extract(path, FileLabel.MALWARE)
            malware_token_lists.append(tokens)
        self._log_stage(2, "malware_extraction", stage_start, len(malware_paths))

        # ── Stage 3 : Extraction features bénins ─────────────────────────
        stage_start = time.monotonic()
        benign_token_lists: list[list[str]] = []
        for path in benign_paths:
            _, tokens = self._extractor.extract(path, FileLabel.BENIGN)
            benign_token_lists.append(tokens)
        self._log_stage(3, "benign_extraction", stage_start, len(benign_paths))

        # ── Stage 4 : Enrichissement IOC M1 (optionnel) ──────────────────
        stage_start = time.monotonic()
        if m1_bundle_path and self._settings.m1_integration_enabled:
            m1_tokens: list[str] = await self._enrich_with_m1(m1_bundle_path)
            if m1_tokens:
                # Ajouter les tokens M1 à chaque liste de tokens malware
                for token_list in malware_token_lists:
                    token_list.extend(m1_tokens)
            self._log_stage(4, "m1_enrichment", stage_start, len(m1_tokens) if m1_tokens else 0)
        else:
            self._log_stage(4, "m1_enrichment_skipped", stage_start, 0)

        # ── Stage 5 : Calcul TF-IDF + scoring ───────────────────────────
        stage_start = time.monotonic()
        features: list[TokenFeature] = self._tfidf.compute_corpus_tfidf(
            malware_token_lists, benign_token_lists, corpus_id
        )
        scores: list[TokenScore] = self._scorer.filter_and_score(features)
        top_tokens: list[TokenScore] = self._scorer.top_n(
            scores, self._settings.max_tokens_per_rule
        )
        self._log_stage(5, "tfidf_scoring", stage_start, len(features))

        # ── Stage 6 : Construction + validation ──────────────────────────
        stage_start = time.monotonic()
        rules: list[YaraRule] = []

        if len(top_tokens) >= self._settings.min_tokens_per_rule:
            # Calculer un hash du corpus pour les métadonnées
            corpus_hash: str = self._compute_corpus_hash(malware_paths + benign_paths)

            metadata: RuleMetadata = RuleMetadata(
                description=f"Auto-generated YARA rule for corpus {corpus_id}",
                date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                corpus_id=corpus_id,
                malware_family=malware_family,
                mitre_attack=mitre_attack or [],
                hash_corpus=corpus_hash,
            )

            rule_name: str = malware_family or corpus_id
            rule: YaraRule = self._builder.build_rule(top_tokens, metadata, rule_name)
            validated_rule: YaraRule = self._validator.validate_rule(rule)
            rules.append(validated_rule)

        compiled_count: int = sum(1 for r in rules if r.compiled)
        failed_count: int = len(rules) - compiled_count

        ruleset: YaraRuleSet = YaraRuleSet(
            ruleset_id=f"RS_{uuid.uuid4().hex[:12]}",
            corpus_id=corpus_id,
            rules=rules,
            total_rules=len(rules),
            compiled_rules=compiled_count,
            failed_rules=failed_count,
            generation_duration_ms=(time.monotonic() - pipeline_start) * 1000,
        )

        self._log_stage(6, "build_validate", stage_start, len(rules))

        logger.info(
            "pipeline_complete",
            corpus_id=corpus_id,
            ruleset_id=ruleset.ruleset_id,
            total_rules=len(rules),
            compiled_rules=compiled_count,
            duration_ms=ruleset.generation_duration_ms,
        )

        return ruleset

    # ── Méthodes privées ─────────────────────────────────────────────────

    def _validate_paths(self, paths: list[str]) -> None:
        """Valide que tous les fichiers existent et respectent la taille max.

        Vérifie aussi l'absence de traversée de chemin (``..``).
        """
        for path in paths:
            # Sécurité : pas de traversée de chemin
            normalized: str = os.path.normpath(path)
            if ".." in normalized.split(os.sep):
                raise ValueError(f"Traversée de chemin détectée : {path}")

            if not os.path.isfile(path):
                raise FileNotFoundError(f"Fichier introuvable : {path}")

            file_size: int = os.path.getsize(path)
            if file_size > self._settings.max_file_size_bytes:
                raise ValueError(
                    f"Fichier trop volumineux ({file_size} bytes) : {path}"
                )

    async def _enrich_with_m1(self, bundle_path: str) -> list[str]:
        """Charge un IOCBundle M1 et extrait les tokens pertinents."""
        try:
            from admap_m3.integrations.m1_client import M1IOCClient

            client: M1IOCClient = M1IOCClient(self._settings)
            bundle: dict[str, Any] = await client.load_bundle(bundle_path)
            return client.extract_tokens(bundle)
        except Exception as exc:
            logger.warning(
                "m1_enrichment_failed",
                bundle_path=bundle_path,
                error=str(exc),
            )
            return []

    def _compute_corpus_hash(self, paths: list[str]) -> str:
        """Calcule un SHA-256 à partir des chemins du corpus."""
        hasher = hashlib.sha256()
        for path in sorted(paths):
            hasher.update(path.encode("utf-8"))
        return hasher.hexdigest()

    def _log_stage(self, stage: int, name: str, start: float, items: int) -> None:
        """Log structuré inter-stage."""
        duration_ms: float = (time.monotonic() - start) * 1000
        logger.info(
            "pipeline_stage_complete",
            stage=stage,
            stage_name=name,
            duration_ms=round(duration_ms, 2),
            items_processed=items,
        )
