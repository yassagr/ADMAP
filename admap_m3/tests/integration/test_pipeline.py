"""
Tests d'intégration pour le GenerationPipeline (admap_m3.core.pipeline).
"""
from __future__ import annotations

import pytest

from admap_m3.config import Settings
from admap_m3.core.pipeline import GenerationPipeline
from admap_m3.models.rule import YaraRuleSet


class TestPipelineInit:
    """Tests d'initialisation du pipeline."""

    def test_pipeline_init_no_args(self) -> None:
        """GenerationPipeline() → instanciation sans erreur."""
        pipeline: GenerationPipeline = GenerationPipeline()
        assert pipeline is not None

    def test_pipeline_init_with_settings(self, settings: Settings) -> None:
        """GenerationPipeline(settings=settings) → OK."""
        pipeline: GenerationPipeline = GenerationPipeline(settings=settings)
        assert pipeline is not None
        assert pipeline._settings is settings


class TestPipelineRun:
    """Tests d'exécution du pipeline."""

    @pytest.mark.asyncio
    async def test_pipeline_run_minimal_corpus(
        self,
        settings: Settings,
        malware_text_files: list[str],
        benign_text_files: list[str],
    ) -> None:
        """Avec un mini corpus texte, run() retourne un YaraRuleSet."""
        pipeline: GenerationPipeline = GenerationPipeline(settings=settings)

        ruleset: YaraRuleSet = await pipeline.run(
            malware_paths=malware_text_files,
            benign_paths=benign_text_files,
            corpus_id="test_minimal",
        )

        assert isinstance(ruleset, YaraRuleSet)
        assert ruleset.corpus_id == "test_minimal"
        assert ruleset.total_rules >= 0
        assert ruleset.generation_duration_ms > 0

    @pytest.mark.asyncio
    async def test_pipeline_run_returns_yara_ruleset(
        self,
        settings: Settings,
        malware_text_files: list[str],
        benign_text_files: list[str],
    ) -> None:
        """Le type de retour est YaraRuleSet."""
        pipeline: GenerationPipeline = GenerationPipeline(settings=settings)

        result = await pipeline.run(
            malware_paths=malware_text_files,
            benign_paths=benign_text_files,
            corpus_id="test_type_check",
        )

        assert isinstance(result, YaraRuleSet)
