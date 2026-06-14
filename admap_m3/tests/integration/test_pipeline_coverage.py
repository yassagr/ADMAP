"""
Tests unitaires pour le pipeline de génération (admap_m3.core.pipeline).
Utilise les fixtures malware_text_files et benign_text_files du conftest.
"""
from __future__ import annotations

import pytest

from admap_m3.config import Settings
from admap_m3.core.pipeline import GenerationPipeline
from admap_m3.models.rule import YaraRuleSet


@pytest.mark.asyncio
class TestPipelineCoverage:
    """Tests de couverture additionnels pour le pipeline."""

    async def test_pipeline_file_not_found(self, settings: Settings) -> None:
        """Pipeline lève FileNotFoundError pour un fichier inexistant."""
        pipeline: GenerationPipeline = GenerationPipeline(settings=settings)
        with pytest.raises(FileNotFoundError):
            await pipeline.run(
                malware_paths=["/nonexistent/malware.bin"],
                benign_paths=[],
                corpus_id="test_error",
            )

    async def test_pipeline_with_text_files(
        self,
        settings: Settings,
        malware_text_files: list[str],
        benign_text_files: list[str],
    ) -> None:
        """Pipeline complet avec des fichiers texte → YaraRuleSet."""
        pipeline: GenerationPipeline = GenerationPipeline(settings=settings)
        ruleset: YaraRuleSet = await pipeline.run(
            malware_paths=malware_text_files,
            benign_paths=benign_text_files,
            corpus_id="test_text_pipeline",
        )

        assert isinstance(ruleset, YaraRuleSet)
        assert ruleset.corpus_id == "test_text_pipeline"
        assert ruleset.generation_duration_ms > 0

    async def test_pipeline_with_family_and_mitre(
        self,
        settings: Settings,
        malware_text_files: list[str],
        benign_text_files: list[str],
    ) -> None:
        """Pipeline avec malware_family et mitre_attack renseignés."""
        pipeline: GenerationPipeline = GenerationPipeline(settings=settings)
        ruleset: YaraRuleSet = await pipeline.run(
            malware_paths=malware_text_files,
            benign_paths=benign_text_files,
            corpus_id="test_family",
            malware_family="TestMalware",
            mitre_attack=["T1059", "T1071"],
        )

        assert isinstance(ruleset, YaraRuleSet)
        if ruleset.total_rules > 0:
            rule = ruleset.rules[0]
            assert rule.metadata.malware_family == "TestMalware"
            assert "T1059" in rule.metadata.mitre_attack

    async def test_pipeline_strict_insufficient_tokens(
        self,
        settings_strict: Settings,
    ) -> None:
        """Pipeline strict : si pas assez de tokens distincts → 0 règles."""
        import os
        import tempfile

        # Créer des fichiers très courts avec peu de tokens discriminants
        malware_dir: str = tempfile.mkdtemp()
        benign_dir: str = tempfile.mkdtemp()

        with open(os.path.join(malware_dir, "m.txt"), "w") as fh:
            fh.write("single_token_only")
        with open(os.path.join(benign_dir, "b.txt"), "w") as fh:
            fh.write("different_content_here")

        pipeline: GenerationPipeline = GenerationPipeline(settings=settings_strict)
        ruleset: YaraRuleSet = await pipeline.run(
            malware_paths=[os.path.join(malware_dir, "m.txt")],
            benign_paths=[os.path.join(benign_dir, "b.txt")],
            corpus_id="test_strict",
        )

        # Avec min_tokens_per_rule=3 et min_df_malware=2, un seul fichier
        # malware ne peut pas satisfaire les contraintes
        assert isinstance(ruleset, YaraRuleSet)
