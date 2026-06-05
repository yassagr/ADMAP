"""
Module   : admap_m1.tests.integration.test_pipeline
"""
from __future__ import annotations

from pathlib import Path

import pytest

from admap_m1.models.job import AnalysisOptions
from admap_m1.pipeline.orchestrator import AnalysisPipeline


@pytest.mark.asyncio
async def test_full_pipeline_text_file(mock_vt_client, tmp_path):
    """Test du pipeline complet (sans VT réel) sur un fichier texte simple."""
    # Création d'un payload factice
    payload = b"""
    This is a malicious config.
    Connect to 8.8.8.8 or download http://evil.com/payload.exe
    Base64 hidden: aHR0cDovL2hpZGRlbi1ldmlsLmNvbS9wYXlsb2FkLmV4ZQ==
    """
    
    test_file = tmp_path / "config.txt"
    test_file.write_bytes(payload)
    
    # Options avec VT activé (mocké par la fixture mock_vt_client)
    options = AnalysisOptions(
        enable_vt_enrichment=True,
        enable_deobfuscation=True,
        vt_api_key="mock_key"
    )
    
    pipeline = AnalysisPipeline(options=options)
    bundle = await pipeline.run(payload, test_file)
    
    # Vérifications globales
    assert bundle.metadata.filename == "config.txt"
    assert bundle.analysis_stats.total_iocs > 0
    assert bundle.analysis_stats.vt_enriched > 0  # Notre mock retourne toujours une info
    
    # Vérification de l'extraction
    values = [ioc.value for ioc in bundle.iocs]
    
    assert "8.8.8.8" in values
    assert "http://evil.com/payload.exe" in values
    
    # Vérification de la désobfuscation
    assert "http://hidden-evil.com/payload.exe" in values
    
    # Vérification du scoring (VT mocké a malicious=5, suspicious=1 -> devrait être > 80 ou du moins CONFIRMED grâce au mock VT si on le prenait en compte dans le score,
    # or dans M1 le score VT n'affecte pas le confidence_score natif qui est purement statique selon le plan, mais il est présent dans l'objet)
    hidden_ioc = next(i for i in bundle.iocs if i.value == "http://hidden-evil.com/payload.exe")
    assert hidden_ioc.vt_result is not None
    assert hidden_ioc.vt_result.malicious == 5
    assert hidden_ioc.vt_result.verdict == "MALVEILLANT"
    
    # in_decoded_layer flag doit être True
    assert any("in_decoded_layer" in r for r in hidden_ioc.scoring_reasons)
