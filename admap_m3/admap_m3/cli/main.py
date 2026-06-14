"""
Module   : admap_m3.cli.main
Version  : 1.0.0
Dépend   : [click, asyncio, structlog]

Point d'entrée CLI Click pour le module M3.
Commandes : ``generate``, ``validate``, ``serve``.

ZÉRO ``input()``.  Toutes les entrées via les options Click.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

import click
import structlog

from admap_m3.config import Settings, get_settings

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


@click.group()
def cli() -> None:
    """ADMAP M3 — YARA Signature Generator CLI."""


@cli.command("generate")
@click.option("--malware-dir", required=True, type=click.Path(exists=True), help="Dossier des fichiers malware")
@click.option("--benign-dir", required=True, type=click.Path(exists=True), help="Dossier des fichiers bénins")
@click.option("--output-dir", required=True, type=click.Path(), help="Dossier de sortie")
@click.option("--m1-bundle", default=None, type=click.Path(exists=True), help="IOCBundle M1 (JSON)")
@click.option("--family", default=None, help="Famille de malware ciblée")
@click.option("--mitre", default=None, help="IDs MITRE ATT&CK séparés par des virgules")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["yar", "json", "stix", "csv", "all"]),
    default="all",
    help="Format d'export",
)
def generate_cmd(
    malware_dir: str,
    benign_dir: str,
    output_dir: str,
    m1_bundle: str | None,
    family: str | None,
    mitre: str | None,
    fmt: str,
) -> None:
    """Lance la génération YARA depuis des dossiers locaux (mode hors-API)."""
    from admap_m3.core.pipeline import GenerationPipeline
    from admap_m3.exporters.csv_exporter import CSVExporter
    from admap_m3.exporters.json_exporter import JSONExporter
    from admap_m3.exporters.stix_exporter import STIXExporter
    from admap_m3.exporters.yara_exporter import YaraFileExporter

    # Collecter les chemins
    malware_paths: list[str] = _list_files(malware_dir)
    benign_paths: list[str] = _list_files(benign_dir)

    if not malware_paths:
        click.echo(json.dumps({"status": "error", "error": "Aucun fichier malware trouvé"}), err=True)
        sys.exit(1)

    if not benign_paths:
        click.echo(json.dumps({"status": "error", "error": "Aucun fichier bénin trouvé"}), err=True)
        sys.exit(1)

    # Créer le dossier de sortie
    os.makedirs(output_dir, exist_ok=True)

    # Préparer les paramètres
    mitre_list: list[str] | None = None
    if mitre:
        mitre_list = [m.strip() for m in mitre.split(",") if m.strip()]

    corpus_id: str = f"cli_{os.path.basename(malware_dir)}"

    # Exécuter le pipeline
    settings: Settings = get_settings()
    pipeline: GenerationPipeline = GenerationPipeline(settings=settings)

    ruleset = asyncio.run(
        pipeline.run(
            malware_paths=malware_paths,
            benign_paths=benign_paths,
            corpus_id=corpus_id,
            m1_bundle_path=m1_bundle,
            malware_family=family,
            mitre_attack=mitre_list,
        )
    )

    # Exporter
    export_results: list[dict[str, Any]] = []

    if fmt in ("yar", "all"):
        path: str = os.path.join(output_dir, f"{ruleset.ruleset_id}.yar")
        result: dict[str, Any] = YaraFileExporter().export(ruleset, path)
        export_results.append(result)

    if fmt in ("json", "all"):
        path = os.path.join(output_dir, f"{ruleset.ruleset_id}.json")
        result = JSONExporter().export(ruleset, path)
        export_results.append(result)

    if fmt in ("stix", "all"):
        path = os.path.join(output_dir, f"{ruleset.ruleset_id}_stix.json")
        result = STIXExporter().export(ruleset, path)
        export_results.append(result)

    if fmt in ("csv", "all"):
        path = os.path.join(output_dir, f"{ruleset.ruleset_id}.csv")
        result = CSVExporter().export(ruleset, path)
        export_results.append(result)

    # Résumé JSON sur stdout
    summary: dict[str, Any] = {
        "status": "ok",
        "ruleset_id": ruleset.ruleset_id,
        "corpus_id": corpus_id,
        "total_rules": ruleset.total_rules,
        "compiled_rules": ruleset.compiled_rules,
        "failed_rules": ruleset.failed_rules,
        "duration_ms": round(ruleset.generation_duration_ms, 2),
        "exports": export_results,
    }

    sys.stdout.write(json.dumps(summary, indent=2) + "\n")


@cli.command("validate")
@click.argument("yara_file", type=click.Path(exists=True))
def validate_cmd(yara_file: str) -> None:
    """Valide syntaxiquement un fichier .yar existant via yara.compile()."""
    import yara

    try:
        yara.compile(filepath=yara_file)
        result: dict[str, str] = {
            "status": "ok",
            "file": yara_file,
            "message": "Compilation YARA réussie",
        }
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
    except yara.SyntaxError as exc:
        result_err: dict[str, str] = {
            "status": "error",
            "file": yara_file,
            "error": str(exc),
        }
        click.echo(json.dumps(result_err, indent=2), err=True)
        sys.exit(1)


@cli.command("serve")
@click.option("--host", default="0.0.0.0", help="Adresse d'écoute")
@click.option("--port", default=8002, help="Port d'écoute")
def serve_cmd(host: str, port: int) -> None:
    """Lance le serveur FastAPI en mode développement."""
    import uvicorn

    uvicorn.run(
        "admap_m3.api.app:app",
        host=host,
        port=port,
        reload=False,
    )


def _list_files(directory: str) -> list[str]:
    """Liste récursivement tous les fichiers d'un répertoire."""
    result: list[str] = []
    for root, _dirs, files in os.walk(directory):
        for filename in sorted(files):
            file_path: str = os.path.join(root, filename)
            if os.path.isfile(file_path):
                result.append(file_path)
    return result
