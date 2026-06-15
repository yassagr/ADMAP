from __future__ import annotations
import asyncio
import json
import sys
import click
import structlog
from admap_m4.config import get_settings
from admap_m4.core.pipeline import AnalysisPipeline
from admap_m4.models.report import AnalysisOptions
from admap_m4.exporters.json_exporter import JSONExporter
from admap_m4.exporters.csv_exporter import CSVExporter
from admap_m4.exporters.stix_exporter import STIXExporter

@click.group()
@click.version_option(version="1.0.0", prog_name="admap-m4")
def cli() -> None:
    """ADMAP M4 — APT Mapper / Clustering CLI."""

@cli.command("analyze")
@click.option("--alert-bundle", "-a", required=True, type=click.Path(exists=True),
              help="Chemin vers le fichier JSON AlertBundle M2.")
@click.option("--ioc-bundle", "-i", default=None, type=click.Path(exists=True),
              help="Chemin vers le fichier JSON IOCBundle M1 (optionnel).")
@click.option("--yara-ruleset", "-y", default=None, type=click.Path(exists=True),
              help="Chemin vers le fichier JSON YaraRuleSet M3 (optionnel).")
@click.option("--epsilon", default=0.3, type=float, show_default=True,
              help="Epsilon DBSCAN (distance cosinus max).")
@click.option("--min-samples", default=2, type=int, show_default=True,
              help="Min samples DBSCAN.")
@click.option("--format", "-f", "export_format",
              type=click.Choice(["json", "csv", "stix", "all"]),
              default="json", show_default=True)
@click.option("--output", "-o", default=None, type=click.Path(),
              help="Fichier de sortie (stdout si non spécifié).")
def analyze_command(
    alert_bundle: str,
    ioc_bundle: str | None,
    yara_ruleset: str | None,
    epsilon: float,
    min_samples: int,
    export_format: str,
    output: str | None,
) -> None:
    """Lance l'analyse APT Mapping sur un AlertBundle M2."""
    settings = get_settings()
    options = AnalysisOptions(
        dbscan_epsilon=epsilon,
        dbscan_min_samples=min_samples,
    )

    with open(alert_bundle, "r", encoding="utf-8") as f:
        alert_bundle_json = f.read()

    ioc_bundle_json = None
    if ioc_bundle:
        with open(ioc_bundle, "r", encoding="utf-8") as f:
            ioc_bundle_json = f.read()

    yara_ruleset_json = None
    if yara_ruleset:
        with open(yara_ruleset, "r", encoding="utf-8") as f:
            yara_ruleset_json = f.read()

    pipeline = AnalysisPipeline(settings=settings, options=options)
    report = asyncio.run(pipeline.run(alert_bundle_json, ioc_bundle_json, yara_ruleset_json))

    if export_format == "json":
        result = json.dumps(JSONExporter().export(report), indent=2, ensure_ascii=False)
    elif export_format == "csv":
        result = CSVExporter().export(report)
    elif export_format == "stix":
        result = json.dumps(STIXExporter().export(report), indent=2, ensure_ascii=False)
    else:  # all
        result = json.dumps({
            "json": JSONExporter().export(report),
            "csv": CSVExporter().export(report),
            "stix": STIXExporter().export(report),
        }, indent=2, ensure_ascii=False)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(result)
    else:
        click.echo(result)  # stdout

@cli.command("serve")
@click.option("--host", default=None)
@click.option("--port", default=None, type=int)
def serve_command(host: str | None, port: int | None) -> None:
    """Démarre le serveur FastAPI M4."""
    import uvicorn
    settings = get_settings()
    uvicorn.run(
        "admap_m4.main:app",
        host=host or settings.host,
        port=port or settings.port,
        reload=settings.debug,
    )

if __name__ == "__main__":
    cli()
