"""
Module   : admap_m2.cli.main
Version  : 1.0.0
Dépend   : [click, uvicorn, admap_m2.pipeline.orchestrator]
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
import uvicorn

from admap_m2.core.config import get_settings
from admap_m2.core.logging import get_logger, setup_logging
from admap_m2.exporters.csv_exporter import CSVExporter
from admap_m2.exporters.json_exporter import JSONExporter
from admap_m2.exporters.stix_exporter import STIXExporter
from admap_m2.models.job import AnalysisJob
from admap_m2.pipeline.orchestrator import AnalysisPipeline


@click.group()
def cli() -> None:
    """ADMAP M2 - C2 Detector CLI"""
    pass


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True, dir_okay=False))
def analyze(pcap_file: str) -> None:
    """Analyse un fichier PCAP."""
    settings = get_settings()
    setup_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)
    logger = get_logger("cli.analyze")

    try:
        path = Path(pcap_file)
        file_bytes = path.read_bytes()
        
        job = AnalysisJob(
            filename=path.name,
            pcap_sha256="", # Handled by orchestrator or pre-computed
        )
        
        pipeline = AnalysisPipeline(settings)
        bundle = pipeline.run(job, file_bytes)
        
        # Output JSON machine-readable to stdout
        click.echo(bundle.model_dump_json(indent=2))
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("bundle_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "stix", "csv"]), default="json")
def export(bundle_file: str, fmt: str) -> None:
    """Exporte un résultat d'analyse (JSON bundle)."""
    settings = get_settings()
    setup_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)
    
    try:
        path = Path(bundle_file)
        from admap_m2.models.alert import AlertBundle
        bundle = AlertBundle.model_validate_json(path.read_text())
        
        if fmt == "json":
            exporter = JSONExporter()
        elif fmt == "csv":
            exporter = CSVExporter()
        elif fmt == "stix":
            exporter = STIXExporter()
        else:
            sys.exit(1)
            
        content = exporter.export(bundle)
        click.echo(content)
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
def serve() -> None:
    """Lance le serveur API FastAPI."""
    settings = get_settings()
    uvicorn.run(
        "admap_m2.api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        workers=settings.API_WORKERS,
    )


if __name__ == "__main__":
    cli()
