from __future__ import annotations
import asyncio
import json
import sys
from pathlib import Path
import click
import structlog

logger = structlog.get_logger(__name__)


@click.group()
def cli() -> None:
    """ADMAP M5 — Attribution CLI"""


@cli.command("attribute")
@click.option("--apt-map-report", required=True, type=click.Path(exists=True),
              help="Chemin vers l'APTMapReport JSON de M4")
@click.option("--ioc-bundle", default=None, type=click.Path(exists=True),
              help="Chemin vers l'IOCBundle JSON de M1 (optionnel)")
@click.option("--alert-bundle", default=None, type=click.Path(exists=True),
              help="Chemin vers l'AlertBundle JSON de M2 (optionnel)")
@click.option("--top-k", default=3, type=int, show_default=True,
              help="Nombre de candidats APT à retourner")
@click.option("--min-confidence", default=10.0, type=float, show_default=True,
              help="Score de confiance minimum (0-100)")
@click.option("--output", default="-", help="Fichier de sortie (défaut: stdout)")
def attribute_cmd(
    apt_map_report: str,
    ioc_bundle: str | None,
    alert_bundle: str | None,
    top_k: int,
    min_confidence: float,
    output: str,
) -> None:
    """Lance une attribution APT en ligne de commande."""
    from admap_m5.core.pipeline import AttributionPipeline
    from admap_m5.models.input import AttributionOptions

    apt_json = Path(apt_map_report).read_text(encoding="utf-8")
    ioc_json = Path(ioc_bundle).read_text(encoding="utf-8") if ioc_bundle else None
    alert_json = Path(alert_bundle).read_text(encoding="utf-8") if alert_bundle else None

    options = AttributionOptions(top_k=top_k, min_confidence=min_confidence)
    pipeline = AttributionPipeline(options=options)

    async def _run() -> None:
        report = await pipeline.run(
            apt_map_report_json=apt_json,
            ioc_bundle_json=ioc_json,
            alert_bundle_json=alert_json,
            options=options,
        )
        result_json = report.model_dump_json(indent=2)
        if output == "-":
            sys.stdout.write(result_json + "\n")
        else:
            Path(output).write_text(result_json, encoding="utf-8")
            logger.info("cli.output_written", path=output)

    asyncio.run(_run())


@cli.command("serve")
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8004, type=int, show_default=True)
@click.option("--reload", is_flag=True, default=False)
def serve_cmd(host: str, port: int, reload: bool) -> None:
    """Démarre le serveur FastAPI M5."""
    import uvicorn
    uvicorn.run(
        "admap_m5.api.app:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    cli()
