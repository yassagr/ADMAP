"""
Module   : admap_m1.cli.main
Version  : 3.0.0
Dépend   : [click, asyncio, admap_m1.pipeline.orchestrator,
            admap_m1.exporters.*, admap_m1.models.job]

CLI non-interactif ADMAP M1. Zéro input(), zéro menu, zéro bannière.
Sortie machine-readable JSON sur stdout. Logs sur stderr via click.echo(err=True).
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from admap_m1.core.config import get_settings
from admap_m1.core.exceptions import ADMAPM1Error
from admap_m1.core.logging import get_logger, setup_logging
from admap_m1.exporters.cytomic_exporter import CytomicExporter
from admap_m1.exporters.misp_exporter import MISPExporter
from admap_m1.exporters.openioc_exporter import OpenIOCExporter
from admap_m1.exporters.stix_exporter import STIXExporter
from admap_m1.models.ioc import IOCBundle
from admap_m1.models.job import AnalysisOptions
from admap_m1.pipeline.orchestrator import AnalysisPipeline


def _build_exporters_map() -> dict[str, object]:
    return {
        "stix":    STIXExporter(),
        "openioc": OpenIOCExporter(),
        "misp":    MISPExporter(),
        "cytomic": CytomicExporter(),
    }


@click.group()
@click.version_option(version="3.0.0", prog_name="admap-m1")
def cli() -> None:
    """ADMAP M1 — IOC Extractor v3.0 | Programmatic cybersecurity IOC engine"""


@cli.command()
@click.argument("file_path", type=click.Path(exists=True, readable=True, path_type=Path))
@click.option("--format", "-f", "export_formats", multiple=True,
    type=click.Choice(["stix", "openioc", "misp", "cytomic"]),
    help="Export format(s). Repeatable: -f stix -f misp")
@click.option("--vt-key", envvar="ADMAP_M1_VT_API_KEY", default="",
    help="VirusTotal API key")
@click.option("--vt-limit", default=5, type=int, show_default=True)
@click.option("--no-deobfuscation", is_flag=True, default=False)
@click.option("--min-confidence", default=20, type=click.IntRange(0, 100),
    show_default=True)
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("."))
@click.option("--output-json", type=click.Path(path_type=Path), default=None)
@click.option("--quiet", "-q", is_flag=True, default=False)
def analyze(
    file_path: Path,
    export_formats: tuple[str, ...],
    vt_key: str,
    vt_limit: int,
    no_deobfuscation: bool,
    min_confidence: int,
    output_dir: Path,
    output_json: Path | None,
    quiet: bool,
) -> None:
    """Analyze FILE_PATH and extract IOCs.

    Examples:
      admap-m1 analyze malware.exe -f stix -f misp --output-dir ./results
      admap-m1 analyze report.txt --vt-key $VT_KEY --min-confidence 40
    """
    settings = get_settings()
    setup_logging(
        log_level="WARNING" if quiet else settings.LOG_LEVEL,
        log_format="console",
    )

    options = AnalysisOptions(
        enable_vt_enrichment=bool(vt_key),
        vt_api_key=vt_key or None,
        vt_max_per_type=vt_limit,
        enable_deobfuscation=not no_deobfuscation,
        export_formats=list(export_formats),
        min_confidence_threshold=min_confidence,
    )

    pipeline = AnalysisPipeline(options=options)

    def on_progress(pct: int, stage: str) -> None:
        if not quiet:
            click.echo(f"[{pct:3d}%] {stage}", err=True)

    try:
        bundle: IOCBundle = asyncio.run(
            pipeline.run(
                file_bytes=file_path.read_bytes(),
                file_path=file_path,
                progress_callback=on_progress,
            )
        )
    except ADMAPM1Error as e:
        click.echo(f"ERROR [{e.code}]: {e.message}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"UNEXPECTED ERROR: {e}", err=True)
        sys.exit(1)

    if output_json:
        output_json.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
        if not quiet:
            click.echo(f"Bundle JSON saved: {output_json}", err=True)

    output_dir.mkdir(parents=True, exist_ok=True)
    exporters_map = _build_exporters_map()

    for fmt in export_formats:
        exporter = exporters_map.get(fmt)
        if not exporter:
            continue
        result = exporter.export(bundle)
        out_file = output_dir / result.filename
        out_file.write_text(result.content, encoding="utf-8")
        if not quiet:
            click.echo(f"Export {fmt.upper()} -> {out_file}", err=True)

    # Sortie machine-readable JSON sur stdout UNIQUEMENT
    summary = {
        "bundle_id":            str(bundle.bundle_id),
        "filename":             bundle.metadata.filename,
        "filetype":             bundle.metadata.filetype,
        "total_iocs":           bundle.analysis_stats.total_iocs,
        "by_type":              bundle.analysis_stats.by_type,
        "filtered_out":         bundle.analysis_stats.filtered_out,
        "deobfuscation_layers": bundle.analysis_stats.deobfuscation_layers,
        "is_packed":            bundle.metadata.is_packed,
        "packer_name":          bundle.metadata.packer_name,
        "duration_ms":          bundle.analysis_stats.duration_ms,
    }
    click.echo(json.dumps(summary, indent=2))
    sys.exit(0)


@cli.command()
@click.argument("bundle_json", type=click.Path(exists=True, path_type=Path))
@click.option("--format", "-f", "fmt", required=True,
    type=click.Choice(["stix", "openioc", "misp", "cytomic", "all"]))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
@click.option("--misp-url", default=None)
@click.option("--misp-key", default=None, envvar="ADMAP_M1_MISP_KEY")
def export(
    bundle_json: Path,
    fmt: str,
    output: Path | None,
    misp_url: str | None,
    misp_key: str | None,
) -> None:
    """Export an existing IOCBundle JSON to a specific format."""
    try:
        bundle = IOCBundle.model_validate_json(bundle_json.read_text())
    except Exception as e:
        click.echo(f"ERROR: Cannot parse bundle: {e}", err=True)
        sys.exit(1)

    exporters_map = _build_exporters_map()

    if fmt == "all":
        out_dir = Path(output) if output else Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)
        for _fmt, exporter in exporters_map.items():
            result = exporter.export(bundle)
            out_file = out_dir / result.filename
            out_file.write_text(result.content, encoding="utf-8")
            click.echo(str(out_file))
        sys.exit(0)

    if fmt == "misp" and misp_url and misp_key:
        try:
            push_result = MISPExporter().push_to_misp(bundle, misp_url, misp_key)
            click.echo(json.dumps(push_result, indent=2))
        except ADMAPM1Error as e:
            click.echo(f"ERROR [{e.code}]: {e.message}", err=True)
            sys.exit(1)
        sys.exit(0)

    exporter = exporters_map.get(fmt)
    if not exporter:
        click.echo(f"ERROR: Unknown format {fmt}", err=True)
        sys.exit(1)

    result = exporter.export(bundle)
    out_path = Path(output) if output else Path(result.filename)
    out_path.write_text(result.content, encoding="utf-8")
    click.echo(str(out_path))
    sys.exit(0)


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8000, type=int, show_default=True)
@click.option("--reload", is_flag=True, default=False)
@click.option("--workers", default=1, type=int, show_default=True)
def serve(host: str, port: int, reload: bool, workers: int) -> None:
    """Start the ADMAP M1 FastAPI server."""
    import uvicorn
    uvicorn.run(
        "admap_m1.api.main:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers,
    )


if __name__ == "__main__":
    cli()
