"""
Module   : admap_m2.cli.main
Version  : 1.0.0
Dépend   : [click, asyncio, uvicorn, admap_m2.pipeline.orchestrator,
            admap_m2.exporters, admap_m2.models]
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from admap_m2.core.config import get_settings
from admap_m2.core.exceptions import ADMAPM2Error
from admap_m2.core.logging import get_logger, setup_logging
from admap_m2.exporters.csv_exporter import CSVExporter
from admap_m2.exporters.json_exporter import JSONExporter
from admap_m2.exporters.stix_exporter import STIXExporter
from admap_m2.models.alert import AlertBundle
from admap_m2.models.job import AnalysisOptions
from admap_m2.pipeline.orchestrator import AnalysisPipeline


@click.group()
@click.version_option(version="1.0.0", prog_name="admap-m2")
def cli() -> None:
    """ADMAP M2 — C2 Detector v1.0 | PCAP analysis for C2 traffic detection"""


@cli.command()
@click.argument("pcap_path", type=click.Path(exists=True, readable=True, path_type=Path))
@click.option("--m1-bundle", default=None, help="Path to M1 IOCBundle JSON for correlation")
@click.option("--no-beaconing", is_flag=True, default=False, help="Disable beaconing detector")
@click.option("--no-dga", is_flag=True, default=False, help="Disable DGA detector")
@click.option("--no-dns-tunnel", is_flag=True, default=False, help="Disable DNS tunnel detector")
@click.option("--no-http-c2", is_flag=True, default=False, help="Disable HTTP C2 detector")
@click.option("--no-tls", is_flag=True, default=False, help="Disable TLS detector")
@click.option("--no-irc", is_flag=True, default=False, help="Disable IRC detector")
@click.option("--no-port-scan", is_flag=True, default=False, help="Disable port scan detector")
@click.option(
    "--format", "-f", "export_formats", multiple=True,
    type=click.Choice(["json", "stix", "csv"]), default=["json"],
    help="Export formats (multiple allowed)",
)
@click.option(
    "--output-dir", type=click.Path(path_type=Path), default=Path("."),
    help="Output directory for exported files",
)
@click.option(
    "--min-confidence", default=20, type=click.IntRange(0, 100),
    help="Minimum confidence threshold for alerts (0-100)",
)
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress progress output")
def analyze(
    pcap_path: Path,
    m1_bundle: str | None,
    no_beaconing: bool,
    no_dga: bool,
    no_dns_tunnel: bool,
    no_http_c2: bool,
    no_tls: bool,
    no_irc: bool,
    no_port_scan: bool,
    export_formats: tuple[str, ...],
    output_dir: Path,
    min_confidence: int,
    quiet: bool,
) -> None:
    """Analyze PCAP_PATH for C2 traffic patterns."""
    settings = get_settings()
    setup_logging(log_level="WARNING" if quiet else settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)

    options = AnalysisOptions(
        enable_beaconing=not no_beaconing,
        enable_dga=not no_dga,
        enable_dns_tunnel=not no_dns_tunnel,
        enable_http_c2=not no_http_c2,
        enable_tls=not no_tls,
        enable_irc=not no_irc,
        enable_port_scan=not no_port_scan,
        m1_bundle_path=m1_bundle,
        min_confidence_threshold=min_confidence,
    )

    pipeline = AnalysisPipeline(options=options)

    def on_progress(pct: int, stage: str) -> None:
        if not quiet:
            click.echo(f"[{pct:3d}%] {stage}", err=True)

    try:
        bundle = asyncio.run(
            pipeline.run(
                file_bytes=pcap_path.read_bytes(),
                filename=pcap_path.name,
                progress_callback=on_progress,
            )
        )
    except ADMAPM2Error as e:
        click.echo(f"ERROR [{e.code}]: {e.message}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"UNEXPECTED ERROR: {e}", err=True)
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)
    ext_map = {"json": ".alerts.json", "stix": ".stix.json", "csv": ".alerts.csv"}
    exporters_map = {
        "json": JSONExporter(),
        "stix": STIXExporter(),
        "csv": CSVExporter(),
    }

    for fmt in export_formats:
        exporter = exporters_map.get(fmt)
        if not exporter:
            continue
        try:
            content: str = exporter.export(bundle)
            out_file = output_dir / f"{pcap_path.stem}{ext_map.get(fmt, f'.{fmt}')}"
            out_file.write_text(content, encoding="utf-8")
            if not quiet:
                click.echo(f"Export {fmt.upper()} → {out_file}", err=True)
        except Exception as e:
            click.echo(f"Export {fmt.upper()} failed: {e}", err=True)

    summary = {
        "bundle_id": str(bundle.bundle_id),
        "pcap_filename": bundle.pcap_filename,
        "pcap_sha256": bundle.pcap_sha256,
        "total_packets": bundle.total_packets,
        "total_flows": bundle.total_flows,
        "total_alerts": len(bundle.alerts),
        "alerts_by_type": bundle.alerts_by_type,
        "alerts_by_severity": bundle.alerts_by_severity,
        "top_suspicious_ips": bundle.top_suspicious_ips[:5],
        "ioc_hits": bundle.ioc_hits,
        "duration_ms": bundle.analysis_duration_ms,
    }
    click.echo(json.dumps(summary, indent=2))
    sys.exit(0)


@cli.command()
@click.argument("bundle_json", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format", "-f", "fmt", required=True,
    type=click.Choice(["json", "stix", "csv", "all"]),
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None)
def export(bundle_json: Path, fmt: str, output: Path | None) -> None:
    """Export an existing AlertBundle JSON to a specific format."""
    try:
        bundle = AlertBundle.model_validate_json(bundle_json.read_text())
    except Exception as e:
        click.echo(f"ERROR: Cannot parse bundle: {e}", err=True)
        sys.exit(1)

    exporters_map = {
        "json": JSONExporter(),
        "stix": STIXExporter(),
        "csv": CSVExporter(),
    }
    ext_map = {"json": ".alerts.json", "stix": ".stix.json", "csv": ".alerts.csv"}

    if fmt == "all":
        out_dir = Path(output) if output else Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)
        for _fmt, exporter in exporters_map.items():
            try:
                content: str = exporter.export(bundle)
                out_file = out_dir / f"{bundle_json.stem}{ext_map[_fmt]}"
                out_file.write_text(content, encoding="utf-8")
                click.echo(str(out_file))
            except Exception as e:
                click.echo(f"Export {_fmt} failed: {e}", err=True)
        sys.exit(0)

    exporter = exporters_map.get(fmt)
    if not exporter:
        click.echo(f"ERROR: Unknown format {fmt}", err=True)
        sys.exit(1)
    try:
        content_str: str = exporter.export(bundle)
    except Exception as e:
        click.echo(f"ERROR: Export failed: {e}", err=True)
        sys.exit(1)

    out_path = Path(output) if output else Path(f"{bundle_json.stem}{ext_map[fmt]}")
    out_path.write_text(content_str, encoding="utf-8")
    click.echo(str(out_path))
    sys.exit(0)


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=8001, type=int, show_default=True)
@click.option("--reload", is_flag=True, default=False)
@click.option("--workers", default=1, type=int, show_default=True)
def serve(host: str, port: int, reload: bool, workers: int) -> None:
    """Start the ADMAP M2 FastAPI server."""
    import uvicorn
    uvicorn.run(
        "admap_m2.api.main:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers,
    )


if __name__ == "__main__":
    cli()
