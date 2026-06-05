"""
Module   : admap_m1.cli.main
Version  : 3.0.0
Dépend   : [argparse, rich, asyncio, admap_m1.pipeline.orchestrator]

Interface en ligne de commande pour le module M1.
Permet d'exécuter l'analyse en mode "stand-alone" sans l'API.
Seul module autorisé à utiliser print() et rich pour l'affichage console.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from admap_m1.core.config import get_settings
from admap_m1.core.logging import setup_logging
from admap_m1.exporters.cytomic_exporter import CytomicExporter
from admap_m1.exporters.misp_exporter import MISPExporter
from admap_m1.exporters.openioc_exporter import OpenIOCExporter
from admap_m1.exporters.stix_exporter import STIXExporter
from admap_m1.models.job import AnalysisOptions
from admap_m1.pipeline.orchestrator import AnalysisPipeline

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False


def print_msg(msg: str, style: str = "") -> None:
    """Wrapper pour print/rich."""
    if RICH_AVAILABLE:
        if style:
            console.print(f"[{style}]{msg}[/{style}]")
        else:
            console.print(msg)
    else:
        print(msg)


async def async_main() -> None:
    """Fonction principale asynchrone du CLI."""
    parser = argparse.ArgumentParser(
        description="ADMAP M1 - Static IOC Extractor v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument("file", type=str, help="Fichier binaire à analyser")
    parser.add_argument("--vt", action="store_true", help="Activer l'enrichissement VirusTotal")
    parser.add_argument("--no-deobf", action="store_true", help="Désactiver la désobfuscation")
    parser.add_argument("--format", type=str, choices=["json", "stix21", "openioc", "misp", "cytomic"], 
                        default="json", help="Format de sortie (défaut: json)")
    parser.add_argument("--out", type=str, help="Fichier de sortie (défaut: stdout)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Activer les logs détaillés")

    args = parser.parse_args()

    # Configuration des logs
    log_level = "DEBUG" if args.verbose else "WARNING"
    setup_logging(log_level=log_level, log_format="console")

    file_path = Path(args.file)
    if not file_path.exists() or not file_path.is_file():
        print_msg(f"Erreur : Le fichier {file_path} est introuvable.", "bold red")
        sys.exit(1)

    try:
        file_bytes = file_path.read_bytes()
    except Exception as e:
        print_msg(f"Erreur de lecture du fichier : {e}", "bold red")
        sys.exit(1)

    settings = get_settings()
    options = AnalysisOptions(
        enable_vt_enrichment=args.vt,
        enable_deobfuscation=not args.no_deobf,
        vt_api_key=settings.VT_API_KEY if args.vt else None
    )

    pipeline = AnalysisPipeline(options=options)
    
    bundle = None
    if RICH_AVAILABLE and not args.verbose:
        # Affichage avec barre de progression
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("[cyan]Analyse en cours...", total=100)
            
            def progress_cb(prog: int, stage: str):
                progress.update(task_id, completed=prog, description=f"[cyan]{stage}")
                
            bundle = await pipeline.run(file_bytes, file_path, progress_callback=progress_cb)
    else:
        # Sans interface riche ou en mode verbose (où les logs interfèrent)
        print_msg("Démarrage de l'analyse...", "cyan")
        def progress_cb(prog: int, stage: str):
            if args.verbose:
                print_msg(f"[{prog}%] {stage}")
                
        bundle = await pipeline.run(file_bytes, file_path, progress_callback=progress_cb)

    if not bundle:
        print_msg("Échec de l'analyse.", "bold red")
        sys.exit(1)

    # Affichage du résumé
    if RICH_AVAILABLE:
        console.print()
        console.print(Panel.fit(
            f"[bold green]Analyse terminée en {bundle.analysis_stats.duration_ms} ms[/bold green]\n"
            f"Fichier  : {bundle.metadata.filename}\n"
            f"Type     : {bundle.metadata.filetype}\n"
            f"SHA256   : {bundle.metadata.hashes.sha256}\n"
            f"IOCs     : {bundle.analysis_stats.total_iocs} extraits "
            f"({bundle.analysis_stats.filtered_out} filtrés)",
            title="Résultats ADMAP M1"
        ))
        
        if bundle.iocs:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Type", style="dim", width=12)
            table.add_column("Valeur Defangée", style="green")
            table.add_column("Confiance", justify="right")
            table.add_column("Origine", style="dim")
            
            # Limiter à 20 résultats pour l'affichage console
            display_limit = 20
            for ioc in sorted(bundle.iocs, key=lambda x: x.confidence_score, reverse=True)[:display_limit]:
                level_color = "red" if ioc.confidence_score >= 80 else "yellow" if ioc.confidence_score >= 60 else "white"
                table.add_row(
                    ioc.type.value,
                    ioc.value_defanged,
                    f"[{level_color}]{ioc.confidence_score}[/{level_color}]",
                    ioc.extraction_method
                )
            
            console.print(table)
            if len(bundle.iocs) > display_limit:
                console.print(f"... et {len(bundle.iocs) - display_limit} autres IOCs.", style="dim")

    # Export
    output_data = ""
    if args.format == "json":
        output_data = bundle.model_dump_json(indent=2)
    elif args.format == "stix21":
        output_data = STIXExporter().export(bundle)
    elif args.format == "openioc":
        output_data = OpenIOCExporter().export(bundle)
    elif args.format == "misp":
        output_data = MISPExporter().export(bundle)
    elif args.format == "cytomic":
        output_data = CytomicExporter().export(bundle)

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(output_data, encoding="utf-8")
        print_msg(f"\nRésultats exportés vers : {out_path.absolute()}", "bold blue")
    else:
        # En mode standalone sans fichier de sortie, on print le résultat brut à la fin
        if not RICH_AVAILABLE:
            print("\n--- RÉSULTAT EXPORT ---")
            print(output_data)


def main() -> None:
    """Point d'entrée synchrone."""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print_msg("\nInterruption par l'utilisateur.", "bold red")
        sys.exit(130)


if __name__ == "__main__":
    main()
