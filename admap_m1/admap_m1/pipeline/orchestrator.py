"""
Module   : admap_m1.pipeline.orchestrator
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.models.job]

Orchestrateur principal M1 (AnalysisPipeline).
Exécute le pipeline en 7 étapes selon le plan architectural.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Callable

from admap_m1.core.config import get_settings
from admap_m1.core.exceptions import ADMAPM1Error, ArchiveExtractionError
from admap_m1.core.logging import get_logger
from admap_m1.deobfuscators.base64_decoder import Base64Decoder
from admap_m1.deobfuscators.packer_detector import PackerDetector
from admap_m1.deobfuscators.powershell_decoder import PowerShellDecoder
from admap_m1.deobfuscators.rot_decoder import ROTDecoder
from admap_m1.deobfuscators.xor_decoder import XOR1ByteDecoder
from admap_m1.enrichers.virustotal import VirusTotalEnricher
from admap_m1.extractors.elf_extractor import ELFExtractor
from admap_m1.extractors.pe_extractor import PEExtractor
from admap_m1.extractors.regex_extractor import RegexExtractor
from admap_m1.extractors.string_extractor import StringExtractor
from admap_m1.extractors.vba_extractor import VBAExtractor
from admap_m1.filters.deduplicator import IOCDeduplicator
from admap_m1.filters.defanger import IOCDefanger
from admap_m1.heuristics.context_analyzer import ContextAnalyzer
from admap_m1.heuristics.ioc_scorer import IOCScorer
from admap_m1.models.ioc import (
    AnalysisStats,
    IOC,
    IOCBundle,
    RawIOC,
)
from admap_m1.models.job import AnalysisOptions
from admap_m1.parsers.archive_parser import ArchiveParser
from admap_m1.parsers.elf_parser import ELFParser
from admap_m1.parsers.office_parser import OfficeParser
from admap_m1.parsers.pe_parser import PEParser


class AnalysisPipeline:
    """Orchestrateur du traitement M1.

    Pipeline asynchrone en 7 étapes :
    1. Parsing structuré (PE, ELF, Office)
    2. Extraction des sous-fichiers (Archives)
    3. Désobfuscation statique
    4. Extraction des IOCs bruts (RawIOC)
    5. Scoring & Dédoublonnage
    6. Enrichissement (VT)
    7. Defanging final & Bundle
    """

    def __init__(self, options: AnalysisOptions | None = None) -> None:
        self.settings = get_settings()
        self.options = options or AnalysisOptions()
        self._logger = get_logger("pipeline.orchestrator")

        # Initialisation statique des composants pour éviter la création à chaque job
        self.pe_parser = PEParser()
        self.elf_parser = ELFParser()
        self.office_parser = OfficeParser()
        self.archive_parser = ArchiveParser()

        self.pe_extractor = PEExtractor()
        self.elf_extractor = ELFExtractor()
        self.vba_extractor = VBAExtractor()
        self.regex_extractor = RegexExtractor()
        self.string_extractor = StringExtractor()

        self.deobfuscators = [
            Base64Decoder(),
            XOR1ByteDecoder(),
            ROTDecoder(),
            PowerShellDecoder(),
        ]

        self.defanger = IOCDefanger()
        self.vt_enricher = VirusTotalEnricher(api_key=self.options.vt_api_key)

    async def run(
        self,
        file_bytes: bytes,
        file_path: Path,
        progress_callback: Callable[[int, str], None] | None = None,
    ) -> IOCBundle:
        """Exécute le pipeline complet sur un fichier.

        Args:
            file_bytes: Contenu binaire du fichier.
            file_path: Chemin ou nom original (pour metadata).
            progress_callback: Fonction optionnelle appelée à chaque étape (progression 0-100).

        Returns:
            Le bundle d'analyse complet.

        Raises:
            ADMAPM1Error: En cas d'erreur critique bloquante.
        """
        start_time = time.perf_counter()
        stats = AnalysisStats()

        def _report(progress: int, stage: str) -> None:
            if progress_callback:
                progress_callback(progress, stage)
            self._logger.info("pipeline_stage", stage=stage, progress=progress)

        _report(5, "Étape 1: Identification du fichier")
        metadata = self._run_stage1_parsing(file_bytes, file_path)

        _report(15, "Étape 2: Pré-traitement et archives")
        files_to_process = self._run_stage2_archives(file_bytes, file_path, metadata)

        _report(30, "Étape 3: Désobfuscation")
        if self.options.enable_deobfuscation:
            self._run_stage3_deobfuscation(files_to_process, stats)

        _report(55, "Étape 4: Extraction des IOCs")
        raw_iocs = self._run_stage4_extraction(files_to_process, metadata)

        _report(70, "Étape 5: Filtrage et déduplication")
        # Le scoring est dans l'étape 6 de la nomenclature
        
        _report(85, "Étape 6: Scoring et contextualisation")
        scored_iocs = self._run_stage5_scoring(raw_iocs, metadata, stats)

        _report(90, "Étape 6b: Enrichissement VT (si activé)")
        if self.options.enable_vt_enrichment:
            await self._run_stage6_enrichment(scored_iocs, stats)

        _report(100, "Étape 7: Construction du bundle final")
        final_iocs = self._run_stage7_defanging(scored_iocs)

        stats.total_iocs = len(final_iocs)
        for ioc in final_iocs:
            stats.by_type[ioc.type.value] = stats.by_type.get(ioc.type.value, 0) + 1
            
        stats.duration_ms = int((time.perf_counter() - start_time) * 1000)

        bundle = IOCBundle(
            metadata=metadata,
            iocs=final_iocs,
            analysis_stats=stats,
        )
        self._logger.info(
            "pipeline_completed",
            filename=file_path.name,
            total_iocs=len(final_iocs),
            duration_ms=stats.duration_ms
        )

        return bundle

    def _run_stage1_parsing(self, file_bytes: bytes, file_path: Path):
        """Détermine le type de fichier et extrait ses métadonnées de base."""
        # 1. PE (EXE/DLL)
        if self.pe_parser.can_handle(file_bytes, file_path):
            metadata = self.pe_parser.parse_metadata(file_bytes, file_path)
            # Détection de packer
            if metadata.pe_info:
                packer = PackerDetector.detect(metadata.pe_info)
                if packer:
                    metadata.is_packed = True
                    metadata.packer_name = packer
            return metadata

        # 2. ELF (Linux)
        if self.elf_parser.can_handle(file_bytes, file_path):
            return self.elf_parser.parse_metadata(file_bytes, file_path)

        # 3. Office (Word, Excel, VBA)
        if self.office_parser.can_handle(file_bytes, file_path):
            return self.office_parser.parse_metadata(file_bytes, file_path)

        # 4. Archive (ZIP, TAR, etc.) géré au stage 2, on prend un fallback metadata
        if self.archive_parser.can_handle(file_bytes, file_path):
            return self.archive_parser.parse_metadata(file_bytes, file_path)

        # Fallback générique
        return self.pe_parser._compute_basic_metadata(file_bytes, file_path, "unknown")

    def _run_stage2_archives(
        self,
        file_bytes: bytes,
        file_path: Path,
        metadata
    ) -> list[tuple[str, bytes]]:
        """Décompresse les archives récursivement. Retourne la liste des (nom, contenu)."""
        files_to_process = [("ROOT", file_bytes)]

        if self.archive_parser.can_handle(file_bytes, file_path):
            try:
                extracted = self.archive_parser.extract_members(file_bytes, file_path)
                files_to_process.extend(extracted)
                metadata.filetype = f"Archive ({len(extracted)} files)"
            except ArchiveExtractionError as e:
                self._logger.warning("archive_extraction_aborted", error=str(e))
                # On continue l'analyse sur le fichier ZIP brut (peut contenir des infos en clair)
        
        return files_to_process

    def _run_stage3_deobfuscation(self, files_to_process: list[tuple[str, bytes]], stats: AnalysisStats):
        """Applique les désobfuscateurs statiques pour trouver des layers cachés."""
        new_layers: list[tuple[str, bytes]] = []

        for name, data in files_to_process:
            for deobfuscator in self.deobfuscators:
                results = deobfuscator.decode(data)
                for res in results:
                    if res.success and res.decoded_data:
                        stats.deobfuscation_layers += 1
                        new_layers.append((f"{name}_decoded_{deobfuscator.technique_name}", res.decoded_data))

        # Ajouter les couches désobfusquées à la liste des fichiers à analyser
        files_to_process.extend(new_layers)

    def _run_stage4_extraction(self, files_to_process: list[tuple[str, bytes]], metadata) -> list[RawIOC]:
        """Extrait les IOCs bruts en utilisant les extracteurs appropriés."""
        raw_iocs: list[RawIOC] = []

        for name, data in files_to_process:
            file_path = Path(name)
            is_decoded = "decoded" in name
            
            extracted = []

            if self.pe_extractor.can_handle(data, file_path):
                extracted = self.pe_extractor.extract(data, file_path, metadata)
            elif self.elf_extractor.can_handle(data, file_path):
                extracted = self.elf_extractor.extract(data, file_path, metadata)
            elif self.vba_extractor.can_handle(data, file_path):
                extracted = self.vba_extractor.extract(data, file_path, metadata)
            elif self.string_extractor.can_handle(data, file_path):
                # Binaire non identifié (ex: payload chargé en mémoire)
                extracted = self.string_extractor.extract(data, file_path, metadata)
            else:
                # Texte pur (script, config, JSON, XML)
                extracted = self.regex_extractor.extract(data, file_path, metadata)

            # Tagguer les IOCs issus de couches désobfusquées
            if is_decoded:
                for ioc in extracted:
                    ioc.in_decoded_layer = True

            raw_iocs.extend(extracted)

        return raw_iocs

    def _run_stage5_scoring(self, raw_iocs: list[RawIOC], metadata, stats: AnalysisStats) -> list[IOC]:
        """Dédoublonne, annote via le ContextAnalyzer et score les IOCs."""
        # 1. Dédoublonnage brut
        initial_count = len(raw_iocs)
        unique_raw_iocs = IOCDeduplicator.deduplicate_raw(raw_iocs)
        stats.filtered_out += (initial_count - len(unique_raw_iocs))

        scored_iocs: list[IOC] = []

        # 2. Contextualisation et Scoring
        for raw in unique_raw_iocs:
            flags = ContextAnalyzer.analyze(raw, metadata)
            score, level, reasons = IOCScorer.score(raw, flags)

            if score >= self.options.min_confidence_threshold:
                # Création du modèle final. 'value_defanged' sera mis à jour au stage 7
                ioc = IOC(
                    type=raw.type,
                    value=str(raw.value),
                    value_defanged=str(raw.value),
                    confidence_score=score,
                    confidence_level=level,
                    context_snippet=raw.context_snippet,
                    source_offset=raw.source_offset,
                    entropy_context=raw.entropy_context,
                    extraction_method=raw.extraction_method,
                    tags=flags,
                    scoring_reasons=reasons,
                )
                scored_iocs.append(ioc)
            else:
                stats.filtered_out += 1

        return scored_iocs

    async def _run_stage6_enrichment(self, scored_iocs: list[IOC], stats: AnalysisStats) -> None:
        """Enrichit les IOCs (requêtes asynchrones VirusTotal)."""
        await self.vt_enricher.enrich_bulk(scored_iocs)
        
        # Mettre à jour stats
        for ioc in scored_iocs:
            if getattr(ioc, "vt_result", None) and getattr(ioc.vt_result, "found", False):
                stats.vt_enriched += 1

    def _run_stage7_defanging(self, scored_iocs: list[IOC]) -> list[IOC]:
        """Finalise les IOCs en appliquant le defanging."""
        for ioc in scored_iocs:
            defanged = self.defanger.defang(ioc.value, ioc.type)
            # Puisque IOC est frozen, on bypass la restriction avec object.__setattr__ 
            # (valide ici car le bundle est en cours de construction)
            object.__setattr__(ioc, "value_defanged", defanged)
            
        return scored_iocs
