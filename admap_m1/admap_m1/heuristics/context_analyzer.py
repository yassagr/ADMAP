"""
Module   : admap_m1.heuristics.context_analyzer
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc]

Analyse le contexte d'un IOC pour identifier des "Context Flags"
qui seront utilisés par le Scorer. Implémentation de la section 29.
"""
from __future__ import annotations

import re

from admap_m1.models.ioc import FileMetadata, RawIOC


class ContextAnalyzer:
    """Analyse contextuelle pour tagger les IOCs avant le scoring."""

    # Verbes d'exécution dangereux (à chercher dans le snippet)
    EXECUTION_VERBS = re.compile(
        r'\b(run|execute|shell|download|invoke|start|create|inject|alloc|write)\b',
        re.IGNORECASE
    )

    # APIs suspectes (identiques à PEParser mais pour le texte)
    SUSPICIOUS_APIS = re.compile(
        r'\b(VirtualAlloc|CreateRemoteThread|WriteProcessMemory|LoadLibrary|'
        r'GetProcAddress|InternetOpen|URLDownloadToFile|WSAStartup)\b',
        re.IGNORECASE
    )

    @staticmethod
    def analyze(ioc: RawIOC, metadata: FileMetadata) -> list[str]:
        """Analyse le RawIOC et ses métadonnées pour extraire les flags contextuels.

        Args:
            ioc: L'IOC brut extrait.
            metadata: Les métadonnées du fichier analysé.

        Returns:
            Liste de tags contextuels (ex: 'is_pe_import', 'near_execution_verb').
        """
        flags: list[str] = []

        # 1. Origine de l'extraction
        if ioc.extraction_method == "pe_section":
            flags.append("in_pe_section")
            # Vérifier l'entropie de la section si applicable
            if metadata.pe_info and ioc.section_name:
                for sec in metadata.pe_info.sections:
                    if sec.name == ioc.section_name and sec.is_suspicious:
                        flags.append("in_high_entropy_section")
                        break

        elif ioc.extraction_method == "vba_macro":
            flags.append("in_vba_macro")
            # Le flag "in_autoexec_macro" nécessiterait l'info globale du parser VBA.
            # On va utiliser une heuristique locale sur le snippet pour pallier
            if re.search(r'(autoopen|autoclose|document_open|workbook_open)', ioc.context_snippet, re.IGNORECASE):
                flags.append("in_autoexec_macro")

        # 2. Indicateurs d'obfuscation
        if ioc.in_decoded_layer:
            flags.append("in_decoded_layer")

        # 3. Analyse lexicale du snippet (voisinage)
        snippet = ioc.context_snippet
        if snippet:
            if ContextAnalyzer.EXECUTION_VERBS.search(snippet):
                flags.append("near_execution_verb")
            if ContextAnalyzer.SUSPICIOUS_APIS.search(snippet):
                flags.append("near_suspicious_api")

        # 4. Vérifier si l'IOC a été trouvé dans les imports PE
        if metadata.pe_info and metadata.pe_info.imports:
            # Pour les imports, les valeurs extraites par Regex peuvent ne pas matcher
            # directement. Mais si l'IOC est du texte et correspond à un import...
            # On vérifie seulement si value correspond exactement à un func_name ou dll_name
            val_lower = str(ioc.value).lower()
            found_in_imports = False
            for dll, funcs in metadata.pe_info.imports.items():
                if val_lower == dll:
                    found_in_imports = True
                    break
                for func in funcs:
                    if val_lower == func.lower():
                        found_in_imports = True
                        break
            if found_in_imports:
                flags.append("is_pe_import")

        return flags
