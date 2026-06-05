"""
Module   : admap_m1.deobfuscators.packer_detector
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc]

Détection heuristique de packers (UPX, MPRESS, etc.) dans les fichiers PE.
M1 ne dépack pas, il détecte seulement et alerte l'analyste.
"""
from __future__ import annotations

from admap_m1.models.ioc import PEInfo


class PackerDetector:
    """Détecte la présence de packers sur un fichier PE.

    M1 est un extracteur statique et ne fait pas de dépacking dynamique
    ou statique avancé (qui requerrait un émulateur). Son rôle est
    d'identifier le packer pour tagguer le fichier.
    """

    # Signatures heuristiques basées sur les noms de sections
    PACKER_SECTIONS = {
        "UPX0": "UPX",
        "UPX1": "UPX",
        "UPX2": "UPX",
        ".MPRESS1": "MPRESS",
        ".MPRESS2": "MPRESS",
        ".aspack": "ASPack",
        ".adata": "ASPack",
        "PECompact2": "PECompact",
        ".tsu": "TSULoader",
        ".vmp0": "VMProtect",
        ".vmp1": "VMProtect",
        ".themida": "Themida",
    }

    @staticmethod
    def detect(pe_info: PEInfo) -> str | None:
        """Détecte le packer d'après les informations PE.

        Args:
            pe_info: Les métadonnées PE extraites.

        Returns:
            Le nom du packer ou None si aucun n'est détecté.
        """
        # 1. Vérifier les noms de sections
        for section in pe_info.sections:
            sec_name = section.name.strip("\x00")
            if sec_name in PackerDetector.PACKER_SECTIONS:
                return PackerDetector.PACKER_SECTIONS[sec_name]

        # 2. Heuristique : peu d'imports et entropie élevée => typique packer custom
        # Si moins de 3 DLLs importées et entropie globale élevée
        if pe_info.sections:
            high_entropy_sections = sum(1 for s in pe_info.sections if s.entropy > 7.0)
            if high_entropy_sections >= 1 and len(pe_info.imports) < 3:
                return "Unknown/Heuristic"

        return None
