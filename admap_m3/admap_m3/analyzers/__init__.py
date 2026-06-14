"""
Module   : admap_m3.analyzers
Version  : 1.0.0

Analyseurs de fichiers binaires pour l'extraction de features.
"""
from __future__ import annotations

from admap_m3.analyzers.base import BaseAnalyzer
from admap_m3.analyzers.elf_analyzer import ELFAnalyzer
from admap_m3.analyzers.generic_analyzer import GenericBinaryAnalyzer
from admap_m3.analyzers.pe_analyzer import PEAnalyzer
from admap_m3.analyzers.text_analyzer import TextAnalyzer

__all__: list[str] = [
    "BaseAnalyzer",
    "PEAnalyzer",
    "ELFAnalyzer",
    "TextAnalyzer",
    "GenericBinaryAnalyzer",
]
